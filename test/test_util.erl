-module(test_util).

 -include_lib("common_test/include/ct.hrl").

-export([setup/0,
         setup_sock_pair/1, teardown_sock_pair/1,
         setup_mplex_streams/3,
         mk_identify_keys/0,
         pid_should_die/1, wait_until/1, wait_until/3,
         rm_rf/1, nonl/1]).

setup() ->
    application:set_env(lager, error_logger_flush_queue, false),
    application:ensure_all_started(lager),
    lager:set_loglevel(lager_console_backend, debug),
    lager:set_loglevel({lager_file_backend, "log/console.log"}, debug),
    ok.

setup_sock_pair(Config) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}]),
    Parent = self(),
    spawn(fun() ->
                  {ok, ServerSock} = gen_tcp:accept(LSock),
                  gen_tcp:controlling_process(ServerSock, Parent),
                  Parent ! {accepted, ServerSock}
          end),
    {ok, LPort} = inet:port(LSock),
    {ok, CSock} = gen_tcp:connect("localhost", LPort, [binary,
                                                       {active, false},
                                                       {packet, raw},
                                                       {nodelay, true}]),
    receive
        {accepted, SSock} -> SSock
    end,
    [{listen_sock, LSock}, {client_server, {CSock, SSock}} | Config].

setup_mplex_streams(ClientOpts, ServerOpts, Config) ->
    {CSock, SSock} = ?config(client_server, Config),

    %% Server muxer
    {ok, SPid} = libp2p_stream_tcp:start_link(server, #{socket => SSock,
                                                        mod => libp2p_stream_mplex,
                                                        mod_opts => ServerOpts
                                                    }),
    gen_tcp:controlling_process(SSock, SPid),

    %% Client muxer
    {ok, CPid} = libp2p_stream_tcp:start_link(client, #{socket => CSock,
                                                        mod => libp2p_stream_mplex,
                                                        mod_opts => ClientOpts
                                                       }),
    gen_tcp:controlling_process(CSock, CPid),
    [{stream_client_server, {CPid, SPid}} | Config].


teardown_sock_pair(Config) ->
    LSock = ?config(listen_sock, Config),
    catch gen_tcp:close(LSock),
    {CSock, SSock} = ?config(client_server, Config),
    catch gen_tcp:close(CSock),
    catch gen_tcp:close(SSock).

pid_should_die(Pid) ->
    ok == test_util:wait_until(fun() ->
                                       not erlang:is_process_alive(Pid)
                               end).
wait_until(Fun) ->
    wait_until(Fun, 40, 100).

wait_until(Fun, Retry, Delay) when Retry > 0 ->
    Res = Fun(),
    case Res of
        true ->
            ok;
        _ when Retry == 1 ->
            {fail, Res};
        _ ->
            timer:sleep(Delay),
            wait_until(Fun, Retry-1, Delay)
    end.

get_md(K, Pid) ->
    {dictionary, PDict} = erlang:process_info(Pid, dictionary),
    case lists:keyfind('__libp2p_stream_md', 1, PDict) of
        false -> [];
        {_, MD} -> libp2p_stream_md:get(K, MD)
    end.

mk_identify_keys() ->
    #{public := PubKey, secret := PrivKey } = libp2p_crypto:generate_keys(ecc_compact),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    PubKeyBin = libp2p_crypto:pubkey_to_bin(PubKey),
    #{pubkey_bin => PubKeyBin, sig_fun => SigFun }.


-spec rm_rf(file:filename()) -> ok.
rm_rf(Dir) ->
    Paths = filelib:wildcard(Dir ++ "/**"),
    {Dirs, Files} = lists:partition(fun filelib:is_dir/1, Paths),
    ok = lists:foreach(fun file:delete/1, Files),
    Sorted = lists:reverse(lists:sort(Dirs)),
    ok = lists:foreach(fun file:del_dir/1, Sorted),
    file:del_dir(Dir).


nonl([$\n|T]) -> nonl(T);
nonl([H|T]) -> [H|nonl(T)];
nonl([]) -> [].
