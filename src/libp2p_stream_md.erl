-module(libp2p_stream_md).

-type md_key() :: stack | addr_info | muxer | identify.
-type md_entry() :: {stack, {atom(), client | server}} |
                    {addr_info, {Local::string(), Remote::string()}} |
                    {muxer, pid()} |
                    {identify, identify_md()}.
-type md() :: [md_entry()].
-type identify_entry() :: {addr_info, {LocalP2P::string(), RemoteP2P::string()}} |
                          {observed_addr, string()}.
-type identify_md() :: [identify_entry()].

-export([update/1, get/1, get/2,
         md/0, md/1
        ]).

-define(LIBP2P_STREAM_MD_KEY, '__libp2p_stream_md').

-spec update(md_entry()) -> md().
update({stack, {Mod, NewKind}}) ->
    Stack = lists:keystore(Mod, 1, ?MODULE:get(stack, md()), {Mod, NewKind}),
    update({stack, Stack});
update({K, V}) ->
    md(lists:keystore(K, 1, md(), {K, V})).


-spec get(md_key()) -> md_entry() | undefined.
get(K) ->
    get(K, md()).

-spec get(md_key(), md()) -> md_entry() | undefined.
get(stack, MD) ->
    case lists:keyfind(stack, 1, MD) of
        false -> [];
        {stack, Other} -> Other
    end;
get(K, MD) ->
    case lists:keyfind(K, 1, MD) of
        false -> undefined;
        {K, Other} -> Other
    end.

-spec md() -> md().
md() ->
    case erlang:get(?LIBP2P_STREAM_MD_KEY) of
        undefined -> [];
        MD-> MD
    end.


-spec md(md()) -> ok.
md(MD) when is_list(MD) ->
    erlang:put(?LIBP2P_STREAM_MD_KEY, MD),
    ok.
