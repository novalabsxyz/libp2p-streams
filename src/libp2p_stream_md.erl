-module(libp2p_stream_md).

-type md_key() :: stack | addr_info | muxer | identify.

-type stack_kind() :: client | server.
-type md_entry() :: {stack,
                     [{Mod::atom(), Kind::stack_kind()}] |
                     {Mod::atom(), Kind::stack_kind()} |
                     {OldMod::atom(), {Mod::atom(), Kind::stack_kind()}}} |
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

-spec update(md_entry()) -> ok.
update({stack, {Mod, Kind}}) when is_atom(Kind) ->
    Stack = lists:keystore(Mod, 1, ?MODULE:get(stack), {Mod, Kind}),
    update({stack, Stack});
update({stack, {OldMod, {Mod, Kind}}}) ->
    Stack = lists:keyreplace(OldMod, 1, ?MODULE:get(stack), {Mod, Kind}),
    update({stack, Stack});
update({K, V}) ->
    md(lists:keystore(K, 1, md(), {K, V})).


-spec get(md_key()) -> any().
get(K) ->
    get(K, md()).

-spec get(md_key(), md()) -> any().
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
