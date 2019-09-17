-module(libp2p_stream_md).

-type md_key() :: stack | addr_info | muxer | identify.

-type stack_kind() :: client | server.
-type md_entry() :: {stack,
                     [{Mod::atom(), Kind::stack_kind()}] |
                     {Mod::atom(), Kind::stack_kind()} |
                     {OldMod::atom(), {Mod::atom(), Kind::stack_kind()}}} |
                    {addr_info, {Local::string(), Remote::string()}} |
                    {muxer, pid()} |
                    {identify, libp2p_identify:identify()}.
-type md() :: [md_entry()].

-export([update/1, update/2,
         get/1, get/2,
         md/0, md/1
        ]).

-define(LIBP2P_STREAM_MD_KEY, '__libp2p_stream_md').

-spec update(md_entry()) -> md().
update(Entry) ->
    md(update(Entry, md())).

-spec update(md_entry(), md()) -> md().
update({stack, {Mod, Kind}}, MD) when is_atom(Kind) ->
    Stack = lists:keystore(Mod, 1, ?MODULE:get(stack, MD), {Mod, Kind}),
    update({stack, Stack}, MD);
update({stack, {OldMod, {Mod, Kind}}}, MD) ->
    Stack = lists:keyreplace(OldMod, 1, ?MODULE:get(stack, MD), {Mod, Kind}),
    update({stack, Stack}, MD);
update({K, V}, MD) ->
    lists:keystore(K, 1, MD, {K, V}).


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


-spec md(md()) -> md().
md(MD) when is_list(MD) ->
    erlang:put(?LIBP2P_STREAM_MD_KEY, MD),
    MD.
