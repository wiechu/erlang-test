-module(pwnedpassword).
-export([start/1,start/0]).

% Based on: https://github.com/pczajkowski/pwnedpassword

get_sha1_hex_str(Str) ->
    <<Bin:160>> = crypto:hash( sha, Str ),
    io_lib:format( "~40.16.0B", [Bin] ).

pwned_msg(N) ->
    io:fwrite( "This is how many times your password was pwned: ~s\n", [N] ).

chk_pwned( _, [] ) ->
    io:fwrite("Password not pwned!\n");

chk_pwned( Sfx, [Line|Lines] ) ->
    % Line format is: "35-hex-digits:count"
    [ Hash, N ] = re:split( Line, ":" ),
    if
        Hash =:= Sfx ->
            pwned_msg(N);
        true ->
            chk_pwned( Sfx, Lines )
    end.

start() ->
    io:fwrite("usage:\n  pwnedpassword start <passwd>\n").

start(Pass) ->
    inets:start(),
    ssl:start(),
    crypto:start(),
    BaseUrl = "https://api.pwnedpasswords.com/range/",
    % Let's rock!
    SHA = get_sha1_hex_str(Pass),
    Pfx = string:substr( SHA, 1, 5 ),
    Sfx = list_to_binary(string:substr( SHA, 6 )),
    % TODO check request results
    { _, { { _, _, _ }, _, Body } } = httpc:request( BaseUrl ++ Pfx ),
    chk_pwned( Sfx, re:split( Body, "\r*\n" ) ).
