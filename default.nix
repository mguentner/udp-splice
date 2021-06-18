{ stdenv, buildGoModule, fetchFromGitHub, nixosTests }:

buildGoModule rec {
  pname = "udp-splice";
  version = "1.0.0";

  src = ./.;
  vendorSha256=null;

  subPackages = [ "." ];

  runVend = true;

  meta = with stdenv.lib; {
    description = "Splice UDP packets (receive and send to multiple hosts)";
    homepage = "https://github.com/mguentner/udp-splice";
    license = licenses.gpl2;
    maintainers = with maintainers; [ mguentner ];
  };
}
