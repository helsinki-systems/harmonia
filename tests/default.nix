testArgs:
{
  t00-simple = import ./t00-simple.nix testArgs;
  t01-signing = import ./t01-signing.nix testArgs;
  t02-varnish = import ./t02-varnish.nix testArgs;
}
