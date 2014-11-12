Pod::Spec.new do |spec|
  spec.name         = 'Ecc25519'
  spec.version      = '1.0'
  spec.license      = { :type => 'GPLv3' }
  spec.homepage     = 'https://github.com/mukarev/Ecc25519'
  spec.preserve_path = 'Sources/ed25519/**/*.{c,h}'
  spec.authors      = { 'Markus Kosmal' => 'mko@adorsys.de' }
  spec.summary      = 'Provider for elliptic curve/edwards cryptographic functionalities'
  
  spec.description  =  <<-DESC
    Extended elliptic curve/edwards provider with optimized x64 support. Uses work of D.J. Bernstein, Adam Langley, Matthijs van Duin, Trevor Perrin and others.
  DESC

  spec.source       = { :git => 'https://github.com/mukarev/Ecc25519.git', :tag => "#{spec.version}" }
  spec.source_files = 'Classes/*.{h,m}', 'Sources/ed25519/*.{c,h}','Sources/Curve25519/curve25519-donna.c', 'Sources/Curve25519/curve25519_i64/*.{c,h}' , 'Sources/ed25519/*.{c,h}', 'Sources/ed25519/additions/*.{c,h}', 'Sources/ed25519/sha512/sha2big.{c,h}', 'Sources/ed25519/sha512/sph_sha2.h', 'Sources/ed25519/nacl_includes/*.{c,h}'
  spec.private_header_files = 'Sources/ed25519/*.h', 'Sources/ed25519/nacl_includes/*.h','Sources/ed25519/additions/*.h', 'Sources/ed25519/sha512/*.h'
  spec.framework    = 'Security'
  spec.public_header_files = "Classes/*.h"
  spec.requires_arc = true
end
