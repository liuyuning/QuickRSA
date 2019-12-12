
Pod::Spec.new do |spec|
  
  spec.name         = "QuickRSA"
  spec.version      = "0.0.1"
  spec.summary      = "RSA Encrypt and Decrypt lib for iOS (Using Security.framework and OpenSSL)"
  spec.description  = <<-DESC
  1. Run script of gen_rsa_key.sh to generate RSA keys
  2. Create a RSA SecKeyRef from data
  3. RSA Enc/Dec/Sign/Verify with SecKeyRef
  4. RSA Enc/Dec with OpenSSL
  5. Format conversion of PEM and DER
  DESC
  
  spec.homepage     = "https://github.com/liuyuning/QuickRSA"
  spec.screenshots  = "https://raw.githubusercontent.com/liuyuning/QuickRSA/master/ScreenShotDemo.png"
  spec.license      = { :type => 'MIT', :file => 'LICENSE.txt' }
  
  spec.author             = { "liuyuning" => "115709874@qq.com" }
  spec.social_media_url   = "https://twitter.com/liuyuning"
  
  spec.platform     = :ios, "8.0"
  spec.source       = { :git => "https://github.com/liuyuning/QuickRSA.git", :tag => "#{spec.version}" }
  
  spec.source_files  = "Classes", "QuickRSA/**/*.{h,m}"
  spec.public_header_files = "QuickRSA/**/*.h"
  
  # == subspec ==
  # spec.default_subspec = 'Static'
  
  spec.subspec 'Static' do |sp|
    sp.source_files        = 'third-party/OpenSSL/include/openssl/**/*.h'
    sp.public_header_files = 'third-party/OpenSSL/include/openssl/**/*.h'
    sp.header_dir          = 'openssl'
    sp.xcconfig            = { "HEADER_SEARCH_PATHS" => "/Users/liuyuning/Desktop/GitHub/QuickRSA/third-party/OpenSSL/include" }
    sp.vendored_libraries  = 'third-party/OpenSSL/lib/libcrypto.a', 'third-party/OpenSSL/lib/libssl.a'
  end
  #   spec.dependency "OpenSSL-Universal", "~> 1.0"
  #   spec.dependency "OpenSSL-Universal", "~> 1.0", :subspecs => %w[Framework]
end
