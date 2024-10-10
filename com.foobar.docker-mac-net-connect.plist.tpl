<!--- Example blatantly ripped off from http://www.launchd.info/ -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>com.foobar.docker-mac-net-connect</string>
		<key>EnvironmentVariables</key>
		<dict>
			<key>DOCKER_MAC_NET_SETUP_IMAGE_TAG</key>
			<string>v0.1.3</string>
		</dict>
		<key>StandardOutPath</key><string>/tmp/docker-mac-net-connect.out.log</string>
		<key>StandardErrorPath</key><string>/tmp/docker-mac-net-connect.err.log</string>
		<key>WorkingDirectory</key>
		<string>{{ .WorkingDir }}</string>
		<key>Program</key>
		<string>{{ .BinPath }}</string>
		<key>KeepAlive</key><true/>
	</dict>
</plist>
