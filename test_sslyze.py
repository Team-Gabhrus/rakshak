from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand
scanner = Scanner()
server_location = ServerNetworkLocation(hostname="cloudflare.com", port=443)
scan_request = ServerScanRequest(server_location=server_location, scan_commands={ScanCommand.CERTIFICATE_INFO})
scanner.queue_scans([scan_request])
for r in scanner.get_results():
    cert_info = getattr(r.scan_result, "certificate_info", None)
    print("Cert info dir:", dir(cert_info))
    if cert_info and cert_info.result:
        print("Cert info result dir:", dir(cert_info.result))
