foreach(
    scapfile
    curl_google.scap
    single_ipv6_conn.scap
    test_ipv6_client.scap
)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/${scapfile} ${CMAKE_CURRENT_BINARY_DIR}/${scapfile}
        COPYONLY
    )

endforeach(scapfile)