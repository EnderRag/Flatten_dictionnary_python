# Le script retourne un string au format {}\n{}\n{}\n{}

def flatten(json_obj: list) -> str:
    result = ""
    result_list = []
    curr_dict = {}

    def flatten_dict_rec(dictio: dict, result_list: list, curr_dict: dict) -> None:
        final_rec = True

        # Ajout des valeurs non dictionnaire

        for k, v in dictio.items():
            if type(v) != list:
                curr_dict[k] = v
            else:
                try:
                    if type(v[0]) != dict:
                        curr_dict[k] = v
                except IndexError:
                    curr_dict[k] = v

        # Récursion sur dictionnaire

        for k, v in dictio.items():
            if type(v) == list:
                try:
                    if type(v[0]) == dict:
                        final_rec = False
                        for dictio_v in v:
                            copy_dict = curr_dict.copy()
                            flatten_dict_rec(dictio_v, result_list, copy_dict)
                except IndexError:
                    pass

        if final_rec:
            result_list.append(curr_dict)
        return

    for ip_dict in json_obj:
        curr_dict = {}
        flatten_dict_rec(ip_dict, result_list, curr_dict)

    for i in result_list:
        result += str(i) + "\n"

    return result

json_obj = [
    {
        "ip": ".60.94.33",
        "scan_list": [
            {
                "scan_name": "syn",
                "status": "found",
                "port_list": [
                    {
                        "port": "113/tcp",
                        "state": "closed",
                        "service": "ident"
                    },
                    {
                        "port": "2000/tcp",
                        "state": "open",
                        "service": "cisco-sccp"
                    },
                    {
                        "port": "5060/tcp",
                        "state": "open",
                        "service": "sip"
                    },
                    {
                        "port": "8008/tcp",
                        "state": "open",
                        "service": "http"
                    }
                ],
                "infos": []
            },
            {
                "scan_name": "udp",
                "status": "Couldn't find anything",
                "port_list": []
            },
            {
                "scan_name": "version",
                "status": "found",
                "port_list": [
                    {
                        "port": "113/tcp",
                        "state": "closed",
                        "service": "ident"
                    },
                    {
                        "port": "2000/tcp",
                        "state": "open",
                        "service": "cisco-sccp?"
                    },
                    {
                        "port": "5060/tcp",
                        "state": "open",
                        "service": "sip?"
                    },
                    {
                        "port": "8008/tcp",
                        "state": "open",
                        "service": "http"
                    }
                ],
                "infos": []
            },
            {
                "scan_name": "connect",
                "status": "found",
                "port_list": [
                    {
                        "port": "113/tcp",
                        "state": "closed",
                        "service": "ident"
                    },
                    {
                        "port": "2000/tcp",
                        "state": "open",
                        "service": "cisco-sccp"
                    },
                    {
                        "port": "5060/tcp",
                        "state": "open",
                        "service": "sip"
                    },
                    {
                        "port": "8008/tcp",
                        "state": "open",
                        "service": "http"
                    }
                ],
                "infos": []
            }
        ]
    },
    {
        "ip": ".60.94.34",
        "scan_list": [
            {
                "scan_name": "syn",
                "status": "found",
                "port_list": [
                    {
                        "port": "113/tcp",
                        "state": "closed",
                        "service": "ident"
                    },
                    {
                        "port": "2000/tcp",
                        "state": "open",
                        "service": "cisco-sccp"
                    },
                    {
                        "port": "5060/tcp",
                        "state": "open",
                        "service": "sip"
                    },
                    {
                        "port": "8008/tcp",
                        "state": "open",
                        "service": "http"
                    }
                ],
                "infos": []
            },
            {
                "scan_name": "udp",
                "status": "Couldn't find anything",
                "port_list": []
            },
            {
                "scan_name": "version",
                "status": "found",
                "port_list": [
                    {
                        "port": "113/tcp",
                        "state": "closed",
                        "service": "ident"
                    },
                    {
                        "port": "2000/tcp",
                        "state": "open",
                        "service": "cisco-sccp?"
                    },
                    {
                        "port": "5060/tcp",
                        "state": "open",
                        "service": "sip?"
                    },
                    {
                        "port": "8008/tcp",
                        "state": "open",
                        "service": "http"
                    }
                ],
                "infos": []
            },
            {
                "scan_name": "connect",
                "status": "found",
                "port_list": [
                    {
                        "port": "113/tcp",
                        "state": "closed",
                        "service": "ident"
                    },
                    {
                        "port": "2000/tcp",
                        "state": "open",
                        "service": "cisco-sccp"
                    },
                    {
                        "port": "5060/tcp",
                        "state": "open",
                        "service": "sip"
                    },
                    {
                        "port": "8008/tcp",
                        "state": "open",
                        "service": "http"
                    }
                ],
                "infos": []
            }
        ]
    },
    {
        "ip": ".60.94.62",
        "scan_list": [
            {
                "scan_name": "syn",
                "status": "Couldn't find anything",
                "port_list": []
            },
            {
                "scan_name": "udp",
                "status": "Couldn't find anything",
                "port_list": []
            },
            {
                "scan_name": "version",
                "status": "Couldn't find anything",
                "port_list": []
            },
            {
                "scan_name": "connect",
                "status": "Couldn't find anything",
                "port_list": []
            }
        ]
    },
    {
        "ip": ".0.0.1",
        "scan_list": [
            {
                "scan_name": "os_scan",
                "status": "found",
                "os_infos": [
                    "Device type: general purpose",
                    "Running: Linux 2.6.X",
                    "OS CPE: cpe:/o:linux:linux_kernel:2.6.32",
                    "OS details: Linux 2.6.32",
                    "Network Distance: 0 hops"
                ]
            }
        ]
    },
    {
        "ip": ".0.0.1",
        "scan_list": [
            {
                "scan_name": "cve",
                "status": "found",
                "port_list": [
                    {
                        "port": "25/tcp",
                        "state": "open",
                        "service": "smtp",
                        "cve": [
                            "CVE-2020-28026 9.3 https://vulners.com/cve/CVE-2020-28026",
                            "CVE-2020-28021 9.0 https://vulners.com/cve/CVE-2020-28021",
                            "CVE-2020-28024 7.5 https://vulners.com/cve/CVE-2020-28024",
                            "CVE-2020-28022 7.5 https://vulners.com/cve/CVE-2020-28022",
                            "CVE-2020-28018 7.5 https://vulners.com/cve/CVE-2020-28018",
                            "CVE-2020-28016 7.2 https://vulners.com/cve/CVE-2020-28016",
                            "CVE-2020-28015 7.2 https://vulners.com/cve/CVE-2020-28015",
                            "CVE-2020-28013 7.2 https://vulners.com/cve/CVE-2020-28013",
                            "CVE-2020-28012 7.2 https://vulners.com/cve/CVE-2020-28012",
                            "CVE-2020-28011 7.2 https://vulners.com/cve/CVE-2020-28011",
                            "CVE-2020-28010 7.2 https://vulners.com/cve/CVE-2020-28010",
                            "CVE-2020-28009 7.2 https://vulners.com/cve/CVE-2020-28009",
                            "CVE-2020-28008 7.2 https://vulners.com/cve/CVE-2020-28008",
                            "CVE-2020-28007 7.2 https://vulners.com/cve/CVE-2020-28007",
                            "CVE-2021-27216 6.3 https://vulners.com/cve/CVE-2021-27216",
                            "CVE-2020-28014 5.6 https://vulners.com/cve/CVE-2020-28014",
                            "CVE-2021-38371 5.0 https://vulners.com/cve/CVE-2021-38371",
                            "CVE-2020-28025 5.0 https://vulners.com/cve/CVE-2020-28025",
                            "CVE-2020-28023 5.0 https://vulners.com/cve/CVE-2020-28023"
                        ]
                    }
                ],
                "infos": [
                    "smtp-vuln-cve2010-4344: ",
                    "The SMTP server is not Exim: NOT VULNERABLE",
                    "sslv2-drown: ",
                    "vulners: ",
                    "cpe:/a:exim:exim:4.94.2: "
                ]
            }
        ]
    }
]
print(flatten(json_obj))
