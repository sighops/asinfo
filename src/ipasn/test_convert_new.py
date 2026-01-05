from ipasn import newrt as mrtx

f = open('/Users/caleb/.ipasn/cache/rib', 'rb')

out_file = '/Users/caleb/.ipasn/cache/rib_converted'

prefixes = mrtx.parse_mrt_file(
            f,
            print_progress=True,
            skip_record_on_error=True
        )
mrtx.dump_prefixes_to_file(prefixes, out_file)