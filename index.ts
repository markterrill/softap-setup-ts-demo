import { SoftAP, SoftAPOptions } from './lib/SoftAP';

var defaultPortMapping = {
  tcp: 5609,
  http: 80
};

export class SoftAPSetup extends SoftAP {
  constructor (options:any) {
    var opts:any = SoftAPOptions.defaultOptions();

    opts.protocol = 'tcp';

    SoftAPOptions.assign(opts, options);

    if (opts.protocol !== 'tcp' && opts.protocol !== 'http') {
      throw new Error('Invalid command object specified.');
    }
    if (!opts.port) {
      opts.port = defaultPortMapping[opts.protocol];
    }

    super(opts);
  }
}