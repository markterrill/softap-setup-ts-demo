var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
import { SoftAP, SoftAPOptions } from './lib/SoftAP';
var defaultPortMapping = {
    tcp: 5609,
    http: 80
};
var SoftAPSetup = /** @class */ (function (_super) {
    __extends(SoftAPSetup, _super);
    function SoftAPSetup(options) {
        var _this = this;
        var opts = SoftAPOptions.defaultOptions();
        opts.protocol = 'tcp';
        SoftAPOptions.assign(opts, options);
        if (opts.protocol !== 'tcp' && opts.protocol !== 'http') {
            throw new Error('Invalid command object specified.');
        }
        if (!opts.port) {
            opts.port = defaultPortMapping[opts.protocol];
        }
        _this = _super.call(this, opts) || this;
        return _this;
    }
    return SoftAPSetup;
}(SoftAP));
export { SoftAPSetup };
//# sourceMappingURL=index.js.map