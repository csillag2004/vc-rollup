import * as path from 'path';
import * as dotenv from 'dotenv';
import { Before } from '@cucumber/cucumber';
import { Verifier } from '../../../ts-scripts/verifier';
import { Holder } from '../../../ts-scripts/holder';
import { Issuer } from '../../../ts-scripts/issuer';
import { setDefaultTimeout } from '@cucumber/cucumber';

setDefaultTimeout(60 * 1000); // 60 másodperc

dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

declare global {
  interface VCWorld {
    issuer: Issuer;
    holder: Holder;
    verifier: Verifier;
  }
}

Before(async function (this: VCWorld) {
  this.issuer = new Issuer();
  this.holder = new Holder();
  this.verifier = new Verifier();
}); 