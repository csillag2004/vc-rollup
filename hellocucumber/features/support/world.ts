import { setWorldConstructor, World } from '@cucumber/cucumber';
//import { Issuer } from '../../../ts-scripts/issuer';
//import { Holder } from '../../../ts-scripts/holder';
//import { Verifier } from '../../../ts-scripts/verifier';
import { Issuer } from './issuer';
import { Holder } from './holder';
import { Verifier } from './verifier';

class VCWorld extends World {
  issuer!: Issuer;
  holder!: Holder;
  verifier!: Verifier;
  // a stepek között megosztott állapot:
  accumulator: any;
}

setWorldConstructor(VCWorld);
