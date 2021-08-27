
const states = {
    'L': 'Non-existent Account',
    'M': 'Sponsored Lite Account with < 2 * Reserve',
    'N': 'Unsponsored Lite Account',
    'O': 'Full Account',
    'P': 'Sponsored Lite Account with >= 2 * Reserve'
}

const transitions = {
    '0': 'Payment to Account From Sponsor with tfSponsor Flag',
    '1': 'Remove Sponsor from Account (Upgrade 1)',
    '2': 'Become Full Account (Upgrade 2)',
    '3': 'Forced Delete of Account by Sponsor',
    '4': 'Forced Upgrade of Account by Sponsor',
    '5': 'Downgrade Account by Account',
    '6': 'Delete Account by Account',
    '7': 'Normal Payment To Account From Sponsor',
    '8': 'Normal Payment To Sponsor From Account',
    '9': 'Normal Payment To Non-Sponsor account From Account',
    'A': 'Normal Payment To Account from Non-Sponsor'
}

const reserve_base = 200000000;
const lite_reserve = 40000000;
const normal_payment_min = 10;
const normal_payment_max = 50000;

const transition_amounts = {
    '0': ()=>{return lite_reserve * 1.5},
    '1': ()=>{return lite_reserve},
    '4': ()=>{return lite_reserve},
    '7': ()=>{return 2.5 * reserve_base + Math.floor(Math.random() * normal_payment_min + normal_payment_max)},
    '8': ()=>{return Math.floor(Math.random() * normal_payment_min + normal_payment_max)},
    '9': ()=>{return Math.floor(Math.random() * normal_payment_min + normal_payment_max)},
    'A': ()=>{return 2.5 * reserve_base + Math.floor(Math.random() * normal_payment_min + normal_payment_max)}
}

const  transition = {
    'L': {'0': 'M', '7': 'O'},
    'M': {'3': 'L', '7': 'P', '8': 'M', '9': 'M', 'A': 'P'},
    'N': {'2': 'O', '6': 'L', '7': 'N', '8': 'N', '9': 'M', 'A': 'N'},
    'O': {'5': 'N', '6': 'L', '7': 'O', '8': 'O', '9': 'M', 'A': 'O'},
    'P': {'4': 'N', '1': 'N', '3': 'L', '7': 'P', '8': 'P', '9': 'P', 'A': 'P'}
}

const lsfSponsor = 0x00080000;
const asfSponsored = 11;
const asfLiteAccount = 10;

var global_error_counter = 10000;

const transition_action = {
    '0': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Payment with tfSponsor flag from sponsor to account
        return generate_payment(indent_level, s, positive_test, resolve, reject,
            sponsor_seed, sponsor, amount, account, lsfSponsor,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '1': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed,third_account, third_account_seed, amount) => {
        // Remove sponsor (Upgrade 1)
        return generate_accountset(indent_level, s, positive_test, resolve, reject,
            account_seed, account, null, asfSponsored, 
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '2': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Become Full (Upgrade 2)
        return generate_accountset(indent_level, s, positive_test, resolve, reject,
            account_seed, account, null, asfLiteAccount, 
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '3': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Forced Delete by Sponsor
        return generate_accountdelete(indent_level, s, positive_test, resolve, reject,
            sponsor_seed, account, sponsor, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
    },
    '4': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Forced Upgrade 1 by Sponsor
        return generate_accountset(indent_level, s, positive_test, resolve, reject,
            sponsor_seed, account, null, asfSponsored, 
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '5': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Downgrade by accoount
        return generate_accountset(indent_level, s, positive_test, resolve, reject,
            account_seed, account, asfLiteAccount, null, 
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '6': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Delete by Accoount
        return generate_accountdelete(indent_level, s, positive_test, resolve, reject,
            account_seed, account, sponsor, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
    },
    '7': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Sponsor
        return generate_payment(indent_level, s, positive_test, resolve, reject,
            sponsor_seed, sponsor, amount, account, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '8': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Account
        return generate_payment(indent_level, s, positive_test, resolve, reject,
            account_seed, account, amount, sponsor, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '9': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Account to third account
        return generate_payment(indent_level, s, positive_test, resolve, reject,
            account_seed, account, amount, third_account, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    'A': (indent_level, s, positive_test, resolve, reject,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Non-Sponsor
        return generate_payment(indent_level, s, positive_test, resolve, reject,
            third_account_seed, third_account, amount, account, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    }
}

function generate_code(indent_level, s, positive_test, resolve, reject,
                        sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = ""

    /*
    out =  '/' + '* ' + s + JSON.stringify({
        positive_test: positive_test,
        resolve: resolve,
        reject: reject,
        sponsor: sponsor,
        sponsor_seed: sponsor_seed,
        account: account,
        account_seed: account_seed,
        third_account: third_account,
        third_account_seed: third_account_seed
    }) + '*' + '/' + "\n";
    */

    if (s == "")
        return out + spacer.repeat(indent_level) + resolve + '(); // t1\n';

    c = s.slice(0,1)
    // todo check current state c

    t = s.slice(1,2)

    if (t == "")
        return out + spacer.repeat(indent_level) + resolve + '(); // t2\n';

    amount = null
    if (t in transition_amounts)
        amount = transition_amounts[t]()
    return out + spacer.repeat(indent_level) + '/* ' + transitions[t] + ' [' + t + '] */\n' +
                transition_action[t](indent_level, s.slice(2), positive_test, resolve, reject,
                    sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount);
}


const spacer = '    ';
function human_readable(indent_level, s)
{
    let out = "";
    let level = 1;
    for (let x in s)
    {
        x = parseInt(x, 16)
        if (x == s.length-1)
            break;
        let c = s[x];
        let n = (x + 1 < s.length ? s[x+1] : '')
        n = (n in states ? "(" + states[n] + ")" : "(INVALID)")
        if (c in transitions)
            out += " + " +
                transitions[c] + "" + (n != '' ? " = " + n : "") + (x == s.length-2 ? "" : "\n")
        else if (c in states)
            out += spacer.repeat(indent_level + level) + "(" + states[c] + ")"
        else if (c == 'X')
            out += spacer.repeat(indent_level + level) + "(INVALID)"
        else
            throw("invalid char " + c)
    }

    return out;
}

function generate_payment(indent_level, s, positive_test, resolve, reject, seed, from, amount, dest, flags,
                          sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = "";
    /*
    out =  '/' + '* PAYMENT ' + s + "\n" + 
        "positive_test: " + positive_test + ",\n" +
        "resolve: " + resolve + ",\n" +
        "reject:" + reject + ",\n" +
        "from: " + from + ",\n" +
        "amount: " + amount + ",\n" +
        "dest: " + dest + ",\n" +
        "flags: " + flags + ",\n" +
        "sponsor: " + sponsor + ",\n" +
        "sponsor_seed: " + sponsor_seed + ",\n" +
        "account: " + account + ",\n" +
        "account_seed: " + account_seed + ",\n" +
        "third_account: " + third_account + ",\n" +
        "third_account_seed: " + third_account_seed + '*' + '/' + "\n";
    */
    out += spacer.repeat(indent_level) + 'api.prepareTransaction({\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'Account: ' + from + ',\n';
        out += spacer.repeat(indent_level) + 'TransactionType: "Payment",\n';
        out += spacer.repeat(indent_level) + 'Amount: "' + amount + '",\n';
        out += spacer.repeat(indent_level) + 'Destination: ' + dest + ',\n';
        if (flags)
            out += spacer.repeat(indent_level) + 'Flags: ' + flags + ',\n';
        out += spacer.repeat(indent_level) + 'Fee: "10000"\n';
    indent_level--;
    out += spacer.repeat(indent_level) + '}).then(unsigned_txn => {\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'console.log("submitting txn", unsigned_txn.txJSON);\n';
        out += spacer.repeat(indent_level) + 'let signed_txn = api.sign(unsigned_txn.txJSON, ' + seed + ')\n';
        out += spacer.repeat(indent_level) + 'api.submit(signed_txn.signedTransaction).then(response => {\n';
        indent_level++;
        if (s.length > 1)
        {
            out += spacer.repeat(indent_level) + 'if (response.resultCode != "tesSUCCESS") return ' + reject + 
                '([response.resultCode,' + global_error_counter++ + ']);\n';
            out += generate_code(indent_level, s, positive_test, resolve, reject,
                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed
            );
        }
        else
            out += spacer.repeat(indent_level) + resolve + '(response.resultCode ' +
                (positive_test ? '=' : '!') + '= "tesSUCCESS");\n';
        indent_level--;
        out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    return out;
}

function generate_accountdelete(indent_level, s, positive_test, resolve, reject, seed, from, dest, flags,
                                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = "";
    out += spacer.repeat(indent_level) + 'api.prepareTransaction({\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'Account: ' + from + ',\n';
        out += spacer.repeat(indent_level) + 'TransactionType: "AccountDelete",\n';
        out += spacer.repeat(indent_level) + 'Destination: ' + dest + ',\n';
        if (flags)
            out += spacer.repeat(indent_level) + 'Flags: ' + flags + ',\n';
        out += spacer.repeat(indent_level) + 'Fee: "10000"\n';
    indent_level--;
    out += spacer.repeat(indent_level) + '}).then(unsigned_txn => {\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'console.log("submitting txn", unsigned_txn.txJSON);\n';
        out += spacer.repeat(indent_level) + 'let signed_txn = api.sign(unsigned_txn.txJSON, ' + seed + ')\n';
        out += spacer.repeat(indent_level) + 'api.submit(signed_txn.signedTransaction).then(response => {\n';
        indent_level++;
        if (s.length > 1)
        {
            out += spacer.repeat(indent_level) + 'if (response.resultCode != "tesSUCCESS") return ' + reject + 
                '([response.resultCode,' + global_error_counter++ + ']);\n';
            out += generate_code(indent_level, s, positive_test, resolve, reject,
                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed
            );
        }
        else
            out += spacer.repeat(indent_level) + resolve + '(response.resultCode ' +
                (positive_test ? '=' : '!') + '= "tesSUCCESS");\n';
        indent_level--;
        out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    return out;
}

function generate_accountset(indent_level, s, positive_test, resolve, reject, seed, from, setflag, clearflag,
                             sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = "";
    out += spacer.repeat(indent_level) + 'api.prepareTransaction({\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'Account: ' + from + ',\n';
        out += spacer.repeat(indent_level) + 'TransactionType: "AccountSet",\n';
        if (setflag !== undefined && setflag !== null)
            out += spacer.repeat(indent_level) + "SetFlag: " + setflag + ",\n";
        else
            out += spacer.repeat(indent_level) + "ClearFlag: " + clearflag + ",\n";
        out += spacer.repeat(indent_level) + 'Fee: "10000"\n';
    indent_level--;
    out += spacer.repeat(indent_level) + '}).then(unsigned_txn => {\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'console.log("submitting txn", unsigned_txn.txJSON);\n';
        out += spacer.repeat(indent_level) + 'let signed_txn = api.sign(unsigned_txn.txJSON, ' + seed + ')\n';
        out += spacer.repeat(indent_level) + 'api.submit(signed_txn.signedTransaction).then(response => {\n';
        indent_level++;
        if (s.length > 1)
        {
            out += spacer.repeat(indent_level) + 'if (response.resultCode != "tesSUCCESS") return ' + reject + 
                '([response.resultCode,' + global_error_counter++ + ']);\n';
            out += generate_code(indent_level, s, positive_test, resolve, reject,
                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed
            );
        }
        else
            out += spacer.repeat(indent_level) + resolve + '(response.resultCode ' +
                (positive_test ? '=' : '!') + '= "tesSUCCESS");\n';
        indent_level--;
        out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    return out;
}




function positive(state, stack, positive_cases)
{

    if (positive_cases === undefined)
        positive_cases = [];

    if (stack == undefined) stack = "";

    if (stack.match(state))
    {
        positive_cases.push(stack + state);
        return;
    }

    stack += state;

    for (let x in transition[state])
        positive(transition[state][x], stack + x, positive_cases);

    return positive_cases;
}

function negative(state, stack, negative_cases)
{
    if (negative_cases === undefined)
        negative_cases = [];

    if (stack == undefined) stack = "";

    if (stack.match(state))
    {
        return;
    }

    stack += state;

    let allowed_transitions = transition[state];

    for (let t in transitions)
        if (!(t in transition[state]))
            negative_cases.push(stack + t + 'X');
        else
            negative(transition[state][t], stack + t, negative_cases);

    return negative_cases;
}


let positive_cases = positive('L').sort();
let negative_cases = negative('L').sort();
let counter = 1;

// print header
console.log(`
const keypairs = require("ripple-keypairs")
const api_factory = require('ripple-lib').RippleAPI
const api = new api_factory({server: 'ws://localhost:6005'})

function random_address()
{
    let s = keypairs.generateSeed()
    let k = keypairs.deriveKeypair(s)
    let r = keypairs.deriveAddress(k.publicKey)
    return {seed: s, address: r, key: k}
}

const genesis = {seed: 'snoPBrXtMeMyMHUVTgbuqAfg1SUTb', address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'};
const sponsor = random_address();
const third = random_address();

api.connect().then(() => {
    (new Promise((resolve, reject)=>{
`);
console.log(generate_payment(2, '', true, 'resolve','reject', 'genesis.seed', 'genesis.address', '100000000000', 'sponsor.address', ''));
console.log(`
    })).then(setup_result=>{
        console.log("setup result:", setup_result);
        tests = {};
        tests_description = {};
        const tests_updated = (testid)=>{
            console.log(tests_description[testid])
            console.log("===> " + (tests[testid] === true ? 'PASS' : 
                tests[testid] === false ? 'FAIL' : tests[testid]))
        }
`);


function produce_cases(cases, namespace, counter = 0, should_succeed = true)
{
    for (let x in cases)
    {
        console.log(spacer.repeat(2) + '/* ' + namespace + ' test ' + counter + ' [' + cases[x] + ']')
        console.log(human_readable(2, cases[x]) + ' */')
        console.log(spacer.repeat(2) + 'let test' + counter + ' = new Promise((resolve, reject)=>{');
        console.log(spacer.repeat(3) + 'const account = random_address();');
        console.log(spacer.repeat(3) + "tests_description[" + counter + "] = `" + namespace + " test " + counter + ": " + cases[x] + "\n" + human_readable(1, cases[x]) + "`;")
        console.log(generate_code(3, cases[x], should_succeed, 'resolve', 'reject',
            'sponsor.address', 'sponsor.seed', 'account.address', 'account.seed', 'third.address', 'third.seed'));
        console.log(spacer.repeat(2) + '});')
        console.log(spacer.repeat(2) + 'test' + counter + '.then(result=>{tests[' + counter + 
            '] = result; tests_updated('+counter+');})' +
            '.catch(e=>{tests[' + counter + 
            ']="ERROR: " + JSON.stringify(e); tests_updated(' + counter + ');})');
        counter++;
    }
    return counter
}

counter = produce_cases(positive_cases.slice(0,1), "positive", 0, true);
//produce_cases(negative_cases, "negative", counter, false);


console.log(`
    }).catch(e=>{throw(e);});
`);
console.log('}).catch(console.error);');

