
const states = {
    'A': 'Non-existent Account',
    'B': 'Sponsored Lite Account',
    'C': 'Unsponsored Lite Account',
    'D': 'Full Account'
}

const transitions = {
    '0': 'Payment with tfSponsor Flag',
    '1': 'Remove Sponsor (Upgrade 1)',
    '2': 'Become Full (Upgrade 2)',
    '3': 'Forced Delete by Sponsor',
    '4': 'Forced Upgrade by Sponsor',
    '5': 'Downgrade',
    '6': 'Delete Account',
    '7': 'Normal Payment'
}

function human_readable(s)
{
    let out = "";
    let level = 1;
    const spacer = '    ';
    for (let x in s)
    {
        x = parseInt(x)
        if (x == s.length-1)
            break;
        let c = s[x];
        let n = (x + 1 < s.length ? s[x+1] : '')
        n = (n in states ? "(" + states[n] + ")" : "(INVALID)")
        if (c in transitions)
            out += " + " + transitions[c] + "" + (n != '' ? " = " + n : "") + "\n"
        else if (c in states)
            out += spacer.repeat(level) + "(" + states[c] + ")"
        else if (c == 'X')
            out += spacer.repeat(level) + "(INVALID)"
        else
            throw("invalid char " + c)
    }

    return out;
}

const  transition = {
    'A': {0: 'B', 7: 'D'}, 
    'B': {3: 'A', 4: 'C', 1: 'C', 7: 'B'},
    'C': {2: 'D', 6: 'A', 7: 'C'},
    'D': {5: 'C', 6: 'A', 7: 'D'}      
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


let positive_cases = positive('A').sort();


let counter = 1;
for (let x in positive_cases)
{
    console.log('POSITIVE TEST ' +(counter++) + " [" + positive_cases[x] + "]")
    console.log(human_readable(positive_cases[x]))
}

let negative_cases = negative('A').sort();
for (let x in negative_cases)
{
    console.log('NEGATIVE TEST ' +(counter++) + " [" + negative_cases[x] + "]")
    console.log(human_readable(negative_cases[x]))
}
