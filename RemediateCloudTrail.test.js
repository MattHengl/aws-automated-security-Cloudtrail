/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 
/*!
    To run this test, you will need:
    1) AWS CLI installed
    2) Access to Sandbox, with a specific access level
*/


//Test function for RemediateUsers.js

const config = require('./config.json');

// //Environment variable values defined from the config.json file.
Object.keys(config).forEach((key) => {
    process.env[key] = config[key];
});

const main = require('./RemediateCloudTrail'); 
const Master = require('aws-automated-master-class/MasterClass').handler;
const getEvent = require('aws-automated-master-class/EventCreater').handler;
let master = new Master();
let path = require('aws-automated-master-class/MasterClass').path;

//overriding the ses.sendEmail operation to just log the html snippet
master.setSes((params) => {
    // let html = params.Message.Body.Html.Data;
    // html = html.replace('data:image/jpeg;base64,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', 'annoying image link');
    // console.log(html);
    return {promise: () => {}};
});

// main.setSqsFunction('sendMessage',(params) => {
//     return {promise: () => {}};
// });
// main.setIamFunction('deleteLoginProfile', (params) => {
//     return {promise: () => {}};
// });

master.setDynamo((params) => {
    return {promise: () => {}};
});
master.setTable((params) => {
    let pulledItem = {
        Item: {}
    }
    return {promise: () => {return pulledItem}};
})

// console.log = (message, attachment) => {};

//*******remediationTest() parameter examples**********
//event > the event that is passed to the main function. (Call getEvent())
//functionName > "detachUserPolicy" (no cap on first letter). The aws iam function you 
//want to override

//_____________getEvent() parameters for reference_____________
//env, launch, eventName, requestParameters, responseElements

let today = new Date();
var date = today.getFullYear() + '-' + (today.getMonth()+1) + '-' + today.getDate();
var time = (today.getHours()-12) + ":" + today.getMinutes() + ":" + today.getSeconds();
var dateTime = date + ' ' + time;

const checkTagsAndAddToTable = jest.fn();
main.setCheckTagsAndAddToTable(checkTagsAndAddToTable);
const remediateDynamo = jest.fn();
main.setRemediateDynamo(remediateDynamo);
const remediate = jest.fn();
main.setRemediate(remediate);  
const autoTag = jest.fn();
main.setAutoTag(autoTag);

master.putItemInTable = jest.fn();

var event;
let env = 'dev';
let RP = {
    name: "tester",
    s3BucketName: "A-Bucket",
    includeGlobalServiceEvents: true,
    isMultiRegionTrail: true,
    enableLogFileValidation: true,
    kmsKeyId: "",
    isOrganizationTrail: false
};
let RE = {
    name: "tester",
    s3BucketName: "A-Bucket",
    includeGlobalServiceEvents: true,
    isMultiRegionTrail: true,
    trailARN: "arn:aws:cloudtrail:us-west-2:<arn>:trail/tester",
    logFileValidationEnabled: true,
    isOrganizationTrail: false
};

beforeEach(async() => {
    path.p = 'Path: ';
});
describe('HandleEvent', () => {
    describe('DynamoDB event', () => {
        tester(env, 'console', 'Testing handleEvent with a dynamoDB event', 'REMOVE', 'tester', {});
        tester(env, 'console', 'Testing handleEvent with a dynamoDB event that should error out', 'REMOVE', null, {});
    });
    describe('Regular Event', () => {
        tester(env, 'console', 'Testing handleEvent with a regular event(CreateTrail)', 'CreateTrail', RP, RE);
        tester(env, 'console', 'Testing handleEvent with a regular event(DeleteTrail)', 'DeleteTrail', RP, RE);
        tester(env, 'console', 'Testing handleEvent with a regular event(StartLogging)', 'StartLogging', RP, RE);
        tester(env, 'console', 'Testing handleEvent with a regular event(StopLogging)', 'StopLogging', RP, RE);
        tester(env, 'console', 'Testing handleEvent with a regular event(UpdateTrail)', 'UpdateTrail', RP, RE);
        tester(env, 'console', 'Testint handleEvent with a regular event which should error out', 'CreateTrail', null, null);
        tester(env, 'console', 'Testing handleEvent with a regular event that should trip errorInlog', 'CreateTrail', 'error', {});
        tester(env, 'console', 'Testing handleEvent with a regular event that is triggered from its self', 'CreateTrail', 'FromSelf', {});
    });
    function tester(environment, launch, description, eventName, requestParams, responseEle){
        test(description, async() => {
            console.log(`---------------${description}---------------`);
            if(eventName == 'REMOVE'){    
                if(requestParams == null){
                    console.log('Should be erroring out.');
                    await main.setCloudTrailFunction('listTags', (params) => {
                        return {promist: () => {throw new Error()}};
                    });
                    Path = 'Path: \nEntered handleEvent\nEvent is DynamoDB\nEvent is of type CloudTrail and has an event of REMOVE\nERROR';
                } 
                else{
                    console.log('Event is a dynamodb event');
                    Path = 'Path: ';
                    let tags = {
                        ResourceTagList: [{
                            TagsList: [
                                {
                                    Key: "TechOwner",
                                    Value: "internemail1@email.com"
                                },
                                {
                                    Key: "Environment",
                                    Value: "snd"
                                }
                            ]
                        }]
                    }
                    await main.setCloudTrailFunction('listTags', (params) => {
                        return {promise: () => {return tags}};
                    });
                    Path = 'Path: \nEntered handleEvent\nEvent is DynamoDB\nEvent is of type CloudTrail and has an event of REMOVE' +
                        '\nTagVerification failed\nResource has the incorrect tags\nSending to user\nDynamoDB event HTML\nGot HTML to send to user\nEmail sent to internEmail1@email.com';
                }   
                event = getEvent(environment, launch, eventName, 'CloudTrail', requestParams, responseEle, dateTime);
                await main.handler(event);
            }else{
                if(requestParams == null || responseEle == null){
                    console.log('Event is a regular event with an error');
                    await main.handler({});
                    Path = 'Path: \nEntered handleEvent\nEvent is Not DynamoDB\nERROR';
                }else{
                    event = getEvent(environment, launch, eventName, 'CloudTrail', requestParams, responseEle, dateTime);
                    console.log('Event is a regular event');
                    remediate.mockReturnValue(master.getResults(event, {ResourceName: event.detail.requestParameters.name}));
                    await main.handler(event);
                    if(eventName == 'CreateTrail'){
                        if(env == 'dev'){
                            Path = `Path: \nEntered handleEvent\nEvent is Not DynamoDB\nNo Error in log\nNot Self Invoked` +
                                `\nEvent is created through console\nPerformed through console and in dev/prd so event log is invalid` +
                                `\nSending to user\nResourceName being added to DynamoDB HTML\nGot HTML to send to user\nEmail sent to internEmail1@email.com`;
                        }else{
                            Path = 'Path: \nEntered handleEvent\nEvent is Not DynamoDB\nNo Error in log\nNot Self Invoked' +
                                '\nPerformed in snd so event is valid';
                        }
                    }else if(eventName == 'DeleteTrail'){
                        if(env == 'dev'){
                            Path = 'Path: \nEntered handleEvent\nEvent is Not DynamoDB\nNo Error in log\nNot Self Invoked' +
                                `\nEvent is created through console\nPerformed through console and in dev/prd so event log is invalid` +
                                `\nSending to user\nResourceName being added to DynamoDB HTML\nGot HTML to send to user\nEmail sent to internEmail1@email.com`;
                        }else{
                            Path = 'Path: \nEntered handleEvent\nEvent is Not DynamoDB\nNo Error in log\nNot Self Invoked' +
                                '\nPerformed in snd so event is valid\nSending to user\nResourceName being added to DynamoDB HTML\nGot HTML to send to user' +
                                '\nEmail sent to internEmail1@email.com';
                        }
                    }else{
                        if(env == 'dev'){
                            Path = `Path: \nEntered handleEvent\nEvent is Not DynamoDB\nNo Error in log\nNot Self Invoked` +
                                `\nEvent is created through console\nPerformed through console and in dev/prd so event log is invalid` +
                                `\nSending to user\nResourceName being added to DynamoDB HTML\nGot HTML to send to user\nEmail sent to internEmail1@email.com`;
                        }else{
                            Path = 'Path: \nEntered handleEvent\nEvent is Not DynamoDB\nNo Error in log\nNot Self Invoked' + 
                                '\nPerformed in snd so event is valid';
                        }
                    }
                }
                if(requestParams == 'error'){
                    console.log('Has error in log');
                    event.detail.errorCode = 'ERRORINLOG';
                    await main.handler(event);
                    Path = `Path: \nEntered handleEvent\nEvent is Not DynamoDB\nError in log ERRORINLOG`;
                }
                if(requestParams == 'FromSelf'){
                    console.log('Is being selfInvoked');
                    console.log(event);
                    event.detail.userIdentity.arn = process.env.name;
                    console.log(event);
                    await main.handler(event);
                    Path = `Path: \nEntered handleEvent\nEvent is Not DynamoDB\nNo Error in log\nSelf Invoked`;
                }
            }
            expect(path.p).toEqual(Path);
        });
    }
});
describe('Remediate', () => {
    describe('CreateTrail', () => {
        remediateTester(env, 'console','Testing remediate with an event of CreateTrail','CreateTrail','deleteTrail', RP, RE);
    });
    describe('DeleteTrail', () => {
        remediateTester(env, 'console','Testing remediate with an event of DeleteTrail','DeleteTrail','', RP, RE);
    });
    describe('UpdateTrail', () => {
        remediateTester(env, 'console','Testing remediate with an event of UpdateTrail','UpdateTrail','', RP, RE);
    });
    describe('StartLogging', () => {
        remediateTester(env, 'console','Testing remediate with an event of StartLogging','StartLogging','stopLogging', RP, RE);
        remediateTester(env, 'console','Testing remediate with an event of StartLogging which should be an error','StartLogging','stopLogging', null, null);
    });
    describe('StopLogging', () => {
        remediateTester(env, 'console','Testing remediate with an event of StopLogging','StopLogging','startLogging', RP, RE);
    });
});
describe('RemediateDynamoDB', () => {
    dynamoTester(env, 'console', 'Testing remediateDynamo with an event of CreateTrail', 'CreateTrail', RP, RE);
    dynamoTester(env, 'console', 'Testing remediateDynamo with an event of REMOVE', 'REMOVE', 'tester', null);
});
describe('CheckTagsAndAddToTable', () => {
    addToTableTester(env, 'console', 'Testing checkTagsAndAddToTable with an event', 'CreateTrail', RP, RE);
    addToTableTester(env, 'console', 'Testing checkTagsAndAddToTable with an event which should be an error', 'CreateTrail', null, null)
});
describe('AutoTag', () => {
    let tags = {
        Key: "Environment",
        Value: "snd"
    };
    autoTagTester(env, 'console','Testing autoTag with an event that is missing tag3', 'CreateTrail', tags, RP, RE);
    tags = {
        Key: `${process.env.tag3}`,
        Value: "internemail1@email.com"
    };
    autoTagTester(env, 'console','Testing autoTag with an event that is missing environment', 'CreateTrail', tags, RP, RE);
});
function remediateTester(environment, launch, description, eventName, response, requestParams, responseEle){
    test(description, async() => {
        console.log(`---------------${description}---------------`);
        event = getEvent(environment, launch, eventName, 'CloudTrail', requestParams, responseEle, dateTime);
        if(requestParams == null || responseEle == null){
            await main.setCloudTrailFunction(response, (params) => {
                return {promise: () => {throw new Error()}};
            });
            Path = `Path: \nEntered the remediation function\nStartLogging\nERROR`;
        }
        
        await main.setCloudTrailFunction(response, (params) => {
            return {promise: () => {}};
        });
        Path = `Path: \nEntered the remediation function\n${eventName}\nRemediation was finished`;
        await main.remediate(event);
        expect(path.p).toEqual(Path);
    });
}
function dynamoTester(environment, launch, description, eventName, requestParams, responseEle){
    test(description, async() => {
        console.log(`---------------${description}---------------`);
        event = getEvent(environment, launch, eventName, 'CloudTrail', requestParams, responseEle, dateTime);
        await main.setCloudTrailFunction('deleteTrail', (params) => {
            return {promise: () => {}};
        })
        if(eventName == 'REMOVE'){
            await main.remediateDynamo(event, master.dbConverter(event));
        }else{
            await main.remediateDynamo(event, master.getResults(event));
        }
        Path = `Path: \nEntered RemediateDynamo\ntester was deleted`;
        expect(path.p).toEqual(Path);
    });
};
function addToTableTester(environment, launch, description, eventName, requestParams, responseEle){
    test(description, async() => {
        console.log(`---------------${description}---------------`);
        event = getEvent(environment, launch, eventName, 'CloudTrail', requestParams, responseEle, dateTime);
        if(requestParams == null || responseEle == null){
            autoTag.mockRejectedValue({code: 'NoSuchEntity'});
            Path = `Path: \nEntering checkTagsAndAddToTable, Created params for function call\nERROR`;
        }else{
            let tags = [ { Key: 'TechOwner', Value: 'internEmail1@email.com' },
                { Key: 'Environment', Value: 'snd' }];
            autoTag.mockReturnValue(tags);
            await main.setDBFunction('putItem', (params) => {
                return {promise: () => {}};
            });
            if(env == 'dev'){
                Path = `Path: \nEntering checkTagsAndAddToTable, Created params for function call\nCalled AutoTag function\nTagVerification failed` +
                    `\nChecking table for item\nFound tester in the table`;
            }else{
                Path = `Path: \nEntering checkTagsAndAddToTable, Created params for function call\nCalled AutoTag function\nTagVerification failed` +
                    `\nChecking table for item\nFound tester in the table`;
            }
        }
        await main.checkTagsAndAddToTable(event);
        expect(path.p).toEqual(Path);
    });
};
function autoTagTester(environment, launch, description, eventName, tags, requestParams, responseEle){
    test(description, async() => {
        console.log(`---------------${description}---------------`);
        event = getEvent(environment, launch, eventName, 'CloudTrail', requestParams, responseEle, dateTime);
        await main.setCloudTrailFunction('listTags', (params) => {
            return {promise: () => {return { ResourceTagList: [{ TagsList: [ tags ]}]}}};
        });
        await main.setCloudTrailFunction('addTags', (params) => {
            return {promise: () => {}};
        });
        await main.autoTag(event);
        if(tags.Key == 'Environment'){
            if(env == 'dev'){
                Path = `Path: \nEnvironment found`;
            }else{
                Path = `Path: \nNo tag3 found\nAdding tag3 to resource\nEnvironment found`;
            }
        }else{
            if(env == 'dev'){
                Path = `Path: \nNo Environment found\nAdding Environment to resource`;
            }else{
                Path = `Path: \ntag3 found\nNo Environment found\nAdding Environment to resource`;
            }
        }
        expect(path.p).toEqual(Path);
    });
};