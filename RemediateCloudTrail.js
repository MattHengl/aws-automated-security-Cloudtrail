/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//
//Main file that controls remediation and notifications for all CloudTrail changes. 
//Remediates actions when possible or necessary based on launch type and tagging. Then, notifies the user/security. 

//Make sure to that the master.invalid call does NOT have a ! infront of it
//Make sure to delete or comment out the change in the process.env.environtment

const AWS = require('aws-sdk');
AWS.config.update({region: process.env.region});
const cloudtrail = new AWS.CloudTrail();
const Master = require("aws-automated-master-class/MasterClass").handler;
let path = require("aws-automated-master-class/MasterClass").path;
const master = new Master();
const dynamodb = new AWS.DynamoDB();

let improperLaunch = false;

//Variables that allow these functions to be overridden in Jest testing by making the variable = jest.fn() 
//instead of its corresponding function
let callAutoTag = autoTag;
let callCheckTagsAndAddToTable = checkTagsAndAddToTable;
let callRemediate = remediate;
let callRemediateDynamo = remediateDynamo;
let callHandler = handleEvent;

//Only used for testing purposes
setCloudTrailFunction = (value, funct) => {
  cloudtrail[value] = funct;
};

async function handleEvent(event){

  console.log(process.env.environment);

  console.log(JSON.stringify(event));
  path.p = 'Path: \nEntered handleEvent';

  if(master.checkDynamoDB(event)){
      
    let convertedEvent = master.dbConverter(event);
    console.log(convertedEvent);
    //Extra console.log statements for testing ===================================
    if (convertedEvent.ResourceName) {
       console.log(`DynamoDB event "${convertedEvent.ResourceName}" is being inspected----------`);
    } else {
       console.log(`DynamoDB event "${event.Records[0].dynamodb.Keys.ResourceName.S}" is being inspected----------`);
    }

    //==================================================
    if (convertedEvent.ResourceType == "CloudTrail" && event.Records[0].eventName == 'REMOVE'){
      path.p += '\nEvent is of type CloudTrail and has an event of REMOVE';
      try{
        let listParams = {ResourceIdList: []};
        if(event.Records[0].dynamodb.OldImage.Action.S == 'CreateTrail'){
          listParams.ResourceIdList.push(`arn:aws:cloudtrail:${process.env.region}:${process.env.sndNum1}:trail/` + event.Records[0].dynamodb.Keys.ResourceName.S);
        }else{
          listParams.ResourceIdList.push(event.Records[0].dynamodb.Keys.ResourceName.S);
        }
      
        let tags = await cloudtrail.listTags(listParams).promise();

        if (!(master.tagVerification(tags.ResourceTagList[0].TagsList))) {
            path.p += '\nResource has the incorrect tags';
            await callRemediateDynamo(event, convertedEvent);
            await master.notifyUser(event, convertedEvent, 'CloudTrail');    
        }    
      }
      catch(e){
        console.log(e);
        path.p += '\nERROR';
        console.log(path.p);
        return e;
      }     
    } else {
      path.p += '\nEvent was not of type CloudTrail and didn\'t have an event of REMOVE';
    }
    console.log(path.p);
    return;
  };

  try{

    event = master.devTest(event);
    console.log(process.env.environment);
    //Checks if there is an error in the log
    if (master.errorInLog(event)) {
      console.log(path.p);
      return; 
    }

    //Checks if the log came from this function, quits the program if it does.
    if (master.selfInvoked(event)) {
      console.log(path.p);
      return;
    }

    console.log(`"${event.detail.requestParameters.name}" is being inspected----------`);
    console.log(`Event action is ${event.detail.eventName}---------- `);

    //if(master.checkKeyUser(event, 'name')){
      //Delete the ! if there is one. Only use ! for testing.
      if(master.invalid(event)){
        improperLaunch = true;
        console.log('Calling notifyUser');
        await master.notifyUser(event, await callRemediate(event), 'CloudTrail');
        if(event.detail.eventName == 'CreateTrail' || event.detail.eventName == 'DeleteTrail'){
            console.log('Event is either CreateTrail or DeleteTrail');
            console.log(path.p);
            return;
        }
      }
      if(event.detail.eventName == 'DeleteTrail'){
        await master.notifyUser(event, await callRemediate(event), 'CloudTrail');
      }else{
        await callCheckTagsAndAddToTable(event)
      }
      console.log(path.p);
      // delete path.p;
    //}
  }catch(e){
    console.log(e);
    path.p += '\nERROR';
    console.log(path.p);
    return e;
  }
};

//Checks for and auto adds tags and then adds resource to the table if it is missing any other tags
async function checkTagsAndAddToTable(event){
  path.p += '\nEntering checkTagsAndAddToTable, Created params for function call';
  let params = {Name: event.detail.requestParameters.name};
  let tags = {};
  try{
    tags = await callAutoTag(event);
    path.p += '\nCalled AutoTag function';
    console.log(tags);
    if (!(master.tagVerification(tags))) {
      //Delete this when  you want to move outside of the environments of snd!
      // process.env.environment = 'snd';
      await master.putItemInTable(event, 'CloudTrail', params.Name);
      return true;
    }else{
      return false;
    }
  }catch(e){
    console.log(e);
    path.p += '\nERROR';
    return e;
  }
}

async function remediate(event){

    path.p += '\nEntered the remediation function';

    const erp = event.detail.requestParameters;

    let params = { Name: erp.name };
    let results = master.getResults(event, {ResourceName: erp.name});

    try{
        switch(results.Action){
          //Done?
            case 'CreateTrail':
                path.p += '\nCreateTrail';
                //DeleteTrail
                //await cloudtrail.deleteTrail(params).promise();
                results.Response = 'DeleteTrail';
                results.Reason = 'Improper Launch';
                await callRemediateDynamo(event, results);
            break;
            //Done
            case 'DeleteTrail':
                path.p += '\nDeleteTrail';
                //Notify
                results.Response = 'Remediation could not be performed';
            break;
            //Not Done
            case 'UpdateTrail':
                path.p += '\nUpdateTrail';
                //UpdateTrail/Notify?
                results.Response = 'Remediation could not be performed?';
            break;
            //Done
            //Having issues with this function call being called WITH CreateTrail
            case 'StartLogging':
                path.p += '\nStartLogging';
                await overrideFunction('stopLogging', params);
                results.Response = 'StopLogging';
            break;
            //Done
            case 'StopLogging':
                path.p += '\nStopLogging';
                await overrideFunction('startLogging', params);
                results.Response = 'StartLogging';
            break;
        }
    }catch(e){
      console.log(e);
      path.p += '\nERROR';
      return e;
    }
    results.Reason = 'Improper Launch';
    if(results.Response == 'Remediation could not be performed'){
      delete results.Reason;
    }
    path.p += '\nRemediation was finished';
    console.log(results);
    return results;
};

async function remediateDynamo(event, results){

  path.p += '\nEntered RemediateDynamo';
  let params = {};
  if(results.KillTime){
    params = {Name: results.ResourceName};
  }else{
    params = {Name: event.detail.requestParameters.name};
  }
  await overrideFunction('deleteTrail', params);
  path.p += `\n${params.Name} was deleted`;
};

//**********************************************************************************************
//Automatically adds missing tags, TechOwner and Environment, if needed 
async function autoTag(event) {

  console.log('Entered autoTag');
  let listParams = {ResourceIdList: []};
  if(event.detail.eventName == 'CreateTrail'){
    listParams.ResourceIdList.push(event.detail.responseElements.trailARN);
  }else{
    listParams.ResourceIdList.push(event.detail.requestParameters.name);
  }
  let tags = await cloudtrail.listTags(listParams).promise();
  tags = tags.ResourceTagList[0].TagsList;

  let addParams = {};
  if(event.detail.eventName == 'CreateTrail'){
    addParams.ResourceId = event.detail.responseElements.trailARN;
  }else{
    addParams.ResourceId = event.detail.requestParameters.name;
  }
  //checks if env is sandbox AND checks for and adds TechOwner tag
  if (master.snd(event) && master.needsTag(tags, `${process.env.tag3}`)){
     
    //Adds the TechOwner tag to the resource
    //await master.getParamsForAddingTags(event, params, `${process.env.tag3}`)
    addParams.TagsList = [{Key: `${process.env.tag3}`, Value: master.getEntity(event)}];
    await cloudtrail.addTags(addParams).promise();
    tags = await cloudtrail.listTags(listParams).promise();
    tags = tags.ResourceTagList[0].TagsList;
    path.p += `\nAdding ${process.env.tag3} to resource`;
  }
  //checks if the resource has an environment tag and adds it if it doesn't
  if (master.needsTag(tags, 'Environment')) {
     
     //Adds the Environment tag to the resource
     //await master.getParamsForAddingTags(event, params, 'Environment')
     addParams.TagsList = [{Key: `Environment`, Value: process.env.environment}];
     await cloudtrail.addTags(addParams).promise();
     tags = await cloudtrail.listTags(listParams).promise();
     tags = tags.ResourceTagList[0].TagsList;
     path.p += '\nAdding Environment to resource';
  }
  return tags;
};

async function overrideFunction(apiFunction, params){
  if(process.env.run == 'false'){
    await setCloudTrailFunction(apiFunction, (params) => {
      console.log(`Overriding ${apiFunction}`);
      return {promise: () => {}};
    });
  }
  await cloudtrail[apiFunction](params).promise();
};

exports.handler = handleEvent;
exports.checkTagsAndAddToTable = checkTagsAndAddToTable; 
exports.remediateDynamo = remediateDynamo;
exports.autoTag = autoTag;
exports.remediate = remediate;

//overrides the given function (only for jest testing)
exports.setCloudTrailFunction = (value, funct) => {
    cloudtrail[value] = funct;
};
exports.setHandler = (funct) => {
  callHandler = funct;
};
exports.setAutoTag = (funct) => {
  callAutoTag = funct;
};
exports.setRemediate = (funct) => {
  callRemediate = funct;
};
exports.setRemediateDynamo = (funct) => {
  callRemediateDynamo = funct;
};
exports.setCheckTagsAndAddToTable = (funct) => {
  callCheckTagsAndAddToTable = funct;
};
exports.setDBFunction = (value, funct) => {
  dynamodb[value] = funct;
};