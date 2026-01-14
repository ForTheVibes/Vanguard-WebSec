var express = require("express");
var multer = require("multer");
var path = require("path");
var app = express();
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const filePath = path.join(__dirname, '..', '..', '..', 'Engine', 'engine.conf'); // Specify the path to your file
const https = require('https');

// import cors
const cors = require("cors");
app.options("*", cors());
app.use(cors());

var bodyParser = require("body-parser");
var urlencodedParser = bodyParser.urlencoded({ extended: false });

app.use(bodyParser.json());
app.use(urlencodedParser);

app.get('/retrieve_uuid', (req, res) => {
  setTimeout(() => {
    // Read the file content
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        console.error('Error reading file:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      // Parse the file content to retrieve the scan_uuid
      const scanUUID = parseScanUUID(data);
      
      // Send the response with the scan_uuid
      res.json({ scan_uuid: scanUUID });
    });
  }, 5000); // 5 seconds in milliseconds
});

app.post('/run_script', (req, res) => {
  const ip_address = req.body.ip_address;

  const scriptPath = '../../Engine/main.py';
  const pythonProcess = spawn('python', [scriptPath, '--scan-start', ip_address]);

  pythonProcess.on('close', (code) => {
    if (code === 0) {
      console.log('Python script executed successfully');
      res.status(200).send('Python script executed successfully');
    } else {
      console.error('Failed to execute Python script');
      res.status(500).send('Failed to execute Python script');
    }
  });
  pythonProcess.stderr.on('data', (data) => {
    console.error(`Python script error: ${data.toString()}`);
  });
});

// Endpoint to retrieve the result scan
app.get('/get-specific-scan/:scan_uuid', (req, res) => {
  const { scan_uuid } = req.params;
  runPythonFunction('retrv_result_scan', scan_uuid)
    .then((result) => res.json(result))
    .catch((error) => res.status(500).send({ error: error }));
});

// Endpoint to get the vuln path pattern
app.get('/get-vuln-path-pattern/:scan_uuid/:cwe_id', (req, res) => {
  const { scan_uuid, cwe_id } = req.params;
  runPythonFunction('get_vuln_path_pattern', scan_uuid, '--cwe_id',cwe_id)
    .then((result) => res.json(result))
    .catch((error) => res.status(500).send({ error: error }));
});

// Endpoint to get all vuln info
app.get('/get-all-vuln-info/:scan_uuid', (req, res) => {
  const { scan_uuid } = req.params;
  runPythonFunction('get_all_vuln_info', scan_uuid)
    .then((result) => {
      console.log(result); // Print the result to the server console
      res.json(result); // Send the result as the response
    })
    .catch((error) => res.status(500).send({ error: error }));
});

function parseScanUUID(fileContent) {
  const lines = fileContent.split('\n');
  const uuidLine = lines.find((line) => line.startsWith('uuid='));
  if (uuidLine) {
    const scanUUID = uuidLine.split('=')[1].trim();
    return scanUUID;
  } else {
    // Handle the case when the 'uuid' line is not found
    return null;
  }
}

function runPythonFunction(functionName, ...args) {
  return new Promise((resolve, reject) => {
    const scriptPath = 'controller/get_db_data.py';
    const commandLine = [scriptPath, functionName, ...args]; // Construct the command line array

    console.log('Running command:', commandLine.join(' ')); // Print the command line

    const pythonProcess = spawn('python', commandLine, { stdio: 'pipe' });
    // const pythonProcess = spawn('python', [scriptPath, functionName, ...args], { stdio: 'pipe' });

    let output = '';

    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      reject(data.toString());
    });

    pythonProcess.on('close', (code) => {
      if (code === 0) {
        try {
          // Parse the JSON data
          const result = JSON.parse(output.trim());
          resolve(result);
        } catch (error) {
          reject(error);
        }
      } else {
        reject(`Python process exited with code ${code}`);
      }
    });
  });
}
module.exports = app;
