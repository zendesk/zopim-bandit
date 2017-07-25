import sys
import json
import linecache
import hashlib
import argparse

def hash(toHash):
	hash_object = hashlib.sha256()
	hash_object.update(toHash)
	hex_dig = hash_object.hexdigest()
	return hex_dig

def issueAttribute(i):
	issueAttributes=""
	filename = i["filename"]
	issueAttributes += filename
	testId = i["test_id"]
	issueAttributes += testId
	rawCode = i["code"]
	issueAttributes += rawCode
	lineRange = i["line_range"]
	for lineNumber in lineRange:
		codeExtract = linecache.getline(filename,lineNumber).rstrip().lstrip()
		issueAttributes += codeExtract	
	return issueAttributes

def calculateIssueHash(i):
	return hash(issueAttribute(i))

def scanResult(issueFingerprint, i, issueSeverity):
	REDC = '\033[31m'
	YELC = '\033[33m'
	BLUC = '\033[36m'
	ENDC = '\033[0m'

	if(issueSeverity=="HIGH"):
		COLOR = REDC
	elif(issueSeverity=="MEDIUM"):
		COLOR = YELC
	else:
		COLOR = BLUC

	output = "--------------------------------------------------\n"
	output += COLOR + "Issue Fingerprint: " + issueFingerprint + "\n"
	output += COLOR + "Issue Severity: %s \t Confidence Level: %s" % (i["issue_severity"], i["issue_confidence"]) + "\n"
	output += COLOR + "Location: %s"  % i["filename"] + "\n"
	output += COLOR + "Issue: %s" % i["issue_text"] + "\n\n"
	output += "Code: \n%s" % i["code"]
	output += ENDC
	return output

def scanSummary(data, falsePositiveSignatures):
	PINKC = '\033[35m'
	ENDC = '\033[0m'
	LINEOFCODE = data["metrics"]["_totals"]["loc"]
	FALSEPOSITIVE = len(falsePositiveSignatures)
	HIGHSEVERITY = data["metrics"]["_totals"]["SEVERITY.HIGH"]
	MEDIUMSEVERITY = data["metrics"]["_totals"]["SEVERITY.MEDIUM"]
	LOWSEVERITY = data["metrics"]["_totals"]["SEVERITY.LOW"]
	HIGHCONFIDENCE = data["metrics"]["_totals"]["CONFIDENCE.HIGH"]
	MEDIUMCONFIDENCE = data["metrics"]["_totals"]["CONFIDENCE.MEDIUM"]
	LOWCONFIDENCE = data["metrics"]["_totals"]["CONFIDENCE.LOW"]

	output =  PINKC + "Code scanned:\n"
	output += "          Total lines of code: %s\n" % (LINEOFCODE)
	output += "          Total false positives: %s\n" % (FALSEPOSITIVE)
	output += PINKC + "\nTotal issues (by severity):\n"
	output += "          High: %s\n" % (HIGHSEVERITY)
	output += "          Medium: %s\n" % (MEDIUMSEVERITY)
	output += "          Low: %s\n" % (LOWSEVERITY)
	output += PINKC + "\nTotal issues (by confidence):\n"
	output += "          High: %s\n" % (HIGHCONFIDENCE)
	output += "          Medium: %s\n" % (MEDIUMCONFIDENCE)
	output += "          Low: %s" % (LOWCONFIDENCE)
	output += ENDC
	return output

def main(argv):
	#Return code to pass/fail travis test
	exitCode = 0

	parser = argparse.ArgumentParser()
	parser.add_argument("-o", "--output", help="bandit output")
	parser.add_argument("-i", "--ignore", help="bandit.ignore file")
	args = parser.parse_args()

	banditOutputFile = args.output
	banditIgnore = args.ignore

	with open(banditOutputFile) as data_file:
		data = json.load(data_file)

	with open(banditIgnore) as file:
		falsepositive = json.load(file)
		
	falsePositiveSignatures = []
	findings = []

	for i in falsepositive["false_positives"]:
		falsePositiveSignatures.append(i["fingerprint"])

	for i in data["results"]:
		issueFingerprint = calculateIssueHash(i)
		if(issueFingerprint not in falsePositiveSignatures):
			findings.append(i)

	issue_weight = dict(HIGH=0, MEDIUM=1, LOW=2)
	findings.sort(key=lambda x: issue_weight[x["issue_confidence"]])
	findings.sort(key=lambda x: issue_weight[x["issue_severity"]])

	for i in findings:
		issueFingerprint = calculateIssueHash(i)
		print scanResult(issueFingerprint, i, i["issue_severity"])

	print scanSummary(data, falsePositiveSignatures)
	sys.exit(exitCode)

if __name__ == "__main__":
    main(sys.argv)
