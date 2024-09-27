#!/usr/bin/python3
import sys
import json

target = " ".join(sys.argv[1:])
to_array = [
	"as_path",
	"comms",
	"lcomms",
	"ecomms"
]

with open(target) as f:
	lines = f.readlines()

json_data = [json.loads(line) for line in lines]

for (i, j) in enumerate(json_data):
	for prop in to_array:
		if prop in j:
			# already an array
			if type(j[prop]) == list:
				continue
			j[prop] = j[prop].strip().split(" ") if j[prop] is not None else []


with open(target, "w") as f:
	[f.write(f"{json.dumps(j)}\n") for j in json_data]
