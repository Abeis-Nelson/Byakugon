user_inputs = [] #input list to store the user inputs 
clear_list = user_inputs.clear() #to clear the input list 

#Getting user inputs
def getting_input():
	while True:
		line = input()
		if line:
			user_inputs.append(line)
		else:
			break
	return user_inputs

	


    