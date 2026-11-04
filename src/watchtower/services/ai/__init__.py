"""Optional, local-only AI security review with user feedback and project memory.

Project memory is retrieval of saved, owner-approved examples into the model's
context. It never trains, fine-tunes or changes the model.
"""

MEMORY_SENTENCE = ("Approved examples can guide future reviews in this project. "
                   "This does not retrain the model.")
