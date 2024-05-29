import mongoose from "mongoose";

const noteSchema = mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    content: {
        type: String,
        required: true
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    sharedWith: [{
        email: {
            type: String
        },
        permission: {
            type: String,
            enum: ['read-only', 'editable'],
            default: 'read-only'
        }
    }],
    date: {
        type: Date,
        default: Date.now
    }
})

const Note = mongoose.model("Note", noteSchema);

export default Note;