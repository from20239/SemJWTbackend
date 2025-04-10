import mongoose from "mongoose";

const subjectSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    teacher: {
        type: String,
        required: true
    },
    students: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User' // Referencia al modelo User
    }]
});

export interface ISubject {
    name: string;
    description: string;
    teacher: string;
    students: mongoose.Schema.Types.ObjectId[];
}

const Subject = mongoose.model('Subject', subjectSchema);
export default Subject;