import Forum, { IForum } from './forum_models.js';

export const createEntry = async (forumData: IForum) => {
    const user = new Forum(forumData);
    return await user.save();
};

export const getAllForum = async () => {
    return await Forum.find();
};

export const getEntryById = async (id: string) => {
    return await Forum.findById(id);
};

export const updateEntry = async (id: string, updateData: Partial<IForum>) => {
    return await Forum.updateOne({ _id: id }, { $set: updateData });
};

export const deleteEntry = async (id: string) => {
    return await Forum.deleteOne({ _id: id });
};
