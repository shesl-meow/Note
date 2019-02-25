> 学习网址：
>
> - https://www.tutorialspoint.com/svn/svn_environment.htm

# SVN

SVN is a Version Control System.

## Life Cycle

1. Create Repository: `create` operation is used to create a new repository.
2. Checkout: `Checkout` operation is used to create a working copy from the repository. 
3. Update: `update` operation is used to update working copy.
4. Perform Changes: 
   - `Rename` operation changes the name of the file/directory.
   - `Move` operation is used to move files/directories from one place to another in a repository tree.
5. Review Changes:`Status` operation lists the modifications that have been made to the working copy. 
6. Fix Mistakes: `Revert` operation reverts the modifications that have been made to the working copy. 
7. Resolve Conflicts: `Merge` operation automatically handles everything that can be done safely.
8. Commit changes: `Commit` operation is used to apply changes from the working copy to the repository.

## Checkout Process

Subversion provides the `checkout` command to check out a working copy from a repository. Below command will create a new directory in the current working directory with the name `project_repo`.

```bash
$ svn checkout http://svn.server.com/svn/project_repo --username=tom
```

After every successful checkout operation, the revision number will get printed. If you want to view more information about the repository, then execute the `info` command:

```bash
$ pwd
/home/tom/project_repo/trunk

$ svn info
```

## Perform Changes

See changes:

```bash
$ svn status
?       array.c
?       array
```

Add `array.c` file to the pending change-list.

```bash
$ svn add array.c 
A         array.c
```

Subversion shows **A** before *array.c*, it means, the file is successfully added to the pending change-list:

```bash
$ svn status
?       array
A       array.c
```

To store `array.c` file to the repository, use the commit command with -m option followed by commit message. If you omit -m option Subversion will bring up the text editor where you can type a multi-line message.

```bash
$ svn commit -m "Initial commit"
Adding         trunk/array.c
Transmitting file data .
Committed revision 2.
```

