package fs

/*

$ yum install pki,io

$ cd a/path

$ pki.io org create a_name

$ cat ~/.pki.io.conf

[a_name]
org_id = abc
path = a/path

$ cd a_name

$ ls 

  private/
    abc.json
    abc/
  public/
    abc/

$ pki.io admin init fscott

$ ls

  private/
    abc.json
    abc/
    xxx.json
    xxx/
  public/
    abc/
    xxx/
:w
*/
