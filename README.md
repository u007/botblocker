# botblocker

to block bad traffic from infected machines and servers (requires csf)

files ignored:

- \*bytes_log
- \*~
- \*.swp
- \*.swpx

# production

```
cd botblocker
./bb.exe watch /usr/local/apache/domlogs
```
