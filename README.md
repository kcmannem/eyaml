# eYaml - an [ejson](https://github.com/shopify/ejson) copycat

Lets you encrypt inlined secrets and not worry about secret managers.

### How? [DRAFT]

eYaml like ejson prepends the public key used to encrypt values with as `_public_key:`. It traverses your yaml file looking for values to encrypt while leaving keys intact.

In other words it turns this:
```yaml
admin_password: hello
```
Into this:
```yaml
_public_key: sibgn2bskbu249
admin_password: kekngniiqllr11rir994
```

Since eyaml encrypts every possible value it can in your file, you specify a whitelist using the `_encrypt:` key and providing a list of only the keys you want hidden away.


```yaml
_public_key: sibgn2bskbu249
_encrypt:
  - admin_password
  
admin_user: krishna
admin_password: kekngniiqllr11rir994
```
