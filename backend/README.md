# Backend setup

Apply the SQL files in `migrations` in order. Migration `003` keeps existing
admin accounts approved and moves existing student accounts to pending. New
public signups and accounts created by admins also require approval. To set up
the first administrator, create an account and promote its email using your
database:

```sql
UPDATE users SET role = 'admin' WHERE email = 'admin@example.com';
```

After the first administrator exists, admins can create admin accounts and
manage account roles from the dashboard.

Set `SESSION_SECRET` in `backend/.env` to a private random value of at least
32 characters. The API uses it to sign its HTTP-only login cookie. Set
`FRONTEND_ORIGIN` if the React app is served from somewhere other than
`http://localhost:5173`.

Administrators can create, view, update, and delete student registrations.
Student accounts can submit one registration for their own account and can only
view registration records whose email matches their account email. The
registration name and email are taken from the signed-in account.

Administrators can also create student or admin accounts, view accounts, and
change account roles. They can approve pending accounts or reject them, which
deletes the login account but keeps any linked student registration. An admin
cannot remove their own administrator access or delete their own account, the
last admin cannot be demoted or deleted, and an approved account linked to a
student registration cannot be deleted until that registration is removed.
