from impacket.smbconnection import SMBConnection


def smb_connect(target, share, user, password, domain, lm_hash, nt_hash, timeout=2):
    smb_connection = None
    error = None
    try:
        smb_connection = SMBConnection(target, target, timeout=timeout)
        smb_connection.login(user, password, domain, lm_hash, nt_hash)
        smb_connection.connectTree(share)
    except Exception as e:
        error = e

    return smb_connection, error
