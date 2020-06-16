Return-Path: <kasan-dev+bncBCPILY4NUAFBBKOOUD3QKGQEBUVIWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 028411FA5D0
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 03:58:02 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id e82sf22629008ybh.12
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 18:58:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592272682; cv=pass;
        d=google.com; s=arc-20160816;
        b=cijIiHVVvxQUeOh8+nfB0792sFNaiUgyXaA9Xuv9WIvYMkb/xb2HAHLNH1YOvr+YZL
         aLLmXHoWuohcTkm778HKfDe7sOMim8ZoUxLJzdl8b1o4z68pV+T1dtPmGgl6/nRWKD3b
         P5voXQRdi0e5zcQ5ZuXKj0wjYAFIlIPAa2pgK542Pp8H2R/AoAssMtvHWOnON+dIlgI/
         LzubtLJkeJ1G9PDhKZAJ4fxxwg+gEpP2zyEAkKhRaaUX2y5s0HD62KbrhJwhSImt1rAX
         gFjNWi8pBOhGd8Z8cBkPxa+rOwE0BdsMbgMjsLrxlZ+bIXFnvJ9WDi84mPvJhtODazkD
         /AQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=dGNRjPdZCdn5yjfSkXhnHz9ttFv6O8z9J2oCj4Dowuw=;
        b=SYgAioHo4hz5YmoF7/8FDmNHQkg8Wn+8ItBKQs0NEh9XjHsPLIqFbwGFtcWdOtTdmZ
         Ogd12uoL6Xkx8HxOWk7MnpyZTYk8IlQ2z8ZfgmK7VFZjrpb9HRJOn7qItEYzov/G9M4C
         7lQK7isjZdLyk1LHVy+Oss2T49+5R3xuWVia/HApVUr4hJF3G7YeUVHVwwYixQd4YmSx
         aToMO7ZAv9HONzoGBte7RuI5Qu/geTFQr5RZktj7xSzcoH04oBC/NNqXW1XV5y4vnNej
         arXUUtcIe3sIi9O52Rye2M2kBuXc4B7P1M3w5/VlVISd5PQKmnw+YF+Qyg1YgR93JVRj
         HSnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f2FwiIn7;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGNRjPdZCdn5yjfSkXhnHz9ttFv6O8z9J2oCj4Dowuw=;
        b=cM3sK89xDeAFejXlI7NtQi1S4w51S9la4CnzdePFLf5XHQR2Oz+numrkTIbtGLXnSY
         giR0ay0Zq+QgToyY9rJef7f0kcCCP7qpU7aXE+az9TunPgnFG9cpnelW9TTWZznsXtuU
         saRuKZvP050WKbVG+n5SWasFljs7Z+dfs10IDX2N1DY2QkKJ24j25pmbm/ZSzk/rDCKY
         8L2vlcb4KaO8dN4+Hv9w+OcIoXufoAOxRJFAnqX1TdSxXCaRZFT+5j1a52gAl/N6yDMP
         4yzj6szgfuwpsu/yF6sqfj6bdmWRCdLXkraKeISOx8ewnd/eJ0M/CIZFNdUbUEUFPL0U
         nDqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dGNRjPdZCdn5yjfSkXhnHz9ttFv6O8z9J2oCj4Dowuw=;
        b=TSegL88tZKyKGXQVu+2+qrvaoH8Q86NWF9fo3aDo4j3zR9Al8X27H83EuZQEz5+zyM
         SA8ggkMRi7s9vU5tocXIlygq6utuqcGJRw/VBDFPWQCf30sVQ0l0GlopFcyH5GtR+Zq9
         YJ+GZXE2ryRoAaB7tEkLOk37lZcZUqaT1nOGFjcSUL6dWg4ZLf+n/lp5Fq/dh7i+WzxW
         DhK4d8pkevzEJjd2ZKgnrzuLT5/gYVB0hDR0rkGbd4fQnCjnS4EKMiyQmZBk6YDm5lAJ
         ffRXaLwH8EiRmx8XrknQIzGulOxOuPX89VJR+o5wzzl+/lD/7/unoYPG0zfKdKfhg7H9
         oHVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531JBuM19WO8MvYxjCRSMQxvvMAllvasw1/lP1lS5sK+Rz7G58KN
	rTEj7zGEsNbA4gDl89qfhQM=
X-Google-Smtp-Source: ABdhPJwY4CdJ/oJ+Wl/qQU8lMM7gszx/m3f5yKZ9hX7fs3EuBFLvV0QbdqL381sy9oyo0AiydwTvxg==
X-Received: by 2002:a25:408:: with SMTP id 8mr658415ybe.500.1592272681999;
        Mon, 15 Jun 2020 18:58:01 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6602:: with SMTP id a2ls6777043ybc.0.gmail; Mon, 15 Jun
 2020 18:58:01 -0700 (PDT)
X-Received: by 2002:a25:244a:: with SMTP id k71mr713870ybk.143.1592272681597;
        Mon, 15 Jun 2020 18:58:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592272681; cv=none;
        d=google.com; s=arc-20160816;
        b=iMXYO7SKCVof2xByoAglhd7AQyi//fzD4yyb4l66fSlmbrcu51USh8z1K40H3nL6Tx
         J1nWj1GDwrAGt5WXDEciFFf7IZE2EenGYw8zPygzEH+yBL0azOuPbMPp/1aCk+/PL/Y6
         YKnk7YoR9ya0WMrJ0FmUlpq1UHlKGMMdDRAy3YZAVzXdohmVI4nNYflt9uOzd526X1d2
         jrRA/GjHUc1qR0IgU23iX/F7CgpsEki1GXvpX3m6EaSnsE9eEwvyVpwzRxXkhIpU1YGD
         SvqU3Eb0IPhX84bzaRf3GV8UqDC/WkvFV1D7jRBcNby6jPRyKw8O6bjvPV+udH8iCStV
         nutA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=MZUCLAMZdmO5EM+jCfqRymLIPQ+NHghkczuzn6RqHtY=;
        b=zM4GYe2uz1FhwdnBSn0roK5GsfWXFAOVW2epAIAoJfeNzQwhM3EDDEp8H5TdOfC4+t
         PzG1KagDZVr0Gv+x9EAP2mdVLjkJugDho3iKwNeQgsBSxpwiEa722WlTRkpFfM2yv/77
         om7VFq6OM/SFnnpAJFsN4K0IZ8Ry/+YdtFuGzJEmi0OH0A7f5LiaOQA4w1BccRLE1Ruf
         q0NHfeTtbXGj6sdtkMlTO89S9nhbBypOk6/GwkKsSyzR5KExxfd27TEkq+HXd1qhR1Y3
         m4eMIA8Rs1jzPkAMY4HQCToZ9sN/27YUoY75Sp/KKhy2kXjz5PvQSEERGT6nqmiU9Wk2
         vc9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f2FwiIn7;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id n63si974409ybb.1.2020.06.15.18.58.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 18:58:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-343-kG50-M7xPwedRKQDZzJkIQ-1; Mon, 15 Jun 2020 21:57:57 -0400
X-MC-Unique: kG50-M7xPwedRKQDZzJkIQ-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 182E77BB2;
	Tue, 16 Jun 2020 01:57:52 +0000 (UTC)
Received: from llong.com (ovpn-117-41.rdu2.redhat.com [10.10.117.41])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 96E15768AE;
	Tue, 16 Jun 2020 01:57:43 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>,
	Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>
Cc: Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	David Sterba <dsterba@suse.cz>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>,
	linux-mm@kvack.org,
	keyrings@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org,
	netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org,
	ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org,
	tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org,
	Waiman Long <longman@redhat.com>
Subject: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Date: Mon, 15 Jun 2020 21:57:15 -0400
Message-Id: <20200616015718.7812-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=f2FwiIn7;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

 v4:
  - Break out the memzero_explicit() change as suggested by Dan Carpenter
    so that it can be backported to stable.
  - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
    now as there can be a bit more discussion on what is best. It will be
    introduced as a separate patch later on after this one is merged.

This patchset makes a global rename of the kzfree() to kfree_sensitive()
to highlight the fact buffer clearing is only needed if the data objects
contain sensitive information like encrpytion key. The fact that kzfree()
uses memset() to do the clearing isn't totally safe either as compiler
may compile out the clearing in their optimizer especially if LTO is
used. Instead, the new kfree_sensitive() uses memzero_explicit() which
won't get compiled out.

Waiman Long (3):
  mm/slab: Use memzero_explicit() in kzfree()
  mm, treewide: Rename kzfree() to kfree_sensitive()
  btrfs: Use kfree() in btrfs_ioctl_get_subvol_info()

 arch/s390/crypto/prng.c                       |  4 +--
 arch/x86/power/hibernate.c                    |  2 +-
 crypto/adiantum.c                             |  2 +-
 crypto/ahash.c                                |  4 +--
 crypto/api.c                                  |  2 +-
 crypto/asymmetric_keys/verify_pefile.c        |  4 +--
 crypto/deflate.c                              |  2 +-
 crypto/drbg.c                                 | 10 +++---
 crypto/ecc.c                                  |  8 ++---
 crypto/ecdh.c                                 |  2 +-
 crypto/gcm.c                                  |  2 +-
 crypto/gf128mul.c                             |  4 +--
 crypto/jitterentropy-kcapi.c                  |  2 +-
 crypto/rng.c                                  |  2 +-
 crypto/rsa-pkcs1pad.c                         |  6 ++--
 crypto/seqiv.c                                |  2 +-
 crypto/shash.c                                |  2 +-
 crypto/skcipher.c                             |  2 +-
 crypto/testmgr.c                              |  6 ++--
 crypto/zstd.c                                 |  2 +-
 .../allwinner/sun8i-ce/sun8i-ce-cipher.c      |  2 +-
 .../allwinner/sun8i-ss/sun8i-ss-cipher.c      |  2 +-
 drivers/crypto/amlogic/amlogic-gxl-cipher.c   |  4 +--
 drivers/crypto/atmel-ecc.c                    |  2 +-
 drivers/crypto/caam/caampkc.c                 | 28 +++++++--------
 drivers/crypto/cavium/cpt/cptvf_main.c        |  6 ++--
 drivers/crypto/cavium/cpt/cptvf_reqmanager.c  | 12 +++----
 drivers/crypto/cavium/nitrox/nitrox_lib.c     |  4 +--
 drivers/crypto/cavium/zip/zip_crypto.c        |  6 ++--
 drivers/crypto/ccp/ccp-crypto-rsa.c           |  6 ++--
 drivers/crypto/ccree/cc_aead.c                |  4 +--
 drivers/crypto/ccree/cc_buffer_mgr.c          |  4 +--
 drivers/crypto/ccree/cc_cipher.c              |  6 ++--
 drivers/crypto/ccree/cc_hash.c                |  8 ++---
 drivers/crypto/ccree/cc_request_mgr.c         |  2 +-
 drivers/crypto/marvell/cesa/hash.c            |  2 +-
 .../crypto/marvell/octeontx/otx_cptvf_main.c  |  6 ++--
 .../marvell/octeontx/otx_cptvf_reqmgr.h       |  2 +-
 drivers/crypto/mediatek/mtk-aes.c             |  2 +-
 drivers/crypto/nx/nx.c                        |  4 +--
 drivers/crypto/virtio/virtio_crypto_algs.c    | 12 +++----
 drivers/crypto/virtio/virtio_crypto_core.c    |  2 +-
 drivers/md/dm-crypt.c                         | 32 ++++++++---------
 drivers/md/dm-integrity.c                     |  6 ++--
 drivers/misc/ibmvmc.c                         |  6 ++--
 .../hisilicon/hns3/hns3pf/hclge_mbx.c         |  2 +-
 .../net/ethernet/intel/ixgbe/ixgbe_ipsec.c    |  6 ++--
 drivers/net/ppp/ppp_mppe.c                    |  6 ++--
 drivers/net/wireguard/noise.c                 |  4 +--
 drivers/net/wireguard/peer.c                  |  2 +-
 drivers/net/wireless/intel/iwlwifi/pcie/rx.c  |  2 +-
 .../net/wireless/intel/iwlwifi/pcie/tx-gen2.c |  6 ++--
 drivers/net/wireless/intel/iwlwifi/pcie/tx.c  |  6 ++--
 drivers/net/wireless/intersil/orinoco/wext.c  |  4 +--
 drivers/s390/crypto/ap_bus.h                  |  4 +--
 drivers/staging/ks7010/ks_hostif.c            |  2 +-
 drivers/staging/rtl8723bs/core/rtw_security.c |  2 +-
 drivers/staging/wlan-ng/p80211netdev.c        |  2 +-
 drivers/target/iscsi/iscsi_target_auth.c      |  2 +-
 fs/btrfs/ioctl.c                              |  2 +-
 fs/cifs/cifsencrypt.c                         |  2 +-
 fs/cifs/connect.c                             | 10 +++---
 fs/cifs/dfs_cache.c                           |  2 +-
 fs/cifs/misc.c                                |  8 ++---
 fs/crypto/keyring.c                           |  6 ++--
 fs/crypto/keysetup_v1.c                       |  4 +--
 fs/ecryptfs/keystore.c                        |  4 +--
 fs/ecryptfs/messaging.c                       |  2 +-
 include/crypto/aead.h                         |  2 +-
 include/crypto/akcipher.h                     |  2 +-
 include/crypto/gf128mul.h                     |  2 +-
 include/crypto/hash.h                         |  2 +-
 include/crypto/internal/acompress.h           |  2 +-
 include/crypto/kpp.h                          |  2 +-
 include/crypto/skcipher.h                     |  2 +-
 include/linux/slab.h                          |  2 +-
 lib/mpi/mpiutil.c                             |  6 ++--
 lib/test_kasan.c                              |  6 ++--
 mm/slab_common.c                              | 10 +++---
 net/atm/mpoa_caches.c                         |  4 +--
 net/bluetooth/ecdh_helper.c                   |  6 ++--
 net/bluetooth/smp.c                           | 24 ++++++-------
 net/core/sock.c                               |  2 +-
 net/ipv4/tcp_fastopen.c                       |  2 +-
 net/mac80211/aead_api.c                       |  4 +--
 net/mac80211/aes_gmac.c                       |  2 +-
 net/mac80211/key.c                            |  2 +-
 net/mac802154/llsec.c                         | 20 +++++------
 net/sctp/auth.c                               |  2 +-
 net/sctp/socket.c                             |  2 +-
 net/sunrpc/auth_gss/gss_krb5_crypto.c         |  4 +--
 net/sunrpc/auth_gss/gss_krb5_keys.c           |  6 ++--
 net/sunrpc/auth_gss/gss_krb5_mech.c           |  2 +-
 net/tipc/crypto.c                             | 10 +++---
 net/wireless/core.c                           |  2 +-
 net/wireless/ibss.c                           |  4 +--
 net/wireless/lib80211_crypt_tkip.c            |  2 +-
 net/wireless/lib80211_crypt_wep.c             |  2 +-
 net/wireless/nl80211.c                        | 24 ++++++-------
 net/wireless/sme.c                            |  6 ++--
 net/wireless/util.c                           |  2 +-
 net/wireless/wext-sme.c                       |  2 +-
 scripts/coccinelle/free/devm_free.cocci       |  4 +--
 scripts/coccinelle/free/ifnullfree.cocci      |  4 +--
 scripts/coccinelle/free/kfree.cocci           |  6 ++--
 scripts/coccinelle/free/kfreeaddr.cocci       |  2 +-
 security/apparmor/domain.c                    |  4 +--
 security/apparmor/include/file.h              |  2 +-
 security/apparmor/policy.c                    | 24 ++++++-------
 security/apparmor/policy_ns.c                 |  6 ++--
 security/apparmor/policy_unpack.c             | 14 ++++----
 security/keys/big_key.c                       |  6 ++--
 security/keys/dh.c                            | 14 ++++----
 security/keys/encrypted-keys/encrypted.c      | 14 ++++----
 security/keys/trusted-keys/trusted_tpm1.c     | 34 +++++++++----------
 security/keys/user_defined.c                  |  6 ++--
 116 files changed, 322 insertions(+), 322 deletions(-)

-- 
2.18.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616015718.7812-1-longman%40redhat.com.
