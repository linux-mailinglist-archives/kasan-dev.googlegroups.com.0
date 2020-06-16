Return-Path: <kasan-dev+bncBCPILY4NUAFBBPORUP3QKGQEIIGDTSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 911981FB71D
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 17:43:58 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id q24sf16089286pfs.7
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 08:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592322237; cv=pass;
        d=google.com; s=arc-20160816;
        b=RSnuNdXuH+7gDj5puCow7MI5gpFdEPXZJ+KVBFfpJOJ434xMP0KaoANYj1jdKAxMnQ
         /Dr/1ODiNagLItSvcH6S4bRGDTi9Vgmd28Q8ePkbrXIaBf3kRvjztVuox0lYT2YKLX8N
         Hep5MflHyDqzYJn0j2GyxWm2VBsG8SswCh9LVgjy9fRpegj4T/WwrFP/MmC/DKU2lV/R
         PFIaBumLspkAnEyLNS177afjudq1mGNOP1Z9ae2axrlqB46290WpB5zoyzzwqv+aurMg
         CHlF7aPnNaGqJULSyzzuJgS3/+MPUb2cG3c8ZJGD6L4XLbV9FJgOtH6EFVbAdRXa+b8Y
         uS6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=XKq9lfZrWA5/5nG13N4Ju0wlWlpWlDiHAhrYnRRndz4=;
        b=BW1JFoi04APE7fQQ+nVJdTHtBVGu6Mr12ecZfRlZJ95YUoI5XTT49SO/KUpUYfaoHA
         /chrAUN65TnUT6S4h2/dD5RJNorj5W8PIaOvEUPl3Idyd60CHW4W/ZlxPyJwEg+GgUW/
         lIfRgmzda2LBBXHn3cxk/rrZWezqzymSDw5Taj4UhkZmj1P0g4rG9dIfKIlCZXYc5lOr
         7iDJ0WHOwCrx+5eoe+CCjparti9uQNBosHQcWZbVW4v6ATzFK7mOa+0H4SP+kVJ76tKh
         49xGBi44OsQEkO4zvEAA6BzLLwgBNGj1Xdsz1Xnye4zpi3YJLOwVN3mtUXohSVwXTgZa
         9Cnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Kr0cwc+H;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XKq9lfZrWA5/5nG13N4Ju0wlWlpWlDiHAhrYnRRndz4=;
        b=h3M/wfQu4g4GK1+chkYykAeWfdZqskbTQdmD1z2CJosaAmGCHS3YGpYl3Tmi9zUTSQ
         i+aFix5kYvAFTd9i3cweE9xzWeHyXVaWWk18AaBgoVWAuhw0C+8G7dfMUdYXERxzel6l
         V5yaAEXIH6velShJfiE+C49vEwJteDvget7raisDKU//cgY0seI6kksaK89J/AtuHCg2
         Y9qe4oMiEcNplw6/3oLcErrlP2ZLi/E7emQS0Ye6K18vLxrJH4CPHvCPP+pb4CoLGG6j
         DOVIW6SInF8PNd9m98cExkuSXKEJ/0CSKiOcNTUTZhLvvGG4Sos3QTmcj2U/rjgIN476
         SiEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XKq9lfZrWA5/5nG13N4Ju0wlWlpWlDiHAhrYnRRndz4=;
        b=hmKWjh/17RSSCKMqzqiRUYdOL+eBkPyjlfADBfCx7720zKhE+udv/LvRP6lp1Xv/5c
         A5Z/sYcsnk0SJNNek+LF6fI52qgCNVTuExuBYGKL6WFsyHfm8i08OSxhYGyW26rx0oJT
         +d1mqRdxAQo6PmaQJVJZNfj5UeT5IsbezpuWNtPBW8uCqPcEy6hlvsX8Ln5heAMc2tID
         Ge89hrtzgh9vrBZphMtbDK2foaR/bvPG2+XzJK9FjuSATnjkpcMSZfyPw/BFEbSj/GaQ
         eZPtAemEKRI7vE+poXH2m+psU+FhKqyEk+fXPMDyaqqBzYfBATkVYmiM2XYbFq8x2zdh
         n+sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PV1lcnPBMQdIjk2ILJjra0jAOUmBXVjgr8dTOqgjVYRSzBpGS
	TyRSY1zDY1mdjgcfZl6ApAw=
X-Google-Smtp-Source: ABdhPJzYUY5wHcc4tcxPv/XWDvtQQpjOV7lGw7jwQSTpCxlP8zAr/8LhyWfTE9icGgNa/abPJqH2FQ==
X-Received: by 2002:a17:90a:b383:: with SMTP id e3mr3519223pjr.57.1592322237320;
        Tue, 16 Jun 2020 08:43:57 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bf05:: with SMTP id bi5ls6338676plb.5.gmail; Tue, 16
 Jun 2020 08:43:57 -0700 (PDT)
X-Received: by 2002:a17:90a:7c4e:: with SMTP id e14mr3882814pjl.52.1592322236914;
        Tue, 16 Jun 2020 08:43:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592322236; cv=none;
        d=google.com; s=arc-20160816;
        b=V0UEDDMz3jkUAqo5vflSfNKGikSt3xIt6XTFr0JjbWShAjm8ROrz5t7W4etCmGG4N3
         Q4pj4t3pwl6OHsA8k9G1YD/8X3arkCQow4DxtEb87r0B2kq+CqClwovpFpsLyRU85l4+
         MQSQODl1yF051JPqQembM88x+xEU5/ChJZBMfqAYd5iuc/XfiuyHO8wP0xTTDfc44g5v
         vdK/xceQ8DiP6be2VbqfIfFkpWACmwjN9eXTMSAdjtkXrJAOTRZdeTNldZbqBC8pkmEK
         ADHOzt0K5DV7K8tXYaDTwvOB5+nIy0tGpmv39x0sQGUtg/o3n4ftS64p5qE/PjTsgSFA
         zz5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=n2vgEtySMMJw+Y6/Iz7yVj4GHK2o/g3YD4HMOMKMGxw=;
        b=r+yWSJFv2orW/0eJeSDFNPNFmvSojW5zugncW04YhuknGwCEi3qI1mTUMWBy8g6uUl
         WsNv1Im/VnM/JaMcSXs/RSrkgOy0WpDmddiXwS2jUkwwTbCE0etdSLNg2dtHp8MFDiI5
         qaYaKzGhM5uP8Nxf/XX0uvWEuOQyzQp7zBzbRdnh3grehIL0qNgpfZzKjoqXtu3GoWyX
         ex9kHzv3eEIx4L5mTXTQQ/6ImIVOWgPibjMOErzXND4yQjFRFqrHgLsCd8tdJ8PNUg2F
         u9c7AcqazApHSusv/rlayxs+v/QDWPrHbvhJLkbfDcRf5lXkfsmotpF6PDXLaEAD9lxU
         iQig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Kr0cwc+H;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id x132si893273pgx.4.2020.06.16.08.43.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 08:43:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-245-iVwDnxGCNeS1_dm-BMJ-EQ-1; Tue, 16 Jun 2020 11:43:51 -0400
X-MC-Unique: iVwDnxGCNeS1_dm-BMJ-EQ-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.phx2.redhat.com [10.5.11.12])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 8A261EC1A2;
	Tue, 16 Jun 2020 15:43:45 +0000 (UTC)
Received: from llong.com (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 68C6460C47;
	Tue, 16 Jun 2020 15:43:37 +0000 (UTC)
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
Subject: [PATCH v5 0/2] mm, treewide: Rename kzfree() to kfree_sensitive()
Date: Tue, 16 Jun 2020 11:43:09 -0400
Message-Id: <20200616154311.12314-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.12
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Kr0cwc+H;
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

 v5:
  - Break the btrfs patch out as a separate patch to be processed
    independently.
  - Update the commit log of patch 1 to make it less scary.
  - Add a kzfree backward compatibility macro in patch 2.

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


Waiman Long (2):
  mm/slab: Use memzero_explicit() in kzfree()
  mm, treewide: Rename kzfree() to kfree_sensitive()

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
 include/linux/slab.h                          |  4 ++-
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
 115 files changed, 323 insertions(+), 321 deletions(-)

-- 
2.18.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616154311.12314-1-longman%40redhat.com.
