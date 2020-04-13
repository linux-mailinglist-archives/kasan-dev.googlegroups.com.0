Return-Path: <kasan-dev+bncBCPILY4NUAFBBPNN2P2AKGQEN4PTWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 70C1D1A6DD5
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 23:16:47 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id b204sf9798446pfb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 14:16:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586812606; cv=pass;
        d=google.com; s=arc-20160816;
        b=LNuqeq6iMTxieqrBFD3bau/W1qitDijP9jlKIWAF/Y74Xm8COpSjji4tRjHqjpzJJT
         ztrQO/4mJCkcGop2G2UAyAFlEJMC9wO73NAPKDMdiAWGADqSsDHLMrvGhsuM+IN+yUP5
         Eq6oFvwU83wRJgPTOZHr0n6+BdkkpFYMOK2DiTIoTnC+jpa8ZozCb4+1xaxoIriQI1yy
         xA/BidB8ezOXhCWtoCB/atT61FgRA+xRnlYSa+MBQNHHgBYatAGWhEjUsbBG+T427n8V
         SrQ00+fY9RNeRTMzG0Exxgsk+OEpxJkWF8TEm7cX5Lg2vYBRRFKSBu+s8HugBfeWlSnq
         s8XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=amk9HW1H6ujvAOtQiW0vahrjP6lbJBndH5+kGM/ebaI=;
        b=QvZOTbiIooJON34LGc7z5ndlw+ftpAOKll3SJNZCPev7muFESXrgaX/Q0uckyLMcGI
         kXRXLtm7KnQBZlIjitAbWE/A5Xgrnd7YtUu+msISD+gMH1cP8g4W05keXNLs3pvRp2dr
         7R11FUwXFsNBmZwNOaBMhlsKYjaCeCwmnZxYCAc9toOk26clXh1P3ZEdbk1ioDuOPrxD
         sCXLI0GBYYB04qGNPpSDESfajzUA61yMuJMrN0rOPKTDZrF3sWDuPXVVKqb8ZNNWLUKw
         YKAjo1DIIr8766W0nVQ5og+Hjbpze1vmzD5e9g5rUQOVs1bU/W2n5eB/Qy4WG/J8YIK/
         9dOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QwJ2OBrK;
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=amk9HW1H6ujvAOtQiW0vahrjP6lbJBndH5+kGM/ebaI=;
        b=avcXJvnc81/eqkNP993lqE+Nn8W0U0/i7I8Ev3FN8c1XCRo8U04kks6YyU2rDpU9HR
         w2R4w9IqhvxORQLtxicJbNWwmQ24gKZaagbZiA03Ysk0YpvciE4ksnno9AP9Dsh2k3cv
         XIF4WDRCg4lnnekBvEdijEcLKkoEqZ4k6pONuUzW5J8dMnjatLvEJIZYbaBV5Ry+r049
         faH9cmULAxwwD1lR3IIpTww1X0FSrndbxWYpPO6fYi26Zyq0Ih8/VL6vdeZo8Homw+ja
         IfuImgADCK4d5rnBkC+rRo2KlWVdJuO8dLCQg4j9ONe2+Ay7lI4FVxjC5tSGwTDjaJ2A
         XMfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=amk9HW1H6ujvAOtQiW0vahrjP6lbJBndH5+kGM/ebaI=;
        b=ce/271Lyp2beMLQddIcUqx04lsj8F5wyN3jr9MEsOwLfXhp+XKduhkwbsSu8SXmeme
         qzahX2UDNJgnrMaobShVLeTJzEpP3h9JY2ZU6+x2/rpSLtmJiSuNFtTc7/Yqr+QRxJWU
         wTbtM7OV2H7SPC6BWeml5qQR8pocbkvctThbU/2Q36k1ljQwVLL41JhoDB9MaC0deaCd
         OnX9QezB181hPCPhLiGAKe77t7Txy48saUYLjafOKhyqtEEt9gqIgC+mm1CoGnqBLJOE
         5bK3TQX2LYI+fZZ/rtiECooXpymjFuvwR0izJyQMAm++Xa702ZfutD772EufOCEiuP0I
         TRvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZjQJZOG4LXCtSgD7IzSwS9sOIj6n5dHsMCUGROzH1WJzUEOES+
	16C+cO7hsptYiF9z2duYQq8=
X-Google-Smtp-Source: APiQypJuT6NaGf/Vl6uwsQjc1wSjGNP5nKpT+fQpQtJIEdmqQFQyGNfiAniJXLdKSi3PcfAj3fMj6g==
X-Received: by 2002:a62:7797:: with SMTP id s145mr3218598pfc.20.1586812605950;
        Mon, 13 Apr 2020 14:16:45 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:23ce:: with SMTP id md14ls1963857pjb.1.canary-gmail;
 Mon, 13 Apr 2020 14:16:45 -0700 (PDT)
X-Received: by 2002:a17:90a:da06:: with SMTP id e6mr24229677pjv.14.1586812605511;
        Mon, 13 Apr 2020 14:16:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586812605; cv=none;
        d=google.com; s=arc-20160816;
        b=fGtLqgBeNMBo0SpO2+jAZy4e7SIOTvoGiOLhh7TCfQq8q4QLu1ecSPhSI9UUI5MC8Z
         uwPd/5tY8CXewD7xNJ100LML/tRyWBtUMOgs8Xn9o7hGgiJ8z9rvtNblfsDrJ16Cijz0
         Isx/sX86i/t2gbAtbGsGBudElRWmJ923mE6mGD2PHn2su5Q8+HyCbrNrHvU8FTOqSYJS
         aKzeAYbXBvVGlVj2m46WAB9zH6wj17VUtDWer51UOnYhKVdollqdjtKP4wcoWTlpS3te
         N3aUISE3sfXp+qWOOm2pKq/BiA82BYFOfIGSj1pKqLP6SM3I3BXvQbMKvwI3WdebPy+H
         zEtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=aZ6g7e8BD4k4NsjW61IF0M2p6EBHyF5yVO1v4ZHY2zM=;
        b=IgyfqUKMiUYf1gvoxfmGjmo70Bw4cq65HO/UCCf6PgDGJE3PjjcEJadWSvMpf29/6k
         KXITw/+Efefhmmb7DrjlJY6NTcYa3hepS1wsbVheyl9Y8mckOw3UT4FcI8kc2ar/ffBd
         wgDCNXtV9o5PXohcn/J65U4soTGPLvcJbSFPTnfiXQJjY+s5mIC86LWecr0sK7FGXxMP
         K4SOCdZUk+xLtIM0izdQpZ4wGsJ8GXLZ/eEpuIsAvO9xYdiw/jNq29nwPDKiA9P8Ygmi
         2yAx1f5SYURlG3l23rhy2d/NyNLTUwMGHvnyya/7p5Tb1Eh+0fkfgjHNtlQoCq7VrTLs
         ZLMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QwJ2OBrK;
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id u124si498658pfb.5.2020.04.13.14.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Apr 2020 14:16:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-458-MoXmhvmhO8yN4Fv14szuWw-1; Mon, 13 Apr 2020 17:16:40 -0400
X-MC-Unique: MoXmhvmhO8yN4Fv14szuWw-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.phx2.redhat.com [10.5.11.11])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id DA0F08018A1;
	Mon, 13 Apr 2020 21:16:33 +0000 (UTC)
Received: from llong.com (ovpn-115-28.rdu2.redhat.com [10.10.115.28])
	by smtp.corp.redhat.com (Postfix) with ESMTP id D8C9C11D2DD;
	Mon, 13 Apr 2020 21:16:23 +0000 (UTC)
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
Cc: linux-mm@kvack.org,
	keyrings@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	linux-crypto@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org,
	netdev@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org,
	linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org,
	samba-technical@lists.samba.org,
	linux-fscrypt@vger.kernel.org,
	ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org,
	tipc-discussion@lists.sourceforge.net,
	cocci@systeme.lip6.fr,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org,
	Waiman Long <longman@redhat.com>
Subject: [PATCH 0/2] mm, treewide: Rename kzfree() to kfree_sensitive()
Date: Mon, 13 Apr 2020 17:15:48 -0400
Message-Id: <20200413211550.8307-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.11
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QwJ2OBrK;
       spf=pass (google.com: domain of longman@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

This patchset makes a global rename of the kzfree() to kfree_sensitive()
to highlight the fact buffer clearing is only needed if the data objects
contain sensitive information like encrpytion key. The fact that kzfree()
uses memset() to do the clearing isn't totally safe either as compiler
may compile out the clearing in their optimizer. Instead, the new
kfree_sensitive() uses memzero_explicit() which won't get compiled out.

Waiman Long (2):
  mm, treewide: Rename kzfree() to kfree_sensitive()
  crypto: Remove unnecessary memzero_explicit()

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
 .../allwinner/sun8i-ce/sun8i-ce-cipher.c      | 17 +++-------
 .../allwinner/sun8i-ss/sun8i-ss-cipher.c      | 18 +++-------
 drivers/crypto/amlogic/amlogic-gxl-cipher.c   | 14 +++-----
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
 drivers/crypto/inside-secure/safexcel_hash.c  |  3 +-
 drivers/crypto/marvell/cesa/hash.c            |  2 +-
 .../crypto/marvell/octeontx/otx_cptvf_main.c  |  6 ++--
 .../marvell/octeontx/otx_cptvf_reqmgr.h       |  2 +-
 drivers/crypto/mediatek/mtk-aes.c             |  2 +-
 drivers/crypto/nx/nx.c                        |  4 +--
 drivers/crypto/virtio/virtio_crypto_algs.c    | 12 +++----
 drivers/crypto/virtio/virtio_crypto_core.c    |  2 +-
 drivers/md/dm-crypt.c                         | 34 +++++++++----------
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
 117 files changed, 332 insertions(+), 358 deletions(-)

-- 
2.18.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200413211550.8307-1-longman%40redhat.com.
