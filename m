Return-Path: <kasan-dev+bncBCLI747UVAFRBYGLSKNAMGQEEM22K7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8085E5FA819
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 01:08:17 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id t12-20020adfa2cc000000b0022adcbb248bsf3140755wra.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 16:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665443297; cv=pass;
        d=google.com; s=arc-20160816;
        b=utZKVexHF6OUyamc+0LZ0pVeYznQVEOsVDoO5uGx2KuVRqzG/bO9O3Z8MOUvVBHc/+
         9f/wZWGkiKqyBCMNa0ZEOnV0E6+iyIq9xf6yzfFslArTOF4xRTCBUUueMXQuixcyh2CN
         ii1fz0D+bAyjcXNnKpC+px1EWr5cV4hQhMlnm/VZePg5g695y71i4X4yKH1TcAuQTYbK
         GpLfw1REFMYD2oSJtb3CsJZR+j/8t62g7ZwV589O3aINDZe/GUVDTD1hDXaUVGbCSkOd
         206I4veIKJdg6PQj2tJKIC0l2+0qDc+4VU8AkbPci3sUneC7GR7daNUZuym7fGGRH0/q
         7QIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=ubOZDss1zIJpalxj9D4GxK70locwnzSoRcLeGF660UE=;
        b=T0Vn7cKmqxrhi+T0F9hOLCDL6cayj3cYrfY4Xsp4ff3dUHR+lgalQ1drurZqm4SySV
         KtAHsRRY9BaZBGoZNN/4ZInWl9lhZnI8fuOa9ooBjESdTExf95n6O1nKIhO/FDEdvxos
         v7YwFaChd9UvTlklpWfuMrKO+40/sA2ZbD0vRLd7HfyaabB+JMLi44AtSIJ+c8AUwoPa
         CFz6Xoa2h7OAawuZAyRN675tGKe2s7IsqQdni5v27H3/GWEuLrqJmsS7baGPm210zuyZ
         7q8k9le4AfqOlRdehV7Tz/dRFJflIcId6O6qPCFJHA5ILDjc0wG6SMgH5zGhNewICYCz
         3qYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="n/DVf6Pi";
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ubOZDss1zIJpalxj9D4GxK70locwnzSoRcLeGF660UE=;
        b=KlLRSRFAlgIsJnO8aFfWFb6A2krMCDxVkjfcnfSvHVWkmcZSlHkHV+9zSG5XfdErbj
         yonvzu1MkPXd7DOJ6tSyP5HEixrijnS6CLnk/sOdLCC1uNhcHsOJvKxy083d79HlB0Xq
         Dcw1n2mJk23RQ1mMcGnmEt3pRo8mvJ8D1g5MC8qGZkTi1AxYSExwMGwdCrptmy7mdnhJ
         rxN5r2us1g/JFotB+IY8nOJMeMDHwOjiamwx3u9fMOk3GuDrJMfMp1afRmQWkuW0Hy22
         pDpupQlMxjfWk8wmjO+xI7KFr66WScAx1eOKUuQ3V9G0uqVRTyXNJrnWAvt9meri0XRh
         dn1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ubOZDss1zIJpalxj9D4GxK70locwnzSoRcLeGF660UE=;
        b=nuuoGXBdJuo/CSv8ZT0NQd5ZsZgWnlE/xien5vl86O3rBz2DLLILOwTv3ARZizH9GN
         tnr6bQ7jt+hQvR+h0MtdnSSDZyHMZASYsL1oWjxQW9TJLMePGjtEIW4H8HMREStUBM/3
         l0+6TIPbJtUJ3gM1Bj/266s2rV+XmCeRLLYFW7HG32Cq78oXBGybba/1ZyRXHamEcvCT
         9U5MchWkgsnwpf702oDWl303S7MaPt4FZbJZgqMhDUFSBnJjUUy1TLks0GMjKPEtDbB3
         l/TeVc+tuFma7uQkX50T+FKcdTYwMR7zo3iMNZoNHdzXiX5JADH5sy63bkZBnknP0Fy3
         Q9qA==
X-Gm-Message-State: ACrzQf3CvXJ5d0R2M0NS1dM3rMHndeNqCjpTh+RgxVvNWy4+TbDbmkvn
	Fg3vS3ha+zNH7wan0CAGFaE=
X-Google-Smtp-Source: AMsMyM4sjiQNi92Q7C3DtuZ+RoT+cRZvvESU/NulrTyMBFSe/c2DT1ViEJ15ZfQ74LdQbn/3ckwsqQ==
X-Received: by 2002:adf:fec6:0:b0:22e:3218:f7e1 with SMTP id q6-20020adffec6000000b0022e3218f7e1mr12891287wrs.522.1665443296788;
        Mon, 10 Oct 2022 16:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f0a:b0:225:6559:3374 with SMTP id
 bv10-20020a0560001f0a00b0022565593374ls12173666wrb.2.-pod-prod-gmail; Mon, 10
 Oct 2022 16:08:15 -0700 (PDT)
X-Received: by 2002:adf:f345:0:b0:22e:3c6a:7797 with SMTP id e5-20020adff345000000b0022e3c6a7797mr13115678wrp.374.1665443295577;
        Mon, 10 Oct 2022 16:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665443295; cv=none;
        d=google.com; s=arc-20160816;
        b=v2aGhA0ZKqjzIxCiWa29/TOCo7xhlvTHyjBnYSWNnzyXwAQkdHVLIpWQnBAGActkYW
         tFPmd5aomWEUpcwQbSFY7jfTAU2UHtc5dPtduLw++XNRr5zaroCWlka3ViAtzi8q3MwT
         5JZo9G9Bbw2VUxq6ReElvCwLLnpWPRIkoJeggY0eJDkmMzCIwGuG0cY65YhjFsvJ7qbG
         avJAWbywMOJNRdxwk0kfddhawljcGNF9DvsMOdIXvJ4jm8tY843BEurbLW+Fd0C9ivUk
         X9kMjdH3pGb7uuC4/WqTLRcr/mqdJHBCfGOde0xgRM+BkAEOSeEuMpZGZDjo0z6DlwQ/
         d23g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sd+hvkfg7FmInCyhwT+I7uBPmttIP2iv9p0pnzmPTLI=;
        b=dU/BliC6PYCAD3SFTGWZl1Krn6GKRNQCQ4lZitCnN382K7kUIpHi0neDT4tChSHxtB
         +YzuXu7kJOvr95KvqfDGp0audv51zZgl5ybBfNexDcZownbT52MQc178+ORdzvYZUisa
         /q8/ysia2A95HEXSaA6I+uD5GSHi9FDb/mKQ0V4qI23YYlsUSiTgElrAOll3ltAlZwqq
         0SB7BfaPRQBrnqG98YEg0sgzLiFnagcAEevR/fyLPPktDnfqJvvhVu7UReQDXkWiK9Tx
         KheewhWHgELEe7up/0IHZPwgfpbHSlrJy6ufADc2USI4bPAulzqxTsK4Iugd6ov2U3Va
         Z5rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="n/DVf6Pi";
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bt28-20020a056000081c00b0022e3df50e0bsi369021wrb.2.2022.10.10.16.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 16:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0017EB81100;
	Mon, 10 Oct 2022 23:08:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D925C433D6;
	Mon, 10 Oct 2022 23:08:07 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 5394c6e1 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 10 Oct 2022 23:08:04 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	patches@lists.linux.dev
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	=?UTF-8?q?Christoph=20B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>,
	Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org,
	linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev,
	netdev@vger.kernel.org,
	sparclinux@vger.kernel.org,
	x86@kernel.org,
	=?UTF-8?q?Toke=20H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>,
	Chuck Lever <chuck.lever@oracle.com>,
	Jan Kara <jack@suse.cz>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	"Darrick J . Wong" <djwong@kernel.org>
Subject: [PATCH v6 5/7] treewide: use get_random_u32() when possible
Date: Mon, 10 Oct 2022 17:06:11 -0600
Message-Id: <20221010230613.1076905-6-Jason@zx2c4.com>
In-Reply-To: <20221010230613.1076905-1-Jason@zx2c4.com>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b="n/DVf6Pi";       spf=pass
 (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

The prandom_u32() function has been a deprecated inline wrapper around
get_random_u32() for several releases now, and compiles down to the
exact same code. Replace the deprecated wrapper with a direct call to
the real function. The same also applies to get_random_int(), which is
just a wrapper around get_random_u32(). This was done as a basic find
and replace.

Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Yury Norov <yury.norov@gmail.com>
Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_cake
Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
Acked-by: Mika Westerberg <mika.westerberg@linux.intel.com> # for thunderbo=
lt
Acked-by: Darrick J. Wong <djwong@kernel.org> # for xfs
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 Documentation/networking/filter.rst            |  2 +-
 arch/parisc/kernel/process.c                   |  2 +-
 arch/parisc/kernel/sys_parisc.c                |  4 ++--
 arch/s390/mm/mmap.c                            |  2 +-
 arch/x86/kernel/cpu/amd.c                      |  2 +-
 drivers/gpu/drm/i915/i915_gem_gtt.c            |  6 +++---
 drivers/gpu/drm/i915/selftests/i915_selftest.c |  2 +-
 drivers/gpu/drm/tests/drm_buddy_test.c         |  2 +-
 drivers/gpu/drm/tests/drm_mm_test.c            |  2 +-
 drivers/infiniband/hw/cxgb4/cm.c               |  4 ++--
 drivers/infiniband/hw/hfi1/tid_rdma.c          |  2 +-
 drivers/infiniband/hw/mlx4/mad.c               |  2 +-
 drivers/infiniband/ulp/ipoib/ipoib_cm.c        |  2 +-
 drivers/md/raid5-cache.c                       |  2 +-
 .../media/test-drivers/vivid/vivid-touch-cap.c |  4 ++--
 drivers/misc/habanalabs/gaudi2/gaudi2.c        |  2 +-
 drivers/net/bonding/bond_main.c                |  2 +-
 drivers/net/ethernet/broadcom/cnic.c           |  2 +-
 .../chelsio/inline_crypto/chtls/chtls_cm.c     |  2 +-
 drivers/net/ethernet/rocker/rocker_main.c      |  6 +++---
 .../wireless/broadcom/brcm80211/brcmfmac/pno.c |  2 +-
 .../net/wireless/marvell/mwifiex/cfg80211.c    |  4 ++--
 .../net/wireless/microchip/wilc1000/cfg80211.c |  2 +-
 .../net/wireless/quantenna/qtnfmac/cfg80211.c  |  2 +-
 drivers/net/wireless/ti/wlcore/main.c          |  2 +-
 drivers/nvme/common/auth.c                     |  2 +-
 drivers/scsi/cxgbi/cxgb4i/cxgb4i.c             |  4 ++--
 drivers/target/iscsi/cxgbit/cxgbit_cm.c        |  2 +-
 drivers/thunderbolt/xdomain.c                  |  2 +-
 drivers/video/fbdev/uvesafb.c                  |  2 +-
 fs/exfat/inode.c                               |  2 +-
 fs/ext4/ialloc.c                               |  2 +-
 fs/ext4/ioctl.c                                |  4 ++--
 fs/ext4/mmp.c                                  |  2 +-
 fs/f2fs/namei.c                                |  2 +-
 fs/fat/inode.c                                 |  2 +-
 fs/nfsd/nfs4state.c                            |  4 ++--
 fs/ntfs3/fslog.c                               |  6 +++---
 fs/ubifs/journal.c                             |  2 +-
 fs/xfs/libxfs/xfs_ialloc.c                     |  2 +-
 fs/xfs/xfs_icache.c                            |  2 +-
 fs/xfs/xfs_log.c                               |  2 +-
 include/net/netfilter/nf_queue.h               |  2 +-
 include/net/red.h                              |  2 +-
 include/net/sock.h                             |  2 +-
 kernel/bpf/bloom_filter.c                      |  2 +-
 kernel/bpf/core.c                              |  2 +-
 kernel/bpf/hashtab.c                           |  2 +-
 kernel/bpf/verifier.c                          |  2 +-
 kernel/kcsan/selftest.c                        |  2 +-
 lib/random32.c                                 |  2 +-
 lib/reed_solomon/test_rslib.c                  |  6 +++---
 lib/test_fprobe.c                              |  2 +-
 lib/test_kprobes.c                             |  2 +-
 lib/test_min_heap.c                            |  6 +++---
 lib/test_rhashtable.c                          |  6 +++---
 mm/shmem.c                                     |  2 +-
 mm/slab.c                                      |  2 +-
 net/core/pktgen.c                              |  4 ++--
 net/ipv4/route.c                               |  2 +-
 net/ipv4/tcp_cdg.c                             |  2 +-
 net/ipv4/udp.c                                 |  2 +-
 net/ipv6/ip6_flowlabel.c                       |  2 +-
 net/ipv6/output_core.c                         |  2 +-
 net/netfilter/ipvs/ip_vs_conn.c                |  2 +-
 net/netfilter/xt_statistic.c                   |  2 +-
 net/openvswitch/actions.c                      |  2 +-
 net/sched/sch_cake.c                           |  2 +-
 net/sched/sch_netem.c                          | 18 +++++++++---------
 net/sunrpc/auth_gss/gss_krb5_wrap.c            |  4 ++--
 net/sunrpc/xprt.c                              |  2 +-
 net/unix/af_unix.c                             |  2 +-
 72 files changed, 101 insertions(+), 101 deletions(-)

diff --git a/Documentation/networking/filter.rst b/Documentation/networking=
/filter.rst
index 43cdc4d34745..f69da5074860 100644
--- a/Documentation/networking/filter.rst
+++ b/Documentation/networking/filter.rst
@@ -305,7 +305,7 @@ Possible BPF extensions are shown in the following tabl=
e:
   vlan_tci                              skb_vlan_tag_get(skb)
   vlan_avail                            skb_vlan_tag_present(skb)
   vlan_tpid                             skb->vlan_proto
-  rand                                  prandom_u32()
+  rand                                  get_random_u32()
   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
=20
 These extensions can also be prefixed with '#'.
diff --git a/arch/parisc/kernel/process.c b/arch/parisc/kernel/process.c
index 7c37e09c92da..18c4f0e3e906 100644
--- a/arch/parisc/kernel/process.c
+++ b/arch/parisc/kernel/process.c
@@ -288,7 +288,7 @@ __get_wchan(struct task_struct *p)
=20
 static inline unsigned long brk_rnd(void)
 {
-	return (get_random_int() & BRK_RND_MASK) << PAGE_SHIFT;
+	return (get_random_u32() & BRK_RND_MASK) << PAGE_SHIFT;
 }
=20
 unsigned long arch_randomize_brk(struct mm_struct *mm)
diff --git a/arch/parisc/kernel/sys_parisc.c b/arch/parisc/kernel/sys_paris=
c.c
index 2b34294517a1..848b0702005d 100644
--- a/arch/parisc/kernel/sys_parisc.c
+++ b/arch/parisc/kernel/sys_parisc.c
@@ -239,14 +239,14 @@ static unsigned long mmap_rnd(void)
 	unsigned long rnd =3D 0;
=20
 	if (current->flags & PF_RANDOMIZE)
-		rnd =3D get_random_int() & MMAP_RND_MASK;
+		rnd =3D get_random_u32() & MMAP_RND_MASK;
=20
 	return rnd << PAGE_SHIFT;
 }
=20
 unsigned long arch_mmap_rnd(void)
 {
-	return (get_random_int() & MMAP_RND_MASK) << PAGE_SHIFT;
+	return (get_random_u32() & MMAP_RND_MASK) << PAGE_SHIFT;
 }
=20
 static unsigned long mmap_legacy_base(void)
diff --git a/arch/s390/mm/mmap.c b/arch/s390/mm/mmap.c
index 5980ce348832..3327c47bc181 100644
--- a/arch/s390/mm/mmap.c
+++ b/arch/s390/mm/mmap.c
@@ -37,7 +37,7 @@ static inline int mmap_is_legacy(struct rlimit *rlim_stac=
k)
=20
 unsigned long arch_mmap_rnd(void)
 {
-	return (get_random_int() & MMAP_RND_MASK) << PAGE_SHIFT;
+	return (get_random_u32() & MMAP_RND_MASK) << PAGE_SHIFT;
 }
=20
 static unsigned long mmap_base_legacy(unsigned long rnd)
diff --git a/arch/x86/kernel/cpu/amd.c b/arch/x86/kernel/cpu/amd.c
index 48276c0e479d..860b60273df3 100644
--- a/arch/x86/kernel/cpu/amd.c
+++ b/arch/x86/kernel/cpu/amd.c
@@ -503,7 +503,7 @@ static void bsp_init_amd(struct cpuinfo_x86 *c)
 		va_align.flags    =3D ALIGN_VA_32 | ALIGN_VA_64;
=20
 		/* A random value per boot for bit slice [12:upper_bit) */
-		va_align.bits =3D get_random_int() & va_align.mask;
+		va_align.bits =3D get_random_u32() & va_align.mask;
 	}
=20
 	if (cpu_has(c, X86_FEATURE_MWAITX))
diff --git a/drivers/gpu/drm/i915/i915_gem_gtt.c b/drivers/gpu/drm/i915/i91=
5_gem_gtt.c
index 329ff75b80b9..7bd1861ddbdf 100644
--- a/drivers/gpu/drm/i915/i915_gem_gtt.c
+++ b/drivers/gpu/drm/i915/i915_gem_gtt.c
@@ -137,12 +137,12 @@ static u64 random_offset(u64 start, u64 end, u64 len,=
 u64 align)
 	range =3D round_down(end - len, align) - round_up(start, align);
 	if (range) {
 		if (sizeof(unsigned long) =3D=3D sizeof(u64)) {
-			addr =3D get_random_long();
+			addr =3D get_random_u64();
 		} else {
-			addr =3D get_random_int();
+			addr =3D get_random_u32();
 			if (range > U32_MAX) {
 				addr <<=3D 32;
-				addr |=3D get_random_int();
+				addr |=3D get_random_u32();
 			}
 		}
 		div64_u64_rem(addr, range, &addr);
diff --git a/drivers/gpu/drm/i915/selftests/i915_selftest.c b/drivers/gpu/d=
rm/i915/selftests/i915_selftest.c
index c4e932368b37..39da0fb0d6d2 100644
--- a/drivers/gpu/drm/i915/selftests/i915_selftest.c
+++ b/drivers/gpu/drm/i915/selftests/i915_selftest.c
@@ -135,7 +135,7 @@ static int __run_selftests(const char *name,
 	int err =3D 0;
=20
 	while (!i915_selftest.random_seed)
-		i915_selftest.random_seed =3D get_random_int();
+		i915_selftest.random_seed =3D get_random_u32();
=20
 	i915_selftest.timeout_jiffies =3D
 		i915_selftest.timeout_ms ?
diff --git a/drivers/gpu/drm/tests/drm_buddy_test.c b/drivers/gpu/drm/tests=
/drm_buddy_test.c
index 7a2b2d6bc3fe..62f69589a72d 100644
--- a/drivers/gpu/drm/tests/drm_buddy_test.c
+++ b/drivers/gpu/drm/tests/drm_buddy_test.c
@@ -729,7 +729,7 @@ static void drm_test_buddy_alloc_limit(struct kunit *te=
st)
 static int drm_buddy_init_test(struct kunit *test)
 {
 	while (!random_seed)
-		random_seed =3D get_random_int();
+		random_seed =3D get_random_u32();
=20
 	return 0;
 }
diff --git a/drivers/gpu/drm/tests/drm_mm_test.c b/drivers/gpu/drm/tests/dr=
m_mm_test.c
index 659d1af4dca7..c4b66eeae203 100644
--- a/drivers/gpu/drm/tests/drm_mm_test.c
+++ b/drivers/gpu/drm/tests/drm_mm_test.c
@@ -2212,7 +2212,7 @@ static void drm_test_mm_color_evict_range(struct kuni=
t *test)
 static int drm_mm_init_test(struct kunit *test)
 {
 	while (!random_seed)
-		random_seed =3D get_random_int();
+		random_seed =3D get_random_u32();
=20
 	return 0;
 }
diff --git a/drivers/infiniband/hw/cxgb4/cm.c b/drivers/infiniband/hw/cxgb4=
/cm.c
index 14392c942f49..499a425a3379 100644
--- a/drivers/infiniband/hw/cxgb4/cm.c
+++ b/drivers/infiniband/hw/cxgb4/cm.c
@@ -734,7 +734,7 @@ static int send_connect(struct c4iw_ep *ep)
 				   &ep->com.remote_addr;
 	int ret;
 	enum chip_type adapter_type =3D ep->com.dev->rdev.lldi.adapter_type;
-	u32 isn =3D (prandom_u32() & ~7UL) - 1;
+	u32 isn =3D (get_random_u32() & ~7UL) - 1;
 	struct net_device *netdev;
 	u64 params;
=20
@@ -2469,7 +2469,7 @@ static int accept_cr(struct c4iw_ep *ep, struct sk_bu=
ff *skb,
 	}
=20
 	if (!is_t4(adapter_type)) {
-		u32 isn =3D (prandom_u32() & ~7UL) - 1;
+		u32 isn =3D (get_random_u32() & ~7UL) - 1;
=20
 		skb =3D get_skb(skb, roundup(sizeof(*rpl5), 16), GFP_KERNEL);
 		rpl5 =3D __skb_put_zero(skb, roundup(sizeof(*rpl5), 16));
diff --git a/drivers/infiniband/hw/hfi1/tid_rdma.c b/drivers/infiniband/hw/=
hfi1/tid_rdma.c
index 2a7abf7a1f7f..18b05ffb415a 100644
--- a/drivers/infiniband/hw/hfi1/tid_rdma.c
+++ b/drivers/infiniband/hw/hfi1/tid_rdma.c
@@ -850,7 +850,7 @@ void hfi1_kern_init_ctxt_generations(struct hfi1_ctxtda=
ta *rcd)
 	int i;
=20
 	for (i =3D 0; i < RXE_NUM_TID_FLOWS; i++) {
-		rcd->flows[i].generation =3D mask_generation(prandom_u32());
+		rcd->flows[i].generation =3D mask_generation(get_random_u32());
 		kern_set_hw_flow(rcd, KERN_GENERATION_RESERVED, i);
 	}
 }
diff --git a/drivers/infiniband/hw/mlx4/mad.c b/drivers/infiniband/hw/mlx4/=
mad.c
index d13ecbdd4391..a37cfac5e23f 100644
--- a/drivers/infiniband/hw/mlx4/mad.c
+++ b/drivers/infiniband/hw/mlx4/mad.c
@@ -96,7 +96,7 @@ static void __propagate_pkey_ev(struct mlx4_ib_dev *dev, =
int port_num,
 __be64 mlx4_ib_gen_node_guid(void)
 {
 #define NODE_GUID_HI	((u64) (((u64)IB_OPENIB_OUI) << 40))
-	return cpu_to_be64(NODE_GUID_HI | prandom_u32());
+	return cpu_to_be64(NODE_GUID_HI | get_random_u32());
 }
=20
 __be64 mlx4_ib_get_new_demux_tid(struct mlx4_ib_demux_ctx *ctx)
diff --git a/drivers/infiniband/ulp/ipoib/ipoib_cm.c b/drivers/infiniband/u=
lp/ipoib/ipoib_cm.c
index ebb35b809f26..b610d36295bb 100644
--- a/drivers/infiniband/ulp/ipoib/ipoib_cm.c
+++ b/drivers/infiniband/ulp/ipoib/ipoib_cm.c
@@ -465,7 +465,7 @@ static int ipoib_cm_req_handler(struct ib_cm_id *cm_id,
 		goto err_qp;
 	}
=20
-	psn =3D prandom_u32() & 0xffffff;
+	psn =3D get_random_u32() & 0xffffff;
 	ret =3D ipoib_cm_modify_rx_qp(dev, cm_id, p->qp, psn);
 	if (ret)
 		goto err_modify;
diff --git a/drivers/md/raid5-cache.c b/drivers/md/raid5-cache.c
index 79c73330020b..832d8566e165 100644
--- a/drivers/md/raid5-cache.c
+++ b/drivers/md/raid5-cache.c
@@ -2994,7 +2994,7 @@ static int r5l_load_log(struct r5l_log *log)
 	}
 create:
 	if (create_super) {
-		log->last_cp_seq =3D prandom_u32();
+		log->last_cp_seq =3D get_random_u32();
 		cp =3D 0;
 		r5l_log_write_empty_meta_block(log, cp, log->last_cp_seq);
 		/*
diff --git a/drivers/media/test-drivers/vivid/vivid-touch-cap.c b/drivers/m=
edia/test-drivers/vivid/vivid-touch-cap.c
index 792660a85bc1..6cc32eb54f9d 100644
--- a/drivers/media/test-drivers/vivid/vivid-touch-cap.c
+++ b/drivers/media/test-drivers/vivid/vivid-touch-cap.c
@@ -210,7 +210,7 @@ static void vivid_fill_buff_noise(__s16 *tch_buf, int s=
ize)
=20
 	/* Fill 10% of the values within range -3 and 3, zero the others */
 	for (i =3D 0; i < size; i++) {
-		unsigned int rand =3D get_random_int();
+		unsigned int rand =3D get_random_u32();
=20
 		if (rand % 10)
 			tch_buf[i] =3D 0;
@@ -272,7 +272,7 @@ void vivid_fillbuff_tch(struct vivid_dev *dev, struct v=
ivid_buffer *buf)
 		return;
=20
 	if (test_pat_idx =3D=3D 0)
-		dev->tch_pat_random =3D get_random_int();
+		dev->tch_pat_random =3D get_random_u32();
 	rand =3D dev->tch_pat_random;
=20
 	switch (test_pattern) {
diff --git a/drivers/misc/habanalabs/gaudi2/gaudi2.c b/drivers/misc/habanal=
abs/gaudi2/gaudi2.c
index 75c4bef7841c..65e6cae6100a 100644
--- a/drivers/misc/habanalabs/gaudi2/gaudi2.c
+++ b/drivers/misc/habanalabs/gaudi2/gaudi2.c
@@ -2948,7 +2948,7 @@ static void gaudi2_user_interrupt_setup(struct hl_dev=
ice *hdev)
=20
 static inline int gaudi2_get_non_zero_random_int(void)
 {
-	int rand =3D get_random_int();
+	int rand =3D get_random_u32();
=20
 	return rand ? rand : 1;
 }
diff --git a/drivers/net/bonding/bond_main.c b/drivers/net/bonding/bond_mai=
n.c
index 24bb50dfd362..e84c49bf4d0c 100644
--- a/drivers/net/bonding/bond_main.c
+++ b/drivers/net/bonding/bond_main.c
@@ -4806,7 +4806,7 @@ static u32 bond_rr_gen_slave_id(struct bonding *bond)
=20
 	switch (packets_per_slave) {
 	case 0:
-		slave_id =3D prandom_u32();
+		slave_id =3D get_random_u32();
 		break;
 	case 1:
 		slave_id =3D this_cpu_inc_return(*bond->rr_tx_counter);
diff --git a/drivers/net/ethernet/broadcom/cnic.c b/drivers/net/ethernet/br=
oadcom/cnic.c
index f597b313acaa..2198e35d9e18 100644
--- a/drivers/net/ethernet/broadcom/cnic.c
+++ b/drivers/net/ethernet/broadcom/cnic.c
@@ -4164,7 +4164,7 @@ static int cnic_cm_init_bnx2_hw(struct cnic_dev *dev)
 {
 	u32 seed;
=20
-	seed =3D prandom_u32();
+	seed =3D get_random_u32();
 	cnic_ctx_wr(dev, 45, 0, seed);
 	return 0;
 }
diff --git a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c b/=
drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
index eda129d0143e..c2e7037c7ba1 100644
--- a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
+++ b/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
@@ -1063,7 +1063,7 @@ static void chtls_pass_accept_rpl(struct sk_buff *skb=
,
 	opt2 |=3D WND_SCALE_EN_V(WSCALE_OK(tp));
 	rpl5->opt0 =3D cpu_to_be64(opt0);
 	rpl5->opt2 =3D cpu_to_be32(opt2);
-	rpl5->iss =3D cpu_to_be32((prandom_u32() & ~7UL) - 1);
+	rpl5->iss =3D cpu_to_be32((get_random_u32() & ~7UL) - 1);
 	set_wr_txq(skb, CPL_PRIORITY_SETUP, csk->port_id);
 	t4_set_arp_err_handler(skb, sk, chtls_accept_rpl_arp_failure);
 	cxgb4_l2t_send(csk->egress_dev, skb, csk->l2t_entry);
diff --git a/drivers/net/ethernet/rocker/rocker_main.c b/drivers/net/ethern=
et/rocker/rocker_main.c
index 023682cd2768..5672d952452f 100644
--- a/drivers/net/ethernet/rocker/rocker_main.c
+++ b/drivers/net/ethernet/rocker/rocker_main.c
@@ -129,7 +129,7 @@ static int rocker_reg_test(const struct rocker *rocker)
 	u64 test_reg;
 	u64 rnd;
=20
-	rnd =3D prandom_u32();
+	rnd =3D get_random_u32();
 	rnd >>=3D 1;
 	rocker_write32(rocker, TEST_REG, rnd);
 	test_reg =3D rocker_read32(rocker, TEST_REG);
@@ -139,9 +139,9 @@ static int rocker_reg_test(const struct rocker *rocker)
 		return -EIO;
 	}
=20
-	rnd =3D prandom_u32();
+	rnd =3D get_random_u32();
 	rnd <<=3D 31;
-	rnd |=3D prandom_u32();
+	rnd |=3D get_random_u32();
 	rocker_write64(rocker, TEST_REG64, rnd);
 	test_reg =3D rocker_read64(rocker, TEST_REG64);
 	if (test_reg !=3D rnd * 2) {
diff --git a/drivers/net/wireless/broadcom/brcm80211/brcmfmac/pno.c b/drive=
rs/net/wireless/broadcom/brcm80211/brcmfmac/pno.c
index d0a7465be586..3a7aded30e8e 100644
--- a/drivers/net/wireless/broadcom/brcm80211/brcmfmac/pno.c
+++ b/drivers/net/wireless/broadcom/brcm80211/brcmfmac/pno.c
@@ -177,7 +177,7 @@ static int brcmf_pno_set_random(struct brcmf_if *ifp, s=
truct brcmf_pno_info *pi)
 	memcpy(pfn_mac.mac, mac_addr, ETH_ALEN);
 	for (i =3D 0; i < ETH_ALEN; i++) {
 		pfn_mac.mac[i] &=3D mac_mask[i];
-		pfn_mac.mac[i] |=3D get_random_int() & ~(mac_mask[i]);
+		pfn_mac.mac[i] |=3D get_random_u32() & ~(mac_mask[i]);
 	}
 	/* Clear multi bit */
 	pfn_mac.mac[0] &=3D 0xFE;
diff --git a/drivers/net/wireless/marvell/mwifiex/cfg80211.c b/drivers/net/=
wireless/marvell/mwifiex/cfg80211.c
index 535995e8279f..bcd564dc3554 100644
--- a/drivers/net/wireless/marvell/mwifiex/cfg80211.c
+++ b/drivers/net/wireless/marvell/mwifiex/cfg80211.c
@@ -239,7 +239,7 @@ mwifiex_cfg80211_mgmt_tx(struct wiphy *wiphy, struct wi=
reless_dev *wdev,
 	tx_info->pkt_len =3D pkt_len;
=20
 	mwifiex_form_mgmt_frame(skb, buf, len);
-	*cookie =3D prandom_u32() | 1;
+	*cookie =3D get_random_u32() | 1;
=20
 	if (ieee80211_is_action(mgmt->frame_control))
 		skb =3D mwifiex_clone_skb_for_tx_status(priv,
@@ -303,7 +303,7 @@ mwifiex_cfg80211_remain_on_channel(struct wiphy *wiphy,
 					 duration);
=20
 	if (!ret) {
-		*cookie =3D prandom_u32() | 1;
+		*cookie =3D get_random_u32() | 1;
 		priv->roc_cfg.cookie =3D *cookie;
 		priv->roc_cfg.chan =3D *chan;
=20
diff --git a/drivers/net/wireless/microchip/wilc1000/cfg80211.c b/drivers/n=
et/wireless/microchip/wilc1000/cfg80211.c
index b89047965e78..9bbfff803357 100644
--- a/drivers/net/wireless/microchip/wilc1000/cfg80211.c
+++ b/drivers/net/wireless/microchip/wilc1000/cfg80211.c
@@ -1161,7 +1161,7 @@ static int mgmt_tx(struct wiphy *wiphy,
 	const u8 *vendor_ie;
 	int ret =3D 0;
=20
-	*cookie =3D prandom_u32();
+	*cookie =3D get_random_u32();
 	priv->tx_cookie =3D *cookie;
 	mgmt =3D (const struct ieee80211_mgmt *)buf;
=20
diff --git a/drivers/net/wireless/quantenna/qtnfmac/cfg80211.c b/drivers/ne=
t/wireless/quantenna/qtnfmac/cfg80211.c
index bfdf03bfa6c5..73e6f9408b51 100644
--- a/drivers/net/wireless/quantenna/qtnfmac/cfg80211.c
+++ b/drivers/net/wireless/quantenna/qtnfmac/cfg80211.c
@@ -449,7 +449,7 @@ qtnf_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *=
wdev,
 {
 	struct qtnf_vif *vif =3D qtnf_netdev_get_priv(wdev->netdev);
 	const struct ieee80211_mgmt *mgmt_frame =3D (void *)params->buf;
-	u32 short_cookie =3D prandom_u32();
+	u32 short_cookie =3D get_random_u32();
 	u16 flags =3D 0;
 	u16 freq;
=20
diff --git a/drivers/net/wireless/ti/wlcore/main.c b/drivers/net/wireless/t=
i/wlcore/main.c
index 3e3922d4c788..28c0f06e311f 100644
--- a/drivers/net/wireless/ti/wlcore/main.c
+++ b/drivers/net/wireless/ti/wlcore/main.c
@@ -6100,7 +6100,7 @@ static int wl1271_register_hw(struct wl1271 *wl)
 			wl1271_warning("Fuse mac address is zero. using random mac");
 			/* Use TI oui and a random nic */
 			oui_addr =3D WLCORE_TI_OUI_ADDRESS;
-			nic_addr =3D get_random_int();
+			nic_addr =3D get_random_u32();
 		} else {
 			oui_addr =3D wl->fuse_oui_addr;
 			/* fuse has the BD_ADDR, the WLAN addresses are the next two */
diff --git a/drivers/nvme/common/auth.c b/drivers/nvme/common/auth.c
index 04bd28f17dcc..d90e4f0c08b7 100644
--- a/drivers/nvme/common/auth.c
+++ b/drivers/nvme/common/auth.c
@@ -23,7 +23,7 @@ u32 nvme_auth_get_seqnum(void)
=20
 	mutex_lock(&nvme_dhchap_mutex);
 	if (!nvme_dhchap_seqnum)
-		nvme_dhchap_seqnum =3D prandom_u32();
+		nvme_dhchap_seqnum =3D get_random_u32();
 	else {
 		nvme_dhchap_seqnum++;
 		if (!nvme_dhchap_seqnum)
diff --git a/drivers/scsi/cxgbi/cxgb4i/cxgb4i.c b/drivers/scsi/cxgbi/cxgb4i=
/cxgb4i.c
index 53d91bf9c12a..c07d2e3b4bcf 100644
--- a/drivers/scsi/cxgbi/cxgb4i/cxgb4i.c
+++ b/drivers/scsi/cxgbi/cxgb4i/cxgb4i.c
@@ -254,7 +254,7 @@ static void send_act_open_req(struct cxgbi_sock *csk, s=
truct sk_buff *skb,
 	} else if (is_t5(lldi->adapter_type)) {
 		struct cpl_t5_act_open_req *req =3D
 				(struct cpl_t5_act_open_req *)skb->head;
-		u32 isn =3D (prandom_u32() & ~7UL) - 1;
+		u32 isn =3D (get_random_u32() & ~7UL) - 1;
=20
 		INIT_TP_WR(req, 0);
 		OPCODE_TID(req) =3D cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
@@ -282,7 +282,7 @@ static void send_act_open_req(struct cxgbi_sock *csk, s=
truct sk_buff *skb,
 	} else {
 		struct cpl_t6_act_open_req *req =3D
 				(struct cpl_t6_act_open_req *)skb->head;
-		u32 isn =3D (prandom_u32() & ~7UL) - 1;
+		u32 isn =3D (get_random_u32() & ~7UL) - 1;
=20
 		INIT_TP_WR(req, 0);
 		OPCODE_TID(req) =3D cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
diff --git a/drivers/target/iscsi/cxgbit/cxgbit_cm.c b/drivers/target/iscsi=
/cxgbit/cxgbit_cm.c
index 3336d2b78bf7..d9204c590d9a 100644
--- a/drivers/target/iscsi/cxgbit/cxgbit_cm.c
+++ b/drivers/target/iscsi/cxgbit/cxgbit_cm.c
@@ -1202,7 +1202,7 @@ cxgbit_pass_accept_rpl(struct cxgbit_sock *csk, struc=
t cpl_pass_accept_req *req)
 	opt2 |=3D CONG_CNTRL_V(CONG_ALG_NEWRENO);
=20
 	opt2 |=3D T5_ISS_F;
-	rpl5->iss =3D cpu_to_be32((prandom_u32() & ~7UL) - 1);
+	rpl5->iss =3D cpu_to_be32((get_random_u32() & ~7UL) - 1);
=20
 	opt2 |=3D T5_OPT_2_VALID_F;
=20
diff --git a/drivers/thunderbolt/xdomain.c b/drivers/thunderbolt/xdomain.c
index bbb248a2686f..f00b2f62d8e3 100644
--- a/drivers/thunderbolt/xdomain.c
+++ b/drivers/thunderbolt/xdomain.c
@@ -2437,7 +2437,7 @@ int tb_xdomain_init(void)
 	tb_property_add_immediate(xdomain_property_dir, "deviceid", 0x1);
 	tb_property_add_immediate(xdomain_property_dir, "devicerv", 0x80000100);
=20
-	xdomain_property_block_gen =3D prandom_u32();
+	xdomain_property_block_gen =3D get_random_u32();
 	return 0;
 }
=20
diff --git a/drivers/video/fbdev/uvesafb.c b/drivers/video/fbdev/uvesafb.c
index 4df6772802d7..285b83c20326 100644
--- a/drivers/video/fbdev/uvesafb.c
+++ b/drivers/video/fbdev/uvesafb.c
@@ -167,7 +167,7 @@ static int uvesafb_exec(struct uvesafb_ktask *task)
 	memcpy(&m->id, &uvesafb_cn_id, sizeof(m->id));
 	m->seq =3D seq;
 	m->len =3D len;
-	m->ack =3D prandom_u32();
+	m->ack =3D get_random_u32();
=20
 	/* uvesafb_task structure */
 	memcpy(m + 1, &task->t, sizeof(task->t));
diff --git a/fs/exfat/inode.c b/fs/exfat/inode.c
index a795437b86d0..5590a1e83126 100644
--- a/fs/exfat/inode.c
+++ b/fs/exfat/inode.c
@@ -552,7 +552,7 @@ static int exfat_fill_inode(struct inode *inode, struct=
 exfat_dir_entry *info)
 	inode->i_uid =3D sbi->options.fs_uid;
 	inode->i_gid =3D sbi->options.fs_gid;
 	inode_inc_iversion(inode);
-	inode->i_generation =3D prandom_u32();
+	inode->i_generation =3D get_random_u32();
=20
 	if (info->attr & ATTR_SUBDIR) { /* directory */
 		inode->i_generation &=3D ~1;
diff --git a/fs/ext4/ialloc.c b/fs/ext4/ialloc.c
index 7575aa359675..e9bc46684106 100644
--- a/fs/ext4/ialloc.c
+++ b/fs/ext4/ialloc.c
@@ -1279,7 +1279,7 @@ struct inode *__ext4_new_inode(struct user_namespace =
*mnt_userns,
 					EXT4_GROUP_INFO_IBITMAP_CORRUPT);
 		goto out;
 	}
-	inode->i_generation =3D prandom_u32();
+	inode->i_generation =3D get_random_u32();
=20
 	/* Precompute checksum seed for inode metadata */
 	if (ext4_has_metadata_csum(sb)) {
diff --git a/fs/ext4/ioctl.c b/fs/ext4/ioctl.c
index 4d49c5cfb690..ded535535b27 100644
--- a/fs/ext4/ioctl.c
+++ b/fs/ext4/ioctl.c
@@ -454,8 +454,8 @@ static long swap_inode_boot_loader(struct super_block *=
sb,
 	inode->i_ctime =3D inode_bl->i_ctime =3D current_time(inode);
 	inode_inc_iversion(inode);
=20
-	inode->i_generation =3D prandom_u32();
-	inode_bl->i_generation =3D prandom_u32();
+	inode->i_generation =3D get_random_u32();
+	inode_bl->i_generation =3D get_random_u32();
 	ext4_reset_inode_seed(inode);
 	ext4_reset_inode_seed(inode_bl);
=20
diff --git a/fs/ext4/mmp.c b/fs/ext4/mmp.c
index 9af68a7ecdcf..588cb09c5291 100644
--- a/fs/ext4/mmp.c
+++ b/fs/ext4/mmp.c
@@ -265,7 +265,7 @@ static unsigned int mmp_new_seq(void)
 	u32 new_seq;
=20
 	do {
-		new_seq =3D prandom_u32();
+		new_seq =3D get_random_u32();
 	} while (new_seq > EXT4_MMP_SEQ_MAX);
=20
 	return new_seq;
diff --git a/fs/f2fs/namei.c b/fs/f2fs/namei.c
index bf00d5057abb..939536982c3e 100644
--- a/fs/f2fs/namei.c
+++ b/fs/f2fs/namei.c
@@ -50,7 +50,7 @@ static struct inode *f2fs_new_inode(struct user_namespace=
 *mnt_userns,
 	inode->i_blocks =3D 0;
 	inode->i_mtime =3D inode->i_atime =3D inode->i_ctime =3D current_time(ino=
de);
 	F2FS_I(inode)->i_crtime =3D inode->i_mtime;
-	inode->i_generation =3D prandom_u32();
+	inode->i_generation =3D get_random_u32();
=20
 	if (S_ISDIR(inode->i_mode))
 		F2FS_I(inode)->i_current_depth =3D 1;
diff --git a/fs/fat/inode.c b/fs/fat/inode.c
index a38238d75c08..1cbcc4608dc7 100644
--- a/fs/fat/inode.c
+++ b/fs/fat/inode.c
@@ -523,7 +523,7 @@ int fat_fill_inode(struct inode *inode, struct msdos_di=
r_entry *de)
 	inode->i_uid =3D sbi->options.fs_uid;
 	inode->i_gid =3D sbi->options.fs_gid;
 	inode_inc_iversion(inode);
-	inode->i_generation =3D prandom_u32();
+	inode->i_generation =3D get_random_u32();
=20
 	if ((de->attr & ATTR_DIR) && !IS_FREE(de->name)) {
 		inode->i_generation &=3D ~1;
diff --git a/fs/nfsd/nfs4state.c b/fs/nfsd/nfs4state.c
index 198d7abf34e4..4e718500a00c 100644
--- a/fs/nfsd/nfs4state.c
+++ b/fs/nfsd/nfs4state.c
@@ -4375,8 +4375,8 @@ nfsd4_init_leases_net(struct nfsd_net *nn)
 	nn->nfsd4_grace =3D 90;
 	nn->somebody_reclaimed =3D false;
 	nn->track_reclaim_completes =3D false;
-	nn->clverifier_counter =3D prandom_u32();
-	nn->clientid_base =3D prandom_u32();
+	nn->clverifier_counter =3D get_random_u32();
+	nn->clientid_base =3D get_random_u32();
 	nn->clientid_counter =3D nn->clientid_base + 1;
 	nn->s2s_cp_cl_id =3D nn->clientid_counter++;
=20
diff --git a/fs/ntfs3/fslog.c b/fs/ntfs3/fslog.c
index e7c494005122..0d611a6c5511 100644
--- a/fs/ntfs3/fslog.c
+++ b/fs/ntfs3/fslog.c
@@ -3819,7 +3819,7 @@ int log_replay(struct ntfs_inode *ni, bool *initializ=
ed)
 		}
=20
 		log_init_pg_hdr(log, page_size, page_size, 1, 1);
-		log_create(log, l_size, 0, get_random_int(), false, false);
+		log_create(log, l_size, 0, get_random_u32(), false, false);
=20
 		log->ra =3D ra;
=20
@@ -3893,7 +3893,7 @@ int log_replay(struct ntfs_inode *ni, bool *initializ=
ed)
=20
 		/* Do some checks based on whether we have a valid log page. */
 		if (!rst_info.valid_page) {
-			open_log_count =3D get_random_int();
+			open_log_count =3D get_random_u32();
 			goto init_log_instance;
 		}
 		open_log_count =3D le32_to_cpu(ra2->open_log_count);
@@ -4044,7 +4044,7 @@ int log_replay(struct ntfs_inode *ni, bool *initializ=
ed)
 		memcpy(ra->clients, Add2Ptr(ra2, t16),
 		       le16_to_cpu(ra2->ra_len) - t16);
=20
-		log->current_openlog_count =3D get_random_int();
+		log->current_openlog_count =3D get_random_u32();
 		ra->open_log_count =3D cpu_to_le32(log->current_openlog_count);
 		log->ra_size =3D offsetof(struct RESTART_AREA, clients) +
 			       sizeof(struct CLIENT_REC);
diff --git a/fs/ubifs/journal.c b/fs/ubifs/journal.c
index 75dab0ae3939..4619652046cf 100644
--- a/fs/ubifs/journal.c
+++ b/fs/ubifs/journal.c
@@ -503,7 +503,7 @@ static void mark_inode_clean(struct ubifs_info *c, stru=
ct ubifs_inode *ui)
 static void set_dent_cookie(struct ubifs_info *c, struct ubifs_dent_node *=
dent)
 {
 	if (c->double_hash)
-		dent->cookie =3D (__force __le32) prandom_u32();
+		dent->cookie =3D (__force __le32) get_random_u32();
 	else
 		dent->cookie =3D 0;
 }
diff --git a/fs/xfs/libxfs/xfs_ialloc.c b/fs/xfs/libxfs/xfs_ialloc.c
index 7838b31126e2..94db50eb706a 100644
--- a/fs/xfs/libxfs/xfs_ialloc.c
+++ b/fs/xfs/libxfs/xfs_ialloc.c
@@ -805,7 +805,7 @@ xfs_ialloc_ag_alloc(
 	 * number from being easily guessable.
 	 */
 	error =3D xfs_ialloc_inode_init(args.mp, tp, NULL, newlen, pag->pag_agno,
-			args.agbno, args.len, prandom_u32());
+			args.agbno, args.len, get_random_u32());
=20
 	if (error)
 		return error;
diff --git a/fs/xfs/xfs_icache.c b/fs/xfs/xfs_icache.c
index 2bbe7916a998..eae7427062cf 100644
--- a/fs/xfs/xfs_icache.c
+++ b/fs/xfs/xfs_icache.c
@@ -596,7 +596,7 @@ xfs_iget_cache_miss(
 	 */
 	if (xfs_has_v3inodes(mp) &&
 	    (flags & XFS_IGET_CREATE) && !xfs_has_ikeep(mp)) {
-		VFS_I(ip)->i_generation =3D prandom_u32();
+		VFS_I(ip)->i_generation =3D get_random_u32();
 	} else {
 		struct xfs_buf		*bp;
=20
diff --git a/fs/xfs/xfs_log.c b/fs/xfs/xfs_log.c
index 386b0307aed8..ad8652cbf245 100644
--- a/fs/xfs/xfs_log.c
+++ b/fs/xfs/xfs_log.c
@@ -3544,7 +3544,7 @@ xlog_ticket_alloc(
 	tic->t_curr_res		=3D unit_res;
 	tic->t_cnt		=3D cnt;
 	tic->t_ocnt		=3D cnt;
-	tic->t_tid		=3D prandom_u32();
+	tic->t_tid		=3D get_random_u32();
 	if (permanent)
 		tic->t_flags |=3D XLOG_TIC_PERM_RESERV;
=20
diff --git a/include/net/netfilter/nf_queue.h b/include/net/netfilter/nf_qu=
eue.h
index 980daa6e1e3a..c81021ab07aa 100644
--- a/include/net/netfilter/nf_queue.h
+++ b/include/net/netfilter/nf_queue.h
@@ -43,7 +43,7 @@ void nf_queue_entry_free(struct nf_queue_entry *entry);
 static inline void init_hashrandom(u32 *jhash_initval)
 {
 	while (*jhash_initval =3D=3D 0)
-		*jhash_initval =3D prandom_u32();
+		*jhash_initval =3D get_random_u32();
 }
=20
 static inline u32 hash_v4(const struct iphdr *iph, u32 initval)
diff --git a/include/net/red.h b/include/net/red.h
index 454ac2b65d8c..425364de0df7 100644
--- a/include/net/red.h
+++ b/include/net/red.h
@@ -363,7 +363,7 @@ static inline unsigned long red_calc_qavg(const struct =
red_parms *p,
=20
 static inline u32 red_random(const struct red_parms *p)
 {
-	return reciprocal_divide(prandom_u32(), p->max_P_reciprocal);
+	return reciprocal_divide(get_random_u32(), p->max_P_reciprocal);
 }
=20
 static inline int red_mark_probability(const struct red_parms *p,
diff --git a/include/net/sock.h b/include/net/sock.h
index 08038a385ef2..9e464f6409a7 100644
--- a/include/net/sock.h
+++ b/include/net/sock.h
@@ -2109,7 +2109,7 @@ static inline kuid_t sock_net_uid(const struct net *n=
et, const struct sock *sk)
=20
 static inline u32 net_tx_rndhash(void)
 {
-	u32 v =3D prandom_u32();
+	u32 v =3D get_random_u32();
=20
 	return v ?: 1;
 }
diff --git a/kernel/bpf/bloom_filter.c b/kernel/bpf/bloom_filter.c
index b9ea539a5561..48ee750849f2 100644
--- a/kernel/bpf/bloom_filter.c
+++ b/kernel/bpf/bloom_filter.c
@@ -158,7 +158,7 @@ static struct bpf_map *bloom_map_alloc(union bpf_attr *=
attr)
 			attr->value_size / sizeof(u32);
=20
 	if (!(attr->map_flags & BPF_F_ZERO_SEED))
-		bloom->hash_seed =3D get_random_int();
+		bloom->hash_seed =3D get_random_u32();
=20
 	return &bloom->map;
 }
diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
index 19593627e037..05d75fe17b9b 100644
--- a/kernel/bpf/core.c
+++ b/kernel/bpf/core.c
@@ -1216,7 +1216,7 @@ static int bpf_jit_blind_insn(const struct bpf_insn *=
from,
 			      bool emit_zext)
 {
 	struct bpf_insn *to =3D to_buff;
-	u32 imm_rnd =3D get_random_int();
+	u32 imm_rnd =3D get_random_u32();
 	s16 off;
=20
 	BUILD_BUG_ON(BPF_REG_AX  + 1 !=3D MAX_BPF_JIT_REG);
diff --git a/kernel/bpf/hashtab.c b/kernel/bpf/hashtab.c
index ed3f8a53603b..f39ee3e05589 100644
--- a/kernel/bpf/hashtab.c
+++ b/kernel/bpf/hashtab.c
@@ -527,7 +527,7 @@ static struct bpf_map *htab_map_alloc(union bpf_attr *a=
ttr)
 	if (htab->map.map_flags & BPF_F_ZERO_SEED)
 		htab->hashrnd =3D 0;
 	else
-		htab->hashrnd =3D get_random_int();
+		htab->hashrnd =3D get_random_u32();
=20
 	htab_init_buckets(htab);
=20
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 6f6d2d511c06..014ee0953dbd 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -13350,7 +13350,7 @@ static int opt_subreg_zext_lo32_rnd_hi32(struct bpf=
_verifier_env *env,
 			    aux[adj_idx].ptr_type =3D=3D PTR_TO_CTX)
 				continue;
=20
-			imm_rnd =3D get_random_int();
+			imm_rnd =3D get_random_u32();
 			rnd_hi32_patch[0] =3D insn;
 			rnd_hi32_patch[1].imm =3D imm_rnd;
 			rnd_hi32_patch[3].dst_reg =3D load_reg;
diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index 75712959c84e..58b94deae5c0 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -26,7 +26,7 @@
 static bool __init test_requires(void)
 {
 	/* random should be initialized for the below tests */
-	return prandom_u32() + prandom_u32() !=3D 0;
+	return get_random_u32() + get_random_u32() !=3D 0;
 }
=20
 /*
diff --git a/lib/random32.c b/lib/random32.c
index d5d9029362cb..d4f19e1a69d4 100644
--- a/lib/random32.c
+++ b/lib/random32.c
@@ -47,7 +47,7 @@
  *	@state: pointer to state structure holding seeded state.
  *
  *	This is used for pseudo-randomness with no outside seeding.
- *	For more random results, use prandom_u32().
+ *	For more random results, use get_random_u32().
  */
 u32 prandom_u32_state(struct rnd_state *state)
 {
diff --git a/lib/reed_solomon/test_rslib.c b/lib/reed_solomon/test_rslib.c
index 4d241bdc88aa..848e7eb5da92 100644
--- a/lib/reed_solomon/test_rslib.c
+++ b/lib/reed_solomon/test_rslib.c
@@ -164,7 +164,7 @@ static int get_rcw_we(struct rs_control *rs, struct wsp=
ace *ws,
=20
 	/* Load c with random data and encode */
 	for (i =3D 0; i < dlen; i++)
-		c[i] =3D prandom_u32() & nn;
+		c[i] =3D get_random_u32() & nn;
=20
 	memset(c + dlen, 0, nroots * sizeof(*c));
 	encode_rs16(rs, c, dlen, c + dlen, 0);
@@ -178,7 +178,7 @@ static int get_rcw_we(struct rs_control *rs, struct wsp=
ace *ws,
 	for (i =3D 0; i < errs; i++) {
 		do {
 			/* Error value must be nonzero */
-			errval =3D prandom_u32() & nn;
+			errval =3D get_random_u32() & nn;
 		} while (errval =3D=3D 0);
=20
 		do {
@@ -206,7 +206,7 @@ static int get_rcw_we(struct rs_control *rs, struct wsp=
ace *ws,
 			/* Erasure with corrupted symbol */
 			do {
 				/* Error value must be nonzero */
-				errval =3D prandom_u32() & nn;
+				errval =3D get_random_u32() & nn;
 			} while (errval =3D=3D 0);
=20
 			errlocs[errloc] =3D 1;
diff --git a/lib/test_fprobe.c b/lib/test_fprobe.c
index ed70637a2ffa..e0381b3ec410 100644
--- a/lib/test_fprobe.c
+++ b/lib/test_fprobe.c
@@ -145,7 +145,7 @@ static unsigned long get_ftrace_location(void *func)
 static int fprobe_test_init(struct kunit *test)
 {
 	do {
-		rand1 =3D prandom_u32();
+		rand1 =3D get_random_u32();
 	} while (rand1 <=3D div_factor);
=20
 	target =3D fprobe_selftest_target;
diff --git a/lib/test_kprobes.c b/lib/test_kprobes.c
index a5edc2ebc947..eeb1d728d974 100644
--- a/lib/test_kprobes.c
+++ b/lib/test_kprobes.c
@@ -341,7 +341,7 @@ static int kprobes_test_init(struct kunit *test)
 	stacktrace_driver =3D kprobe_stacktrace_driver;
=20
 	do {
-		rand1 =3D prandom_u32();
+		rand1 =3D get_random_u32();
 	} while (rand1 <=3D div_factor);
 	return 0;
 }
diff --git a/lib/test_min_heap.c b/lib/test_min_heap.c
index d19c8080fd4d..7b01b4387cfb 100644
--- a/lib/test_min_heap.c
+++ b/lib/test_min_heap.c
@@ -83,7 +83,7 @@ static __init int test_heapify_all(bool min_heap)
 	/* Test with randomly generated values. */
 	heap.nr =3D ARRAY_SIZE(values);
 	for (i =3D 0; i < heap.nr; i++)
-		values[i] =3D get_random_int();
+		values[i] =3D get_random_u32();
=20
 	min_heapify_all(&heap, &funcs);
 	err +=3D pop_verify_heap(min_heap, &heap, &funcs);
@@ -116,7 +116,7 @@ static __init int test_heap_push(bool min_heap)
=20
 	/* Test with randomly generated values. */
 	while (heap.nr < heap.size) {
-		temp =3D get_random_int();
+		temp =3D get_random_u32();
 		min_heap_push(&heap, &temp, &funcs);
 	}
 	err +=3D pop_verify_heap(min_heap, &heap, &funcs);
@@ -158,7 +158,7 @@ static __init int test_heap_pop_push(bool min_heap)
=20
 	/* Test with randomly generated values. */
 	for (i =3D 0; i < ARRAY_SIZE(data); i++) {
-		temp =3D get_random_int();
+		temp =3D get_random_u32();
 		min_heap_pop_push(&heap, &temp, &funcs);
 	}
 	err +=3D pop_verify_heap(min_heap, &heap, &funcs);
diff --git a/lib/test_rhashtable.c b/lib/test_rhashtable.c
index 5a1dd4736b56..b358a74ed7ed 100644
--- a/lib/test_rhashtable.c
+++ b/lib/test_rhashtable.c
@@ -291,7 +291,7 @@ static int __init test_rhltable(unsigned int entries)
 	if (WARN_ON(err))
 		goto out_free;
=20
-	k =3D prandom_u32();
+	k =3D get_random_u32();
 	ret =3D 0;
 	for (i =3D 0; i < entries; i++) {
 		rhl_test_objects[i].value.id =3D k;
@@ -369,12 +369,12 @@ static int __init test_rhltable(unsigned int entries)
 	pr_info("test %d random rhlist add/delete operations\n", entries);
 	for (j =3D 0; j < entries; j++) {
 		u32 i =3D prandom_u32_max(entries);
-		u32 prand =3D prandom_u32();
+		u32 prand =3D get_random_u32();
=20
 		cond_resched();
=20
 		if (prand =3D=3D 0)
-			prand =3D prandom_u32();
+			prand =3D get_random_u32();
=20
 		if (prand & 1) {
 			prand >>=3D 1;
diff --git a/mm/shmem.c b/mm/shmem.c
index 42e5888bf84d..6f2cef73808d 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -2330,7 +2330,7 @@ static struct inode *shmem_get_inode(struct super_blo=
ck *sb, struct inode *dir,
 		inode_init_owner(&init_user_ns, inode, dir, mode);
 		inode->i_blocks =3D 0;
 		inode->i_atime =3D inode->i_mtime =3D inode->i_ctime =3D current_time(in=
ode);
-		inode->i_generation =3D prandom_u32();
+		inode->i_generation =3D get_random_u32();
 		info =3D SHMEM_I(inode);
 		memset(info, 0, (char *)inode - (char *)info);
 		spin_lock_init(&info->lock);
diff --git a/mm/slab.c b/mm/slab.c
index a5486ff8362a..60cd19b9ee04 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -2380,7 +2380,7 @@ static bool freelist_state_initialize(union freelist_=
init_state *state,
 	unsigned int rand;
=20
 	/* Use best entropy available to define a random shift */
-	rand =3D get_random_int();
+	rand =3D get_random_u32();
=20
 	/* Use a random state if the pre-computed list is not available */
 	if (!cachep->random_seq) {
diff --git a/net/core/pktgen.c b/net/core/pktgen.c
index 5ca4f953034c..c3763056c554 100644
--- a/net/core/pktgen.c
+++ b/net/core/pktgen.c
@@ -2464,7 +2464,7 @@ static void mod_cur_headers(struct pktgen_dev *pkt_de=
v)
 		for (i =3D 0; i < pkt_dev->nr_labels; i++)
 			if (pkt_dev->labels[i] & MPLS_STACK_BOTTOM)
 				pkt_dev->labels[i] =3D MPLS_STACK_BOTTOM |
-					     ((__force __be32)prandom_u32() &
+					     ((__force __be32)get_random_u32() &
 						      htonl(0x000fffff));
 	}
=20
@@ -2568,7 +2568,7 @@ static void mod_cur_headers(struct pktgen_dev *pkt_de=
v)
=20
 			for (i =3D 0; i < 4; i++) {
 				pkt_dev->cur_in6_daddr.s6_addr32[i] =3D
-				    (((__force __be32)prandom_u32() |
+				    (((__force __be32)get_random_u32() |
 				      pkt_dev->min_in6_daddr.s6_addr32[i]) &
 				     pkt_dev->max_in6_daddr.s6_addr32[i]);
 			}
diff --git a/net/ipv4/route.c b/net/ipv4/route.c
index 795cbe1de912..1a37a07c7163 100644
--- a/net/ipv4/route.c
+++ b/net/ipv4/route.c
@@ -3664,7 +3664,7 @@ static __net_init int rt_genid_init(struct net *net)
 {
 	atomic_set(&net->ipv4.rt_genid, 0);
 	atomic_set(&net->fnhe_genid, 0);
-	atomic_set(&net->ipv4.dev_addr_genid, get_random_int());
+	atomic_set(&net->ipv4.dev_addr_genid, get_random_u32());
 	return 0;
 }
=20
diff --git a/net/ipv4/tcp_cdg.c b/net/ipv4/tcp_cdg.c
index ddc7ba0554bd..efcd145f06db 100644
--- a/net/ipv4/tcp_cdg.c
+++ b/net/ipv4/tcp_cdg.c
@@ -243,7 +243,7 @@ static bool tcp_cdg_backoff(struct sock *sk, u32 grad)
 	struct cdg *ca =3D inet_csk_ca(sk);
 	struct tcp_sock *tp =3D tcp_sk(sk);
=20
-	if (prandom_u32() <=3D nexp_u32(grad * backoff_factor))
+	if (get_random_u32() <=3D nexp_u32(grad * backoff_factor))
 		return false;
=20
 	if (use_ineff) {
diff --git a/net/ipv4/udp.c b/net/ipv4/udp.c
index d63118ce5900..9f2688246dee 100644
--- a/net/ipv4/udp.c
+++ b/net/ipv4/udp.c
@@ -246,7 +246,7 @@ int udp_lib_get_port(struct sock *sk, unsigned short sn=
um,
 		inet_get_local_port_range(net, &low, &high);
 		remaining =3D (high - low) + 1;
=20
-		rand =3D prandom_u32();
+		rand =3D get_random_u32();
 		first =3D reciprocal_scale(rand, remaining) + low;
 		/*
 		 * force rand to be an odd multiple of UDP_HTABLE_SIZE
diff --git a/net/ipv6/ip6_flowlabel.c b/net/ipv6/ip6_flowlabel.c
index ceb85c67ce39..18481eb76a0a 100644
--- a/net/ipv6/ip6_flowlabel.c
+++ b/net/ipv6/ip6_flowlabel.c
@@ -220,7 +220,7 @@ static struct ip6_flowlabel *fl_intern(struct net *net,
 	spin_lock_bh(&ip6_fl_lock);
 	if (label =3D=3D 0) {
 		for (;;) {
-			fl->label =3D htonl(prandom_u32())&IPV6_FLOWLABEL_MASK;
+			fl->label =3D htonl(get_random_u32())&IPV6_FLOWLABEL_MASK;
 			if (fl->label) {
 				lfl =3D __fl_lookup(net, fl->label);
 				if (!lfl)
diff --git a/net/ipv6/output_core.c b/net/ipv6/output_core.c
index 2880dc7d9a49..2685c3f15e9d 100644
--- a/net/ipv6/output_core.c
+++ b/net/ipv6/output_core.c
@@ -18,7 +18,7 @@ static u32 __ipv6_select_ident(struct net *net,
 	u32 id;
=20
 	do {
-		id =3D prandom_u32();
+		id =3D get_random_u32();
 	} while (!id);
=20
 	return id;
diff --git a/net/netfilter/ipvs/ip_vs_conn.c b/net/netfilter/ipvs/ip_vs_con=
n.c
index fb67f1ca2495..8c04bb57dd6f 100644
--- a/net/netfilter/ipvs/ip_vs_conn.c
+++ b/net/netfilter/ipvs/ip_vs_conn.c
@@ -1308,7 +1308,7 @@ void ip_vs_random_dropentry(struct netns_ipvs *ipvs)
 	 * Randomly scan 1/32 of the whole table every second
 	 */
 	for (idx =3D 0; idx < (ip_vs_conn_tab_size>>5); idx++) {
-		unsigned int hash =3D prandom_u32() & ip_vs_conn_tab_mask;
+		unsigned int hash =3D get_random_u32() & ip_vs_conn_tab_mask;
=20
 		hlist_for_each_entry_rcu(cp, &ip_vs_conn_tab[hash], c_list) {
 			if (cp->ipvs !=3D ipvs)
diff --git a/net/netfilter/xt_statistic.c b/net/netfilter/xt_statistic.c
index 203e24ae472c..b26c1dcfc27b 100644
--- a/net/netfilter/xt_statistic.c
+++ b/net/netfilter/xt_statistic.c
@@ -34,7 +34,7 @@ statistic_mt(const struct sk_buff *skb, struct xt_action_=
param *par)
=20
 	switch (info->mode) {
 	case XT_STATISTIC_MODE_RANDOM:
-		if ((prandom_u32() & 0x7FFFFFFF) < info->u.random.probability)
+		if ((get_random_u32() & 0x7FFFFFFF) < info->u.random.probability)
 			ret =3D !ret;
 		break;
 	case XT_STATISTIC_MODE_NTH:
diff --git a/net/openvswitch/actions.c b/net/openvswitch/actions.c
index 868db4669a29..ca3ebfdb3023 100644
--- a/net/openvswitch/actions.c
+++ b/net/openvswitch/actions.c
@@ -1033,7 +1033,7 @@ static int sample(struct datapath *dp, struct sk_buff=
 *skb,
 	actions =3D nla_next(sample_arg, &rem);
=20
 	if ((arg->probability !=3D U32_MAX) &&
-	    (!arg->probability || prandom_u32() > arg->probability)) {
+	    (!arg->probability || get_random_u32() > arg->probability)) {
 		if (last)
 			consume_skb(skb);
 		return 0;
diff --git a/net/sched/sch_cake.c b/net/sched/sch_cake.c
index 7193d25932ce..817cd0695b35 100644
--- a/net/sched/sch_cake.c
+++ b/net/sched/sch_cake.c
@@ -573,7 +573,7 @@ static bool cobalt_should_drop(struct cobalt_vars *vars=
,
=20
 	/* Simple BLUE implementation.  Lack of ECN is deliberate. */
 	if (vars->p_drop)
-		drop |=3D (prandom_u32() < vars->p_drop);
+		drop |=3D (get_random_u32() < vars->p_drop);
=20
 	/* Overload the drop_next field as an activity timeout */
 	if (!vars->count)
diff --git a/net/sched/sch_netem.c b/net/sched/sch_netem.c
index bab45b3b1fdb..fb00ac40ecb7 100644
--- a/net/sched/sch_netem.c
+++ b/net/sched/sch_netem.c
@@ -171,7 +171,7 @@ static inline struct netem_skb_cb *netem_skb_cb(struct =
sk_buff *skb)
 static void init_crandom(struct crndstate *state, unsigned long rho)
 {
 	state->rho =3D rho;
-	state->last =3D prandom_u32();
+	state->last =3D get_random_u32();
 }
=20
 /* get_crandom - correlated random number generator
@@ -184,9 +184,9 @@ static u32 get_crandom(struct crndstate *state)
 	unsigned long answer;
=20
 	if (!state || state->rho =3D=3D 0)	/* no correlation */
-		return prandom_u32();
+		return get_random_u32();
=20
-	value =3D prandom_u32();
+	value =3D get_random_u32();
 	rho =3D (u64)state->rho + 1;
 	answer =3D (value * ((1ull<<32) - rho) + state->last * rho) >> 32;
 	state->last =3D answer;
@@ -200,7 +200,7 @@ static u32 get_crandom(struct crndstate *state)
 static bool loss_4state(struct netem_sched_data *q)
 {
 	struct clgstate *clg =3D &q->clg;
-	u32 rnd =3D prandom_u32();
+	u32 rnd =3D get_random_u32();
=20
 	/*
 	 * Makes a comparison between rnd and the transition
@@ -268,15 +268,15 @@ static bool loss_gilb_ell(struct netem_sched_data *q)
=20
 	switch (clg->state) {
 	case GOOD_STATE:
-		if (prandom_u32() < clg->a1)
+		if (get_random_u32() < clg->a1)
 			clg->state =3D BAD_STATE;
-		if (prandom_u32() < clg->a4)
+		if (get_random_u32() < clg->a4)
 			return true;
 		break;
 	case BAD_STATE:
-		if (prandom_u32() < clg->a2)
+		if (get_random_u32() < clg->a2)
 			clg->state =3D GOOD_STATE;
-		if (prandom_u32() > clg->a3)
+		if (get_random_u32() > clg->a3)
 			return true;
 	}
=20
@@ -632,7 +632,7 @@ static void get_slot_next(struct netem_sched_data *q, u=
64 now)
=20
 	if (!q->slot_dist)
 		next_delay =3D q->slot_config.min_delay +
-				(prandom_u32() *
+				(get_random_u32() *
 				 (q->slot_config.max_delay -
 				  q->slot_config.min_delay) >> 32);
 	else
diff --git a/net/sunrpc/auth_gss/gss_krb5_wrap.c b/net/sunrpc/auth_gss/gss_=
krb5_wrap.c
index 5f96e75f9eec..48337687848c 100644
--- a/net/sunrpc/auth_gss/gss_krb5_wrap.c
+++ b/net/sunrpc/auth_gss/gss_krb5_wrap.c
@@ -130,8 +130,8 @@ gss_krb5_make_confounder(char *p, u32 conflen)
=20
 	/* initialize to random value */
 	if (i =3D=3D 0) {
-		i =3D prandom_u32();
-		i =3D (i << 32) | prandom_u32();
+		i =3D get_random_u32();
+		i =3D (i << 32) | get_random_u32();
 	}
=20
 	switch (conflen) {
diff --git a/net/sunrpc/xprt.c b/net/sunrpc/xprt.c
index f8fae7815649..9407007f47ae 100644
--- a/net/sunrpc/xprt.c
+++ b/net/sunrpc/xprt.c
@@ -1868,7 +1868,7 @@ xprt_alloc_xid(struct rpc_xprt *xprt)
 static void
 xprt_init_xid(struct rpc_xprt *xprt)
 {
-	xprt->xid =3D prandom_u32();
+	xprt->xid =3D get_random_u32();
 }
=20
 static void
diff --git a/net/unix/af_unix.c b/net/unix/af_unix.c
index 15dbb392c875..b3545fc68097 100644
--- a/net/unix/af_unix.c
+++ b/net/unix/af_unix.c
@@ -1147,7 +1147,7 @@ static int unix_autobind(struct sock *sk)
 	addr->name->sun_family =3D AF_UNIX;
 	refcount_set(&addr->refcnt, 1);
=20
-	ordernum =3D prandom_u32();
+	ordernum =3D get_random_u32();
 	lastnum =3D ordernum & 0xFFFFF;
 retry:
 	ordernum =3D (ordernum + 1) & 0xFFFFF;
--=20
2.37.3

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221010230613.1076905-6-Jason%40zx2c4.com.
