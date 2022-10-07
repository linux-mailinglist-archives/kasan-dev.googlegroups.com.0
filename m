Return-Path: <kasan-dev+bncBCLI747UVAFRBDGTQGNAMGQEMXUSRRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3291F5F7CB6
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 20:01:49 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id o18-20020a05600c339200b003bf24961658sf3004834wmp.6
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 11:01:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665165709; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVyL6fIXWQAuIYRC8a2oavDdz6N3lkMbiVDE6HsZ6E50fxzCRcXztowJAAAzsQ9Nkf
         bgwWvvgIDBNpml7x8My/fyNxSWSU8jo9NdSULiCJCAcjEQ/hV6sQMJ6NxWzo1uxtazMf
         oDt0m59kEowjJ7XTqlg/nNfw8kpeUVWFHy5rRS1eycnEQLCNuEFZv3fu1T+zrctCSDam
         7H2sYRWQrQMva1e5aJRafVHiXWmeKTUVIH0X2qVVRrfIEXBX/I0ZOAt22qxmVGssC7qr
         ogk0lHKZ+HBGWvlQj002lMChOxKXvbnuxlNyB5ehpcUtHrR3xZrfFHdRnH5Tjg2JzrhC
         vjSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=oPGlqy33hLlN/wHmFtrtH4JgWsR2SFlzyiH6ukZhKiQ=;
        b=Mi6SQmeR1VNUyApLQk8vJ83glruRxv9dprjTARZX0XtSd72N0pZq4F4mGT0znBOGkP
         qiMNEqiZjmSxfwZn3M/I/soxibk5/qKHAhayzpbj4bGo/9/kUvOYA13xDlSjBd+bT3IB
         ggSryIENC7+j06cAOBU9JHYEjnGK2EuXtOtDQUTP+JKtrcrgAKs5Nyr1z53yUvGQxZHH
         r5KVSoQlKDKSuBccsAapIOu6QS1oDmllT4ICIRX1fBlUoggBsWJlGxIXcKoLDRPCKTKt
         hZFG3WPJkDqzyxXEhcbmxDDLCgYZyH9EXUmhlaphvndh6fyPJFNxFl9JZmff3wf5+NCL
         Ev1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=jtpfM9yS;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oPGlqy33hLlN/wHmFtrtH4JgWsR2SFlzyiH6ukZhKiQ=;
        b=Oj8MYC68+jMwHd5VC9FHBHlME8fre6eKgFdxWbRxDO7NaJOKHRMIAdZ0FIPJv6sa2S
         jmAnTK9ST25IJkQPf3TDnEWJf9m3v1fef7FV3U5/QwY2uZKKA5iK61+mlJu2dqRm7IAP
         jljwATfYF7ZJ3sKJSjcx4r2tr8bYzgkRiLB1/+//Jg3pre3JtVXpBUDo1fT1MO0E06OC
         9gHS8DZ586L0Tobvq1wGfc4LyYnaKOU1fSE9hkFxuWh5qWaKVel/To13vJv2NbiseNAL
         CviME0J7wLmkbcR4WEYIIVOlU3hl21FLOcGfwAY+ii1nBgVUnSej4crVJ4WQ/jlbBChj
         tC+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oPGlqy33hLlN/wHmFtrtH4JgWsR2SFlzyiH6ukZhKiQ=;
        b=oGJQRP5Um+PHmuOGozZzMGklywN++XLxNWDiWPGgrUfFA0CziilkKLvNABT3Vllihf
         aWnnO+9E7IusRvWP+xsgHVdiDdVhI9Ptd1An11tkRY31l1VlVR7raD6jyIly0sYOmL2N
         ZUeLjGnSy2vhKaJ/lOiX0LEN1HADvSoko8fpN++JAK4sbtBNMKnRa/BQkglPGV+3WiSC
         n2gstShih22/ZOrhIEHNbjtrTTmqMBf4lLZYC1B2rTIwGenMG7nE4mndm7U7KHpE8JX7
         pAffgSe6ZsSI0JvABuxaKCBwRtxSG7kC2vnaalP3XTvP1647Dc0Cg80roSmtMkj89CO1
         YGhQ==
X-Gm-Message-State: ACrzQf2M5tr2Ehoa3zUPfzw1xDcZ/GRTUdwpIUy8dWfUiQdZdkuLP0EK
	QuhCYxl9crq3oDlkUtL3m0c=
X-Google-Smtp-Source: AMsMyM44wx69JaJ64gqBQI8VbcPzTphKJYaG2SFWU7wI0uJLwaSkLPaGqTXlBPyhh0THMOA/EBHLBw==
X-Received: by 2002:a05:600c:444b:b0:3b4:cb9e:bd5c with SMTP id v11-20020a05600c444b00b003b4cb9ebd5cmr11193705wmn.124.1665165708780;
        Fri, 07 Oct 2022 11:01:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c40b:0:b0:3c4:9c0:44ca with SMTP id k11-20020a7bc40b000000b003c409c044cals348020wmi.2.-pod-control-gmail;
 Fri, 07 Oct 2022 11:01:47 -0700 (PDT)
X-Received: by 2002:a05:600c:1e87:b0:3b5:1e2:3c3c with SMTP id be7-20020a05600c1e8700b003b501e23c3cmr4147301wmb.130.1665165707735;
        Fri, 07 Oct 2022 11:01:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665165707; cv=none;
        d=google.com; s=arc-20160816;
        b=mZe2Ox8qxM+NJlbac4MXMhZBpsmPk68A4yZjpxQdTbUb/kD0xDo/UEk7iHbrMVG+Wr
         EnwahkLRdqpV7E5+HrkGnPwLxpIcy5ZETiAiDdUyYLeOzmlYJdXxTcY0H+ZuKAZGTJVt
         01YXn06ALaZ2UsZu6o0PIyCCgqkv5adUZNLy/E3Dg5Zv8k0zsqWb2kTMtOpjvlyjyMvw
         Ft2pMRlJkq3pmKKQZ+Adsh+cWDMDZR+3TE7HbQP/CqQ6QserMmqVBt3RNbEcihvA4jtb
         xnCmFCMWlkYTZtfCjoXL7SzRvZQtth3D5AA/5OOwpWW/V0QzW9IaPxRUORnQ/2939ZW/
         DFwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SRC0yDTW0mt75wzDb9dHc03R21A1YNbYmob7gKuK8jQ=;
        b=NflCwbw/PzNctJR03KXzjy/iCo0btci5tMzYzx73NP4cUBtQSG3ljBaDnrHugtTCPb
         CEE9MPoIlvoi1mlEYou8CbHG0uj2RoaDXyomVNabJdjgW5q+mGepAYxiJRePXHcannes
         cyvUsO63wYr9bNVhqTSZeawAc+sMVwJO2I8XzID3/CEVjU4duSBihQF7TeZNHC7FQb8N
         dL+DbauOncqcmM6Y+KBz4BIoWzi9o+DEsbMl6AG4ZNQnjYlwcuBu7Vs7xZ6cjzKsTYlD
         1q9YtL/lUdwiw62Dm9VBh4sBVC8qk6GnvwGvCCCcLTM/9X0veRm9jtosqL2D1bJQxvST
         00OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=jtpfM9yS;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id q17-20020a7bce91000000b003c446598833si3683wmj.0.2022.10.07.11.01.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 11:01:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 3C5B1B81FCF;
	Fri,  7 Oct 2022 18:01:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DF34FC433C1;
	Fri,  7 Oct 2022 18:01:39 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 417aa62e (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Fri, 7 Oct 2022 18:01:38 +0000 (UTC)
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
	Jan Kara <jack@suse.cz>
Subject: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Date: Fri,  7 Oct 2022 12:01:03 -0600
Message-Id: <20221007180107.216067-3-Jason@zx2c4.com>
In-Reply-To: <20221007180107.216067-1-Jason@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=jtpfM9yS;       spf=pass
 (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
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

Rather than incurring a division or requesting too many random bytes for
the given range, use the prandom_u32_max() function, which only takes
the minimum required bytes from the RNG and avoids divisions.

Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: KP Singh <kpsingh@kernel.org>
Reviewed-by: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.com> #=
 for drbd
Reviewed-by: Jan Kara <jack@suse.cz> # for ext2, ext4, and sbitmap
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 arch/arm64/kernel/process.c          |  2 +-
 arch/loongarch/kernel/process.c      |  2 +-
 arch/loongarch/kernel/vdso.c         |  2 +-
 arch/mips/kernel/process.c           |  2 +-
 arch/mips/kernel/vdso.c              |  2 +-
 arch/parisc/kernel/vdso.c            |  2 +-
 arch/powerpc/kernel/process.c        |  2 +-
 arch/s390/kernel/process.c           |  2 +-
 drivers/block/drbd/drbd_receiver.c   |  4 ++--
 drivers/md/bcache/request.c          |  2 +-
 drivers/mtd/tests/stresstest.c       | 17 ++++-------------
 drivers/mtd/ubi/debug.h              |  6 +++---
 drivers/net/ethernet/broadcom/cnic.c |  3 +--
 fs/ext2/ialloc.c                     |  3 +--
 fs/ext4/ialloc.c                     |  5 ++---
 fs/ubifs/lpt_commit.c                |  2 +-
 fs/ubifs/tnc_commit.c                |  2 +-
 fs/xfs/libxfs/xfs_alloc.c            |  2 +-
 fs/xfs/libxfs/xfs_ialloc.c           |  2 +-
 include/linux/nodemask.h             |  2 +-
 lib/cmdline_kunit.c                  |  4 ++--
 lib/kobject.c                        |  2 +-
 lib/reed_solomon/test_rslib.c        |  2 +-
 lib/sbitmap.c                        |  2 +-
 lib/test_hexdump.c                   |  2 +-
 lib/test_vmalloc.c                   | 17 ++++-------------
 net/core/pktgen.c                    |  4 ++--
 net/ipv4/inet_hashtables.c           |  2 +-
 net/sunrpc/cache.c                   |  2 +-
 net/sunrpc/xprtsock.c                |  2 +-
 30 files changed, 42 insertions(+), 63 deletions(-)

diff --git a/arch/arm64/kernel/process.c b/arch/arm64/kernel/process.c
index 92bcc1768f0b..87203429f802 100644
--- a/arch/arm64/kernel/process.c
+++ b/arch/arm64/kernel/process.c
@@ -595,7 +595,7 @@ unsigned long __get_wchan(struct task_struct *p)
 unsigned long arch_align_stack(unsigned long sp)
 {
 	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
-		sp -=3D get_random_int() & ~PAGE_MASK;
+		sp -=3D prandom_u32_max(PAGE_SIZE);
 	return sp & ~0xf;
 }
=20
diff --git a/arch/loongarch/kernel/process.c b/arch/loongarch/kernel/proces=
s.c
index 660492f064e7..1256e3582475 100644
--- a/arch/loongarch/kernel/process.c
+++ b/arch/loongarch/kernel/process.c
@@ -293,7 +293,7 @@ unsigned long stack_top(void)
 unsigned long arch_align_stack(unsigned long sp)
 {
 	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
-		sp -=3D get_random_int() & ~PAGE_MASK;
+		sp -=3D prandom_u32_max(PAGE_SIZE);
=20
 	return sp & STACK_ALIGN;
 }
diff --git a/arch/loongarch/kernel/vdso.c b/arch/loongarch/kernel/vdso.c
index f32c38abd791..8c9826062652 100644
--- a/arch/loongarch/kernel/vdso.c
+++ b/arch/loongarch/kernel/vdso.c
@@ -78,7 +78,7 @@ static unsigned long vdso_base(void)
 	unsigned long base =3D STACK_TOP;
=20
 	if (current->flags & PF_RANDOMIZE) {
-		base +=3D get_random_int() & (VDSO_RANDOMIZE_SIZE - 1);
+		base +=3D prandom_u32_max(VDSO_RANDOMIZE_SIZE);
 		base =3D PAGE_ALIGN(base);
 	}
=20
diff --git a/arch/mips/kernel/process.c b/arch/mips/kernel/process.c
index 35b912bce429..bbe9ce471791 100644
--- a/arch/mips/kernel/process.c
+++ b/arch/mips/kernel/process.c
@@ -711,7 +711,7 @@ unsigned long mips_stack_top(void)
 unsigned long arch_align_stack(unsigned long sp)
 {
 	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
-		sp -=3D get_random_int() & ~PAGE_MASK;
+		sp -=3D prandom_u32_max(PAGE_SIZE);
=20
 	return sp & ALMASK;
 }
diff --git a/arch/mips/kernel/vdso.c b/arch/mips/kernel/vdso.c
index b2cc2c2dd4bf..5fd9bf1d596c 100644
--- a/arch/mips/kernel/vdso.c
+++ b/arch/mips/kernel/vdso.c
@@ -79,7 +79,7 @@ static unsigned long vdso_base(void)
 	}
=20
 	if (current->flags & PF_RANDOMIZE) {
-		base +=3D get_random_int() & (VDSO_RANDOMIZE_SIZE - 1);
+		base +=3D prandom_u32_max(VDSO_RANDOMIZE_SIZE);
 		base =3D PAGE_ALIGN(base);
 	}
=20
diff --git a/arch/parisc/kernel/vdso.c b/arch/parisc/kernel/vdso.c
index 63dc44c4c246..47e5960a2f96 100644
--- a/arch/parisc/kernel/vdso.c
+++ b/arch/parisc/kernel/vdso.c
@@ -75,7 +75,7 @@ int arch_setup_additional_pages(struct linux_binprm *bprm=
,
=20
 	map_base =3D mm->mmap_base;
 	if (current->flags & PF_RANDOMIZE)
-		map_base -=3D (get_random_int() & 0x1f) * PAGE_SIZE;
+		map_base -=3D prandom_u32_max(0x20) * PAGE_SIZE;
=20
 	vdso_text_start =3D get_unmapped_area(NULL, map_base, vdso_text_len, 0, 0=
);
=20
diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index 0fbda89cd1bb..ff920f4d4317 100644
--- a/arch/powerpc/kernel/process.c
+++ b/arch/powerpc/kernel/process.c
@@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
 unsigned long arch_align_stack(unsigned long sp)
 {
 	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
-		sp -=3D get_random_int() & ~PAGE_MASK;
+		sp -=3D prandom_u32_max(PAGE_SIZE);
 	return sp & ~0xf;
 }
diff --git a/arch/s390/kernel/process.c b/arch/s390/kernel/process.c
index d5119e039d85..5ec78555dd2e 100644
--- a/arch/s390/kernel/process.c
+++ b/arch/s390/kernel/process.c
@@ -224,7 +224,7 @@ unsigned long __get_wchan(struct task_struct *p)
 unsigned long arch_align_stack(unsigned long sp)
 {
 	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
-		sp -=3D get_random_int() & ~PAGE_MASK;
+		sp -=3D prandom_u32_max(PAGE_SIZE);
 	return sp & ~0xf;
 }
=20
diff --git a/drivers/block/drbd/drbd_receiver.c b/drivers/block/drbd/drbd_r=
eceiver.c
index af4c7d65490b..d8b1417dc503 100644
--- a/drivers/block/drbd/drbd_receiver.c
+++ b/drivers/block/drbd/drbd_receiver.c
@@ -781,7 +781,7 @@ static struct socket *drbd_wait_for_connect(struct drbd=
_connection *connection,
=20
 	timeo =3D connect_int * HZ;
 	/* 28.5% random jitter */
-	timeo +=3D (prandom_u32() & 1) ? timeo / 7 : -timeo / 7;
+	timeo +=3D prandom_u32_max(2) ? timeo / 7 : -timeo / 7;
=20
 	err =3D wait_for_completion_interruptible_timeout(&ad->door_bell, timeo);
 	if (err <=3D 0)
@@ -1004,7 +1004,7 @@ static int conn_connect(struct drbd_connection *conne=
ction)
 				drbd_warn(connection, "Error receiving initial packet\n");
 				sock_release(s);
 randomize:
-				if (prandom_u32() & 1)
+				if (prandom_u32_max(2))
 					goto retry;
 			}
 		}
diff --git a/drivers/md/bcache/request.c b/drivers/md/bcache/request.c
index f2c5a7e06fa9..3427555b0cca 100644
--- a/drivers/md/bcache/request.c
+++ b/drivers/md/bcache/request.c
@@ -401,7 +401,7 @@ static bool check_should_bypass(struct cached_dev *dc, =
struct bio *bio)
 	}
=20
 	if (bypass_torture_test(dc)) {
-		if ((get_random_int() & 3) =3D=3D 3)
+		if (prandom_u32_max(4) =3D=3D 3)
 			goto skip;
 		else
 			goto rescale;
diff --git a/drivers/mtd/tests/stresstest.c b/drivers/mtd/tests/stresstest.=
c
index cb29c8c1b370..d2faaca7f19d 100644
--- a/drivers/mtd/tests/stresstest.c
+++ b/drivers/mtd/tests/stresstest.c
@@ -45,9 +45,8 @@ static int rand_eb(void)
 	unsigned int eb;
=20
 again:
-	eb =3D prandom_u32();
 	/* Read or write up 2 eraseblocks at a time - hence 'ebcnt - 1' */
-	eb %=3D (ebcnt - 1);
+	eb =3D prandom_u32_max(ebcnt - 1);
 	if (bbt[eb])
 		goto again;
 	return eb;
@@ -55,20 +54,12 @@ static int rand_eb(void)
=20
 static int rand_offs(void)
 {
-	unsigned int offs;
-
-	offs =3D prandom_u32();
-	offs %=3D bufsize;
-	return offs;
+	return prandom_u32_max(bufsize);
 }
=20
 static int rand_len(int offs)
 {
-	unsigned int len;
-
-	len =3D prandom_u32();
-	len %=3D (bufsize - offs);
-	return len;
+	return prandom_u32_max(bufsize - offs);
 }
=20
 static int do_read(void)
@@ -127,7 +118,7 @@ static int do_write(void)
=20
 static int do_operation(void)
 {
-	if (prandom_u32() & 1)
+	if (prandom_u32_max(2))
 		return do_read();
 	else
 		return do_write();
diff --git a/drivers/mtd/ubi/debug.h b/drivers/mtd/ubi/debug.h
index 118248a5d7d4..dc8d8f83657a 100644
--- a/drivers/mtd/ubi/debug.h
+++ b/drivers/mtd/ubi/debug.h
@@ -73,7 +73,7 @@ static inline int ubi_dbg_is_bgt_disabled(const struct ub=
i_device *ubi)
 static inline int ubi_dbg_is_bitflip(const struct ubi_device *ubi)
 {
 	if (ubi->dbg.emulate_bitflips)
-		return !(prandom_u32() % 200);
+		return !prandom_u32_max(200);
 	return 0;
 }
=20
@@ -87,7 +87,7 @@ static inline int ubi_dbg_is_bitflip(const struct ubi_dev=
ice *ubi)
 static inline int ubi_dbg_is_write_failure(const struct ubi_device *ubi)
 {
 	if (ubi->dbg.emulate_io_failures)
-		return !(prandom_u32() % 500);
+		return !prandom_u32_max(500);
 	return 0;
 }
=20
@@ -101,7 +101,7 @@ static inline int ubi_dbg_is_write_failure(const struct=
 ubi_device *ubi)
 static inline int ubi_dbg_is_erase_failure(const struct ubi_device *ubi)
 {
 	if (ubi->dbg.emulate_io_failures)
-		return !(prandom_u32() % 400);
+		return !prandom_u32_max(400);
 	return 0;
 }
=20
diff --git a/drivers/net/ethernet/broadcom/cnic.c b/drivers/net/ethernet/br=
oadcom/cnic.c
index e86503d97f32..f597b313acaa 100644
--- a/drivers/net/ethernet/broadcom/cnic.c
+++ b/drivers/net/ethernet/broadcom/cnic.c
@@ -4105,8 +4105,7 @@ static int cnic_cm_alloc_mem(struct cnic_dev *dev)
 	for (i =3D 0; i < MAX_CM_SK_TBL_SZ; i++)
 		atomic_set(&cp->csk_tbl[i].ref_count, 0);
=20
-	port_id =3D prandom_u32();
-	port_id %=3D CNIC_LOCAL_PORT_RANGE;
+	port_id =3D prandom_u32_max(CNIC_LOCAL_PORT_RANGE);
 	if (cnic_init_id_tbl(&cp->csk_port_tbl, CNIC_LOCAL_PORT_RANGE,
 			     CNIC_LOCAL_PORT_MIN, port_id)) {
 		cnic_cm_free_mem(dev);
diff --git a/fs/ext2/ialloc.c b/fs/ext2/ialloc.c
index 998dd2ac8008..f4944c4dee60 100644
--- a/fs/ext2/ialloc.c
+++ b/fs/ext2/ialloc.c
@@ -277,8 +277,7 @@ static int find_group_orlov(struct super_block *sb, str=
uct inode *parent)
 		int best_ndir =3D inodes_per_group;
 		int best_group =3D -1;
=20
-		group =3D prandom_u32();
-		parent_group =3D (unsigned)group % ngroups;
+		parent_group =3D prandom_u32_max(ngroups);
 		for (i =3D 0; i < ngroups; i++) {
 			group =3D (parent_group + i) % ngroups;
 			desc =3D ext2_get_group_desc (sb, group, NULL);
diff --git a/fs/ext4/ialloc.c b/fs/ext4/ialloc.c
index f73e5eb43eae..36d5bc595cc2 100644
--- a/fs/ext4/ialloc.c
+++ b/fs/ext4/ialloc.c
@@ -463,10 +463,9 @@ static int find_group_orlov(struct super_block *sb, st=
ruct inode *parent,
 			hinfo.hash_version =3D DX_HASH_HALF_MD4;
 			hinfo.seed =3D sbi->s_hash_seed;
 			ext4fs_dirhash(parent, qstr->name, qstr->len, &hinfo);
-			grp =3D hinfo.hash;
+			parent_group =3D hinfo.hash % ngroups;
 		} else
-			grp =3D prandom_u32();
-		parent_group =3D (unsigned)grp % ngroups;
+			parent_group =3D prandom_u32_max(ngroups);
 		for (i =3D 0; i < ngroups; i++) {
 			g =3D (parent_group + i) % ngroups;
 			get_orlov_stats(sb, g, flex_size, &stats);
diff --git a/fs/ubifs/lpt_commit.c b/fs/ubifs/lpt_commit.c
index cd4d5726a78d..cfbc31f709f4 100644
--- a/fs/ubifs/lpt_commit.c
+++ b/fs/ubifs/lpt_commit.c
@@ -1970,7 +1970,7 @@ static int dbg_populate_lsave(struct ubifs_info *c)
=20
 	if (!dbg_is_chk_gen(c))
 		return 0;
-	if (prandom_u32() & 3)
+	if (prandom_u32_max(4))
 		return 0;
=20
 	for (i =3D 0; i < c->lsave_cnt; i++)
diff --git a/fs/ubifs/tnc_commit.c b/fs/ubifs/tnc_commit.c
index 58c92c96ecef..01362ad5f804 100644
--- a/fs/ubifs/tnc_commit.c
+++ b/fs/ubifs/tnc_commit.c
@@ -700,7 +700,7 @@ static int alloc_idx_lebs(struct ubifs_info *c, int cnt=
)
 		c->ilebs[c->ileb_cnt++] =3D lnum;
 		dbg_cmt("LEB %d", lnum);
 	}
-	if (dbg_is_chk_index(c) && !(prandom_u32() & 7))
+	if (dbg_is_chk_index(c) && !prandom_u32_max(8))
 		return -ENOSPC;
 	return 0;
 }
diff --git a/fs/xfs/libxfs/xfs_alloc.c b/fs/xfs/libxfs/xfs_alloc.c
index e2bdf089c0a3..6261599bb389 100644
--- a/fs/xfs/libxfs/xfs_alloc.c
+++ b/fs/xfs/libxfs/xfs_alloc.c
@@ -1520,7 +1520,7 @@ xfs_alloc_ag_vextent_lastblock(
=20
 #ifdef DEBUG
 	/* Randomly don't execute the first algorithm. */
-	if (prandom_u32() & 1)
+	if (prandom_u32_max(2))
 		return 0;
 #endif
=20
diff --git a/fs/xfs/libxfs/xfs_ialloc.c b/fs/xfs/libxfs/xfs_ialloc.c
index 6cdfd64bc56b..7838b31126e2 100644
--- a/fs/xfs/libxfs/xfs_ialloc.c
+++ b/fs/xfs/libxfs/xfs_ialloc.c
@@ -636,7 +636,7 @@ xfs_ialloc_ag_alloc(
 	/* randomly do sparse inode allocations */
 	if (xfs_has_sparseinodes(tp->t_mountp) &&
 	    igeo->ialloc_min_blks < igeo->ialloc_blks)
-		do_sparse =3D prandom_u32() & 1;
+		do_sparse =3D prandom_u32_max(2);
 #endif
=20
 	/*
diff --git a/include/linux/nodemask.h b/include/linux/nodemask.h
index 4b71a96190a8..66ee9b4b7925 100644
--- a/include/linux/nodemask.h
+++ b/include/linux/nodemask.h
@@ -509,7 +509,7 @@ static inline int node_random(const nodemask_t *maskp)
 	w =3D nodes_weight(*maskp);
 	if (w)
 		bit =3D bitmap_ord_to_pos(maskp->bits,
-			get_random_int() % w, MAX_NUMNODES);
+			prandom_u32_max(w), MAX_NUMNODES);
 	return bit;
 #else
 	return 0;
diff --git a/lib/cmdline_kunit.c b/lib/cmdline_kunit.c
index e6a31c927b06..a72a2c16066e 100644
--- a/lib/cmdline_kunit.c
+++ b/lib/cmdline_kunit.c
@@ -76,7 +76,7 @@ static void cmdline_test_lead_int(struct kunit *test)
 		int rc =3D cmdline_test_values[i];
 		int offset;
=20
-		sprintf(in, "%u%s", prandom_u32_max(256), str);
+		sprintf(in, "%u%s", get_random_int() % 256, str);
 		/* Only first '-' after the number will advance the pointer */
 		offset =3D strlen(in) - strlen(str) + !!(rc =3D=3D 2);
 		cmdline_do_one_test(test, in, rc, offset);
@@ -94,7 +94,7 @@ static void cmdline_test_tail_int(struct kunit *test)
 		int rc =3D strcmp(str, "") ? (strcmp(str, "-") ? 0 : 1) : 1;
 		int offset;
=20
-		sprintf(in, "%s%u", str, prandom_u32_max(256));
+		sprintf(in, "%s%u", str, get_random_int() % 256);
 		/*
 		 * Only first and leading '-' not followed by integer
 		 * will advance the pointer.
diff --git a/lib/kobject.c b/lib/kobject.c
index 5f0e71ab292c..a0b2dbfcfa23 100644
--- a/lib/kobject.c
+++ b/lib/kobject.c
@@ -694,7 +694,7 @@ static void kobject_release(struct kref *kref)
 {
 	struct kobject *kobj =3D container_of(kref, struct kobject, kref);
 #ifdef CONFIG_DEBUG_KOBJECT_RELEASE
-	unsigned long delay =3D HZ + HZ * (get_random_int() & 0x3);
+	unsigned long delay =3D HZ + HZ * prandom_u32_max(4);
 	pr_info("kobject: '%s' (%p): %s, parent %p (delayed %ld)\n",
 		 kobject_name(kobj), kobj, __func__, kobj->parent, delay);
 	INIT_DELAYED_WORK(&kobj->release, kobject_delayed_cleanup);
diff --git a/lib/reed_solomon/test_rslib.c b/lib/reed_solomon/test_rslib.c
index 6faf9c9a6215..4d241bdc88aa 100644
--- a/lib/reed_solomon/test_rslib.c
+++ b/lib/reed_solomon/test_rslib.c
@@ -199,7 +199,7 @@ static int get_rcw_we(struct rs_control *rs, struct wsp=
ace *ws,
=20
 		derrlocs[i] =3D errloc;
=20
-		if (ewsc && (prandom_u32() & 1)) {
+		if (ewsc && prandom_u32_max(2)) {
 			/* Erasure with the symbol intact */
 			errlocs[errloc] =3D 2;
 		} else {
diff --git a/lib/sbitmap.c b/lib/sbitmap.c
index c4f04edf3ee9..ef0661504561 100644
--- a/lib/sbitmap.c
+++ b/lib/sbitmap.c
@@ -21,7 +21,7 @@ static int init_alloc_hint(struct sbitmap *sb, gfp_t flag=
s)
 		int i;
=20
 		for_each_possible_cpu(i)
-			*per_cpu_ptr(sb->alloc_hint, i) =3D prandom_u32() % depth;
+			*per_cpu_ptr(sb->alloc_hint, i) =3D prandom_u32_max(depth);
 	}
 	return 0;
 }
diff --git a/lib/test_hexdump.c b/lib/test_hexdump.c
index 0927f44cd478..41a0321f641a 100644
--- a/lib/test_hexdump.c
+++ b/lib/test_hexdump.c
@@ -208,7 +208,7 @@ static void __init test_hexdump_overflow(size_t buflen,=
 size_t len,
 static void __init test_hexdump_overflow_set(size_t buflen, bool ascii)
 {
 	unsigned int i =3D 0;
-	int rs =3D (prandom_u32_max(2) + 1) * 16;
+	int rs =3D prandom_u32_max(2) + 1 * 16;
=20
 	do {
 		int gs =3D 1 << i;
diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
index 4f2f2d1bac56..56ffaa8dd3f6 100644
--- a/lib/test_vmalloc.c
+++ b/lib/test_vmalloc.c
@@ -151,9 +151,7 @@ static int random_size_alloc_test(void)
 	int i;
=20
 	for (i =3D 0; i < test_loop_count; i++) {
-		n =3D prandom_u32();
-		n =3D (n % 100) + 1;
-
+		n =3D prandom_u32_max(n % 100) + 1;
 		p =3D vmalloc(n * PAGE_SIZE);
=20
 		if (!p)
@@ -293,16 +291,12 @@ pcpu_alloc_test(void)
 		return -1;
=20
 	for (i =3D 0; i < 35000; i++) {
-		unsigned int r;
-
-		r =3D prandom_u32();
-		size =3D (r % (PAGE_SIZE / 4)) + 1;
+		size =3D prandom_u32_max(PAGE_SIZE / 4) + 1;
=20
 		/*
 		 * Maximum PAGE_SIZE
 		 */
-		r =3D prandom_u32();
-		align =3D 1 << ((r % 11) + 1);
+		align =3D 1 << (prandom_u32_max(11) + 1);
=20
 		pcpu[i] =3D __alloc_percpu(size, align);
 		if (!pcpu[i])
@@ -393,14 +387,11 @@ static struct test_driver {
=20
 static void shuffle_array(int *arr, int n)
 {
-	unsigned int rnd;
 	int i, j;
=20
 	for (i =3D n - 1; i > 0; i--)  {
-		rnd =3D prandom_u32();
-
 		/* Cut the range. */
-		j =3D rnd % i;
+		j =3D prandom_u32_max(i);
=20
 		/* Swap indexes. */
 		swap(arr[i], arr[j]);
diff --git a/net/core/pktgen.c b/net/core/pktgen.c
index a13ee452429e..5ca4f953034c 100644
--- a/net/core/pktgen.c
+++ b/net/core/pktgen.c
@@ -2469,11 +2469,11 @@ static void mod_cur_headers(struct pktgen_dev *pkt_=
dev)
 	}
=20
 	if ((pkt_dev->flags & F_VID_RND) && (pkt_dev->vlan_id !=3D 0xffff)) {
-		pkt_dev->vlan_id =3D prandom_u32() & (4096 - 1);
+		pkt_dev->vlan_id =3D prandom_u32_max(4096);
 	}
=20
 	if ((pkt_dev->flags & F_SVID_RND) && (pkt_dev->svlan_id !=3D 0xffff)) {
-		pkt_dev->svlan_id =3D prandom_u32() & (4096 - 1);
+		pkt_dev->svlan_id =3D prandom_u32_max(4096);
 	}
=20
 	if (pkt_dev->udp_src_min < pkt_dev->udp_src_max) {
diff --git a/net/ipv4/inet_hashtables.c b/net/ipv4/inet_hashtables.c
index b9d995b5ce24..9dc070f2018e 100644
--- a/net/ipv4/inet_hashtables.c
+++ b/net/ipv4/inet_hashtables.c
@@ -794,7 +794,7 @@ int __inet_hash_connect(struct inet_timewait_death_row =
*death_row,
 	 * on low contention the randomness is maximal and on high contention
 	 * it may be inexistent.
 	 */
-	i =3D max_t(int, i, (prandom_u32() & 7) * 2);
+	i =3D max_t(int, i, prandom_u32_max(8) * 2);
 	WRITE_ONCE(table_perturb[index], READ_ONCE(table_perturb[index]) + i + 2)=
;
=20
 	/* Head lock still held and bh's disabled */
diff --git a/net/sunrpc/cache.c b/net/sunrpc/cache.c
index c3c693b51c94..f075a9fb5ccc 100644
--- a/net/sunrpc/cache.c
+++ b/net/sunrpc/cache.c
@@ -677,7 +677,7 @@ static void cache_limit_defers(void)
=20
 	/* Consider removing either the first or the last */
 	if (cache_defer_cnt > DFR_MAX) {
-		if (prandom_u32() & 1)
+		if (prandom_u32_max(2))
 			discard =3D list_entry(cache_defer_list.next,
 					     struct cache_deferred_req, recent);
 		else
diff --git a/net/sunrpc/xprtsock.c b/net/sunrpc/xprtsock.c
index e976007f4fd0..c2caee703d2c 100644
--- a/net/sunrpc/xprtsock.c
+++ b/net/sunrpc/xprtsock.c
@@ -1619,7 +1619,7 @@ static int xs_get_random_port(void)
 	if (max < min)
 		return -EADDRINUSE;
 	range =3D max - min + 1;
-	rand =3D (unsigned short) prandom_u32() % range;
+	rand =3D (unsigned short) prandom_u32_max(range);
 	return rand + min;
 }
=20
--=20
2.37.3

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221007180107.216067-3-Jason%40zx2c4.com.
