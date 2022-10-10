Return-Path: <kasan-dev+bncBCLI747UVAFRBTOLSKNAMGQEULAI2RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD7A5FA817
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 01:07:57 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 133-20020a1c028b000000b003c5e6b44ebasf2661556wmc.9
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 16:07:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665443277; cv=pass;
        d=google.com; s=arc-20160816;
        b=bRRmEfc6VmgBBPZS5yhbATXJEvuLLRMyQlWfsN0FJxzisxoHoJmbOXlO9vQ0gPlEds
         qNUz8+mguVjIwXzWsGyvxbLFUyQZ5i1p9jC5vazChFBkhWAYeGvwB63vVTJbf/tnisbM
         5lYyAsCaiW97itVAAhJuEY6B26fW7Vp3D8SXvI/mGs4D0H9oLbeYicak2a77xb7CKDDs
         8ABFbcI/Ry/oK0P7X7WlYT7i0vft8prl7z+0Ep2j6lgVr6ziyfLUnuBmPAjIWFP6v0rx
         dHuJ2SkoB6EBJlzuyf6NduosUDtyM5w8okQg/XoSX/MPYLRaJA8OeUqkeRvSYWGShtyU
         FPZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=q9uSlwnKUqR23KEXFOB5LbI2yIIzWiJ6vAy2X/e8tI0=;
        b=bUrNJwK/yJKgVeqV58krMF11d2qwnn4Vn3/JftqubpVwnwevLODwWdDn0P2O3Y6p8Q
         +puLeutvCa+1lI9HiZCYiJUFHpoQVyPGvaplo87pjCv9c4jhwAXIpU9DSr6X7WEtRiHI
         Kl4yUM6IP4z+w1leeL4E2+daAwyiQh1oJC0SpGmHEQjxPaTqF7a6AhwiUSWdd3WWZYo1
         D2fGsan1tnOJc7jPiAP/Pi9eWtq5EOSnnzBrQAYVKoyEeTiwgutEftxUn+SQdefivz5Q
         Ajz4WmSmJWtr8efIvZ74eVfEUgcZos4g1+BSgkOGbIpOEFwG/vkng7l2nyKnndwD2Y+I
         ydnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ROyrpi8L;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=q9uSlwnKUqR23KEXFOB5LbI2yIIzWiJ6vAy2X/e8tI0=;
        b=iqRu2dcHkdWsSsYE17MCg43cMxklMWE55osh+SmXaj+Zd6qMEh8dF3l5hNZXDnu2+h
         ++bhYilc8j4eHucB896SldLkBejKzm7tQA5VxBgoNlyomW8VyrWaiNohwcwIwJCM5Swg
         WQXpmeE/lOptWN24KlkJc2JLH8MgFx+haWcY7p77lhh8Vy79bVz53p6cGhP/E5f/uUn8
         rTjSi5H/ORfMNmfIF3EPE/Js2LzszdcxtEoCrRB/PjOF1ICy/iuV8CZCWIoOXmmjabFx
         GQnIZdWAR198PsLEvvOzVgrnwj9XHCo1AIRe52/GeMZUQyu5vh3DHLpQ4OaY5QoBDx4x
         ctBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=q9uSlwnKUqR23KEXFOB5LbI2yIIzWiJ6vAy2X/e8tI0=;
        b=Aq7tU3nL+3pBQnn8xAw8FPDtUsk0DmVoCYXddK4adpM1Zai381bHZE/4Zhg8Nusous
         LGp+el3XZX3lNzKB1+Yzw56igvqPfy76GZsE8Mlui2+fgp5/+Fn1jG/SqOA+fZ985M6p
         ccAkF4dSDwvw+/FvhGOUN+QuOkCqhcD1TR5iD5crRL6clz/UBKOkd9OWCCOy1AOM9BRf
         SQxlFWTdSkBwKlbnAEXGq4C5d+M662cfQp0+rTsG7ql1lTXQSghrDR50dDoZ3r34oiKP
         Fg2Q3xpObL4X4O5oN0qTo/UhR/gkuBo1zsc6ShPoqelb9xTrAFcL4DUqExT86+HsL5W5
         sI9Q==
X-Gm-Message-State: ACrzQf2bQBSVUhcig/9928I48FlDwcXETetOGvzm2UWmLAMsJmgjNr6g
	fSFXZSKugt96pD0ohxkGdPs=
X-Google-Smtp-Source: AMsMyM78QbO2M33XDm5sebmY46jmKfWQ4CEx0i2e8FDOtymux5tsqvqrVNu6Nci3q0CykiBSLmsieA==
X-Received: by 2002:a05:600c:3781:b0:3a6:804a:afc with SMTP id o1-20020a05600c378100b003a6804a0afcmr21033472wmr.27.1665443277190;
        Mon, 10 Oct 2022 16:07:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22a:0:b0:228:ddd7:f40e with SMTP id k10-20020adfd22a000000b00228ddd7f40els12181772wrh.3.-pod-prod-gmail;
 Mon, 10 Oct 2022 16:07:56 -0700 (PDT)
X-Received: by 2002:a05:6000:1d94:b0:22e:34ef:b07f with SMTP id bk20-20020a0560001d9400b0022e34efb07fmr13141067wrb.272.1665443276238;
        Mon, 10 Oct 2022 16:07:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665443276; cv=none;
        d=google.com; s=arc-20160816;
        b=XncA+m1kFEHNJY++CtUkOQv0YsZRUu05Vk6XjZQ8gH7xXCX4pciBmvLgp1mkgbEJS2
         7jrMDOV0JW23idltkCmcfAniA/dgcgdd6GAQJG/HVUC+zGzQxYGKB4pamXB0E1p5Stk1
         yzq0VAgbITiBAnuOJ4bgVVd0jT30N8UV1EaJUX1qPaSAordkkF/PpOHKMpB1A0L65yf8
         p3ZeCyn6QSh+F6ClzCF1jA3ABIoAJMCBGYnV+ZLr9qVvqnqZJZ8+AFxrGKcYzUqyeMGy
         6DwawABkIlPrvcJG8akrBi18DjOk61QV42Vee3EmHQ8REUfGw7WFPJFBOEJWbvh+bFd0
         zrEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=N5SmbVVHQod3YQjtwLm60J+z+obZf2+Cacrefjm9UsY=;
        b=ybF39G8u+/oUDtEKUdC1dNNorx7dnWuTykylcFDI5QfB9SJvq9VRogldKBBxll8WcK
         uZ2kB1pK7XHYXEUsESl/pCybJe1TMCaxUsGCGg8e81qOOoKlNGrry3ErcA4uNJYrCFT8
         S7zWTvJcE8FXQ2g5M09CMXIekN6FOu3pkHLIeJIY/ozNFf+Y0MjRE2yFtPUENGAkwHso
         oA4boYdoESQ4UdsBhU+1xrHJawTZ/2pcsYra4YyBeZ66SQn9TMwQ2XhCzu0Px0sbjLAt
         LjjcUNehL3qJeh1nSc/l6OFj+lz8ql45pxXJX5mwP8WtG9ier1qoJIgF2Q0tK6jo2g13
         kZcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ROyrpi8L;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id m125-20020a1ca383000000b003b56ce98812si4846wme.3.2022.10.10.16.07.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 16:07:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id BF123B810FD;
	Mon, 10 Oct 2022 23:07:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0DEBC433C1;
	Mon, 10 Oct 2022 23:07:48 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 823f4769 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 10 Oct 2022 23:07:46 +0000 (UTC)
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
	x86@kernel.org
Subject: [PATCH v6 4/7] treewide: use get_random_{u8,u16}() when possible, part 2
Date: Mon, 10 Oct 2022 17:06:10 -0600
Message-Id: <20221010230613.1076905-5-Jason@zx2c4.com>
In-Reply-To: <20221010230613.1076905-1-Jason@zx2c4.com>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=ROyrpi8L;       spf=pass
 (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

Rather than truncate a 32-bit value to a 16-bit value or an 8-bit value,
simply use the get_random_{u8,u16}() functions, which are faster than
wasting the additional bytes from a 32-bit value. This was done by hand,
identifying all of the places where one of the random integer functions
was used in a non-32-bit context.

Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Yury Norov <yury.norov@gmail.com>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 arch/s390/kernel/process.c     | 2 +-
 drivers/mtd/nand/raw/nandsim.c | 2 +-
 lib/test_vmalloc.c             | 2 +-
 net/rds/bind.c                 | 2 +-
 net/sched/sch_sfb.c            | 2 +-
 5 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/s390/kernel/process.c b/arch/s390/kernel/process.c
index 5ec78555dd2e..42af4b3aa02b 100644
--- a/arch/s390/kernel/process.c
+++ b/arch/s390/kernel/process.c
@@ -230,7 +230,7 @@ unsigned long arch_align_stack(unsigned long sp)
 
 static inline unsigned long brk_rnd(void)
 {
-	return (get_random_int() & BRK_RND_MASK) << PAGE_SHIFT;
+	return (get_random_u16() & BRK_RND_MASK) << PAGE_SHIFT;
 }
 
 unsigned long arch_randomize_brk(struct mm_struct *mm)
diff --git a/drivers/mtd/nand/raw/nandsim.c b/drivers/mtd/nand/raw/nandsim.c
index 50bcf745e816..d211939c8bdd 100644
--- a/drivers/mtd/nand/raw/nandsim.c
+++ b/drivers/mtd/nand/raw/nandsim.c
@@ -1402,7 +1402,7 @@ static int ns_do_read_error(struct nandsim *ns, int num)
 
 static void ns_do_bit_flips(struct nandsim *ns, int num)
 {
-	if (bitflips && prandom_u32() < (1 << 22)) {
+	if (bitflips && get_random_u16() < (1 << 6)) {
 		int flips = 1;
 		if (bitflips > 1)
 			flips = prandom_u32_max(bitflips) + 1;
diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
index a26bbbf20e62..cf7780572f5b 100644
--- a/lib/test_vmalloc.c
+++ b/lib/test_vmalloc.c
@@ -80,7 +80,7 @@ static int random_size_align_alloc_test(void)
 	int i;
 
 	for (i = 0; i < test_loop_count; i++) {
-		rnd = prandom_u32();
+		rnd = get_random_u8();
 
 		/*
 		 * Maximum 1024 pages, if PAGE_SIZE is 4096.
diff --git a/net/rds/bind.c b/net/rds/bind.c
index 5b5fb4ca8d3e..97a29172a8ee 100644
--- a/net/rds/bind.c
+++ b/net/rds/bind.c
@@ -104,7 +104,7 @@ static int rds_add_bound(struct rds_sock *rs, const struct in6_addr *addr,
 			return -EINVAL;
 		last = rover;
 	} else {
-		rover = max_t(u16, prandom_u32(), 2);
+		rover = max_t(u16, get_random_u16(), 2);
 		last = rover - 1;
 	}
 
diff --git a/net/sched/sch_sfb.c b/net/sched/sch_sfb.c
index e2389fa3cff8..0366a1a029a9 100644
--- a/net/sched/sch_sfb.c
+++ b/net/sched/sch_sfb.c
@@ -379,7 +379,7 @@ static int sfb_enqueue(struct sk_buff *skb, struct Qdisc *sch,
 		goto enqueue;
 	}
 
-	r = prandom_u32() & SFB_MAX_PROB;
+	r = get_random_u16() & SFB_MAX_PROB;
 
 	if (unlikely(r < p_min)) {
 		if (unlikely(p_min > SFB_MAX_PROB / 2)) {
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221010230613.1076905-5-Jason%40zx2c4.com.
