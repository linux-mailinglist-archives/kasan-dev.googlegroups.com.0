Return-Path: <kasan-dev+bncBCLI747UVAFRBZNBQSNAMGQEX5XTX7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AF3F5F8342
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 07:55:50 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id h205-20020a1c21d6000000b003c3eb8683acsf817956wmh.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 22:55:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665208550; cv=pass;
        d=google.com; s=arc-20160816;
        b=rl39RbENemZCKpwJZRo/ilU7HTu+HiBpz8GuOnShz5Njp4lR6n1gSXFw4c+66q494K
         RLwUqsNoTgstyMvBuake1Y3vqs7aUCwQGK1Oxl42JAL2HCouN/YfLPE73e/C7msrnfKN
         XbtVcHJ7HI8V9gOybZIFFN03d7voMcwAh2s3XRrmnUW5ny7m0sr87YqRI34R9KxyHnun
         gBw5r6kzfe3byRm3xd03gzRV6XISH+FkrSNv5XGwf81AdoWEPSq8Nmoyj8jR1QBmPq/2
         XLDgIa0zZHD4bp1HgQJ7rUKKcVevuAUil87nNekkg1x0YRKMfcaFrmZH7xdc96EiSczW
         PaCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AmicRX0QaLfk03MhxJ9NB5L2DFVjpe0B3KPYGRCSRlk=;
        b=BdW/l/WFxDrx5utHNeJWZeFNnYcYwO2PjyjceHO4OFUxp4fOxyo4isPQJXOU8Zg8Pq
         Im0TMFaDlKERnSDxGStOAZfS0aVNyj4FGCt9ZZrV4/4tQ4oCsnrj+CBnsNUL/KaNTPuf
         eMCAnhUCby2lIuaQLJHLJcSzO+vyAj9Avfdx259qPGB0COBPfGYEU+Ui1lkZKJWmACtt
         Smgj2auVWm/e390XYjKGYT0GuqeiEIY2UXL+VC1BxbUnwWWk/P4VUdRg7lity5o/n2qL
         Z+jBrnmdevMINyvVjrFmfk7AKkDi8VMyK1OEvCLha1gdRtv+dx+uRBXbL6Y25qZFqyTE
         jYGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=VjWtB1zu;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AmicRX0QaLfk03MhxJ9NB5L2DFVjpe0B3KPYGRCSRlk=;
        b=ciUgRD4BoT2XSgkFS1rPY1aNIcomnbHm3EvoJXk1xHFS8jKxjRBYTggNzexxhvF0Au
         S/KWwWG/OjmYcMDNWGy+gQ5jStKQnYcPoQOFXd8fHFw3EV0J07PpIcI/pzUqKXZkIqOa
         QaBU05FEtpMiisSsYfYwtUhjuLJLpKU0Hd6l++cvIMbboamLgY5YOZ2qRoSBgi6M1IDR
         xuv6pdb+pAM25zAKOm7fekWdih16+763eOHoD49K+aWMnofg+CemGDmzLHi5OpX5fj7t
         YLkTQ8rrYuOAMcDGgySX6f7S6tZOXwulaHLdAhozHuVD2crSoPlPfw76JwAucT8/C7EU
         cetw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=AmicRX0QaLfk03MhxJ9NB5L2DFVjpe0B3KPYGRCSRlk=;
        b=n6flgqOn5VhF0EwtnA2hITjn5I0kBEPWzRZqwgKOxcwG6IimPHp8WYAaYVQtNhraPt
         zLFm5YDgEF1y1YsZQzDSJaHOM4zFHJ2hR7UsmUi6xm9PNX3NYSYw6+4/Zwd1kkajtPyL
         5DXt/iVVGufFcmBtGvALTY20+F1v2AXhbiCh/v9S4e2wMNkXzvIm9bT8918p84Y8ncv+
         7nFFKz65z8wH7CWAtaeb9KHajTPqaJZav168jkZt94WGy2Ho7HRXa4HAlKAmZa21YYlI
         wdhy23Y98nHgRAY91jlnsUIvmGk4Y9DBCmnBliil656yGaRuhwweKEWRXtpo/kV1Znrd
         IlLw==
X-Gm-Message-State: ACrzQf38SsYSXfS0V8+7smyR1hHc+hCN2xqVSKqvveZOPC/kYb4MiM2U
	1Dgc2Iqz/4Z0VsQPVFyetMA=
X-Google-Smtp-Source: AMsMyM4OhdUjg24gBO2z46U3+7QL5QfWjtG26E8rrhXsjoSLxxIpDC7SvRW43rEsMVX2avD3Uul3eQ==
X-Received: by 2002:a5d:620c:0:b0:22b:e59:8d3a with SMTP id y12-20020a5d620c000000b0022b0e598d3amr5137126wru.28.1665208549858;
        Fri, 07 Oct 2022 22:55:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f0a:b0:225:6559:3374 with SMTP id
 bv10-20020a0560001f0a00b0022565593374ls2798120wrb.2.-pod-prod-gmail; Fri, 07
 Oct 2022 22:55:48 -0700 (PDT)
X-Received: by 2002:a5d:4104:0:b0:22c:dd2d:9028 with SMTP id l4-20020a5d4104000000b0022cdd2d9028mr5497490wrp.577.1665208548900;
        Fri, 07 Oct 2022 22:55:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665208548; cv=none;
        d=google.com; s=arc-20160816;
        b=HDN2GcAeSLaedg6fO5yxcHAfF3aH+vVqD7nHQggPFn3yPMhZ7X+lmV/c87HSqnIDQE
         EgEwHeMu/xpB6/oSdzmr1kMS0svIIsL0Sj9MnDqWajQwr1x3CgPv8IDmXOZJXI4sP2b/
         u2HqnsFQK3ZJ8g7mYPwqqVsLsPtqCfelt0yULjup+QreMY3KfuZ978Sk0yvkksCI1CEr
         ryQGDmATDhx079HVsPvvX1rT1fnDznJnmezpzHMhcQs+kV0cWakbVPA0xTpwXx+BrJ97
         IcfKjkI5+ywRxI3FOgjvM01PG5R6RJajZoxSFFBwj/mif5f0n0x9YixjrD1fv5lgAsOE
         YOdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=b9+Cj23d0QLjz/zJyugpHCrgyef3w8ya5Q+kavhuScs=;
        b=c30O3e4cGw+iubHW+8nbpfEGLdh3ET70R29GWpp/Frmpp+NybzTVDEtXTWNRlcOcKN
         W40Ixfx//+8d2J0OFyVEdcSLEc+/itQ7pesG9RLox2eg2Wy7Zlt5dqFru8pJtc0TGsfc
         tPHgFp8ZtFdgO0lJr4A42TD8XGWS2HYqmz9awk9ZIF7e2Por64ql/Qoyu9GdldpGsZBf
         G9ymT6aCc3IQG2MjrK6YQJhgRrFZW2Nb17p+5WuXba2Wb/jV7n4FL3TbZhCSLh+4U+tb
         aY/EfghYUyVn9R7XwtCHvEN2KVH6FLdb+tLe5zcF/bbgU+LfQh3e2Lr3mPDuDkp+bf/K
         rpEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=VjWtB1zu;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id bo2-20020a056000068200b0022c8a1af685si165049wrb.4.2022.10.07.22.55.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 22:55:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9AB11B803F2;
	Sat,  8 Oct 2022 05:55:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7E717C433D6;
	Sat,  8 Oct 2022 05:55:41 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 75de389f (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 05:55:40 +0000 (UTC)
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
Subject: [PATCH v5 4/7] treewide: use get_random_{u8,u16}() when possible, part 2
Date: Fri,  7 Oct 2022 23:53:56 -0600
Message-Id: <20221008055359.286426-5-Jason@zx2c4.com>
In-Reply-To: <20221008055359.286426-1-Jason@zx2c4.com>
References: <20221008055359.286426-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=VjWtB1zu;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
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

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 arch/s390/kernel/process.c  | 2 +-
 lib/test_vmalloc.c          | 2 +-
 net/ipv4/ip_output.c        | 2 +-
 net/netfilter/nf_nat_core.c | 4 ++--
 net/rds/bind.c              | 2 +-
 net/sched/sch_sfb.c         | 2 +-
 6 files changed, 7 insertions(+), 7 deletions(-)

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
diff --git a/net/ipv4/ip_output.c b/net/ipv4/ip_output.c
index 04e2034f2f8e..a4fbdbff14b3 100644
--- a/net/ipv4/ip_output.c
+++ b/net/ipv4/ip_output.c
@@ -172,7 +172,7 @@ int ip_build_and_send_pkt(struct sk_buff *skb, const struct sock *sk,
 		 * Avoid using the hashed IP ident generator.
 		 */
 		if (sk->sk_protocol == IPPROTO_TCP)
-			iph->id = (__force __be16)prandom_u32();
+			iph->id = (__force __be16)get_random_u16();
 		else
 			__ip_select_ident(net, iph, 1);
 	}
diff --git a/net/netfilter/nf_nat_core.c b/net/netfilter/nf_nat_core.c
index 7981be526f26..57c7686ac485 100644
--- a/net/netfilter/nf_nat_core.c
+++ b/net/netfilter/nf_nat_core.c
@@ -468,7 +468,7 @@ static void nf_nat_l4proto_unique_tuple(struct nf_conntrack_tuple *tuple,
 	if (range->flags & NF_NAT_RANGE_PROTO_OFFSET)
 		off = (ntohs(*keyptr) - ntohs(range->base_proto.all));
 	else
-		off = prandom_u32();
+		off = get_random_u16();
 
 	attempts = range_size;
 	if (attempts > max_attempts)
@@ -490,7 +490,7 @@ static void nf_nat_l4proto_unique_tuple(struct nf_conntrack_tuple *tuple,
 	if (attempts >= range_size || attempts < 16)
 		return;
 	attempts /= 2;
-	off = prandom_u32();
+	off = get_random_u16();
 	goto another_round;
 }
 
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
index 2829455211f8..7eb70acb4d58 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221008055359.286426-5-Jason%40zx2c4.com.
