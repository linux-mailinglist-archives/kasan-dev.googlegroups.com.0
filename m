Return-Path: <kasan-dev+bncBC5JXFXXVEGRBHNVR3GQMGQEHFOWA2I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WKErA6Gao2l4IAUAu9opvQ
	(envelope-from <kasan-dev+bncBC5JXFXXVEGRBHNVR3GQMGQEHFOWA2I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 02:47:13 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 88A2C1CBB46
	for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 02:47:12 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2ae44c7553dsf2827775ad.0
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Feb 2026 17:47:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772329630; cv=pass;
        d=google.com; s=arc-20240605;
        b=EBjckk7DeBmSz/lRpJmfco/Mg0QBoY/B6dvxeeZR/pSVugB5GCZHIn/14eJ3sUJ+Qy
         KKsvqc+4xwUKgStE4FQ/o8rzil65Cy0//m871OlxaAK3uIhH2x6C4QcyUl34/nZi5wKp
         RyB7kOEO44lDt+56BgIWgelbKVM2bnfFcw5bRZ6CEwTxvaID+hqe+acj64TPlGMU/0TX
         F9nvfnNvadDYmqZ7KZ3uZtnh8UHbVA8i31WmoWspQJvAHnEig5iRsR31TSP/LTNj3jEy
         R9ZTtyZtft6wuhlbS7fxU7ZIpLLxN4YjLiUxJq6WxnTjwOutIGkw4CD24jo8qNDM4SjN
         YxxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=pLT27ORtbMSrwcbMIJCBBZuJqwPLYelhncZeJE3jci4=;
        fh=hf9QtmAkvjkhV0kLQ8bxFDSI5FxqH2hHcjyvuZKm6AA=;
        b=WGZl1keoy6PuVELF1G1Xm5hn3C9+LMgylqHwMxoyiEWzxiWDepYQ6VLFkysDjEX4Vb
         Khb4KwPg46fX72FJ2b9cEGnTrMMXEPDa+vw5s3Yvv8BmeQXphXtrBUGYWZMToHhPOIWu
         aX5tFpaBxRo7rYbmpsfqUU30/cP2fb9G7bOAZwcX3qH2fp3+c0ZWD01nwnRxvVeQJq74
         +0Znsk+0Zu4GKQ5QL7M01iWRIjGWKmPMolJmSXgb79AY+XkKi2j3bfQX2Ny2zAOO05KF
         UqFURhQpObkLZed01unLIdYjdXqrnL9+n8aiFMPR500J931PPyg+m65SbsvQUiu2+yEl
         bFdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FVhrEg50;
       spf=pass (google.com: domain of sashal@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772329630; x=1772934430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pLT27ORtbMSrwcbMIJCBBZuJqwPLYelhncZeJE3jci4=;
        b=ojePmC8BeZl0cNOTFRwbOXZMWn2XF0paI3a0+BLf2v4x28K7pWCOpj7SNZ+3/aPVWF
         5EZ1K0stilLa83HWAj8ogo2BxkKKr8n5AJQP0tCA1oiv+fZMOt4h/cWVsu1EMdCxU7jI
         xALGj04zFVsgIj1PUbvMRH1HfjA49vc0IrNkHtIVI/VumQOA/YdrBJeC3TkjNDR77iGg
         lzKwfGK61JWA0ZaaWnXZFoTM27MeuZRYHtNe6fQxJcY9Fcc6ah5LsEYlrUz7+RW6vl6+
         gfIxJ+NwPN8sAi+s2CNFba9RaKW3SjHzdaovRoXW7bot6QffSKSGVKZ4YlYUdlbQYygA
         lVRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772329630; x=1772934430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pLT27ORtbMSrwcbMIJCBBZuJqwPLYelhncZeJE3jci4=;
        b=ELs3eCzcuzpd+CobkoDip2Hi5GFApdhIxZKQ0oeWnMfx7xAFQ/Us1amhpbFxAqA09o
         /ayxUyYwAiP9beWhqWdoVtYD5qNFxWV36eFxdvuip+GZt3waymJ9SfQL++QJkYDWP1we
         efVxVITsd7JPmqI1ursxSnweLuzFHMkXA/oiphQh8YBIX6D39+J3Nv4dEmDn7gkM+3mM
         FxQY40jj6vUhyjUR5KMWGPIBWsHpCAQ9pc77mOGRREjhO/7SDNGGf5i8hW3ibR5z/mlX
         zkV52rAyQzX9nIpG2D/bSiINhNTjOxsXr8zVf7CVXnunvKXohEqrNmQ0tdFJh+pkbAv3
         8dgw==
X-Forwarded-Encrypted: i=2; AJvYcCWn6EC42Uxhn6IPPA5OAo0sJQPIwS+y97sV1/z8RQHbG3Rhd5/3KOjxlHaBLaEPb1vOjx/3zQ==@lfdr.de
X-Gm-Message-State: AOJu0YyvwfaOACmrpFCDXf6aAek/kHMRFu+L9GiT/BgkrYaCnshfehMS
	e3kHByx5egNSVRYLw8vlMR03F3wmXNMtHtxZoETgTnh5SAy8bmwLKPry
X-Received: by 2002:a17:903:2281:b0:2aa:cfee:a46f with SMTP id d9443c01a7336-2ae2e496a82mr50226545ad.4.1772329630222;
        Sat, 28 Feb 2026 17:47:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FeFca11BXqbHd02jIGuIfTg/X/ob8yP0zBa85NAF9kZg=="
Received: by 2002:a17:903:450:b0:2ad:ae6f:313a with SMTP id
 d9443c01a7336-2ae48dbc778ls1568435ad.1.-pod-prod-06-us; Sat, 28 Feb 2026
 17:47:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWEt5RjaquNTGqNaMc1u2/mdNov6qlS0OWPTokZgJAoTBHo9tJnwNpEJlkbaGULpwSz4BAZAI0gq60=@googlegroups.com
X-Received: by 2002:a17:902:e78b:b0:2a0:e5cd:80a1 with SMTP id d9443c01a7336-2ae2e4b950cmr81315705ad.41.1772329628643;
        Sat, 28 Feb 2026 17:47:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772329628; cv=none;
        d=google.com; s=arc-20240605;
        b=S5PF5dW/ia5lSXg/C9yb/FXUB4qxbmi05TXsKdl2oiWaVyuqAbqaQ5If/CrPAKlezu
         F/mzDkL1lj2/3h6x9vHdpKdhxyi54k9F/38DknOT78J1j4JU1khzZb/DwYzjAFZmvrWY
         kTGEwITByoVDJvQwsYBMA4TE8VZM3OFnMDpZJaspZ8lvKDMJYNYfGP0s7SIdoCMFHitj
         Fswdni/fUUEeLXVVALR2HabN5ii6mF2hCy3wc38wpqemIkAlO0hZ7KZAlxMQsBvsUhHE
         F88iXYxc0GdnIeESBHB5nbYj0sUx4NmHEKO1nfdIwKVH20MINvVs87BAlbMUt7W92CNU
         Wo7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=B+v1JEW+pJ/qw8fHGdUi+BaJu75eqnWFkcgEIhnBgkA=;
        fh=OFg15krBVjoIlzgWex7GQ3ydYCZjTlkv/NwJdnRxFdU=;
        b=dq+3tDZBVkwhAeNxP6Up/YqX2afNygu4DiFrZjSgLkeUXUavKTI+QmNyPFYSZqPYXg
         U+CUPnzCwpYkuiHcW4tSzACKt+2UV+G8+VoigWV3Q18RHHL9UQF+JAOzjjAmtqeGxBQl
         a8jNU5s4YMjeL9gKMm08zqRj8zQVPKRjCp5s9lVo1rPF9h1hc/p6/+fr6WqBVom5iDhq
         UL5aYDpRvDqvLLIHXxZSixlFuVYJ3Ix4zZxAowEyOCbJ7i84ySU39/kifTR/0mox9A2i
         fJ97h2NsdyCOSx9et2dYDRnPXpFibXMMwWFc7OSwbi2uUA77mYY4dKvHUhqpe9ocCBis
         ro0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FVhrEg50;
       spf=pass (google.com: domain of sashal@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ae490e0e17si187775ad.0.2026.02.28.17.47.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Feb 2026 17:47:08 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id AD44A60123;
	Sun,  1 Mar 2026 01:47:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C896EC19421;
	Sun,  1 Mar 2026 01:47:06 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: stable@vger.kernel.org,
	yangtiezhu@loongson.cn
Cc: Huacai Chen <chenhuacai@loongson.cn>,
	kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev
Subject: FAILED: Patch "LoongArch: Rework KASAN initialization for PTW-enabled systems" failed to apply to 6.1-stable tree
Date: Sat, 28 Feb 2026 20:47:05 -0500
Message-ID: <20260301014705.1710302-1-sashal@kernel.org>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Patchwork-Hint: ignore
X-stable: review
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FVhrEg50;       spf=pass
 (google.com: domain of sashal@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Sasha Levin <sashal@kernel.org>
Reply-To: Sasha Levin <sashal@kernel.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBC5JXFXXVEGRBHNVR3GQMGQEHFOWA2I];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCPT_COUNT_FIVE(0.00)[5];
	HAS_REPLYTO(0.00)[sashal@kernel.org];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[loongson.cn:email,googlegroups.com:email,googlegroups.com:dkim,mail-pl1-x63b.google.com:helo,mail-pl1-x63b.google.com:rdns]
X-Rspamd-Queue-Id: 88A2C1CBB46
X-Rspamd-Action: no action

The patch below does not apply to the 6.1-stable tree.
If someone wants it applied there, or to any other stable or longterm
tree, then please email the backport, including the original git commit
id to <stable@vger.kernel.org>.

Thanks,
Sasha

------------------ original commit in Linus's tree ------------------

From 5ec5ac4ca27e4daa234540ac32f9fc5219377d53 Mon Sep 17 00:00:00 2001
From: Tiezhu Yang <yangtiezhu@loongson.cn>
Date: Tue, 10 Feb 2026 19:31:17 +0800
Subject: [PATCH] LoongArch: Rework KASAN initialization for PTW-enabled
 systems

kasan_init_generic() indicates that kasan is fully initialized, so it
should be put at end of kasan_init().

Otherwise bringing up the primary CPU failed when CONFIG_KASAN is set
on PTW-enabled systems, here are the call chains:

    kernel_entry()
      start_kernel()
        setup_arch()
          kasan_init()
            kasan_init_generic()

The reason is PTW-enabled systems have speculative accesses which means
memory accesses to the shadow memory after kasan_init() may be executed
by hardware before. However, accessing shadow memory is safe only after
kasan fully initialized because kasan_init() uses a temporary PGD table
until we have populated all levels of shadow page tables and writen the
PGD register. Moving kasan_init_generic() later can defer the occasion
of kasan_enabled(), so as to avoid speculative accesses on shadow pages.

After moving kasan_init_generic() to the end, kasan_init() can no longer
call kasan_mem_to_shadow() for shadow address conversion because it will
always return kasan_early_shadow_page. On the other hand, we should keep
the current logic of kasan_mem_to_shadow() for both the early and final
stage because there may be instrumentation before kasan_init().

To solve this, we factor out a new mem_to_shadow() function from current
kasan_mem_to_shadow() for the shadow address conversion in kasan_init().

Cc: stable@vger.kernel.org
Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
---
 arch/loongarch/mm/kasan_init.c | 78 +++++++++++++++++-----------------
 1 file changed, 40 insertions(+), 38 deletions(-)

diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index 170da98ad4f55..0fc02ca064573 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -40,39 +40,43 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
 #define __pte_none(early, pte) (early ? pte_none(pte) : \
 ((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
 
-void *kasan_mem_to_shadow(const void *addr)
+static void *mem_to_shadow(const void *addr)
 {
-	if (!kasan_enabled()) {
+	unsigned long offset = 0;
+	unsigned long maddr = (unsigned long)addr;
+	unsigned long xrange = (maddr >> XRANGE_SHIFT) & 0xffff;
+
+	if (maddr >= FIXADDR_START)
 		return (void *)(kasan_early_shadow_page);
-	} else {
-		unsigned long maddr = (unsigned long)addr;
-		unsigned long xrange = (maddr >> XRANGE_SHIFT) & 0xffff;
-		unsigned long offset = 0;
-
-		if (maddr >= FIXADDR_START)
-			return (void *)(kasan_early_shadow_page);
-
-		maddr &= XRANGE_SHADOW_MASK;
-		switch (xrange) {
-		case XKPRANGE_CC_SEG:
-			offset = XKPRANGE_CC_SHADOW_OFFSET;
-			break;
-		case XKPRANGE_UC_SEG:
-			offset = XKPRANGE_UC_SHADOW_OFFSET;
-			break;
-		case XKPRANGE_WC_SEG:
-			offset = XKPRANGE_WC_SHADOW_OFFSET;
-			break;
-		case XKVRANGE_VC_SEG:
-			offset = XKVRANGE_VC_SHADOW_OFFSET;
-			break;
-		default:
-			WARN_ON(1);
-			return NULL;
-		}
 
-		return (void *)((maddr >> KASAN_SHADOW_SCALE_SHIFT) + offset);
+	maddr &= XRANGE_SHADOW_MASK;
+	switch (xrange) {
+	case XKPRANGE_CC_SEG:
+		offset = XKPRANGE_CC_SHADOW_OFFSET;
+		break;
+	case XKPRANGE_UC_SEG:
+		offset = XKPRANGE_UC_SHADOW_OFFSET;
+		break;
+	case XKPRANGE_WC_SEG:
+		offset = XKPRANGE_WC_SHADOW_OFFSET;
+		break;
+	case XKVRANGE_VC_SEG:
+		offset = XKVRANGE_VC_SHADOW_OFFSET;
+		break;
+	default:
+		WARN_ON(1);
+		return NULL;
 	}
+
+	return (void *)((maddr >> KASAN_SHADOW_SCALE_SHIFT) + offset);
+}
+
+void *kasan_mem_to_shadow(const void *addr)
+{
+	if (kasan_enabled())
+		return mem_to_shadow(addr);
+	else
+		return (void *)(kasan_early_shadow_page);
 }
 
 const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -293,11 +297,8 @@ void __init kasan_init(void)
 	/* Maps everything to a single page of zeroes */
 	kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END, NUMA_NO_NODE, true);
 
-	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
-					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
-
-	/* Enable KASAN here before kasan_mem_to_shadow(). */
-	kasan_init_generic();
+	kasan_populate_early_shadow(mem_to_shadow((void *)VMALLOC_START),
+					mem_to_shadow((void *)KFENCE_AREA_END));
 
 	/* Populate the linear mapping */
 	for_each_mem_range(i, &pa_start, &pa_end) {
@@ -307,13 +308,13 @@ void __init kasan_init(void)
 		if (start >= end)
 			break;
 
-		kasan_map_populate((unsigned long)kasan_mem_to_shadow(start),
-			(unsigned long)kasan_mem_to_shadow(end), NUMA_NO_NODE);
+		kasan_map_populate((unsigned long)mem_to_shadow(start),
+			(unsigned long)mem_to_shadow(end), NUMA_NO_NODE);
 	}
 
 	/* Populate modules mapping */
-	kasan_map_populate((unsigned long)kasan_mem_to_shadow((void *)MODULES_VADDR),
-		(unsigned long)kasan_mem_to_shadow((void *)MODULES_END), NUMA_NO_NODE);
+	kasan_map_populate((unsigned long)mem_to_shadow((void *)MODULES_VADDR),
+		(unsigned long)mem_to_shadow((void *)MODULES_END), NUMA_NO_NODE);
 	/*
 	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so we
 	 * should make sure that it maps the zero page read-only.
@@ -328,4 +329,5 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 }
-- 
2.51.0




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260301014705.1710302-1-sashal%40kernel.org.
