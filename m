Return-Path: <kasan-dev+bncBC5JXFXXVEGRB7VYR3GQMGQE7DD5KOI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0NCwJoGco2k3IQUAu9opvQ
	(envelope-from <kasan-dev+bncBC5JXFXXVEGRB7VYR3GQMGQE7DD5KOI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 02:55:13 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 313DC1CC402
	for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 02:55:13 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-35984b91ffesf215656a91.1
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Feb 2026 17:55:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772330111; cv=pass;
        d=google.com; s=arc-20240605;
        b=HKrOq83bgeEpTva0zwiT/nKk7adcospXkqmKxGTHv78b4DV4gLyc3ivd6eX9N3RFd8
         LvmXI2nDXXq+2LYudlpjmpTxGV0t84uU35xbPbgoPdBK9aezMFHHDe7LKbKrvFtRUcbs
         pbZPx5VQsQenaqgM1TuHHToVH4xdfFGqMv5PYgsQt6IkJtPDRf0aaVuY0RaYaHsXxWHC
         Q8lOW4vjYzzNc6rrDalcYrJltu3lBnmLvSEDIpEHajHoRH2JU95LEl+hmyQHF7vmSWq9
         k+fmX0VFiopId61R4/2ILpzJ/U3fGmGyRGA+6YecucM7DNc48HIbw7iPfDfJ1aLKW94m
         PX1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=+jG2nuPrhg6sDXcO8+L5Dszl5lsw2WzBrpcruqYDDsQ=;
        fh=DAdpnF7odLkwVQ00cWbchg9wy7ds+NRgciY2Fe1weJM=;
        b=O9rdcgayJADqDl3EBjI9GvNQvCUsXDQNExlU77KkdykxsHphGJaBRZHJXMrgJla65D
         rEE7Os7oly0CDGaAqFXzRivtBhSqY413gjNvyZfMyZoaM9fz3DRjMPYPdRMBXv7O0i6I
         OuQBiEB/3kgSrW+eBjk4XoS64OxfTjmWLzaMxZSR7/lOS4w74NpBEYLIi5DDHXxUO8QM
         SpUEaC9B7Gdex+z/LbKuxH2I9kGM21O2s2FnWgNlKOZcaEAujL4qkpuFWBIkhWt1yoCe
         ttr4mc56QL4vrJP1H3lMRba0ZapwfkS54UGuXW+ScNe0FfDOLcgntPjKegZDkUij18V5
         YUBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=enPw3+zQ;
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772330111; x=1772934911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+jG2nuPrhg6sDXcO8+L5Dszl5lsw2WzBrpcruqYDDsQ=;
        b=Ad8l3YblLBeh3IqAxBO31seyX5k+XoD63Lk6eZ2If1xmNfhzaTi39Dv+0gHlL4exx0
         w9K6JG8MWohfvRm/1Ln2YqXSIrmKcsLvZy4EiIlBL2z9mbvnP3z+wIds6fKhuy9J8v27
         K9Eo7PEEinhaG47B//RoeVziEIotOMvb+UBjN/U33NdGxsi8WGEXs7A4z9qSmdmdSSEb
         HHwgSruZfIr6ftn5B+URMn0zdLn7VG9AX+Da3FMPXF7IFnUi7OOpzUkLwAKMVbBNsIzB
         wHfizIIUvR5yJrc8n3zmXmjaJhjzWdpqqsfv0/HgWMJtN11fnAi0JPT7Na6ByNgGtfI0
         KmuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772330111; x=1772934911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+jG2nuPrhg6sDXcO8+L5Dszl5lsw2WzBrpcruqYDDsQ=;
        b=bsusS1/ikQ3vqq85NZT+PjJ14IsPFtKaSDcECoQWshOqPGH5tIjOhrNm+6t4a1vQNZ
         WULK8suf73bpYgg4IllYW/8bXUwrOQLBSeb4GfERz6I03pOqQTW1fbiamLw0foT9pgXK
         seBDuthcT/ebiuYskGgCbJ7bVQY91/lKrjNc1Hvs7qNZ6YQWNCzCTf4k18Wsn+Q+BDoN
         9TYJMnPOE3yZQ8IMnQ/1FTr90AMJpXMrVsOgXWNsUbDh0xNYmadTzA27wzngW2cdID58
         Jqlvqcn6fRYxeEk8U49hk7nn3yfGg3FRufsqdLTUcykf1NH0qE9G3Lc2Oao+0e7YJ47E
         BRVg==
X-Forwarded-Encrypted: i=2; AJvYcCW7jhEYe8p6qxAVrCM0aEnzSmnBVOKQKoZ802YhEpeyBk7QrqTiLXVLs79HeL1gIqAxkiZRBw==@lfdr.de
X-Gm-Message-State: AOJu0YyF7lIin2y93nH9riljZXyoafRVZnID8On1XVtduvNlm8Fls7bR
	FvBpt5fnHP3IuOUQlOvfoXsbj2OjAeo6TK5OIvsoPz1izLi0QhVCeHbz
X-Received: by 2002:a17:90b:5790:b0:358:fbe2:b3df with SMTP id 98e67ed59e1d1-359388c525emr10230464a91.15.1772330111327;
        Sat, 28 Feb 2026 17:55:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eej5tucFWjLwDWkpAScsf5r6TX6dKtO7kbzU6PZSMTfw=="
Received: by 2002:a17:90a:d704:b0:359:7cbd:389c with SMTP id
 98e67ed59e1d1-3597cbd392als278088a91.2.-pod-prod-00-us-canary; Sat, 28 Feb
 2026 17:55:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU0tWutR94+nh0ClTtkQBeCtwVD7H+05Jdcm3f3t1jZZH5S2AL42bMGhujq//LKl6pahsIJI/uq4qY=@googlegroups.com
X-Received: by 2002:a05:6a21:1145:b0:394:505d:fcf8 with SMTP id adf61e73a8af0-395b1e7e03dmr9591351637.30.1772330107376;
        Sat, 28 Feb 2026 17:55:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772330107; cv=none;
        d=google.com; s=arc-20240605;
        b=AaDlTi3JQZAY9QP/i6slMSsh1/13UElG92DRGBJJ5VL5DPCHuqfEfKPyNiJSKBttDr
         mdLvNqXw8QkJutTWjutG+FA3G6cyObxsjebROAGEpoTSN7vT41GzperqvVwFIusnFvRb
         4rkCCQbkSVVwgPybLJjgf78Dkceoj3+jlLoyfVua9G0WUm4qS6dR1cFIp/YJHCGBsjPl
         0MT6+aICC/BLAgTYRKqS8w5bRomk+DbAy0W6r+9YXE629VqfdmETqhQz4nnNwtoqXBwE
         5UU8nt5ktsM0/XJxZh05w10fKzasPoOsKWuS9rV7sdCAQisB9IR8C45mu8rnxK2L06RK
         tmYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gRscD/XbJ5WP9IPAmDs1jrfvJ+3CnTcutEj1v7uP1ZQ=;
        fh=OFg15krBVjoIlzgWex7GQ3ydYCZjTlkv/NwJdnRxFdU=;
        b=LeGDa2HMqPcAjymX8KI2z773WqdrRCWeTyRFt8HOzS+9PqpNWLw1YmmjdSpRqrCo8G
         +9i8biTOf2GK9Dg2MAW4MvMUJBbEF2lt/LQjIbDVW3Wjrdznk3l6m+COCwDbYmogGQCY
         UGf4Y7xwx0DL1wFr5QNQh/y5BB5dm258AbYZ7tdhY0B9yQn/aUdwErjLbFwh3hdYbCb+
         QV6M8JPOHbiaYUJ8lL7zArSF78tysP/MBWx4yfVVcgF8Q+xlcumknPe2uqUOV2ptSuaj
         pLja1fevuAP05/ipZboKf4W0XCctDWgUL1z2Bs+yQfuPwiRXvvkkTgvB8A/ZtlUQPy3/
         cjPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=enPw3+zQ;
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c70fa6d0b88si316151a12.7.2026.02.28.17.55.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Feb 2026 17:55:07 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0252B43D8D;
	Sun,  1 Mar 2026 01:55:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4D493C19421;
	Sun,  1 Mar 2026 01:55:06 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: stable@vger.kernel.org,
	yangtiezhu@loongson.cn
Cc: Huacai Chen <chenhuacai@loongson.cn>,
	kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev
Subject: FAILED: Patch "LoongArch: Rework KASAN initialization for PTW-enabled systems" failed to apply to 5.15-stable tree
Date: Sat, 28 Feb 2026 20:55:04 -0500
Message-ID: <20260301015505.1722202-1-sashal@kernel.org>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Patchwork-Hint: ignore
X-stable: review
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=enPw3+zQ;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass
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
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_FROM(0.00)[bncBC5JXFXXVEGRB7VYR3GQMGQE7DD5KOI];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCPT_COUNT_FIVE(0.00)[5];
	HAS_REPLYTO(0.00)[sashal@kernel.org];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[loongson.cn:email,mail-pj1-x1038.google.com:helo,mail-pj1-x1038.google.com:rdns]
X-Rspamd-Queue-Id: 313DC1CC402
X-Rspamd-Action: no action

The patch below does not apply to the 5.15-stable tree.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260301015505.1722202-1-sashal%40kernel.org.
