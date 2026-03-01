Return-Path: <kasan-dev+bncBC5JXFXXVEGRBTV5R3GQMGQEHI7QSNI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id OAvuI9Geo2lzIgUAu9opvQ
	(envelope-from <kasan-dev+bncBC5JXFXXVEGRBTV5R3GQMGQEHI7QSNI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 03:05:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 20FEB1CCDD2
	for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 03:05:05 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-354490889b6sf13238959a91.3
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Feb 2026 18:05:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772330703; cv=pass;
        d=google.com; s=arc-20240605;
        b=eS3IXuLlmneo5N1kIiK4oGhmnAb4sCoSC381782f39HAAw71/6vaCNB52L2Hzb/cJU
         iLCgIRXQm+heXYz+59o7cVfKBxfNiKR2xcbjeYYy3Rms2K1CuTZudl8Flf6/SvoF1vGD
         BgDmXz6oV1JEVAGSzXzyqTorSGcJXCwQFB1Ywre9PdLdf/G0QU2BichNMmlEiWCKkVnd
         M6If1kWepwKZnFXvA2uRrfIv2RYVjKfaaugqpO51ltRRESsZInGvYiBrpKJTFdzLcRPe
         TjrG5bgQiFRcUgATEnZEegymRHxSU8I3nDjhvgZZ3AlYl0z1cJhGh8Kv4lQzRZj3CjRJ
         kEKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=yxnhbVjozR47eu7zto9QTKmMCxL3VXWPE0t2CVNQ5wg=;
        fh=Se+hFchxJFkwfwDPJRKhh7YMUHJzb1p9PtgOfrHMCMU=;
        b=VTxZMPKAeyZiCiFIeL+WU7So0q3l0nv7/f/y8Fxs0u3IEAJOCG1ZDZFs/HCEXyNUPh
         q/pbRXr0eu/LaohCfs9k9WdESFK1ckX1JBfx+/P7S7g1Z6++c2qmEMvShQhmQ/+0eZK/
         jvBM+GmYIYuaTlqwL0GX0jDfrhSSGwilCCgD5FjHC2YnRHn0aEclF7Ojjav/K/grfZdq
         2Oo1GOB0EJZYjeVAOvJNKyoCtlYuB0Qlzphd3nhdZeAn+WUu+BSi5o0SlaLB0/iywTNM
         T2cfYt0joU2vFx5W54+fzi9OCUs63xa2DSuXtSPmczQTjAtVUpDOKMIrH6bMoY7kYBsK
         7C7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iGg9CiZo;
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772330703; x=1772935503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yxnhbVjozR47eu7zto9QTKmMCxL3VXWPE0t2CVNQ5wg=;
        b=RlzGxUw+HvM10UatHdPyMD2zc3xBV80uFtyxu17nJSyK95f7TUcYtjs1YNf2WKflCE
         0mm3Owl2wzU202XsURNnUapkf4J6dZAtvNADy3R3qERlgArtmR7VfWHgDit34ToC+gAk
         t0oS1ev61GxUrWxKClCaVYOY9qYOgv1G4qoKjgdpmSZOibANsOYo2bYPlOqFEPo3PO4S
         9fKbCDY724ufYLABDKY/Jg6UyC3xepzy0/4HegToSE+TEcyDO2eEaG5Hr3RjkdUZLA2m
         qbAazx5iQSHxjwWM8ux8hyzK3juE2DnavptNrp2H5vJVnfS0UltdRXDuu4qPxxsRR0BN
         9BNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772330703; x=1772935503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yxnhbVjozR47eu7zto9QTKmMCxL3VXWPE0t2CVNQ5wg=;
        b=L+AQZidDSsVFC1PtgHHh9zQ1wU2J49nFiOR2Jks9FnEV181KQLc3cdFSeXQBqCk3af
         3l8JuhKGywDml0rT2gIgjbLCxAckpJ1EPRnD7osLTKHcmP/1dhbglupzt0OpVAMVubXo
         KpAE5pvOUHiJagdg7GCR18AY44oEMCQgAFyGBTvCsCe+VfgwUHz32t7p8TFwhLuDo0O/
         h+0QgqBxUvyyXXW7JxbBaWRwS2uX8nLr2XPFKwowYFpUEqtdx6agmDvumUiIZlUUSQhe
         uW3LFqoH5xBYFm9Scxx2J2D0s6sENdSkw2XHMsTxVzm51j+OGngzCUHQqA5W+YUGwoKt
         LAeg==
X-Forwarded-Encrypted: i=2; AJvYcCVO5MQI5doPGMuSfkKEol2j8pYsNSf3vKahc0NHmqYzp0buRtJq4d+SMOWih8F/Hf2CjLQ1sQ==@lfdr.de
X-Gm-Message-State: AOJu0YwUI1m/2YEGHGq/xlJ8RdjKHkaR5Sv4TueTpFpdwcOvZ1flGmX/
	2PwEvCjuLpmcW/SXxflziZx9TJGFWxmMp38dUzcUXo0mLJaljIqiCkJ0
X-Received: by 2002:a17:90b:3f85:b0:359:806c:7a94 with SMTP id 98e67ed59e1d1-359806c7d92mr1925380a91.7.1772330703387;
        Sat, 28 Feb 2026 18:05:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FoMUKGq1BbRxKU4R9Z/FqfnXAGustHGmr789L052YNtw=="
Received: by 2002:a17:90b:2d08:b0:356:7f26:51f2 with SMTP id
 98e67ed59e1d1-35910fb3f4bls4912935a91.1.-pod-prod-03-us; Sat, 28 Feb 2026
 18:05:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWqE+Caqk9ztQJaeCGg8pxh5DANpgzWSRsDuWLFtrw/f9IcKhS5kaoeN30iZdvcufi3rAtyMdXmbNk=@googlegroups.com
X-Received: by 2002:a17:90b:3b48:b0:359:3082:a97d with SMTP id 98e67ed59e1d1-35965c2d201mr7415838a91.11.1772330701940;
        Sat, 28 Feb 2026 18:05:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772330701; cv=none;
        d=google.com; s=arc-20240605;
        b=XTVcmOXjm55icPJ8Rn8JZIAeVnShUsZvmun6FSVrUXJx3+e0bmWK/7cz3TGM4XBd3q
         XHtSS4NOYCuAiKWnEgdTWmQDd5M3Dgod4oAqd4fheSu+uGY9qWQABVkXSN9o2RAKPIYj
         m80g7nOK8C41koVrQ+MvHCN5FAbgswJoYozcHlcEEk8/ATKlmzRQxXIysL+Bj7xXcnVe
         IgHU9t5e3y7324Nb2dl6C2+T4/SJiKvQYqRduDS8wn9ukHLtWEdzIuf4DdyfN3JTp3qM
         PUfccaszkzsvCzvuCamUncXo9weiKledcdL0GXm/PiPTKcYmrPmEMCg5w6VuLXIdmBvy
         qndA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=eoB30G9D6ZUyCPxG9AfleameqeUSi2jqL2jDRAT67Rk=;
        fh=OFg15krBVjoIlzgWex7GQ3ydYCZjTlkv/NwJdnRxFdU=;
        b=L2u/0Cw63ndxAS5fg0ZXcWCb1/wvSgohBm8Zsg7lxFKIHAREwgqx+OJ8boxm3pmbA5
         FMTKmF5mjD+AsFKdiLm+B+HMvkDBT86iGYYrY8U18Cp866Dm508Th9AttyIFAHFDBQg2
         uB34hTakdkPlhtbDIZ4MPs+D+sMUZupzGAhFyGTEPjgQZx2NtB+ojd4v/p9EC7/f5CQi
         tncGzfnBf3TFo9x50M+ElbJgKdK8O3t5Q+pbpXVx6zSj7bvIkA7DXuTHjKHHD4xKH1ZZ
         LaTGIs/13dkpLoI6JEUuBNSB13ETXpy+xPkBw0io3ARPCtjEO6XB8MkphlDkk9kzw2kW
         WewQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iGg9CiZo;
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3593dd8666esi316048a91.2.2026.02.28.18.05.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Feb 2026 18:05:01 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E536D6014B;
	Sun,  1 Mar 2026 02:05:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0E0ABC19421;
	Sun,  1 Mar 2026 02:04:59 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: stable@vger.kernel.org,
	yangtiezhu@loongson.cn
Cc: Huacai Chen <chenhuacai@loongson.cn>,
	kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev
Subject: FAILED: Patch "LoongArch: Rework KASAN initialization for PTW-enabled systems" failed to apply to 5.10-stable tree
Date: Sat, 28 Feb 2026 21:04:58 -0500
Message-ID: <20260301020458.1733544-1-sashal@kernel.org>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Patchwork-Hint: ignore
X-stable: review
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iGg9CiZo;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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
	TAGGED_FROM(0.00)[bncBC5JXFXXVEGRBTV5R3GQMGQEHI7QSNI];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-pj1-x1040.google.com:helo,mail-pj1-x1040.google.com:rdns]
X-Rspamd-Queue-Id: 20FEB1CCDD2
X-Rspamd-Action: no action

The patch below does not apply to the 5.10-stable tree.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260301020458.1733544-1-sashal%40kernel.org.
