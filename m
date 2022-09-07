Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBTHT4GMAMGQEMMJ7E4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9969C5B0246
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 13:00:33 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id b17-20020adfc751000000b00228732b437asf2783294wrh.5
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 04:00:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662548428; cv=pass;
        d=google.com; s=arc-20160816;
        b=u747Jp74DOKRhnxr6e3cxfTw8eLhkZuSiwWaL3UP+0XFBSDxalbZ0uIiQbk1nbPYsf
         HA79eU8eqd8jZsZDc62e566USNyCx6aamMOVxOJye+tW8YD29MML/ywmKB2zSGuyGGMH
         MUnd7sTdMouaOvCIYceSVqF0JRlues9IceYNJikIt723f1TZbGecuSmsVqVW0LMabo/z
         5d9k7aQ6+3Nvr6UnZzitSOaytvHPC9Q8qwyKAUhzuOMdF76LmS9Uf94AdUvlBbAkaXhr
         68WMSSv3fsSY21YV33rVxmAhtMTpSiMdSHaBI7V+agHaoUYTBQwLBrR4M8734kKfb9b8
         t+UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rzn41t3kiFm/grFlHwf0cclKpyBfN5oVnODpJB2WhPw=;
        b=dlEcZ4rNjZToVpDI4EiTTd5EhcsY4h+uqMr6QNsb8x7Z8gq9Bk3B61FinuU00CkWhZ
         MXZZXrW8bWOn3LDXYjTB85jBHTisUkB++uUUPFlYDNyB8tYI+EUw36CmeB3/63O49X2w
         ZTfP8V4CxSgwGZd4wb5M8Xtlv4MVDKcmlHb+28voRBmd541OqPJk7zUlgi+rRvCpJSnn
         Ju0sR08WBzhgSmrWuUzElucATwZ1VEYRa4jy83tuw7YWWOjhVLspCVupe+inrmDwBZPl
         xFmmU1BzziqDHFtbkqR6GqTK43sKayczz9xMTwqYlVZBEC/cfOcqeFE2surLwoQ1P6R7
         Nvig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=rzn41t3kiFm/grFlHwf0cclKpyBfN5oVnODpJB2WhPw=;
        b=V/NlNdEhpgLDcv7Zkfimsr1EA+idV3wARle1c1L+BOiyTQMSeeOu3n1T8qGukeURTs
         dwKntaldJDCynlEI6f8COBiCklRFERKcPVfRn9c3E4RFOvVayAvZO0GnNlg+mvlMfeng
         oYKBKoXTtaMGYWCLeghTfmTm0WkbxrgJflI8Yl8WvG+PLAsjyJl9HkNIjsQ9eCSHV1Wo
         A/SCCjVAq44suFuHM+RDyTinQWRIQwajtK7M7YQsZ6OmUhBzeMW3h+3jFrFOw1zOEmHn
         0Vib4wkkqV7adEPFd3Q1lZHYhLNfDqx5KyVpmi8JyIWaMArTodniqZHKIXYykmvisVFv
         fR3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=rzn41t3kiFm/grFlHwf0cclKpyBfN5oVnODpJB2WhPw=;
        b=sbSpli7lph+BSGrktJ7sL5eHwX4OFqfUSRc/uHhgzMji+9pfgLtsf+t0PuE0d++q0l
         pKoVx3XkcD/HdPbrkFECxh51vx1lmrXDd8VR7+2ucydBrO/X5O9ZddY/xWi9SygDErsW
         BgX+VBkc9vFs6BDJzZe5l+AX7hX0srB3Gj8dFZm/v37nbJ//DBM5E4hDHjG2Rj3pp9KL
         qVsyHsA+bDlzBaAn/u62tgN0qrMvpUbWvp+zV6MiTWlImtNNLr5/Hh0FuzWhdhTXHoPM
         /jP7OrSjuqa7yubFICi/HshqGjL0RwixStbGkfI+l2UyWXMUN4u0m7aR2WfqSVjyu6Lv
         0d/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1kIX19k6Zf+f6WStawYU2Flh9h4jAmCHL7pbTrjoYlMxaTgsIp
	4uiiBvFHOL4IJTaREcY+SJM=
X-Google-Smtp-Source: AA6agR4bUnEJOimuR1l+8ee/oCICaIN0fcAch7tgCmM27y/8rupFJI+PrrJGuxtfF3LvNTe2CqTupg==
X-Received: by 2002:a5d:4405:0:b0:228:dab2:d900 with SMTP id z5-20020a5d4405000000b00228dab2d900mr1746538wrq.502.1662548428247;
        Wed, 07 Sep 2022 04:00:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5b08:0:b0:225:6559:3374 with SMTP id bx8-20020a5d5b08000000b0022565593374ls1589190wrb.2.-pod-prod-gmail;
 Wed, 07 Sep 2022 04:00:27 -0700 (PDT)
X-Received: by 2002:a5d:458e:0:b0:228:cd6e:dc56 with SMTP id p14-20020a5d458e000000b00228cd6edc56mr1800537wrq.614.1662548427242;
        Wed, 07 Sep 2022 04:00:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662548427; cv=none;
        d=google.com; s=arc-20160816;
        b=o06mGAZ141bBo+ZruTvYC2uVf4ujdZ2tyhA1lBQVXoTlAkgJbV3KGRZ6F8dvsSGOi5
         eMLzQSb3jAE0YBAnf+LOL7YZ1t/H6LjyfmaqpNsYH4MoS6JV+6buvuGmuJknQMqNr3yP
         DG42/GDEnopeSqVRyCtLCUu8Wuxndb6bygDcmeJxIw2T08gX6WpZJxl5adycLCEW606N
         lepFeMisqzR5PeEC7bNBiPfuuLCwOY38SiD8B3HGTHVqPkAlfiBDAx7518pZhR7U4IDD
         x52vZRvOr5vJ52m1cy5z9Pgaw1uS+9Qlq/uzrR7X1uFLgHbDMXu3v+Lx+nNMhoKgUMjL
         Ez6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=1TemiwDM9GIiIqJyU/XBBU89DzZ4XYPEsTNvRcp3/KI=;
        b=knByXGy/7bhs7HGADCdnV8O3RcdgwNxEMU5KAIu4bOObFB40yC1eaphJczFE3dqfX3
         CW6aFFBU4ezfAudiHplYNGHp8v0kRB/iZ6eur9Oe83DfQFfP5soHAaMkf9KXfnQvFWAH
         QMbK1xXFzdJrkdI1s1+l3VdprASTCBOXvYAsmDlQj4DJDoLGRsaVrrnoWs32mMEyjqE8
         pGNkILUFkKzYCxy/gFKVsptVQ3ejBAi4yIopq79fvzffpuYVB9o9RLYvJPoshl7QVIy7
         HwyQrmnyZWMZ9myEwAyU4s2kJe7sOihRrIq1dZMStOZZhit4T3AgjF7aJL+IsnqJiyge
         QzIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bp28-20020a5d5a9c000000b00226f006a4eesi885509wrb.7.2022.09.07.04.00.26
        for <kasan-dev@googlegroups.com>;
        Wed, 07 Sep 2022 04:00:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B4DAE106F;
	Wed,  7 Sep 2022 04:00:32 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8A3B43F7B4;
	Wed,  7 Sep 2022 04:00:25 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH v2] mte: Initialize tag storage to KASAN_TAG_INVALID
Date: Wed,  7 Sep 2022 12:00:15 +0100
Message-Id: <20220907110015.11489-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.37.3
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

When the kernel is entered on aarch64, the MTE allocation tags are in an
UNKNOWN state.

With MTE enabled, the tags are initialized:
 - When a page is allocated and the user maps it with PROT_MTE.
 - On allocation, with in-kernel MTE enabled (HW_TAGS KASAN).

If the tag pool is zeroed by the hardware at reset, it makes it
difficult to track potential places where the initialization of the
tags was missed.

This can be observed under QEMU for aarch64, which initializes the MTE
allocation tags to zero.

Initialize to tag storage to KASAN_TAG_INVALID to catch potential
places where the initialization of the tags was missed.

This is done introducing a new kernel command line parameter
"mte.tags_init" that enables the debug option.

Note: The proposed solution should be considered a debug option because
it might have performance impact on large machines at boot.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/kernel/mte.c | 47 +++++++++++++++++++++++++++++++++++++++++
 1 file changed, 47 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index b2b730233274..af9a8eba9be4 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -6,6 +6,7 @@
 #include <linux/bitops.h>
 #include <linux/cpu.h>
 #include <linux/kernel.h>
+#include <linux/memblock.h>
 #include <linux/mm.h>
 #include <linux/prctl.h>
 #include <linux/sched.h>
@@ -35,6 +36,8 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
 EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
 #endif
 
+static bool mte_tags_init __ro_after_init;
+
 static void mte_sync_page_tags(struct page *page, pte_t old_pte,
 			       bool check_swap, bool pte_is_tagged)
 {
@@ -98,6 +101,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
 	return ret;
 }
 
+/* mte.tags_init=off/on */
+static int __init early_mte_tags_init(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		mte_tags_init = false;
+	else if (!strcmp(arg, "on"))
+		mte_tags_init = true;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("mte.tags_init", early_mte_tags_init);
+
+static inline void __mte_tag_storage_init(void)
+{
+	static bool mte_tags_uninitialized = true;
+	phys_addr_t pa_start, pa_end;
+	u64 index;
+
+	if (mte_tags_init && !mte_tags_uninitialized)
+		return;
+
+	for_each_mem_range(index, &pa_start, &pa_end) {
+		void *va_start = (void *)__phys_to_virt(pa_start);
+		void *va_end = (void *)__phys_to_virt(pa_end);
+		size_t va_size = (u64)va_end - (u64)va_start;
+
+		if (va_start >= va_end)
+			break;
+
+		mte_set_mem_tag_range(va_start, va_size, KASAN_TAG_INVALID, false);
+	}
+
+	/* Tags are now initialized to KASAN_TAG_INVALID */
+	mte_tags_uninitialized = false;
+	pr_info("MTE: Tag Storage Initialized\n");
+}
+
 static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 {
 	/* Enable MTE Sync Mode for EL1. */
@@ -105,6 +150,8 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 			 SYS_FIELD_PREP(SCTLR_EL1, TCF, tcf));
 	isb();
 
+	__mte_tag_storage_init();
+
 	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
 }
 
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907110015.11489-1-vincenzo.frascino%40arm.com.
