Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBRHO7SKAMGQEPZUSAOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id F03DC53FD83
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jun 2022 13:32:22 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id p7-20020a170906614700b006f87f866117sf7608034ejl.21
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jun 2022 04:32:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654601542; cv=pass;
        d=google.com; s=arc-20160816;
        b=BPErvyamq2FxNBk7HLaPLC8U5PBauagt+B2lg15C5n5DbNDVECHS7TSHl764+7Xlcu
         z2Su7J8WfFgLbou05f+3gTxa0qFEmmFGYdRjBkjMeb0Jb5OPWCwlBO9TH5wZnC27yfVv
         XDm//1g3YO9ZErv9QxXMmLOKXRS1TzeicmgpZ8TncSoZLOnaiVKYnU50nsylIIFBWl9e
         CxIilNMS1jFKt6HcTeY75wb/TMQd1oWKXCgtuXGntOP56+p5zWJ0xLonomJh4sNII7QO
         sNwf4MFLFpMRuRTO2lpYO9gc4GQQEpfUQRGi0iZGhoOsspeTkzfhTnZxspZNY0Ev/Y3A
         0OPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7LJA9QVAWMG8sZTMCBc+NnmnTvcda6W6zEkGJlHfvrc=;
        b=WAfUzIfuFdnWpMwqSBmcc9oZpLwsnLE+Mj3p+G2Wl6GFfiIDdFhxDiGTt/k8x+bMSw
         Ep+Wv/FtEYNrI2qpHxqn3xbxY9OzMGgWfTUN9Th0ASTwPgZtmsG4QMYinEDQ7ZjJoeWB
         G05NCpkimk/nmrCMSKf1aZZJdCSrKoct4yjdBCCt/RvGyoPINncRjMiUkqyq/lFds/PY
         d4I3y8M8FJzh/+1vJm+pQ22/Z2tVNqXBDDVXjsf0GILCsEmFAEDjyD78lCwY85V04TE7
         REGuai/Xmqia143DL+knQHzFg9qLp8OG9Jj/jIAJoWcO1eUVasptSvmcZT/KBMmfHeAt
         ChfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7LJA9QVAWMG8sZTMCBc+NnmnTvcda6W6zEkGJlHfvrc=;
        b=qg+Katr1F2kuFQKe7ZcrzAKAooNwcjOF+3IC1LzbzdYspbKn4JP8CduarZrMvmC5Y7
         b9KjN6m5WgGmJsOZbyWJKM/n7c3Y5JOS8diU3yL4uu48bpFAK0qxKdpDzzO3VCZk473O
         50L9+RGUAHegqRpFCfZS/4Mr13kCgBPUbv+hUQz2tJwdgdi7YFMgsd/JCtYn99g6jRbL
         cXEI/bek1Dfc3D9tl5ThvSRUwR+tLacyLbXzIgxq+o9g4GvRNz4Vq/Kiezj08Be0XZ2L
         zpgf2cDmXWcbQ5wIrnNrHsZGtFXu9yqMNE0+SGYjgzkmnEn2PgRZ6Y9NnA7OJOi4BDi0
         UUuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7LJA9QVAWMG8sZTMCBc+NnmnTvcda6W6zEkGJlHfvrc=;
        b=r+MiPrmfkRXUxss0r293R1YPgu1dCv3as8sdSaBiliCMnoYaW1Txll+oZdT20Hj7eT
         bl60ZNZeERnr+vMSPQS2PehKLB93MNZlB6jCXR6l0YTYAVR488zHF+I/FVOpqDgRUL+h
         u2iZHhRAtgQKcQLMHktK8e/a7i9zKCHNzhm4lb4OYO7eWUP6Ok4ZONCQz9oFgEeJdPfd
         vURItpAIW1oz5AKTbNki0toId1xvfSXQEtAuUvwsaX65EDRf+p1gRrmgzjOoduUhhZgX
         X7f0WJdz808Dzh5ttRWzN6XNbXfGw2c2jusf9FXWtV0XhFQp0VR9P86k+JSyAjT267ln
         kPpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Txy5F8d0O1sEowFF6UKelePQj8Lpn33YIq2XBvR5/CAH1f2GZ
	heBTR/Bz+IPtqx/cjSuizwE=
X-Google-Smtp-Source: ABdhPJyImbAU2UDs1LZMhQhyyWcDiiPayeN0NSoD7sE223EDmbtkej30gT9mycgYpO6JI4cTDl0+Lw==
X-Received: by 2002:a17:907:6e01:b0:704:8c0e:872f with SMTP id sd1-20020a1709076e0100b007048c0e872fmr26309626ejc.387.1654601540882;
        Tue, 07 Jun 2022 04:32:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7f91:b0:704:cf38:c76b with SMTP id
 qk17-20020a1709077f9100b00704cf38c76bls757357ejc.11.gmail; Tue, 07 Jun 2022
 04:32:19 -0700 (PDT)
X-Received: by 2002:a17:907:7284:b0:6ff:16b8:3073 with SMTP id dt4-20020a170907728400b006ff16b83073mr26767930ejc.196.1654601539820;
        Tue, 07 Jun 2022 04:32:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654601539; cv=none;
        d=google.com; s=arc-20160816;
        b=WgCqZYAntH3a7IdWLwLDru2veH/SF+IUXApnzi0LWNaqaeKLSGKWgcb5K+jbJeOmky
         9hRFQkKJipYAb0SGF39HeBdJGAEv10vbS9/i4FP5a8LAQSKFMOBjOx6416ZmsV5VuHx8
         59Yae9HMKJY3H6YBR21COWbi51sG35WKtV8LQ1H+PvTbMQJJ9FD+c0/j/4MfL8QUgyij
         pzZOnAXHvVpPwG48QT4eN0sHSEOE2fc7Nt+aOwaVwk9zP5nnaK8b6qVx58MA3EiRVJbP
         ZyuzR3PFM9Z+YF6WzuW65EUdFNcQpaB+WXi/2uE+kSpX9o+GaDjUCSM2q92t+QXutMLd
         eNZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=2IcJNTiHKGCtW7DPU7PZ37C+lDAfeMUQ54tTJc0beNI=;
        b=hckVd8bnqFtRXTWzqC0ytO6qAlnn7nYmtnTpg/Xs3s4aSudy8S0nVSCA5T35I02pvN
         dZ95ZdVO0Jov10uwkyZeo52aFjjZ3rdxQlrdDuhGUxFWxeGDcQnW9JEqtcETRuah5ezm
         K77TiUaelqQid8fb1ANvDKqBieQJ+mZUyUFnONTZ/ROT1vrHwngvDR8tLolBqJZsQWMO
         uNELkb9xvWlIEwrT8GMT2k/JscUby2b7Uz7IiBSFGyEUjLCJpWEEAcp3Hbihxn16TmL6
         a72qFTXQ8D0KC+dwJ6nXPYEQf7rW31wLlIUp6YgMs66aR/G9rWrVQd+Aq1pmOHSa14NG
         uDDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g16-20020a056402321000b0042dc6f36b02si730509eda.4.2022.06.07.04.32.19
        for <kasan-dev@googlegroups.com>;
        Tue, 07 Jun 2022 04:32:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1763814BF;
	Tue,  7 Jun 2022 04:32:19 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1B90D3F73B;
	Tue,  7 Jun 2022 04:32:18 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH] mte: Initialize tag storage to KASAN_TAG_INVALID
Date: Tue,  7 Jun 2022 12:31:50 +0100
Message-Id: <20220607113150.55140-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.36.1
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
 - On allocation, with in-kernel MTE enabled (KHWASAN).

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
index 57b30bcf9f21..259a826363f1 100644
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
@@ -107,6 +110,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
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
@@ -114,6 +159,8 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 			 SYS_FIELD_PREP(SCTLR_EL1, TCF, tcf));
 	isb();
 
+	__mte_tag_storage_init();
+
 	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
 }
 
-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220607113150.55140-1-vincenzo.frascino%40arm.com.
