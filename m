Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZG6QT5QKGQEFCQAUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D003C26AF64
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:24 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id x6sf256522wmi.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204644; cv=pass;
        d=google.com; s=arc-20160816;
        b=eGswSSg2Tka0Cu7jWPcdUHw8dEzB50J+Q7o81Udnf5mH/iNvXZTJF3vI94FFrwp0PO
         UL52bhEHdPtiYn/0Up4z0alQJ2GwtzHncOHzb6Ey5FJ1wTpHPYNZ/PV6xxIpBh4Rgn5Z
         zyrfBvBRgKGcj4+Du5pIYJlaT/DiWWKcDFryKe5kZ4JZAAeBGIhdCOrsfITYNVETyiAK
         iHFEl3uZkiZN6juOi/qOa4Dv1b7IDRjJfKRjjLut8ZvBqj062r8elsMd/rnzPBB0SCk+
         cYXLzAgrmzWbm6ZSaS41d7yg82bKhPxcemGEeaUWBJZMMIn9/Oecq/cnwyATmZupIP0V
         2/tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6lq2M5Eyv8k8ds9YQRUQr13wuTRGBjVFibbgqAOVHIM=;
        b=KSnHc9xuI9CA57DLUdZKhLdf+cnuYrjTgLAbb4/pbhINeibkIXXW9GTuFhYrqeMPHJ
         XbWN8mCmDqM3AfjBSmCUmSQUXAwmhrbXxx14WE7f5HzalohBZUNVk3vAf9g8Zzul6HVa
         Nn3Yhdb+nyzCKdBN4nh6+1Bo2JkhnTyq/ZfTPWmediD61hkF2MopORhjd0VxperXWir4
         EpDB8MpAjAoDCVh8Z9BHgoDpqtK5vpR9/HG3uVWWnOqjUr4P0HTDO424yHzRRWzppxXJ
         CDUwxcfcptShXqNfpoT04g4SSU6C0RavNKAwvZjeE71EkMFq8OIXwBwIeUT2FvynrkMS
         eVzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p2QNOStD;
       spf=pass (google.com: domain of 3yy9hxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Yy9hXwoKCUgkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6lq2M5Eyv8k8ds9YQRUQr13wuTRGBjVFibbgqAOVHIM=;
        b=r0JokO2jjtMS5KiUX9ZZg97hUkT/SgfvophYeClATAWw5OS+gRGa8mQVs3ccjCAywJ
         NbGad0mNKFIhC/9wBohT5T/AC1oiKHKM8fvXtDUpgz1GqEksRFOUzuIO6GACUHPuXJ1t
         TZ1D93rcKd3tu0TDewEaY3uwgNe3dK7GWRf+Vj3wXPAk8T+TzfEGnB2XkjYZaqUgBgV7
         Px3OQsPcuGeDIY/FF3tUDT0WSIebQhjBaVUxH0gBUTUkUMU2VmvQaP07Djfk1SgLwTwv
         RWU52MIXAzCfp2SsQLppuq5V/cnKEwwWlrtXXoXbTGUYc308wvOtqenqpWv8pHt4xTDR
         ZmIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6lq2M5Eyv8k8ds9YQRUQr13wuTRGBjVFibbgqAOVHIM=;
        b=tyzEG7Whsg+d31FgEm0RoZDXKDkbp4doonnhBRluuRhVBST8yEWMxW1tLmxAnfHQKg
         e/FlkxMxiEs+0oz7wLcJeDRao5e185a462GSmt2gkEQLzPOqg3yHu4tLGTQJ9EB9IxRz
         KGPCnmTQSlCXZg1buWgoucpldXSEQdB7yaN5rqB3dEDpR4kdhmjxczPz/IXYlDgN4Q9b
         UVGwIUphlSS1rKYjCeVd5eNQK0n66vVo5Qu5sl82zWjh8ceGKqIGBKyNNkhwP2uTqEp5
         xue9T0dn0D72WCohhPhRWlZM9/jmkjUQkYbvmq2CNiN2ADEScHF0fuNQl0xQ3APJdK9n
         jM5w==
X-Gm-Message-State: AOAM530E8806vGg0cbKID6qHW66nzHlbMRzg5o/o3Zj2C/bxs85f+WN3
	RAfGDtf64EdOY+Vy1szpAhE=
X-Google-Smtp-Source: ABdhPJyA28+ShTGLG2Luw2YUfNsL9gkq/fyc2+PtTNp5jvH4E4DDc8RE1zQ14VHTXYb7iu/w3c6/mw==
X-Received: by 2002:adf:f585:: with SMTP id f5mr24299013wro.64.1600204644562;
        Tue, 15 Sep 2020 14:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls351950wrm.1.gmail; Tue, 15 Sep
 2020 14:17:23 -0700 (PDT)
X-Received: by 2002:adf:ec47:: with SMTP id w7mr24963504wrn.175.1600204643759;
        Tue, 15 Sep 2020 14:17:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204643; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/7ovY2IUXdQWN1W2ZR0PP958/eIcJSG2tP7vAQSQRexubXefDDBqA97qFP+CuMnWf
         EjbjW/d8lNmdxK2SIbjHycwK7x0kiQc/DmQnsBZy7fARLjFN3cIWBFf/S1t5tyFmOqHi
         d0FyWyEaU1zSpuTeenIWvHdvQNpkwyKQVG0GRuE3yXHBeqfk0JITz3NTpjQFM87JyNqo
         DGiQuUCFgJgo96d0Aj7V3Az4GSQlSVl3h9c9CBFgaceDs5RiLUtq021tf3v8OqbyFbKv
         yCYbMeVYk/5FiuHh3YrQjukOX58OcGFclpqN9pQfyvicDT0o2Fb90jK7KxOPa6v7Y8EW
         1vGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=pBsGqTIqbR91modi76ePsvmJJRuaBk1hVSkVG5VFwBQ=;
        b=rI2EZmgAVCMc9PZ1EmFmOFQJuulB3prGharDrlHiUohhlKzl/nDKEZ7/GwGSUhADBE
         K9ve9buejWsNo1o4r9QGkSXGHEj9zhQ7ek9a4E5aQzNm/Mqu3Bim+k0V/g/49fbjcjUK
         eLbw2IPp/+wLVvk5oSagoJB2glbGUvC2Nk+rKw9QDKapuLr4YNatFb/EMQ3QfI7P4nU1
         A60K2GA9qzSV1Enem/T6RIkGGDPEXNlPeHDhjw3N4effPxgMu2i95Q/M6/qbrRa9O4Ho
         fLZMllTdNwpEVqqaZrQgGpwvSFNvVsgCTQq8r4SXiPuB8v86cGWfzABX7Q8I5CiB9bMA
         72kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p2QNOStD;
       spf=pass (google.com: domain of 3yy9hxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Yy9hXwoKCUgkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id b1si22816wmj.1.2020.09.15.14.17.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yy9hxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id bm14so1816492edb.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:23 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:8559:: with SMTP id
 h25mr21784179ejy.536.1600204643277; Tue, 15 Sep 2020 14:17:23 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:07 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <859111cf1d862ce26f094cf14511461c372e5bbc.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 25/37] arm64: kasan: Enable in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p2QNOStD;       spf=pass
 (google.com: domain of 3yy9hxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Yy9hXwoKCUgkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
feature and requires it to be enabled.

The Tag Checking operation causes a synchronous data abort as
a consequence of a tag check fault when MTE is configured in
synchronous mode.

Enable MTE in Synchronous mode in EL1 to provide a more immediate
way of tag check failure detection in the kernel.

As part of this change enable match-all tag for EL1 to allow the
kernel to access user pages without faulting. This is required because
the kernel does not have knowledge of the tags set by the user in a
page.

Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
similar way as TCF0 affects EL0.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
---
 arch/arm64/kernel/cpufeature.c |  7 +++++++
 arch/arm64/mm/proc.S           | 13 +++++++++++++
 2 files changed, 20 insertions(+)

diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index add9da5d8ea3..eca06b8c74db 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1718,6 +1718,13 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 		cleared_zero_page = true;
 		mte_clear_page_tags(lm_alias(empty_zero_page));
 	}
+
+	/* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
+		/* Enable MTE Sync Mode for EL1 */
+		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+		isb();
+	}
 }
 #endif /* CONFIG_ARM64_MTE */
 
diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 23c326a06b2d..5ba7ac5e9c77 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -427,6 +427,10 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x5, MAIR_EL1_SET
 #ifdef CONFIG_ARM64_MTE
+	mte_present	.req	x20
+
+	mov	mte_present, #0
+
 	/*
 	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
 	 * (ID_AA64PFR1_EL1[11:8] > 1).
@@ -447,6 +451,8 @@ SYM_FUNC_START(__cpu_setup)
 	/* clear any pending tag check faults in TFSR*_EL1 */
 	msr_s	SYS_TFSR_EL1, xzr
 	msr_s	SYS_TFSRE0_EL1, xzr
+
+	mov	mte_present, #1
 1:
 #endif
 	msr	mair_el1, x5
@@ -485,6 +491,13 @@ SYM_FUNC_START(__cpu_setup)
 	orr	x10, x10, #TCR_HA		// hardware Access flag update
 1:
 #endif	/* CONFIG_ARM64_HW_AFDBM */
+#ifdef CONFIG_ARM64_MTE
+	/* Update TCR_EL1 if MTE is supported (ID_AA64PFR1_EL1[11:8] > 1) */
+	cbz	mte_present, 1f
+	orr	x10, x10, #SYS_TCR_EL1_TCMA1
+1:
+	.unreq	mte_present
+#endif
 	msr	tcr_el1, x10
 	/*
 	 * Prepare SCTLR
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/859111cf1d862ce26f094cf14511461c372e5bbc.1600204505.git.andreyknvl%40google.com.
