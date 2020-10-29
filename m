Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX5O5T6AKGQEU6FLVRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F5E929F4E3
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:24 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 76sf1649482ljf.22
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999583; cv=pass;
        d=google.com; s=arc-20160816;
        b=XUz428nYRSnX8MpjVwye1vktrWr5wP7tdhsGa6BGHIIBXd+JovMh2bV8YfaRHZJ+9F
         KkrRuq7WkyunbhtSJLPG533vWxqwVkhZPabqqraZ1CwTiM2aQuPw3gPp8GZ+RUF2/Lj1
         6aRZilex77GsHs0f7M8XRyVjF8S0xqm8UvIp3VdXrkGLonEaEHEeEs46zhKZHzT8Bp4S
         EVPVGYyf67k64s3BWmRL5APio5F+5WK2z6rFaCeQfHyish+80gItYEZZ9fl4ND5zXALM
         f6BekA8mwgIknRM7ExZ2TWXouZJ19SGmNJqOtR2gxsVEGQaa6/lFW4d+NL9lRoFFoQFd
         uGCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=SE74l74X3L8ppi8LQTCSPsAfZSz3Kc7lVFYG43nzSEU=;
        b=h29JL/ylAV6r4lm/YjBq1nZA3QL01sO02c6tbH+85YxLPMXlif4Zu6BGVjWw9kkfKb
         fxYx6iAt6vEehkaBIl0b4LwqQPwMrv6CDYNVBvpAHZX3MrbsJ08fqoopLQSFgB/4ZHPw
         tbGEtmCPToVG8P/Shh+a1U41UhqlDEwryer44pDhF/RMYEcFrG6B99ZibovU/CuUI+VN
         PB6zRwRzLQYrfZ0BtLnPJ1sWhorXhnWa7i/ToCYhgfeM9xa8wBZ9o4eJ7sKk9xVJTraW
         ROgYTrTOC0boergQLeodd2hJeuDtyCCjMDOWo2wekBlsgtheymFDN1wP4gNhdhLzboln
         0hRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aMgPSNzn;
       spf=pass (google.com: domain of 3xrebxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3XRebXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SE74l74X3L8ppi8LQTCSPsAfZSz3Kc7lVFYG43nzSEU=;
        b=a/TnBcU/FGnEPXz70JA0rKawJXXrmaS15GHw9T3qFM32NCIWsBCp4WtvhNK0XAW1wJ
         O1wEzFcVpO61SYF6E8e+fM46W8JElSQJ+VA3fyQbrrkzcLdKQVhxhNXwuNbuVYJG2wEG
         fVd04pkZLZTcdmqu6X04p88dJfEI2AsiQqMG0DZAYBdGsm4+7cbGlqhsFtwwqI6NLiUi
         y1hTF3xqkoeZDUKYdQCwjvvKjt7/ccjeQ2PvvH8mzSYKmRh/JyQd6ZN+vYYtPDticpAw
         T5197bJ2RV9SDIukunZIIjqspUkxbVvdxZqk+QDEKbothd7k1bTolCM6TM/+qjw9zAcF
         62+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SE74l74X3L8ppi8LQTCSPsAfZSz3Kc7lVFYG43nzSEU=;
        b=pZLZgRF5bIrZB9qqfnfWep21sKSH/hFJNC7M/OMrNRDCdaArdlYbHpY+LkaNga/VoM
         7m7kOcpZi3IpZWRIofci4+1CIybbiaaX6TQx+JglI9cNO8QzhB5WzITvGzhXa97OOcBZ
         7BFIYZcmsoQEwq7qIQPdfeB4SyHDtb/S2oJvUhej5qEIKUyPqrrQYp6BZ68xT7e6WZl/
         5R5a20obMDuSZTKLBsS5qCiaH5HYecvqSs7uBq8FjS6L6TWgHivHQqngYdSoE7Tz0f2r
         2k3bpxRhPf78HHnuHTnDZDPHZVOS/ft+84I2iG47RfhC/5zuuYUCoGs6hMdLoRnuQoIX
         IP2g==
X-Gm-Message-State: AOAM531CdtFDilir1sW8Q2OgQeihAMiu9W9xD19/6vEtR2gdGZ7th7SK
	G35l8A/B7pSANQHr02xmIWI=
X-Google-Smtp-Source: ABdhPJwpq6nC+Foe4FpUEb4Yo3Qpoqsa/P8V2I2B5UPWBziSPBfBDbMbUmoR3Bpb8CUAqRfVcFKptQ==
X-Received: by 2002:ac2:418b:: with SMTP id z11mr2358847lfh.371.1603999583582;
        Thu, 29 Oct 2020 12:26:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls2395686lff.1.gmail; Thu, 29 Oct
 2020 12:26:22 -0700 (PDT)
X-Received: by 2002:a05:6512:3193:: with SMTP id i19mr1932837lfe.80.1603999582470;
        Thu, 29 Oct 2020 12:26:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999582; cv=none;
        d=google.com; s=arc-20160816;
        b=Gp0vTad8khLumynwP20ZTTt/07O6uRoFCimqrmTUpOdNMBa7NqOfO8Uk9XBDyxTAzI
         9WPuQs0/RGyFoubtHCsdgDsCoCXA4DHnfQTt8dD3llo9FDEaPQdTI9m7XXVCtR1p4nTQ
         QSukxN7ntgNYUyIZBcQAnNkthbv7cRhKFlH0IQn49NjkWNB8RnImHheb2gEWso8ZQIRI
         OQPXqdfnOuqV6RqB5jcZrf+AQDAo4+2QktvOPlihSzgFnnwPcVpyYLiZhPXwvxlg1yJd
         sWaeY4eATSDynJvh6tTK7+8C8HWeIDS9qtjDmc72r4ZEE9uEOR1lxW5zTCrlFTVA+ErH
         ++/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VsN8c2WI1TMox3v/PYtKI3bTw78pIVnf1hcHZhXvdoM=;
        b=GxhRTfKsp8zag7wbeb4BFdtHLbPMo5ozbq8HpszLMlLzUF4FYCp64WXEi11LWS2U9B
         qNXORqlGnKz8xND8he3MMsXalzQUzLMngYXUUfNCApYKjSBdZY6Agqtnbai6+hMgtDDm
         eM5/PL7roPTbIojhbu0npfS7SBvmXs/pgMc4iskh6BQXed30q1QkeZwHJ9KzsuZoY4sB
         yxlLcgHdtsUKyCIbj8Pwe5A6Rh3nkKH6qlxsWpcGzuGLM8jdS/4oHn9ZRbS4nAaOra3S
         KjL/2o3N2JDPLHauft1hhYYqB3V4I1Hcbt6En0ndRIceXG5JpwyuL5VkXO32V2SKxrdf
         25UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aMgPSNzn;
       spf=pass (google.com: domain of 3xrebxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3XRebXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i16si124600ljj.3.2020.10.29.12.26.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xrebxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c204so304063wmd.5
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:22 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c957:: with SMTP id
 i23mr405696wml.155.1603999581892; Thu, 29 Oct 2020 12:26:21 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:27 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <9b5881af53f0206f423117d400167c96e8584024.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 06/40] arm64: kasan: Enable in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aMgPSNzn;       spf=pass
 (google.com: domain of 3xrebxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3XRebXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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
MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
enable it as part of this patch as well.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
---
 arch/arm64/kernel/cpufeature.c |  7 +++++++
 arch/arm64/mm/proc.S           | 23 ++++++++++++++++++++---
 2 files changed, 27 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index dcc165b3fc04..c61f201042b2 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1704,6 +1704,13 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
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
index 23c326a06b2d..7c3304fb15d9 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -40,9 +40,15 @@
 #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define TCR_KASAN_FLAGS TCR_TBI1
+#define TCR_KASAN_SW_FLAGS TCR_TBI1
 #else
-#define TCR_KASAN_FLAGS 0
+#define TCR_KASAN_SW_FLAGS 0
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1 | TCR_TBI1
+#else
+#define TCR_KASAN_HW_FLAGS 0
 #endif
 
 /*
@@ -427,6 +433,10 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x5, MAIR_EL1_SET
 #ifdef CONFIG_ARM64_MTE
+	mte_tcr	.req	x20
+
+	mov	mte_tcr, #0
+
 	/*
 	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
 	 * (ID_AA64PFR1_EL1[11:8] > 1).
@@ -447,6 +457,9 @@ SYM_FUNC_START(__cpu_setup)
 	/* clear any pending tag check faults in TFSR*_EL1 */
 	msr_s	SYS_TFSR_EL1, xzr
 	msr_s	SYS_TFSRE0_EL1, xzr
+
+	/* set the TCR_EL1 bits */
+	mov_q	mte_tcr, TCR_KASAN_HW_FLAGS
 1:
 #endif
 	msr	mair_el1, x5
@@ -456,7 +469,11 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
-			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
+#ifdef CONFIG_ARM64_MTE
+	orr	x10, x10, mte_tcr
+	.unreq	mte_tcr
+#endif
 	tcr_clear_errata_bits x10, x9, x5
 
 #ifdef CONFIG_ARM64_VA_BITS_52
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9b5881af53f0206f423117d400167c96e8584024.1603999489.git.andreyknvl%40google.com.
