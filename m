Return-Path: <kasan-dev+bncBDX4HWEMTEBRB44LXT6QKGQE4YCLSIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 584292B2822
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:24 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id d3sf533105eds.3
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305844; cv=pass;
        d=google.com; s=arc-20160816;
        b=CLpm7/5uXa/aQxIZh5qFj+mTCiuwV8PrBUG9ycNw3PoewvNHGrAQBBbWTuk6RQnr/C
         6URbbYIUIopYIOy0Ih/2Z4Uc62EuKWMu3o7jUbipvlyEXE+gbdzYANkHD5mOCQvxLadu
         BJQkTG5xC4Y+ByVNdI93k7Lc7S2vrhyKUw+q6vUnIG3O5qTPu9M9nkFz99KBgFQQIsqn
         s+nYd7vtN2W7S8YURGqFkhGaIfUYu3OJwj6IyCTkpcvnxxs3vb+If/gFKbcVYl/Wp/Rg
         kcbjA/4yLCVih72gsk1fdQR/EsvVQNV6zTRAc+a5Wy2GsBRosqgbzTHDQl5aebO6wUzs
         ibfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QJP1amsV1hXivE7OccES4NBTU6V1gm26KnOiDjre/NI=;
        b=n3W6nPfyQyU60P+d65FP7fBrNcI9DTOVXittCnLAbcMhHQlC18xHvgK1XPWtGXyT+O
         ChvMXQ62B2U9c+rSrsv7x2Vr+8F5j6t7vfbj4LLR1ypxdH/41cWtolKD1YHXVSaRxsCc
         lSSHN0MCfSJUf5g4u6mLCwGIvzc5jCNOmqry+Cn70HtF/SvdzmuxZwIekRMULI0e4/4O
         vk+XH6MEOpN6Rg7bCEJkQYSkcg1gqGCd9EjhS2uembEoDe2gT9IdR0jkPsk5DxmFnaXy
         rr+qasXiGT8lZ+gMXZH2lMwbJd3/JYC32Y3rL2vbUfoY6p7732XMRNDfGhi8bnEUvt1V
         8Gpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OOL94VYx;
       spf=pass (google.com: domain of 38gwvxwokcb0dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=38gWvXwoKCb0dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QJP1amsV1hXivE7OccES4NBTU6V1gm26KnOiDjre/NI=;
        b=UEAoTWG8iA5dUZC4iNrND1s4P00rPRMBOqUvrjW3vqQ3RmMZFqtP+16DMWcHWgNFJe
         R1ncHCcbVi7hMaDFgaMTsts8zS5RRhQ+IIfIgEZG7vBtHGP3lPiiXB+6ynWZIQoH3Ojx
         4hxhdYpIwTdrCfuo83mAcKQYr4iNNTOQsmE91EJ75yVnYoSXQoY2t6XWqF2AcV8UZmy/
         kaSMZKENifZDff6jrbPF2bOpC4g8okXpd/yModxeyys7R+oxqNKhanxu9P3jwwP4vYo5
         5g0QdS/q6olvsH4wbxiqYxqVYFn3ucnd7gJjvlwSYxcy8hI2UMfwnyMbSBnK7qHh+tOb
         UaUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QJP1amsV1hXivE7OccES4NBTU6V1gm26KnOiDjre/NI=;
        b=UWJwjnGpBYiqp8ES9fyL+vnsUmwqB0VfSnFG0p67+tNs1kqF9NFs1lnlvxsvFdlzli
         Yo0XIggzg/Kc8iolkLaYehb3QoesL8kIxHZCqHBFPA2vcbvOVmVa71l5HqZI2FuEOZjE
         +aKhkx47sH/W/+U3pdOmFl/0EX54H2zGtc4earvbPzC6Cs9ZTPrey1Ljr3dge044F2qo
         oE4iU19Wb3l1JOonYL1BGwfIR7fGxBcbji7BfsCPgnO8PBegssNS5FrdPkt2f4HEZ1az
         5hy2Gf77lx4oqDBfjjPEOGLco3/9U9Y427BrUTrx4eHcfRkvwJ+a8v4BJBt+pn4is6Co
         Bk6w==
X-Gm-Message-State: AOAM532kPXmuwT07ksy7Jxy4O2pdfzATrNdY8JV9zyMvyQwkWMbL3w4r
	6wdw56mK3SKrTLr3DkPd7ZU=
X-Google-Smtp-Source: ABdhPJyAzu/FkqKGUSM8wml5dIqqy4Cz8VvW59Fz5dT01tmtcSLy0Jj2jJIWK+fpelFFEyp+Y5x5TA==
X-Received: by 2002:a17:906:8319:: with SMTP id j25mr4449056ejx.68.1605305844068;
        Fri, 13 Nov 2020 14:17:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a98c:: with SMTP id jr12ls448660ejb.2.gmail; Fri, 13
 Nov 2020 14:17:23 -0800 (PST)
X-Received: by 2002:a17:906:f8c5:: with SMTP id lh5mr4327340ejb.77.1605305843225;
        Fri, 13 Nov 2020 14:17:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305843; cv=none;
        d=google.com; s=arc-20160816;
        b=DiZ7A8BMzt/Z4kPKIESFUTAWiKCwUCo5aVbNoRW33uIXDKBYjvJ8tNYaEU+LLembjS
         B4OfhM/PsFx1aaOX4zkUWRX9E3u2XHrxXU/kmpprzi1ZNereMqPnQIZ7bo39C/ZSVzdx
         E1UBBQG8VLGQC26Rf4Pdk2mAJagdmoBm/xZA/qkx/Pks+Yw5PLklaOEHNZBffwJLzdmL
         HZsKG/RCsjCTLTYyKLIWNdBsBU5MYJX14yxSZrt6vXWrLn4/0PNNFLPcSgyq2PyAQKtQ
         TVTSlZCn/7CbdGeQC7X4TBKZuP1eQkplhGMyISGPvpMgRHIOxY0pGEACxE0jjyikJr1/
         mZlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=cfK4RFJv/+x4FxS02JTsoCZH8VGMApR9HDzWNscVs7I=;
        b=WbLge6aAttkYq3LnREfO83cdOo78U2rs49kGzuCu7b/5PPmNJNl33J5M5MDfmkFgUC
         aHI/99qYB8kbOmitlrJDql2UiTUMfF/3s4h8TDYwAAX2ADXtWuZawDuguhShYrf8Gp8y
         AGBe6KLdOSSjnaF8aTn+kekvMG+j54oQLAg8Z15vGPZZe9xkNfYl7hNBRZHFAfpHs/Wd
         53yMlMCQ0mDFMaTtKoZ/938LnJLXbQTSjblWysz1EDVZD9+nd+jU4LiPagoNZBNFF++C
         HRKwGEh6GeeqyqsU4v4wwaC/uVYFykgJzU1RYn/hF1vZYJRRf3qHaYIoSdon85PjebKH
         ATfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OOL94VYx;
       spf=pass (google.com: domain of 38gwvxwokcb0dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=38gWvXwoKCb0dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ss24si223901ejb.1.2020.11.13.14.17.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 38gwvxwokcb0dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z62so5877517wmb.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:eb4f:: with SMTP id
 u15mr6012608wrn.165.1605305842904; Fri, 13 Nov 2020 14:17:22 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:56 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <123c654a82018611d38af8c83d1e90c16558ce52.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 28/42] arm64: kasan: Allow enabling in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OOL94VYx;       spf=pass
 (google.com: domain of 38gwvxwokcb0dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=38gWvXwoKCb0dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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
feature and requires it to be enabled. MTE supports

This patch adds a new mte_enable_kernel() helper, that enables MTE in
Synchronous mode in EL1 and is intended to be called from KASAN runtime
during initialization.

The Tag Checking operation causes a synchronous data abort as
a consequence of a tag check fault when MTE is configured in
synchronous mode.

As part of this change enable match-all tag for EL1 to allow the
kernel to access user pages without faulting. This is required because
the kernel does not have knowledge of the tags set by the user in a
page.

Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
similar way as TCF0 affects EL0.

MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
enable it as part of this patch as well.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
---
 arch/arm64/include/asm/mte-kasan.h |  6 ++++++
 arch/arm64/kernel/mte.c            |  7 +++++++
 arch/arm64/mm/proc.S               | 23 ++++++++++++++++++++---
 3 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3a70fb1807fd..71ff6c6786ac 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void mte_enable_kernel(void);
+
 #else /* CONFIG_ARM64_MTE */
 
 static inline u8 mte_get_ptr_tag(void *ptr)
@@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_enable_kernel(void)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 86d554ce98b6..7899e165f30a 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -129,6 +129,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void mte_enable_kernel(void)
+{
+	/* Enable MTE Sync Mode for EL1. */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	isb();
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 0eaf16b0442a..0d85e6df42bc 100644
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/123c654a82018611d38af8c83d1e90c16558ce52.1605305705.git.andreyknvl%40google.com.
