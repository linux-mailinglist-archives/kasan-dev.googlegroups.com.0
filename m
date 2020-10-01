Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNWE3H5QKGQE7RBADLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id DA937280B15
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:50 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id v5sf117746wrs.17
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593910; cv=pass;
        d=google.com; s=arc-20160816;
        b=hv9srsUm7wM7VD4aEQVWsBkyJ5MLiMdJbedRlXnneVpk1nHUxRpWqNRj8J9PABkkT3
         XytB2QOVLUSxx8tYWNuGXucUiZNQQwX1/AC6jdjZM3T+8Ka7VY3ONGhy9XAoepsCpTQo
         ooh6OEhOWlG+bgKA7j1xsVPI2gtocAYnqxHNh57F1Qn9VpMTVj6Y1LwFHxi+op0yZ2DZ
         YmzwOX9qnVu1nFol38iYJF/u6Z4pQIsLH9/XK6tasiqhCh9g+nJiUXgA9axgCoD1r9cJ
         a6BLEYIsaOVGRsdYM9b3hXEAYaCOdBt8hMKHfLh9P+GozEdXIaMehrNN9E67OGrskVIc
         oXEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=SvERoB6FObWcSemVY2FVPPEkN3MC2UHJ7sqtwskqtu4=;
        b=y8sIS2UOikJ27+lnYC/PeEdY9wsjhOVB5iQkO99boxgXX5Y9kIf4aUUEcxkUvhLof4
         aEC38BKA3pbP4/vvkCYbeag1SzPkCQZXo3GMKMpugdHsvKtPFHvDaXiJXTYoVCNdwbT/
         zPFTV1qXjkzyvsje+RxqbJxPmK9mnqkATswAlt15H9WpqeGs4JuSAOfEr8zSBcPG3ajD
         TPIqOqO9Nbl3HC3jBvjEgp9HB18wc0ZA77UVUlm5vilaIchRaftjQL1YouhwDd3ScAry
         hktzyQ/x8Zhymv0j6eDVlvrjf9i9Uo/k7DKL61NYVSpSf/j4faEaU3jGx4oLxnwwmRLF
         cVwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JBmbjsh0;
       spf=pass (google.com: domain of 3nwj2xwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3NWJ2XwoKCdQ0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SvERoB6FObWcSemVY2FVPPEkN3MC2UHJ7sqtwskqtu4=;
        b=sOWl6KAHNvWGiU2CwmT0aO2Nf9Fpw05TWV9hLyTy81H3BHPLQTRSx/+MJYT8Tjo9aD
         GuHmb8JXGEroYX6pPdRoPSc7uaz9n1AFXV6onYFqYvDHs8ZcQSTn+tYhMLKFKRUTYHEC
         8VOcOpBIjqvuOKgN3c4rir1hOB7Toby8z/9qR1EIENdGN2oVINBWf1uRYUK/brgKEQnE
         hnCQUSGUO8PGcrYdyp+S8wal7kGayiSKiRl7CVV1dqD9vZs3B55zYK7Wd4k7EwepkWQN
         p7LpyVF+V+m8k2QXq/4UEszejvQ2tKUk3a0srhaGR9hrz2fr0c7hXMV1yTa9JImowT83
         f5Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SvERoB6FObWcSemVY2FVPPEkN3MC2UHJ7sqtwskqtu4=;
        b=MH6sUrLSSw+ybi/FP5axPfxw6aJLPYEntUz+qhfiuvb4zHu36yRm1UoRCRfEDKO7gE
         lnisFZ4LpJr7N9Svcc7P5ncVqp8UkOuD/7YTEOLzod3LzrCw1MvJqjHHh+VIC/XBkKE9
         K31aU5aGX4NW79N4pCOd6ubKU+HoQbCo45lFewbE+UYl46WnpmLwQ9iI3BwdW8aD2vvY
         ekLtn/YXJ5ZfvKB0uFTMtXJxnj0yYvfXZ4Mj7uA9KW5ryi5XXu8jPN5aU46sA5j8fihK
         kmcmqtASmQlzD7HVg8/UhOB8WChbS7vQiG5ImGF3zZ0jLVFAgg38HSUZz9D5Gv6bj0xE
         g0OQ==
X-Gm-Message-State: AOAM531+3d6BtyTRY9X8xfPk2qfvCRn/mz0TddWQ2555Q0aVoiUufjym
	wNZL6dUgWEV6SAqrlwsAaOw=
X-Google-Smtp-Source: ABdhPJxjggZqUboJG+4yNt+dPtMex0Tknb3G7O4/oUR13LfuRKUTJ50SkM6UwQu0Z9LZpbT9gvn1kg==
X-Received: by 2002:a1c:1f89:: with SMTP id f131mr2427215wmf.10.1601593910661;
        Thu, 01 Oct 2020 16:11:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd0a:: with SMTP id a10ls6608196wrm.2.gmail; Thu, 01 Oct
 2020 16:11:49 -0700 (PDT)
X-Received: by 2002:adf:ee8d:: with SMTP id b13mr12434372wro.249.1601593909853;
        Thu, 01 Oct 2020 16:11:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593909; cv=none;
        d=google.com; s=arc-20160816;
        b=wo2lJHNufuAOpKHOjSYXcDKjR3cKVL9fGOdbUy+sdsPY1GI+BFZqkmE+ChV5RwfC3g
         KTIS9oq7ZKqC5zfSYTPXBWdrjesuBQ9VZFemMyopReOdGl1xxCJHK0xpR12UGpWFfqz7
         7Z2c2WD/9gCldvJhdBo1D3cgLEiQZZHCsxu+PsTU4R0c0YKQKcDzaLy8iy4Zit7e79+v
         F61dfCuLa2cigsrJOVuc9zcCOJmS8mDTwFzB2KPsTjb3WXb+9E/NL0molcyDN4b4jUpG
         P0kxIRqZUszcOiP+u2nrXJ3dEdTiq/qBk3Xb5MjnbCeH2+CD7WMiEdLsV6iokkU4h1Ub
         FW9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gnytaCb94xVQ7L/CojXY6Um8kg/YstpjCzFIZv8WTx8=;
        b=UxiTjVCYMRP19ZDk6lEWXseXy8FK0gyH0kS9ecn5ugLlLWfWeGYTmmM3W63mU2xToL
         km+UEhY4MWE/NlvYZC4pzHmqNYuZXYmPe/JTnJIhco2zrRDHaEt2zdwq3+xeGfq5tpny
         m/7xG5KLuP5OIpps8e7rxNR0ipmuiZnrMZWhyrwrrygLDB0aX25EYUBacGSpD2HARWq0
         hkoK3ypVO4dRq7SgzUWCVFOXU7PIaXQHgWupdwjsWdHFjnvKu06Trb0uwY67euNdak5h
         Jr0j/SgJrHeum3jvvLEsbYnrd5JxrK7xKGXxEbS6LRLqIbzTy78rNasAU0zwW8uBCQ7G
         ovPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JBmbjsh0;
       spf=pass (google.com: domain of 3nwj2xwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3NWJ2XwoKCdQ0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 24si54512wmg.1.2020.10.01.16.11.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nwj2xwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v5so134589wrr.0
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:49 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:cc8c:: with SMTP id
 p12mr11956869wrj.92.1601593909486; Thu, 01 Oct 2020 16:11:49 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:28 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <e8d5ed9bc12086670cbde30d390de32730d0371f.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 27/39] arm64: kasan: Enable in-kernel MTE
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
 header.i=@google.com header.s=20161025 header.b=JBmbjsh0;       spf=pass
 (google.com: domain of 3nwj2xwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3NWJ2XwoKCdQ0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/mm/proc.S           | 23 ++++++++++++++++++++---
 2 files changed, 27 insertions(+), 3 deletions(-)

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
index 23c326a06b2d..6c1a6621d769 100644
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
+#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e8d5ed9bc12086670cbde30d390de32730d0371f.1601593784.git.andreyknvl%40google.com.
