Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVEASP6AKGQEMMKEWBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4681628C2E5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:10 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id 9sf13341604pfj.22
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535509; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZODqil/YgPHnK6Tov/jd1ACfh7su4eEHgU4PlJ6FxgirRUVJ5gVSosgkGE8iAnQVpt
         nlAdEjg/S6usqn8MuhQdcW6DALv8QjH2tsUl1LzyyFTZOqXSMhc6bj2k8OBu9IYknALX
         SXkXGZ020bv5/L/s5eYxZg6R3LexZ4YLSTA8eteW2YIKdOzG/4FJ9HePSOSZLUg7TZMX
         9z6pfzzt76xh+c3vAjtN92XvVynJOKapylC6n37G38E0z2OmJL0qGvRwrNF+KZm9HwW6
         4O35as0EgTLH7KtYLF1krDmzCFFX1Bxys30dT/obhDZEhK72qyrFIWXWNEL2WsGf+DBB
         E+DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sQ1ljSQmWoiSg/Du29PPWbdz+5edzpRAk9Re83EQpWM=;
        b=VeRGmF5JcfiwsLQpq0tL1qX+SME+KTLLkb9pLxmZgTiKu+ntc/vKxsBybQsYBzRnYp
         bTdID6lMJGBTfR8tSYh1hJitrXcB1itMVaDb7e+uZd0g0yENXaE7TpWyfMzQ9pH9ii3I
         Xt6oxoBfpnAA4vrSn5KTjeDt2tfu+PHlV9boT29ypXMXCURbtgcHX63SQvpZ4XxRs9P8
         rwUo6NaMHTj3omE2KTBAYtzreotbwGaeFrcBuSJbqxFVKXPKybwEumnxNWVSNKntmQbr
         JYLGfwubwjxvZ0vLMg/c97mhNJz+L/H7sBP9PSpiYZTcRXGS2Z6nJen4O8ElNhZw9rLc
         VBrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dFacscOG;
       spf=pass (google.com: domain of 3u8cexwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3U8CEXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sQ1ljSQmWoiSg/Du29PPWbdz+5edzpRAk9Re83EQpWM=;
        b=s31Ek0OOABiw7LlMH8nmnutJqPzfVA+lUVGwOUpOJB36o0ylIe1GL8cv3M3fpHDsEP
         rt4EdImmjeud19Lin+bhi6LdCtjmUuWl/eNgo+V9dU8VbecVIl/4jL5H+swMioZtP1uS
         ub/3gZ4yDdmUKuFpBRf8I9FHUJ3hEnDFM/wazoGkVb4IBVvilzK6hLY/zJ8i4Vg5UVQ5
         HTY77IL5F8HsBVizTxYdghxdN8jvvSKU1za9WNmbqFlBhA9aLX66ziP3P/oBlwczvFrk
         +0wkW5NBy7hQNOQrsrM771SKJUGqxFLUrCaAO5rC8fEJ/f8XlLh4QiQODjB68fbqMbjp
         ImzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sQ1ljSQmWoiSg/Du29PPWbdz+5edzpRAk9Re83EQpWM=;
        b=DePJnSaD+2xxg6W7Dme3j7o+BkLyYYXo7T2NvWPuer+n8b8NrrxvuJx0twg7/x3mL4
         NMq/Ns8ZwRydIrRU5BxW0meoA9T0CfwiMnbtoUIA0kv+pL+ZUygEV6Dfpa+7hfJWqUZZ
         M4uuTN8ci5syMDIdDqukR9Ui5obu5IAWO5BAqD+dtlsaGl2kWaaIcJSHX8k2HTo4X2G+
         yiJS2iiz74K3/1ovdIAWTsZYnYK8yL/EFh8Dmoe/HS2GidOcbcLoDXovBUrb/8PaasPN
         17V5oJXMTITS+KnpXcqxJ0qzkuL2ww5Rgrnm62K4HBRGfZORmrNsfEtLAgjPnCM6Sz5K
         2DPA==
X-Gm-Message-State: AOAM532epJwCzsGlv9P0gR5SKbD3xAtKYH4zTmXIfY3cKIrvk/LdKB5k
	6BWV0zPbn2f4obk/mNXD7ac=
X-Google-Smtp-Source: ABdhPJwjDj88VkEfDkNGVkpI7j7J1Meq1AdptyrgpAEj8y5/JLSkQNgnBHxezLiDBHxAP4RcRZdE+w==
X-Received: by 2002:a17:90a:be05:: with SMTP id a5mr22565688pjs.118.1602535509013;
        Mon, 12 Oct 2020 13:45:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7044:: with SMTP id h4ls8104673plt.2.gmail; Mon, 12
 Oct 2020 13:45:08 -0700 (PDT)
X-Received: by 2002:a17:902:d904:b029:d3:d2dd:2b36 with SMTP id c4-20020a170902d904b02900d3d2dd2b36mr25677057plz.32.1602535508393;
        Mon, 12 Oct 2020 13:45:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535508; cv=none;
        d=google.com; s=arc-20160816;
        b=YUUKeKJJOOfLe3ICMPXZNKCM+CsuXj58L501rHlTz5N/h3LdYVTf4iJIRky5CyuJtP
         oBcX+YL+B00eO5W2+OgLfpWDsnTcoNWsieIilwXGtJz16tcUrPAva7f0nPor+WXJgG18
         3pRAp3wsC5r0cZRPX9ajt0I42HOQMgbGtImkVCGfGoLyKnWNHpvOXxefPeQGepVexRn4
         tUVEoxlsBrzB2JpRwtYiBmq0KZCca3jUEpfAt4trRUa8Los5LPHj5nmoleTG3FcqohF0
         N4532RqgIeNdw1yZthJ4ALJsc6rI732f4JkDGpSjusjjsXMVHfoyCOIfS3k+3Dslhcrs
         gymg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=/tqCUvv4fdg3x4EnuPqwoXn6/w1yXrUSTzIxQHS8YhI=;
        b=gz73amueErD9KgyZ/LSVGXYx6NW0Nu6x4bU+NZU8o6+zk6QGqKODwxKrZRRihK+ZnG
         3fn0zpq58jOEEsh6lYW4WqomrVR30ep5ETYOgtJs+hJFEihQeUGUzF2nZ4sF1QBnpemI
         +tWoB70FNIqRw0tWF+jsuHK+mphHVtbKJun1FHzuOb/UPwTYVMcA2QvWP/74ojQMvquk
         ffudYSRAd+fGc7YCzi/h8Gb4osAw1ocQ6xZyLnohO4wQosx/2y+4HtiMpOCq8I0hLUV/
         bVM6s+q6gH68GnFQJGl6UkTeltqjmuIoPiWuoc4h0ZbR6TxotJ+87/ikgO37otC4Peof
         vWrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dFacscOG;
       spf=pass (google.com: domain of 3u8cexwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3U8CEXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id mj1si1402201pjb.3.2020.10.12.13.45.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3u8cexwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id q15so13474783qkq.23
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:08 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:bd85:: with SMTP id
 n5mr26439786qvg.22.1602535507402; Mon, 12 Oct 2020 13:45:07 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:12 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <6dc1e8a7c6000d1798b36b2f3df8ece589594190.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 06/40] arm64: kasan: Enable in-kernel MTE
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
 header.i=@google.com header.s=20161025 header.b=dFacscOG;       spf=pass
 (google.com: domain of 3u8cexwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3U8CEXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6dc1e8a7c6000d1798b36b2f3df8ece589594190.1602535397.git.andreyknvl%40google.com.
