Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDWGWT5QKGQEEMVZL6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 338A6277BEC
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:59 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id i10sf293435wrq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987919; cv=pass;
        d=google.com; s=arc-20160816;
        b=s8o1tTk1Lx0Aq/lWiZ1sEZ0InHEDgHGDB//gkMtEdQl6fQBZ4Ly45uEM3I1pEK3Buj
         CWFHhm5oFmBQISHqzaHtfHwgtTrucDMqXifFeyfeD+MMBJfatr2RuQi6Ih4/CitCw7MM
         PaLk7bqL82Te8S/3rte6qsa39jytPz48GWEoKDncizW1aJxdplpXbJkb9OlGqg/whQyB
         CR13VxE9Sbo65ySI1kjTbgQZj8woM6FOVnYtyIEeAFlxg7OhXf88og/gw1FhmAuaRwC9
         Rjo/UQFyOSrYGJKOpx8upqPEQ7SS/JSukg5oRvGAPpF+r0mAD/hchsDhZwzNidueUw1Z
         5AbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1khBgDiLklJshB8ABkVwPCh8AQ5a2s/XcfcBRt8CsOQ=;
        b=FA6X2jugiOxE8R0uvPOsVMEUaWGmmPN6fy67WtFCIaGALwYaoBNqQgxN0PMCqh56DR
         1D2Ss6H837nZ1KqoTBFfdDOgXQDF5hytf0j6twMbtnzCgO7qxfpkccChDRXzlO5BolHy
         4TYlVpkYKrQQIKXeHnEUHa7OKud7+jiT9MJbrUeqm3I9+Ttj1U08miqb+iER6QElhFVR
         50yzX8dK/sOHUR7FYJ0ejzovD3/1RHcO9dNzY0UZI3pVSIFfDfs5PLzCmy31R5Upxvla
         6Wm6ZnVVZhTzNETXzgAPLIJ7YaA+98+QZkWx7UzY9fQn20WgHeSnppGqHMnFZtG8FXI3
         f9ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="blC6/eUX";
       spf=pass (google.com: domain of 3dsntxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3DSNtXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1khBgDiLklJshB8ABkVwPCh8AQ5a2s/XcfcBRt8CsOQ=;
        b=Xes4H1nIM7I1+dK416aCq4c/G0kxPVY3uC0AeoYRng1z/NHbhIRLl21w8Y128JgVl7
         GUeRQonP7w9R8LRWYoUf2DY2LwnX0qfa5uxKXoLbcDNmdSODtPO52i2wK0eO1f3XsdVE
         kZe7XAWDkip8buFqYEuVNl8sfzGtNYptss6Li6AW1ShrOkHgVlXfjIrJpYOzUp97okyA
         OQgeYt0IgY6OE7sHxv7fk0NMW/ESc7L/FiCdlk5Ok6UylDs1rObb4QrVpUaf3uuYYTDA
         Qladw4wwTSA1xgTLJJML2lz2baxXLVM8Mc0K4bLC+dfmUD/83u/KlVn2nnnBef84Mf46
         w8ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1khBgDiLklJshB8ABkVwPCh8AQ5a2s/XcfcBRt8CsOQ=;
        b=TZ16FwqE5X3Ymtl4PYAd/0+GeL8g1uXAqHfj3YutevQRHIOf3uPKorr4cqjbU0ddYZ
         FS5tj2tDn9zfYEdyKUGFcirPz56zuaUlCBPNgYsrAth6ci4qzTVcZ6lqd2zgnUyqkyqo
         AOC+UrtkkA+VzTqDax9H0LYaqzeGzz1aW+dv3GjnJ9UqnvsQyq3ho/MD9N/VJSmz7Anf
         zR/OrBt5VTH3/3ZnuHvNehvNlwrnUC02E4TwIWioyeY0BcjaczOpNhv/GIWXsB6J4yKu
         K1ZKLUgUlCTxBbxa2VftZ3gblwj/Jac2QrQmRsKAZNnmCX6lU1JYi+T76TPCC1z9LO3l
         nttQ==
X-Gm-Message-State: AOAM532AAJb8KpQqS3Uxki7N0mVN/XaBIrPQP0bhNQiLgluAlDL32t2d
	XATyb3m2DwJFfe7JkmNHSwY=
X-Google-Smtp-Source: ABdhPJwYlXPZQxja3nOvCicilfwz4lTp+K+hPNFMiWmTGBLvp1jUrItYNodf1UR3RAJdVYqn6goWHg==
X-Received: by 2002:a7b:c1c3:: with SMTP id a3mr947867wmj.68.1600987918932;
        Thu, 24 Sep 2020 15:51:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls1055870wrq.0.gmail; Thu, 24 Sep
 2020 15:51:58 -0700 (PDT)
X-Received: by 2002:adf:efc9:: with SMTP id i9mr1210157wrp.187.1600987918129;
        Thu, 24 Sep 2020 15:51:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987918; cv=none;
        d=google.com; s=arc-20160816;
        b=HxtJ5sfZ1fozMGdCmg5TIK6Lrd0+0DQuoXqdSrb7IHrvTJZtSWytZ1PDIVWSfKcKVg
         d5admWGfVs0Rx+ZZ0YxJSCMa1bXuckFQ5U3SdOUBA1Y4ExTJ0lIKsMvSgvgOJvakpPPH
         0v7UNwq4p0bDmeiRFHulcLRguLOYAy4KWA9puPjggvPe0wwii5XP4h9tWvYjl+89R6J/
         dPvZ/NoMaNSW6vwBE4w/iEfc2yjE8Cnwt8ZamKCWqTci8i2XluMbf3keVQqh3OYqCFH+
         IkoSqwFIiw+nQyXOwFsrpxbKu3rzjYeWjESKJqnJvB8etiLP/0u4JE+FsF/KRolf8l6e
         K6Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=aeL0Vc4/BKzUgRM3E0S3wSW/q500Qn2N9aeyIxmwibc=;
        b=izVY2A2+33qV8i4Bc2gt+A3vChONL7xtWwfbrKKpqNfDSNA0evw49O/D9ZVi8lxYec
         7KUu12L2GrrTzcQlU/rvbU3Zzeyc1A9uAIDLiNdX1D1KbLnAhg8MwhowujJ+C7ZWJ1mM
         RCBvR9vLoYFA2urNKOY49VBcW10FUomeHnQrX0L/GAZaykB3rpTl1cv9b/+YNc5T0d3l
         UyeyO/fDkHD4lDVkzqILVS/v/U6cVlYGwAsscbEZ76ASoh8SExLV2AR2IkjCXXiFLpPN
         Nw0Z5HxspFaPg7r8O+m7yZ+tRs5Ti1T77C2Bbhgvc6nb/T1jfXn4Q+RcRx75KPa+ou2h
         DuAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="blC6/eUX";
       spf=pass (google.com: domain of 3dsntxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3DSNtXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id k14si25742wrx.1.2020.09.24.15.51.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dsntxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h4so295812wrb.4
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:58 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:8b1d:: with SMTP id
 n29mr1105331wra.383.1600987917635; Thu, 24 Sep 2020 15:51:57 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:34 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <20326c060cd1535b15a0df43d1b9627a329f2277.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 27/39] arm64: kasan: Enable in-kernel MTE
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
 header.i=@google.com header.s=20161025 header.b="blC6/eUX";       spf=pass
 (google.com: domain of 3dsntxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3DSNtXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/mm/proc.S           | 11 +++++++++++
 2 files changed, 18 insertions(+)

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
index 23c326a06b2d..12ba98bc3b3f 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -427,6 +427,10 @@ SYM_FUNC_START(__cpu_setup)
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
@@ -447,6 +451,9 @@ SYM_FUNC_START(__cpu_setup)
 	/* clear any pending tag check faults in TFSR*_EL1 */
 	msr_s	SYS_TFSR_EL1, xzr
 	msr_s	SYS_TFSRE0_EL1, xzr
+
+	/* set the TCR_EL1 bits */
+	orr	mte_tcr, mte_tcr, #SYS_TCR_EL1_TCMA1
 1:
 #endif
 	msr	mair_el1, x5
@@ -457,6 +464,10 @@ SYM_FUNC_START(__cpu_setup)
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
 			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+#ifdef CONFIG_ARM64_MTE
+	orr	x10, x10, mte_tcr
+	.unreq	mte_tcr
+#endif
 	tcr_clear_errata_bits x10, x9, x5
 
 #ifdef CONFIG_ARM64_VA_BITS_52
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20326c060cd1535b15a0df43d1b9627a329f2277.1600987622.git.andreyknvl%40google.com.
