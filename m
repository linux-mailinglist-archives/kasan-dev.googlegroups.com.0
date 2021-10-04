Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBNOF5WFAMGQE4MZSLZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D190D42185D
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 22:23:17 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id u3-20020a7bcb03000000b0030d5228cbbdsf4525951wmj.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 13:23:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633378997; cv=pass;
        d=google.com; s=arc-20160816;
        b=kYQEvebgQxk+3bTpkN8dy07s+XeCm64xhFkt5V6XSBRGmy9ztcYzkuE1bWdqu34a4L
         6PF+8Io9H35a3WtmDvs8LeI7YpUlM8Mdx5rXi86paHN2TDzrga281U26aaLXrZH2TvxQ
         sZRtMcnU7DMCgeWuDEMcCzAXEVJOKZtBcA2QUjdQ3jNVswpTdC5u8wOLuukuAxf2Rrvm
         9KJWxYxI9PCd2QsVbrut0iwxjqoCbCDF2kjmMKcfFJ6MQgLmdUPI+mZLKwUcnVkL5JJl
         e2QdCjeYGVURHt0Qy53AB8oKfGdDzKWH1FRCxnuWuxuMAUC0Z9NFjzt7X4Bvcay7v5Ed
         SIUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b2lQCDLE/0bD/QQZx8VpgGrTuidYfWqISIv7Q7zubrE=;
        b=ZiwK0ls0ViO9EJQkSxKYcgGAwg6TSYp5hD15YuG5t/slRQtgO7Z7/L51h6IEMxEnXc
         Sbx/n1wN5eTsPHX2YXnEYPJ7MObmzzrjN7yZyf98z3xdSUxxqqW2h1zaYrySbROr5kAN
         WRsQNzUrZt9IJAEONTz3gtpASKkOuaTsW5ArOhOXv4A9R0kSQojNEwnCRt1OVVfLcWW/
         MroRNfq/OcQqnilHmy/MpOgRb/7MJRxx2YqmHIb1jxGrW8qJ5OrnauD/3WcAbPjT5ETq
         jDQhLc5bp6py2R5i2vBulS+j38/9EyNdYBhnvvq8qmKWkKDO7QtRshPJIjakKEf1q/OO
         KcWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b2lQCDLE/0bD/QQZx8VpgGrTuidYfWqISIv7Q7zubrE=;
        b=a1wKSqdtZNtCe5nw8CnWw03Aiee3m5QTt3nAH0qttVzyctjmNNSOO/hgSPHTqpPiQc
         meo38Wof3FK5WoKN4OchNsnQkdArkvbh7QPR25sYbNOuB7QTJn6BtEk0oaQQMXOvLtvC
         lbG8bkup+Z9xCYItjWZsQMpKaIsqB8q9yw2xTbP5u4PlemIOGUPze3g5IzaLswmEsu4P
         euTYhW0piZo0dfLeCmjkx5wBoDXEAy3BWc2og72NVz/25Jc0GadX3kisZN4lRs4yb6pL
         ZXMrLEbRq2XTxQgfT9+7H2U1MFOVCcEjexMvel7yFwMXCjuUNM+DNQ8YRQuLoLRUKpIa
         iMYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b2lQCDLE/0bD/QQZx8VpgGrTuidYfWqISIv7Q7zubrE=;
        b=aGDYKi6attHI1GgRlDNROvtPentFGvFzNTmDfX7/5Uot6SEv7D1fCG7KN9nTiUD1d7
         +sHScV96WBvB7fgQl4uFTGVkJp/kqI7oQi3FB0JbFYVNpGT1xwUyh9HDFyGvKJ3a314z
         WImPMquYIrS4OxkgQTReUmsPt9b+USVPeg7cfvx9WKB2qceCwwT6gbAxNDbrvD7roJ69
         u/2fpCaJ8mJDjfO13k3sWVssiWGjS94JduuJVX1rOhtUPb2l9Wd7reZKoBgceT5Rsn2Q
         7Ika8H8WkhLyRijR7b7/U/RK72vkqDF2OUo0Am5UEbTkViYwag07izEqMJAdmkkFG2+D
         Fleg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Szj717K5mLvg1JnKVXOh3nZhR4S3h5AcN8xdG279j4pMhPpHN
	wJgttLKiTwGQ+fgCt+MNxVg=
X-Google-Smtp-Source: ABdhPJwGsmKVZmHJgPBM+enfE1VeN/q8kjO3cWgbPk4pNJ+0+F++4Sos2mZXQghqqw3iO5nsKseYeA==
X-Received: by 2002:a7b:c11a:: with SMTP id w26mr5991613wmi.99.1633378997654;
        Mon, 04 Oct 2021 13:23:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3512:: with SMTP id h18ls10447210wmq.2.canary-gmail;
 Mon, 04 Oct 2021 13:23:16 -0700 (PDT)
X-Received: by 2002:a1c:d7:: with SMTP id 206mr16369984wma.116.1633378996866;
        Mon, 04 Oct 2021 13:23:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633378996; cv=none;
        d=google.com; s=arc-20160816;
        b=KVArnzWgr5TuRwdT70VQjWlc3Ogy1kSuuDrCfrhmCi8ZglR2nHn1EkVsl+6e/J9jmD
         RIFeTZDT5klOjVPlWWKMwOHOf66XKMSMtY39uaJ2f0GQtJX5l/fxqQ0Smydkmxpatj0J
         gzgcjDMxJ+EqKQiPfZseOeyAJHasg7hwrWYhX++W1mLxFmspcb65bYoWm6iyBEdgedLT
         u4RBe1FW9hXEh4AWwfYu5CH56YbDKBbo1vIZQxqdS9AbY962PQKqyHgCwuZWQnnvXkEy
         fBUYinCwi44MrnH7gRQBMoh7SZfUsQaSd+RRBFr3Ay7rRXPnM50lNVtRg81u4BTpp6tM
         tbDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=yTlERtHDIlPOQgOV1RlT1zTcUloBx5GrEDg5YkCAcAM=;
        b=tz0wVQLvYsRAqSaKb8yP21B4JHEAvOkVmkLIHhARjDflrnkqZ0HuHb/Xi06oxraeGb
         NV6p6BOOykjrdPoJFnRNuTUQ0uVYZO2LAIvtksAo33PxRuNXjrCVfKXdqBBCOrJE2wzf
         XJywtaulnZvaJyqcHYFZoNCLr/aFM0Oz0nIkcVJ9Jldatlz9zzyus3IQLMp3MLDB/HzG
         YEir7/ofHi1w3TLgUQ+xv8NK80/uexABVO1O62aBZ9I6e+UiBFcircLje2ykgRDWtkQj
         x5+000ILbvtedcZ+G0TD6eVI/Jx8BS3yv8o0t2Hf3X0eutr7MHSLuG1GDkRsB4wI34pF
         SySQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y1si738999wmj.1.2021.10.04.13.23.16
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 13:23:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2CD931FB;
	Mon,  4 Oct 2021 13:23:16 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 113C73F70D;
	Mon,  4 Oct 2021 13:23:13 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>,
	Suzuki K Poulose <Suzuki.Poulose@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>
Subject: [PATCH v2 3/5] arm64: mte: CPU feature detection for Asymm MTE
Date: Mon,  4 Oct 2021 21:22:51 +0100
Message-Id: <20211004202253.27857-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211004202253.27857-1-vincenzo.frascino@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
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

Add the cpufeature entries to detect the presence of Asymmetric MTE.

Note: The tag checking mode is initialized via cpu_enable_mte() ->
kasan_init_hw_tags() hence to enable it we require asymmetric mode
to be at least on the boot CPU. If the boot CPU does not have it, it is
fine for late CPUs to have it as long as the feature is not enabled
(ARM64_CPUCAP_BOOT_CPU_FEATURE).

Cc: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Suzuki K Poulose <Suzuki.Poulose@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Suzuki K Poulose <suzuki.poulose@arm.com>
---
 arch/arm64/kernel/cpufeature.c | 10 ++++++++++
 arch/arm64/tools/cpucaps       |  1 +
 2 files changed, 11 insertions(+)

diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 6ec7036ef7e1..9e3e8ad75f20 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2321,6 +2321,16 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 		.sign = FTR_UNSIGNED,
 		.cpu_enable = cpu_enable_mte,
 	},
+	{
+		.desc = "Asymmetric MTE Tag Check Fault",
+		.capability = ARM64_MTE_ASYMM,
+		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
+		.matches = has_cpuid_feature,
+		.sys_reg = SYS_ID_AA64PFR1_EL1,
+		.field_pos = ID_AA64PFR1_MTE_SHIFT,
+		.min_field_value = ID_AA64PFR1_MTE_ASYMM,
+		.sign = FTR_UNSIGNED,
+	},
 #endif /* CONFIG_ARM64_MTE */
 	{
 		.desc = "RCpc load-acquire (LDAPR)",
diff --git a/arch/arm64/tools/cpucaps b/arch/arm64/tools/cpucaps
index 49305c2e6dfd..74a569bf52d6 100644
--- a/arch/arm64/tools/cpucaps
+++ b/arch/arm64/tools/cpucaps
@@ -39,6 +39,7 @@ HW_DBM
 KVM_PROTECTED_MODE
 MISMATCHED_CACHE_TYPE
 MTE
+MTE_ASYMM
 SPECTRE_V2
 SPECTRE_V3A
 SPECTRE_V4
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211004202253.27857-4-vincenzo.frascino%40arm.com.
