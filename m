Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBOMK66FAMGQEPY2DNAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 40ACB4241C4
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 17:48:10 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id l9-20020adfc789000000b00160111fd4e8sf2411629wrg.17
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 08:48:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633535290; cv=pass;
        d=google.com; s=arc-20160816;
        b=B9P4ANqjkUom3md2/8V9uddcCdboYJkEjc7g0asHB1xDWV1I/hmCWj5N2QaFBHshr8
         iZsfeFddUawMEQoOQySqOYiNzmncIYyEsJPJJeThCkB3JUIfW7Y2DSY6rX7H9al+FmGW
         DEfTTggZe268m4LlMGK7ddcqjEiQ34oIWZFEOWco8z2J9HfW5ivhKxMhd7278bXVBXEu
         EF4to7ePAshszd2MCzmoYNr6BhVUvlOmuxtk+SwwNj1Yqy/RXLcb28E2Vp8CgHPLZXxw
         c99mmCpaiGf+z0QDH91mz8UkRhfvKPeAzSUqhzLcA4bv7Rpoll0lppB80i5sNwp4ugW4
         Z7sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tJPAUeqcPDcHR25845JGm+LTqot6ZIlgbI8Nj+SEXI4=;
        b=OTApoM8y9lRhmojcHZPfGl5Rxg87gNoI0f/VvDMaB4vnDt75T9Z1+THC88tEhwv8hy
         cyovJN6g4a1fILQBfkQx8sihNufGN3aKRc/YIfsXcnXaUD9gSpF7Wn7ahpire9Ryrr/K
         MKJrKdgkaPTK0OLPFzF6KkrjguRqjSXjDyWihHShkaJQE2456t6RVr3AqiAH3nKBJ4G0
         G90gig6//qyGImoV0a+YP7s76Osna74R27JJpiHqVcYT/NhzyRL7Elac61Av3tAs04fo
         yrExpM1j+8seeNw0bflSkeU8QtmMGRGHcGBiq76X+ohKp/dXDuo18DSTiQ4YxA4KK/Z4
         yALA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tJPAUeqcPDcHR25845JGm+LTqot6ZIlgbI8Nj+SEXI4=;
        b=ZFIxaglt2ZIFB5Y38zVy3w3fq+kNaytXAehfAMJ7mxT6+M8iFKF+SEqZ6NIYGi/VQ8
         bn+3qHmSM1rGeht4HzDkcwWUGZSEu+1IOrXFtVAXjZXd596DAOu4bUeBee8mXoRvL+3F
         5JvLDaLH6K9Ioi3ObJ7MF0WMmkF7ntbuMTg8QK6FU3Yw62BfcA1VaW9mkXQg5casDOCR
         x4BosN6n37ayAsh5tvgud0Xvp4qRcNRVLY/cPcO/JqOt+tVQiC5CvnaTNWcbGDlnk8oQ
         4AqJqkxniTq0Rv0scmwYWs/Y8bBfov9LHjW8SUraBV69jPq2Ze1YLrdSFZSJEz/i8Hdh
         Xkzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tJPAUeqcPDcHR25845JGm+LTqot6ZIlgbI8Nj+SEXI4=;
        b=gHEG5FoPzb2sCtBq0OgYANaMYyY8apWPiR9eSAkEpYP7iW4Nl4d/jiAIc8jOLTR/jz
         ITW2cu6oZjdL8MGT3UMYDEsnAwimMNu5OtnQssU4cIIPDHFOCetZ+TO9o2VeknW3mxdR
         MXxqvsuYP5teEUtfa5pUaMRZMZh2iyIiprsQFlXqXpgJfo0lhmCzsDD7dzP2UMKJf5nf
         cdlrWLJz2do7Dhzs8abN2Uik8VdJoZpE9/qhJqtPMGG+v463qCXgKoglGN/LWl2YII7W
         1pGDmi5ADVA5ppbHdNszHW6x69pTbsFlvrMB94+eIFfKyynJSlrpvU9fEUD/BM1qX/9Z
         ktjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MsgTXDk3BHMtWMpwFiUwyigYBpRpK7df+nfdX5AJ3oQNfQyZS
	0n5g82/PV1KmDUan+Uje6t4=
X-Google-Smtp-Source: ABdhPJxJ/MTIDKK2FPEY0NdOc6SE2m/jHtENadIa/aHyQdU82rd/pNIyOmhe+yBK9GhosOF2vRJ3/w==
X-Received: by 2002:adf:97d4:: with SMTP id t20mr23196486wrb.174.1633535289955;
        Wed, 06 Oct 2021 08:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a285:: with SMTP id s5ls712113wra.1.gmail; Wed, 06 Oct
 2021 08:48:09 -0700 (PDT)
X-Received: by 2002:adf:f6c1:: with SMTP id y1mr29556903wrp.172.1633535289145;
        Wed, 06 Oct 2021 08:48:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633535289; cv=none;
        d=google.com; s=arc-20160816;
        b=o7i2Za+v7GAayzbFekFogpsUT1LPJdxgAZx1bqAFV5VT4Yp4NiUo8Zb0tecGmi7B49
         cdIU4RhkbMtjlsdAS9YZmZSEZ2yH75nPFDRCAec8R0DP/saI/i2vaTnyhl5Wlmrxv7aV
         310d0iXvgaxra6HmWdmcRVGtYFElEr3uCi+zO5DyWWr9cAfm2hkfyXO9XWwBLT7QSCod
         W22i0azd1s6QMXfHOGT8/HKkP0NAPpIGn2cNS5FLelgQdMZ18ERTrX9oOVqnRXgcgtqK
         HXJHqGTU51X5xSj+CExi6Jlu8TdIFIfhfpiL57dxE9Nnhlh45F4BNZ/SbeXdeppT4Wt3
         UTqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=yTlERtHDIlPOQgOV1RlT1zTcUloBx5GrEDg5YkCAcAM=;
        b=bxoqRKrF2g9Q+m8Yqs5aLtufRJhveoG57K+X+HBWeYBm7ZAMpnGB82PMHvhQw2WoxM
         9by+0bgMbblW9C8M0+qrgLNFW8c0ju1dHE09AQbZMZRS/hfrlGpiBzx4EaFo1MJkJllr
         rHI60V0Q8WZ14/dGL8lsGgxPoCr2DRYCe63QBZnKHNmhumt37WmHmcgIYDxptRgecdUT
         XXCMIJP4pUCU+8CbLId7kEbUGLeSWnIYAI7sm66q0otWOBpKJBg8mIm4qOuvGOjlAgYk
         gY7jQS/NX5Z8t1cpsT4fb8RkPFUEpXateQqXOmU7zK1kF6Z2Hzcw1xFUXO6eE7KUT3xP
         JWOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g8si1275961wrh.0.2021.10.06.08.48.09
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 08:48:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6FF656D;
	Wed,  6 Oct 2021 08:48:08 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 590FF3F70D;
	Wed,  6 Oct 2021 08:48:06 -0700 (PDT)
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
Subject: [PATCH v3 3/5] arm64: mte: CPU feature detection for Asymm MTE
Date: Wed,  6 Oct 2021 16:47:49 +0100
Message-Id: <20211006154751.4463-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211006154751.4463-1-vincenzo.frascino@arm.com>
References: <20211006154751.4463-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006154751.4463-4-vincenzo.frascino%40arm.com.
