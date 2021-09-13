Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB54Q7SEQMGQEA7UO64A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A575408638
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:14:48 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id d10-20020ac24c8a000000b003dce50ea2c4sf2935577lfl.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 01:14:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631520888; cv=pass;
        d=google.com; s=arc-20160816;
        b=AHUeS0jLCKjXWtiATVeasIgd/ptBe/vQN8XANG9CmRMd68jHSNZigajN+25VCjtZx3
         XcbUz2IKkCbT2voGR3N40NpnBjZr1YcJ4Y5z74WKUfrzF72a81xYvCpTGPxiR5hpVDWz
         PsZog5fVfjnLb7McgfyAb33Zq6Xcvb7WT1EL7iy4JBFB1Y5GKcAZFBxAYoE3W2uwQRKq
         epwcs2jd4A9B80WcFPcVuT6ao64Jzym7o+QcNK2Cxtvmwdxm7D5z6gFZWX9z/XosdO4W
         0h9EFvMt3F05e5qha+zBpNb94MvsR1IZTrrfAQUiKhLOlfnQ4YlAf6CKycN2cGMU8lFX
         JzrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ysi08I+W5CseZccb1vSOW4DV+FCkX66PEdHyh02X/gw=;
        b=PCqrBGKAWjj3cuCw295iKczbHkpLBwioPpObF0AX0vQlLF8wIs0wkGCAkzZ/m0o8bq
         nJ/ESu+UB9JswHVDbwshoNTn6agBlwpxMWFlcjgj5Xlnb+bbJ68z/fZW4GN5hoL17Dhc
         iew7HZLuSp5Kq2BQ0lQbC448nICWjQ+xBKkXqABZGK7WyTn5ychsRBZqyiVP97xmSq8i
         DZIkkPVFSno1GOAGfP2ZNKRIlIevX3LeUNbtX5ySJNF6gy/OSgKwXqQWDDOtNKcz6Sdj
         2hlYcclNTwhVaO6pm+UluPGf6pe1VAn3ZHgAMx12x95j6bd6hJ/bJ29dMEwiPmwk1k0J
         5s7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ysi08I+W5CseZccb1vSOW4DV+FCkX66PEdHyh02X/gw=;
        b=B8a8gioHQ9i9w70VF1AL3Y2jlb/wPlEB5kF2fGT2Ig2VfwKpPL/3F+NXCGArbIPiWE
         p6jQSaGTlikCf4P5qK6j2IPBolEHrEMDKXnAC8QIoaKRmR0csvoXR7V1LEUUMrUahQp+
         9VU+yFWGNAEOQnYfTFoQOsfmVTwdLjv3yQKYhrOHGNti2KV+8GRyuCwMzwp4Xv+cqUTo
         WuAnt8rRrsf8vhozYQfHKU0ftPPsgSprDExlYvm9409iaWfhF3SdvivDL1M4u9uoILZv
         2tlRddrGTj3jipHjfPm1c2EgQyDXcHuQ/zmvb3i/C+xmbTu6yH4qjUIffkpJGcI+4m9R
         jVLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ysi08I+W5CseZccb1vSOW4DV+FCkX66PEdHyh02X/gw=;
        b=PDXRwfw0ruhUuC7pp6j5QMiRx+tLZlNiefaOVZBuPNaUnH1YgA1+munTTCT64SPIaX
         HX3UdT8olg+KkCUPL4RekuGh/TeQA3G9ZiW+PIWJ0Go1eJcGCCvm7TdXQVjZmpNFmwB2
         eC9/otgz6HtJ3kPDS/LJ99vJCcK0j/Wloqi9UbbU/FmIIJWd+JKMVTP5tAQYiWzPuV6Z
         KBor49sAgW5XsszMkBLlBiVbAuioAInC2965Jz2/srpZOGuBAeeb7mKQce65IXPm6eJ6
         VIrow0dcSXLYxun1Nm4phy3cV1graocpfpeqjITblNTQ1ipV8yGp68zCtUTr7IqgZQBC
         uYTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JaxuxSTc3kZJ6vq1mhSriNDKAoW7+STUV3Zk4+M1GIc9e3OeI
	T7I8CP59eFE4yvaYFXMjhK0=
X-Google-Smtp-Source: ABdhPJwbq0w6VoCg3+IfS4sGlvhuvGVkY10uQNRApt/f8/AR2twysAC8E9AfTMK7yCSpt1mKH5PwNA==
X-Received: by 2002:a05:6512:4007:: with SMTP id br7mr1826863lfb.512.1631520888031;
        Mon, 13 Sep 2021 01:14:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls908383lfi.2.gmail; Mon, 13 Sep
 2021 01:14:47 -0700 (PDT)
X-Received: by 2002:a05:6512:3b9b:: with SMTP id g27mr8040064lfv.556.1631520887044;
        Mon, 13 Sep 2021 01:14:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631520887; cv=none;
        d=google.com; s=arc-20160816;
        b=Mkmn7dYpIbIVLycjI4VtFTH0Qemnq8kBFr1OCPrxahVgkvKfnjMo3zTiGeQhRZM+iZ
         jC1eLc4QDqCDaX49GmeJ8f2E0Ftg6aQTP8e3Jx1GaClBDWexlg8ZeRr3KQE9HYHrnLgm
         qOehZ9IDomxwoqNyhG0QXY+pMqhXi2OER0NJ3XnUCF7IYIPVRL+C9R5aYfUVknKEOq6V
         +bUBaokBRp3GPp2cXQCBJROA21ic/J/iGpdZYdUpRUcG0CGKBR+QrfgH7mxZVln9L6/m
         lnbaXYyWF3Vb3k8VyxbOST0HI4fvtV6TT7CMrHgG4y93JYEtD4acgNE2VqG17azMKKVX
         m+Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=/8N4m48b79eqa/c3H38qJy26rzOVK0ps08eU0erevGQ=;
        b=D+BzVdmaUxYcrTRgL/KlQi/FBsGU/16TM60xwsxDwqKUoc7SwYRiD57idpJ0FC/1eG
         Bc35vUqkkhPEB2Yoi9mJ9oicevW1Jv4wuTacZxUCA+H+cM3WEI1vYrPkG0JM0omRs0qi
         1wEeRzErhR52Uklc9d+/XOD7LKKov7xwfGGGLWdtyB0v0u5yI8/5SiKXQSpILoG5zUFZ
         PMFPUOzflOu3whZguIo8I+Qg8aDOsFRVR9Ml9G3EjEtCfwXbZCbKKE8styIv/QRkO+6y
         fjXVaZw+g2eSRO7KsagqLWyh8sjolRKKA6L6qT2hMl9Vze13vsy3ju4OPbrc6DmC6V0g
         1Olg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f16si764687ljj.3.2021.09.13.01.14.46
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Sep 2021 01:14:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CD66331B;
	Mon, 13 Sep 2021 01:14:45 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CE3403F5A1;
	Mon, 13 Sep 2021 01:14:43 -0700 (PDT)
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
	Suzuki K Poulose <Suzuki.Poulose@arm.com>
Subject: [PATCH 3/5] arm64: mte: CPU feature detection for Asymm MTE
Date: Mon, 13 Sep 2021 09:14:22 +0100
Message-Id: <20210913081424.48613-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20210913081424.48613-1-vincenzo.frascino@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
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
---
 arch/arm64/kernel/cpufeature.c | 10 ++++++++++
 arch/arm64/tools/cpucaps       |  1 +
 2 files changed, 11 insertions(+)

diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index f8a3067d10c6..a18774071a45 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2317,6 +2317,16 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 		.sign = FTR_UNSIGNED,
 		.cpu_enable = cpu_enable_mte,
 	},
+	{
+		.desc = "Asymmetric Memory Tagging Extension",
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913081424.48613-4-vincenzo.frascino%40arm.com.
