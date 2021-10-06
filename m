Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBN4K66FAMGQEP23GNUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D5AD24241C2
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 17:48:07 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id e12-20020a056000178c00b001606927de88sf2400642wrg.10
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 08:48:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633535287; cv=pass;
        d=google.com; s=arc-20160816;
        b=pzbKHylJV3RjZzvgMcvAzP5RasYz7HA+bNgZy37K5MMa038gAf8tbmMPK22BehJpwE
         3Dp0maXuM7EvJBclnkS9Zqptm48y7QARZQ/By0ktIdhz3JLRSTckxYaAqHzbIpLX4d0B
         szmnIDOCE0ozn9OCwNna1nDLrJrYlUf/Cu22+FsaC4R2m0a4BIFAzjLyqNZUBv4hgI26
         Y+oRdkJbdWcw0tY4kJUSfnLHKzLZ04I2x87SXSXbCAEj9AAdIjmFnJ5gzbgQiJsT20HY
         nyet3kEp6Xndoi0M/qdDeYUOywDyJLjJIsObuAWP5Q4e3pELAF6P27U3tKZJzdtfa6u2
         7ytQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rIxqBhFZIq3balO63bzTNY4RZs3FiwUAdAEZXnQlICM=;
        b=frwmzYbC7uE7hjq7rcZCkRrEQnTq+x+EY3i2KSFrsePKIbPKmOgDcGB3xb1lKIE8G5
         h0/sPBDqsVqj6C2XQITikCUdyzZuPF+ba3Y1VHc9boEttGkl+hrklNndE3/euLuZdXzk
         MQ1tYbVEY1hl/FDo+t4Srqt34b0Itp+cc9eH8hijde0IJEsGvz6LJp29kGXsXtq9pnuA
         QN0tkIQn6nTvuyLvquriqf+ZLhVYmbj/NgljMRGl6Xx0QEHUZnTb6GXh4UeXmUh9czNm
         WZabWP35mt8ASipyBSLfuJZ2b0Yp2jyawWDRA5tfsr0a88VQnYeJC2HJAX+assawiA17
         WA+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rIxqBhFZIq3balO63bzTNY4RZs3FiwUAdAEZXnQlICM=;
        b=d2BMexPb32K4Ebl0qvI4acmeWSYCgPywz9c2TFjh+6R8bd+lu0xjCenDrQqQjczXgd
         47z69wkfAAvC3ZOkORGUA3R8c6B4PW/3hOeug1oVvVOnvZT+iRwdzHM1kVwAEnZWSzFF
         pLbGax9ElkV19vGvtJJ8Fvnf/FynV6ToNUbZ37bwfMhVe8z0Bp9kfm0HSJ+3b/sEhpkS
         Rl52LWX5mzKa3dLUsBnZJE0De00J6n3Q1iybjGxYaCcitu9EMa3Hd4cJI6uAd8HsnA6v
         grZufXnE92w5nADEq3c0dLfAWjdOeRB5W2QI7R+F/8gV+EGD+2B+2I7XBqGoeNsIlGdn
         NfVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rIxqBhFZIq3balO63bzTNY4RZs3FiwUAdAEZXnQlICM=;
        b=NTDDMpRM1cVkpQurR4K6NtR1KodN80YdJqnXQaRNoBdOa/GwkjOb6xeATVQ4IPkWyp
         VUwNebGPpYbvpE00saTE8X0afs6OJC1ztDC8Ne9sD38yTUCqh1V+MYZUHPnT/Ol8ubM/
         fM18O4i9MQ2dz9GvYh9jsXzF2EUAHFVWeNI9QqTlAWp0u56gfW55mGagevGxDygIRr0m
         2SSV5V0y8+7QvV12VUmii6dpi9rkExC63QNVQpJ1byTT7gT68v573Syl+E2PTYuKV6JM
         tdLHhxPoFvP2CnYGeI/sBzb9yH3zaiT0GY35hIi0/uBGe3xBDfCHVgKqlm5bLO6wAIGE
         Ggvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+P3sOipIoOCuhpMc9fslAyA13I6l9rCK+tI31APKcot8xsMv6
	M1w/8x8hbDidSG0UWGdmAR8=
X-Google-Smtp-Source: ABdhPJxOthEcj5SM7mpZx9az2jJBEutgoQEEBoEZQSB1ctWPebAVaCcjSIPG1ulmnZkZ783Mfm0n7g==
X-Received: by 2002:a1c:9892:: with SMTP id a140mr3249983wme.187.1633535287620;
        Wed, 06 Oct 2021 08:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ef50:: with SMTP id c16ls696099wrp.3.gmail; Wed, 06 Oct
 2021 08:48:06 -0700 (PDT)
X-Received: by 2002:adf:8bd2:: with SMTP id w18mr29809982wra.432.1633535286871;
        Wed, 06 Oct 2021 08:48:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633535286; cv=none;
        d=google.com; s=arc-20160816;
        b=URjaR61PQR/hk9FYZJEvdloR5RgRvMBHHp1k42OsUdLRPBMPcrfuoW/OtltZ4JUVjg
         2/U1IzmVq3+W9ekIioZcrMC0bufReiSYjGnfJ8sV/+XKRygat5w/P4Fdv2u3kEUy9kEv
         1N1L0chjmfDStVJ36HyUwRvAKR00pFzBhNj8aDoCa9WAlrw5P7h4lRhyBswOKym+h7R0
         2vVw6unUZVbMhjBgmF96EcLrB3Xu5FeZm5YQR5kmsORaqXSnAZMqpj0OydloVdw5jvVn
         cwjBBXb+WSJSWItZSs3PbECMd8t6fBYUG6OdBGj1Qe5BNDVUKIn0AZ2FFzZ2dv3THiFW
         WSkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=05JdBgmGpRmNsIOtv2YBGao+hhN4a3vISq8zcxVsC2U=;
        b=oWnyGjIGnp0VtF+o+CqIkl/byYSQR5ngZLvxdDbtJGuVagFfg/vFetE2u+RZXANtGr
         vfjdsBrEJohetuNQu0M2LEk9GBPurv9wD0ESLgKBc/Z0KcB3caTu4AaBLzJH33jbDxHm
         RKGRP7sPNIP4J7oDgQjD9DfH7tJZ6dtn+SzM8wGFkHSuLiNf6Go/OAWmTMTQrk9GRt+E
         0v9J5rQJm6ehpECatDzCdPt6PHS/+visRn74rzz837a4RgoTQp/lYhF1lmlORGP+/oZM
         3CmjSRvVhPhVvXpyaQ9zVWWfsShFYKmKm1sWwPXBMHof3frc76Cf4IxhFW2xLLHKxB+A
         0Gwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p3si1087326wrg.2.2021.10.06.08.48.06
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 08:48:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 23CAF113E;
	Wed,  6 Oct 2021 08:48:06 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 42F743F70D;
	Wed,  6 Oct 2021 08:48:04 -0700 (PDT)
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
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v3 2/5] arm64: mte: Bitfield definitions for Asymm MTE
Date: Wed,  6 Oct 2021 16:47:48 +0100
Message-Id: <20211006154751.4463-3-vincenzo.frascino@arm.com>
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

Add Asymmetric Memory Tagging Extension bitfield definitions.

Cc: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
 arch/arm64/include/asm/sysreg.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/arm64/include/asm/sysreg.h b/arch/arm64/include/asm/sysreg.h
index b268082d67ed..f51d5912b41c 100644
--- a/arch/arm64/include/asm/sysreg.h
+++ b/arch/arm64/include/asm/sysreg.h
@@ -621,6 +621,7 @@
 #define SCTLR_ELx_TCF_NONE	(UL(0x0) << SCTLR_ELx_TCF_SHIFT)
 #define SCTLR_ELx_TCF_SYNC	(UL(0x1) << SCTLR_ELx_TCF_SHIFT)
 #define SCTLR_ELx_TCF_ASYNC	(UL(0x2) << SCTLR_ELx_TCF_SHIFT)
+#define SCTLR_ELx_TCF_ASYMM	(UL(0x3) << SCTLR_ELx_TCF_SHIFT)
 #define SCTLR_ELx_TCF_MASK	(UL(0x3) << SCTLR_ELx_TCF_SHIFT)
 
 #define SCTLR_ELx_ENIA_SHIFT	31
@@ -666,6 +667,7 @@
 #define SCTLR_EL1_TCF0_NONE	(UL(0x0) << SCTLR_EL1_TCF0_SHIFT)
 #define SCTLR_EL1_TCF0_SYNC	(UL(0x1) << SCTLR_EL1_TCF0_SHIFT)
 #define SCTLR_EL1_TCF0_ASYNC	(UL(0x2) << SCTLR_EL1_TCF0_SHIFT)
+#define SCTLR_EL1_TCF0_ASYMM	(UL(0x3) << SCTLR_EL1_TCF0_SHIFT)
 #define SCTLR_EL1_TCF0_MASK	(UL(0x3) << SCTLR_EL1_TCF0_SHIFT)
 
 #define SCTLR_EL1_BT1		(BIT(36))
@@ -807,6 +809,7 @@
 #define ID_AA64PFR1_MTE_NI		0x0
 #define ID_AA64PFR1_MTE_EL0		0x1
 #define ID_AA64PFR1_MTE			0x2
+#define ID_AA64PFR1_MTE_ASYMM		0x3
 
 /* id_aa64zfr0 */
 #define ID_AA64ZFR0_F64MM_SHIFT		56
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006154751.4463-3-vincenzo.frascino%40arm.com.
