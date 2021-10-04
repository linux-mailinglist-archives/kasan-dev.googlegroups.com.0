Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBM6F5WFAMGQE5L55CEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A33E42185B
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 22:23:15 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id m2-20020a05600c3b0200b0030cd1310631sf292777wms.7
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 13:23:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633378995; cv=pass;
        d=google.com; s=arc-20160816;
        b=ldUt+EhhwQm6+QQXM/M8rmaCxMQG01hZn0sFDR3Ab611qHJPLxGqSRexvteFWM5nhb
         J3UCHSGBSbUGOvImf//Cz0FHND1VmQmFzEafED+fhLELUyfwINK18lDkimivjkrzOsrJ
         fOeyJm8JvRSKb+qJvqRWAiLRTWu4uTNI2oucoXQjU1DJ9l1OX8IzT6oKkR4v8ur3LUeE
         +haG7ushbUrZT0DmGpBgM8tIMoVFKRYbiN3scr9xV7gZDNw1FY+iGFgZrFGuSTHMEYQd
         STBX3bWQpRM6CR5bx3vWiKUtmw7RhTbv0acis7lm3VaF+pWZCX08W9V5Cfa1XTX73c9Y
         jCoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kVqbOlN01O8H8iM6rTWS36iRIkHv7E2YAOY5Jz+lZtI=;
        b=GAuSMrMXkWQRLqNhZ6NHh0GqXP1AwJVmzcfsP4PokDy398IrWXf0oHObXBZAWh+5JM
         xT8fFV/+gKaKAt4lXLIoae2UO1WO9nd9+yuJUuFF2rgp8wH1ILIOX4HVSDbx93EpH5Op
         WamKscbQARDIP8H4dMPqcoFjnaLhcyogHw6nP0sOF/uR5CN5cEM1xvsEIveS/wAutKux
         albDtPQhym64NPaRVrTUS3LQvlw1jPosrforFOkS6WgQvBQXJzM8F80AZ0Zka+I+Lvcn
         2HwQZ9hNtHyiSGgV6fByKdu4I/HOzgfqL1jzWbADu1+a+oAmDM8NnHex04DqnCPWQXXg
         gKPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVqbOlN01O8H8iM6rTWS36iRIkHv7E2YAOY5Jz+lZtI=;
        b=WZaFRWCC8UJBq6zooLSbo1OeWj/vaVgZdALBFCdq1DAF9cUwig4x01nldKxFzunp+R
         qqu/HHN64L2lIrqr8K6nGMI5mcBjb6+Oo7Ii+PygbJd7aL39gp63a1yUHVCVZ0HlTzEO
         nlxr/6zYA/0HAlM1oc8v+zV0ipnKlWenGaEgPUHehJYIfb+Nw7eloZ+AE62mltBm7oPk
         H6Zj/CdHDeFr7vbqk16uZlpE+LW1p/Ir/uT4V2g6y3Q7VyogvI/szrOMo07h3mQqR3uZ
         I/TNuhtvRszbOgddxGgXRUImy5qiQHzb6XcWXqu0V8gvxGzLlCnyCUQ7A2l4tA6EFM3K
         7/mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVqbOlN01O8H8iM6rTWS36iRIkHv7E2YAOY5Jz+lZtI=;
        b=bc9JyiTSe0wrouiKkjNqej7yveSijvV1K+UrswLjEDYsaNIz3SGnX6WcjXIp3+/bbC
         2JYJNgsRRm+KU2nswgeQwTkoYLB+vNCvGmH/gGwV990DBNDQNeqrYgINZDHiINKlTo1n
         cGwwVg7ltec3vtIJNKDP966UGy/EeC/O4dO6PPPAH6RLupgUzl1PDk+vJgN+77V6WApn
         96eKLPgbwu8RJANnNGj6QWIZP4eSrkBcqk7JBhH95KGaCycOIpwSKvnPSMYNb8IVNlfR
         Z+9UJ7lJxmIXy84Bh5fvtNwgWlfeaoCbytDVyVfBnhaglWOKZmna71JLWPkvYvDWssqJ
         XUkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QG3cZ38ESfvqiSKl/gcEizklvUwk+IAbJ5ydsImHt9crVsA/S
	44aNX7lzJNurZZ8Fkk8E9bE=
X-Google-Smtp-Source: ABdhPJzmBpOaGT1UfVAxMg/nn35hNgXwiXCH1zhh1GWfmNYnMqirYZVCWXMWsUKeGgByPEqLMx+5CA==
X-Received: by 2002:a1c:1f06:: with SMTP id f6mr18223110wmf.8.1633378995373;
        Mon, 04 Oct 2021 13:23:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a285:: with SMTP id s5ls267748wra.1.gmail; Mon, 04 Oct
 2021 13:23:14 -0700 (PDT)
X-Received: by 2002:adf:a45e:: with SMTP id e30mr15033762wra.269.1633378994516;
        Mon, 04 Oct 2021 13:23:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633378994; cv=none;
        d=google.com; s=arc-20160816;
        b=TWL05QiHDVAFx7aLu/aJqpUo3fMLJ5/cVeVKkTNUxtgrFGXenOYgGUOWDvt1/tj9Yh
         6W2iywPY8liZcd0fba2tkNciFnKYPgYNFV3VN2Llh7oWWUAyxyUNqkPOmyEdKEw4Zp/t
         jdQYPb4WVHQNRS/Jvr1e4KGOxpryzfYxBqSV0pWyuRpWvqsJk/5e41C7REUhhg1OxPxV
         Bc3H2v447ASDixQ5Y08XA8zdJDzBQAUNjf9kAxRsumwH37zWrlcCRnkxAzNZgF7uZ2kw
         yA5VF7CqzyrJWKOHWajMIrEmJ7nYodncVnLVnSDq+QGLv+kjPa6noE4YEA3bqpL+4erb
         GznQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=05JdBgmGpRmNsIOtv2YBGao+hhN4a3vISq8zcxVsC2U=;
        b=JvOZ18Yg4UbNjGqxZVXYUiqJBFxaLu91Dv7+eGyeP8O4iaQacJPn1VJ/BJwACYo6E9
         faPC+0ZL5JSMFROOjEyvfeP6A+Wwfq9FljWG3rN5EtHEtAJ0EtUSpa4ehef6U59B5FZd
         WkCIBaI3r0BjuCV3uxG7eQ7zZjhHvu+YsGSwVGhOoD3HGKBjx3oFYZLI9AB8CgVG/qAG
         glMvGOpW15aiwHkl4oOp0Zjf+qkXnPez54tMPiZdIjNmsOH86/KXs/hi+rds5km6OMEI
         GO/rDIb8InqE50DGO0VGwmPMGRObyTHpoikS/aXveepgnagE+vSUB1iPmw0WjAicj9gL
         Y3uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s194si430121wme.0.2021.10.04.13.23.14
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 13:23:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CF665ED1;
	Mon,  4 Oct 2021 13:23:13 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E89463F881;
	Mon,  4 Oct 2021 13:23:11 -0700 (PDT)
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
Subject: [PATCH v2 2/5] arm64: mte: Bitfield definitions for Asymm MTE
Date: Mon,  4 Oct 2021 21:22:50 +0100
Message-Id: <20211004202253.27857-3-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211004202253.27857-3-vincenzo.frascino%40arm.com.
