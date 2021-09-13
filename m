Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5MQ7SEQMGQE2LJLODI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 70612408634
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:14:45 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id a144-20020a1c7f96000000b002fee1aceb6dsf4587085wmd.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 01:14:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631520885; cv=pass;
        d=google.com; s=arc-20160816;
        b=jwCHaf8y+lKRMTdYUdYltQP7wDqorC1weEEKQ1kHwX4lY4acLHJahTlX+J9SyuRX3T
         xICBJDMFl7paopfbNg4svGLFCDsuPPl4MjfmzdM058Z0JtOU1Ov/dzXFIQ3QkG2pxDyh
         /V4XbX6IxeUZjrgxvAyeQg4mlGM0n4PBOoYZhORyBQeCpzWeosyKmhcW7ma5+Dq3obWQ
         h3jcAGLV4dinK1wx+enYw0XLnPLmk+r31/EnninkXprNhxZHk6q/TnWENGBhFguOaoTv
         C4XhTiwaQOXVlL02t+Hf43rDfmfPCqWcXm5TCnsFLElB76CMLLvMomQXQXpVtSIgSDmr
         AnuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Pt1Mt07ccPKvLjTt1c5UFddgMZrQMKFX+vbh7ktgLy4=;
        b=lstBJwqQoZbbTbfcVyO6oq6MxB+sQV1IDvvSm9GajU7+wp/cj6XRBJ8wYPndFDtSSn
         cZpmqa7N23nigdOq48Nt4c4YCdIglzyoGuaZOJZrPKAvBNkbvrEzF0watmOf1N0tciPE
         XESHE5YFHU0ziAukeXYE+A4v8WUmIlKrbuPYmX+eYVKr0G5IWBb5uNsyQpbJmyW0Zqie
         Helg+L4Z7F9pIAsYxuRGB2pYgk4mkC/tgVqF4oE5EsCHbjMh6dz3rbxkr0Kvvwyq9xHY
         xP7rf8F7Pms2+QKkcNWhLLwj4KnrXjrGQAbvWiQS9mvR8KQrkb3WdWI+TnP4mbi8Ttgg
         MSAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pt1Mt07ccPKvLjTt1c5UFddgMZrQMKFX+vbh7ktgLy4=;
        b=esEWMsk/uab78y6v0YkRbIFMRKB/f1l6Z9j+raShh+SX4ykli2z5T0+eMcYHmRgtTz
         U2i8b9nw3IHBCcITT6z/gB0PLe1dvKfNnWkTtZSNaSn4KDEeawjzC0MJuqAgn+kdp8xp
         v4Y5J8OxOWKQUnjzC5yLfwF4Gu0dUu7Mb11FZ2+i3WFeE8bcLjhaRJwUeh0mEmAn8dHb
         V1nnMDGxZLmIZFm7LnzPXqfDahRZpwQaK0POhnM+ZMJKnzovCsUc8KRrxlfyO0bSjnKf
         yFqoTyWeA6J8cHbbk79xfXj1NtCpYuUFmDLWz0FCTmunxIDS1S170PiNmt8AIBU904Te
         xFKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pt1Mt07ccPKvLjTt1c5UFddgMZrQMKFX+vbh7ktgLy4=;
        b=N82n5DHAeP+ZMLmBs8SZpvaucaLOYX+XJ2wr+SozZE5br3QcTLmVU418uXXuj/Tine
         S58nyIGsW21ZAWTF4pM/Ok6BoLFrIqg7ATelST33KIHfFy8w9VUd2Bz/IQ5Gq8HXvbuH
         nDYwvkHumdG8VvCAuHYumU/ZNzv9vxet1cwPo6Pw/UF00lYQ4j91vWeoFOoA9fawrw4m
         8GjToYergOJxwAWxMCdEh+j7wzPX4j2uWYivuWbPgSvHpEGW0Z9DDxYHwYUdotrSPset
         1W4NfKGImbQAiinVjZ5F/hnwYxpCYzSTQ+Im7cRkVQA9NQFRKaVTAErzVC37cPzTeYbl
         c8FQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fctp2LBnVXyhFCsTBp3mGttSdozmi+Rs28ENtxVQA16k5awb0
	JPwUJ6Oj7sVCO3mTiLlLTSo=
X-Google-Smtp-Source: ABdhPJzNywqkwoybpoqHLRPolmiwrnWBPdHUoDyLSkM8D2ag45Bc5MUnbgZRrSm3Ne2YZjtrqVNm/Q==
X-Received: by 2002:adf:b781:: with SMTP id s1mr11153331wre.165.1631520885170;
        Mon, 13 Sep 2021 01:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:190d:: with SMTP id j13ls2516803wmq.0.canary-gmail;
 Mon, 13 Sep 2021 01:14:44 -0700 (PDT)
X-Received: by 2002:a05:600c:3b26:: with SMTP id m38mr9674984wms.155.1631520884361;
        Mon, 13 Sep 2021 01:14:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631520884; cv=none;
        d=google.com; s=arc-20160816;
        b=uoaCvP92Yu7t2SqND+rWClRPNXRzXrA12iRGp46U+GY/bR9ASb0vqYtUpKn+UCcckN
         Hf8sqV7JC6BQsgEq2ErbaGcmkbWC0vvuuZh1sczTxbz4PF18Nz7i67zew2hKsqgxT9fX
         77+VGQNxjhD9IkdIxCcNWdjm3Y0jdqeZeCzKtCQWRcW7qlvSfool0s8gluTBIuXt+q89
         s3T9vvN1uxLrUOMT/A8oR4bVR/6FC6lrOltupSkP1jDjzscmFZzOS3FoHGoNe7h3irXt
         GXv1Lahaa3VeAgY6Asdpzw90M+vVlZuqXs0BQdwM5wo/hI4+UcC3nxWAIFaveooRS4Ze
         SehA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=bXuAjQsANtIua+f36xileHMhp6brDw2VM250bg3oEzA=;
        b=AxmBwM2vR0JEc28EpJIFIIReC4h69Oj2cGx+yUiD+Hp3H0xWEXgZX4mgzsOlKrDxqu
         LceXXxGYLS/kabCTtwT0N0gos06NZYDU2kcGRwoHneELCjLhBDG4I8Xm1Hw+o2B5fPYI
         h4D4LKbrL5D/sDfeA92vH544Om9Gjp8SdZ62KclnGiOGKwZ9TypPoaLVt9R+eDUA1DbB
         zrca7yO87x8JOtB5IRDwgXA08gVvIPwsKii3lQLSHhofM7yfAdbwtpSRqeGOAWR61weg
         r2TOXEJ7tPC+BUq1fzL2Bobb5wiTSLIMfSZTFt7usIpP+cFOTJm42y+tCZ/kn+9RNvsP
         /SJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b126si736615wmd.2.2021.09.13.01.14.44
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Sep 2021 01:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 97D0B1042;
	Mon, 13 Sep 2021 01:14:43 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B355C3F5A1;
	Mon, 13 Sep 2021 01:14:41 -0700 (PDT)
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
Subject: [PATCH 2/5] arm64: mte: Bitfield definitions for Asymm MTE
Date: Mon, 13 Sep 2021 09:14:21 +0100
Message-Id: <20210913081424.48613-3-vincenzo.frascino@arm.com>
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

Add Asymmetric Memory Tagging Extension bitfield definitions.

Cc: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913081424.48613-3-vincenzo.frascino%40arm.com.
