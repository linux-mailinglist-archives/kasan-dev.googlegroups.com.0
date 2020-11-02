Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIO4QD6QKGQEKU5YQSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 687042A2EFE
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:50 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id s185sf5995754lja.5
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333090; cv=pass;
        d=google.com; s=arc-20160816;
        b=QfKfU5pPZtX9k2RtDtDzo9zFmaVIqNrMTlC8FsvTKcNwHLrxVMpDcyMXl1dMaD4LEr
         D7f0+bNCRcKjf3wiL33nyKGyJ1el1G+Qx+5UTD8SmauRkBAaZRSyp/QRoFxqHhkip8Sb
         rcRqmAEfGw1NyMgPjbyd61jOMSdBX8h5S2wSbPA9fbIlTn7AsJD/E0uyO6qzVzfiZziw
         PjQoR6CEo70wGCxTl1RFWdoQtPc35PGd4Ko3XUzvjMyyjrNlhUDM/tDs+T60zraMUyp1
         yMOc1d3i41FSFRbBlIfLCd3YA8ASuNWHjepefWiLqJnSJr63ik+BhI+ps4S7Zz+rFS3N
         24Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8dd7JYBLMo4iMbKm4bHkQxIrFiSy3v0SBChNQgB023g=;
        b=pwWh0mlQvZl7wgaz7Fkk08obHWAKnuwXJqev1uz1li1RFb/qqLKA2W/S1iZi6Ih5yW
         9A4y28scgTL2JuEAcTIF/LCT/jr4OVPKd3cPQbZRewgTQIixUeI+dkLf70E6p2hnFLSm
         nZ/VZ1IWaMPZbK0c5k8G9TOdbjHgi3lg1/un30tjI8cmuDSAGWQZ76rHQt7k7fWaBQ3y
         REV1/R7Kqt/Px1SMztQZojSmkBqzyLpQou8ZViQ0b1sBia0F+dHisbW82ftjMHPb3ma7
         JZXcCr2nlVZfeRHesRwMdU0fRwYdt0UAKIRFDU207GZ38nGOBLth28Mef/vCWOUb+dbs
         97bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pVFQxBGu;
       spf=pass (google.com: domain of 3ic6gxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3IC6gXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8dd7JYBLMo4iMbKm4bHkQxIrFiSy3v0SBChNQgB023g=;
        b=Gs9Cj1l32/TxhjS4Z5BYe2XLFSXUJqYIpjixKE5Z11wTw9dalsX9LYrWTMFEnAF89g
         sPAYhCwh9Vgni28YwMRTnK7eCWClj+VaIfURRJorjG4xssIOC3jxErDquwftGFiHPXjA
         AOKatHa1OidZIdicyaxGq9uptGk/bhGOfzSrnVrqv3KmXzssbQICujmRhheK6YqnKUqf
         JcZeV7OHcbexIErnhFdc5gg/LnUCL9H5DoVoiOfyTSWM2p6lQPvDQkXjlVe86rkv3VQE
         pcamv0iUPG9Fu1UAFNJzIcYGa+twPuLNYvntgsUW+nwjhYKzQflgu8WOICQnPV3UZaXj
         1bYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8dd7JYBLMo4iMbKm4bHkQxIrFiSy3v0SBChNQgB023g=;
        b=ApUOxZbrL5u2uae1O2QB3BDO6rNLpkWQ6LPi8x7Gp4WCjl+7LSd3IWQKT+XTcueh6Y
         7bNnQxG4m/gTB83Ig+NLipAGBMzihCrbdZZyY2cm65D3SFY3i5G4mCOCH3t5vlt3oFcl
         DGKVzPUPkQbgCAyIq3Wi8MoIXw9PG86cEe+/WjXwz6FbTP+7a08CWoTSLYv2+gioKN84
         NKC7QBbA2Sl5m+CmAGpv7W9VkqPIyvQe7Jho9zaQshJOro5W6fwFzeKFq36eS/CyaKK4
         7IhEEVie5P3TLFMFNAChtlusI2/PwCzaS+Z66bIKHH009uSIhNg2AHj/P330aQ0sm/KU
         nCRg==
X-Gm-Message-State: AOAM533Yn0gr8jtsNAaXFbo0qEaw9+wPYKRcX7xjg11T9rb3B699Nhrc
	mDDrAdSFevIrn/XdKSgdQbc=
X-Google-Smtp-Source: ABdhPJyWIJsQ3uFvnoXwrctHkPhydgKHAcFD4xwfvVBoVmY2vUbDV3Yt+8P4TaU7102GWKcDM9L+Qg==
X-Received: by 2002:a19:888a:: with SMTP id k132mr5714754lfd.239.1604333089970;
        Mon, 02 Nov 2020 08:04:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls1377074lfd.3.gmail; Mon, 02
 Nov 2020 08:04:49 -0800 (PST)
X-Received: by 2002:ac2:4f03:: with SMTP id k3mr6677876lfr.271.1604333088946;
        Mon, 02 Nov 2020 08:04:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333088; cv=none;
        d=google.com; s=arc-20160816;
        b=sA4oP7Qa9fvaRgTEWTDZkrtS+DEZL2SOFppfEjxFeGWAKo5kNIqg0QHJzt29kyuMpQ
         jv2UdoBY0hSmz+2q23Qpj2DQKw0lj9RZtDhB1wfy0hNA3ocLAUwhGmk+5xqd3lQZyFL6
         l6b5jZYvMZ4p30cZ42kM8+3dQMqyd25iaRZ8XZcl7C8kc3oB76weXQ+ccXrL4D0qnqcO
         E5jFAXN1H0xhhKX//FdSHjUdf1pnp5PXHfg38dUlAtP4DI864ycyUqg52rowVFCh5Lbk
         IxCmQ48Mt4HXotTtRkT0GsqEduxhEWV9+outOuqWIhfzOr6nedWpVJB5wVMixguOmEmG
         i73w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=G92npUQrDAzWi0FLCRrGsDUgO/xYzB+b9yo7BatUrLQ=;
        b=Oxf4wCnzourykSH5IdNiqqm/TfScx4c25XH23GMJsqfhd4wh4Q1cprnjYKb8ORkQx9
         OpW25AU8AOgWSSHoG73p+f3GmBjAk5BW2YrXcl0dkJUb/z55AsK1LKjtCs3bNsyNyWmE
         2n2RzePM7nl+V7CHErzpIZ63YRU1pVcqpWNvfT0Q82kfg/zxYCqKB5pnOx7pW95tPb2u
         VmpzN9C0VoXO5Ci18VBeGuz+qOeGrAssoB0hfoS2SNWLs5cT4ZolXum0xwe3u3OWfb/w
         CuQFv21vuTYxDNlhAI8I9v2x6ALDtNB9QaTLa7YNqSWf/s0h8S6ej9x8qECi2kWtjZsM
         Z0ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pVFQxBGu;
       spf=pass (google.com: domain of 3ic6gxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3IC6gXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id k63si358163lfd.0.2020.11.02.08.04.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ic6gxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id b17so4433091ejb.20
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:48 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:ff02:: with SMTP id
 a2mr16764112edu.364.1604333088410; Mon, 02 Nov 2020 08:04:48 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:49 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <5d790812e7b0e8fd6747b0f2cb38de52c686de32.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 09/41] arm64: kasan: Align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=pVFQxBGu;       spf=pass
 (google.com: domain of 3ic6gxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3IC6gXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN uses the memory tagging approach, which requires
all allocations to be aligned to the memory granule size. Align the
allocations to MTE_GRANULE_SIZE via ARCH_SLAB_MINALIGN when
CONFIG_KASAN_HW_TAGS is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I51ebd3f9645e6330e5a92973bf7c86b62d632c2b
---
 arch/arm64/include/asm/cache.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index 63d43b5f82f6..77cbbe3625f2 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-kasan.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -51,6 +52,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
 #endif
 
 #ifndef __ASSEMBLY__
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5d790812e7b0e8fd6747b0f2cb38de52c686de32.1604333009.git.andreyknvl%40google.com.
