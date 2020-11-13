Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSMLXT6QKGQEEF6UXVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id B7FF02B2807
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:42 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id m3sf1010652uak.9
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305801; cv=pass;
        d=google.com; s=arc-20160816;
        b=oLVv7WPQAI2mvXptED8C4czBRIIdCn//rO/4IJPjMegPvFHn4YDVkerfRCR3KimEky
         nLL/t1StsAFl+9MPZk1Kua21GHeSUHTW9h/GJ113uCFnL0gTGVeSO6T7UZBdwK38+f66
         PPpWHXJDq8Sglnov11DopRjJSIQNM1j3RH8mJAIOurLvXmz8cmMFVYXZKKA1b5PlJqnh
         UNFhwA8ZMIMo4QHNtyeVjvpnAOTyQ4y+NrMtq5o74TzE3EEwDD8+1jeKbGa9tZmyJYX2
         6t2WmMR6iEKY3a1/Xnruxtp4ewSZSbGH8yCrkJM4h900nqJIGglXiNNc3o0cfzboPczv
         kOXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8JIWaSVYzI55FTeU2/kz9fTLUgLixcbnk2HQ2Rk8yA4=;
        b=fxiZYbwiW8okLO0TCeyxMmrztyXjppbDEoiP1UXLJR4v+2genjtwlOkD9ZLO7HX0mD
         vrLiYzH5NiUAwgfDcB9/C619QSe4PUjpm3iBINn2CPHuaoDd8av0cEZqNUIp2WcBCw3D
         z9uv7uB+LpjKtVNwvISDJS6Uuq7WSRECMMli11mDSVM7m0noT//XPsIjcYecKUm4Nv8U
         J+UAFqT5mSnNUNUZPPucYhav9rf6LU+xB/K7CGyaBJ7uKc1UWLEFJhApU7xAteztt/6R
         +O7ym0QTTXiazBrHpjMELtDOxG554KPSFm6CqaqcnUsvKk6VL6zNkw3ivhYWg2r1yisa
         e/Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kVmEhB1R;
       spf=pass (google.com: domain of 3yawvxwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3yAWvXwoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8JIWaSVYzI55FTeU2/kz9fTLUgLixcbnk2HQ2Rk8yA4=;
        b=BqDFDaGpCUbOd+YoRfUIiGhFHxFU63hJyEHW7EHEyN3ByjzLiDUu4PYj8DfD0gXziX
         9tuP6b/iOcL9LgOryt6a8kjLzpUYOSsrsGzPONWtJUI60MAyoGBe09Bf7O8ch6XydOzR
         Qncu42pdGWNiiZZA2TpkI299T3rjeYNByMyiAIpuDZ2RAZOvmO+u4u+ip6bG4I4kvlXv
         YUYI1IO/eXn6t7Tr5fppIgKIiUcV0zMAiw8S14AAR1GjbCGxpSf+TImNs4D6HtkNCzgk
         Ar3ALBTIreRjtiRJ3qZX2qy8MEWxz+YBv2vf42BP3CHPfqa8kFuIRuLmIrzDCq0ngbq5
         ru1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8JIWaSVYzI55FTeU2/kz9fTLUgLixcbnk2HQ2Rk8yA4=;
        b=n19IXHo8UxdkjfT0rutJyYpv0DRNuekwxZsKUiEs8bwJf8is6u2qrkq6GksZXR95iS
         YZZz46rSUCoytGyX0rCQl0Xx2yfZIfrH/e9iplonS+RKOi8hpyWsLqmK6aZbAwfhYQ2w
         XZaKx3LPEmBYnLx9wcaSdpBb0qv50VM/nemm8XW5VSSU0irktFO+FmGsGHULv2tRrfX2
         T2CKb/3kmKpmW0fqe1sGRuGRlPzu2fo0Anvhq93JBt2I4xtLcHi6XVg79d9tUaH0rSaY
         x1eYt+onQ8kqKfQjRyS/LIc6uf4pR+Pfz8wwehw1vVFKW+ZjA5izgUaVfgMNWFSUQCNH
         jG6A==
X-Gm-Message-State: AOAM531a779aaQ/0NPe6G6awUoSxcWarwt21ArirsTw8Ur+rpS1lnnPB
	kaXxERM7l/96o3YHjoY83mQ=
X-Google-Smtp-Source: ABdhPJyw1YgGHeIfg4mf4WNpFHYpYc0MFKfP/wYqqJZrBXZW9x+SY0fPd0sZPPfXRloo5CABmsiSwA==
X-Received: by 2002:ab0:654a:: with SMTP id x10mr2987905uap.78.1605305801861;
        Fri, 13 Nov 2020 14:16:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d098:: with SMTP id s24ls1094734vsi.5.gmail; Fri, 13 Nov
 2020 14:16:41 -0800 (PST)
X-Received: by 2002:a67:c41:: with SMTP id 62mr3088548vsm.54.1605305801356;
        Fri, 13 Nov 2020 14:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305801; cv=none;
        d=google.com; s=arc-20160816;
        b=cGFR5VrDxPQLgxujrEJQneNvtqOSDSn6Y0FIH263iNwYypUZWIy3/te32ZEuXu55nX
         guSe69HhWuQrrNRlcmORdtCmGOLSs3mfwrapHU91YvFgT8Aj61HRN0bmNiM0Dr7zOis2
         CLbfZuKj49pPfvgyTAqlGkUMp8ovDsEEsXXl4+S/t4YbN4NnPrEm7iJ+9CyAP1igvsw1
         B7p6U4TK4MxMELJ/djMzshG0t4+eK1UHV5U4qpBxhtFH5BFGC03CnjHysHTRkqQTJrcP
         sXBKpGPWUVPgK+K4dbSkjBO24ITcLcaDkEG7bKApmYLegibmVKMk9p7gKo7KQroekUQA
         VMYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DZs6bFexaQy6yZkAFEYlodVB+nboZ2AhHoU7HLOcEg0=;
        b=z3tKdCxdlwrTlUQcFVjeKydy6b87arijydintn65xoP3rUrG1RIsDi4dcxR40ib92E
         McJ7dc+OuRs31LrJQPdEhhYStF65gwvn3xsNLa+QBF98UO4E0mOU/RBPQ0soocAZ7PWj
         MJEt+C04BR0UfQjVGTdMqzUHfiHrmNmspPAv43mrbXx8GPz2VBjRfO07oqOns7+zg7v0
         efbJuby8XWj1tr6zVqeuwOsFC7gouewzdfdAuoHBAG8OF3UBre96m2Akb+oByVPbLP+L
         eOrlHEqWKB6MRZXolkTXqoUu52F4AVhJCQpr/p6hvmidRv/4w2g7VKsVQnGIApu8EHpZ
         +cjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kVmEhB1R;
       spf=pass (google.com: domain of 3yawvxwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3yAWvXwoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id y17si692722vko.2.2020.11.13.14.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yawvxwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id a1so7039776qvj.3
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:41 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4d84:: with SMTP id
 cv4mr4847839qvb.14.1605305800860; Fri, 13 Nov 2020 14:16:40 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:39 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <7a90eb85cf1f3bedcefa74bbbd73f9b532bcdd46.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 11/42] kasan: don't duplicate config dependencies
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kVmEhB1R;       spf=pass
 (google.com: domain of 3yawvxwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3yAWvXwoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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

Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
those to KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 8 ++------
 1 file changed, 2 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 58dd3b86ef84..c0e9e7874122 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -24,6 +24,8 @@ menuconfig KASAN
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	select CONSTRUCTORS
+	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
@@ -46,10 +48,7 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
 
@@ -70,10 +69,7 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7a90eb85cf1f3bedcefa74bbbd73f9b532bcdd46.1605305705.git.andreyknvl%40google.com.
