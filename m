Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGGGWT5QKGQEFMWMXJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 354CE277BF2
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:10 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id v5sf408895ilj.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987929; cv=pass;
        d=google.com; s=arc-20160816;
        b=D768XEyR65GU9amcUT1ur+phWyNE2nmXPvn1k6erXjhIYtISHCBmlFdlITibuQ3f06
         qxjEaH1xqKDz5AlgUxrMy2pluqJZqm57GdmIOljAflgayLjrfuXniGg/DlxrIsYkJtZP
         DH3MkvwMmAozbTfw019MdIs1QtSmgIz6KBiCsdXwncLWKPUBRC7VKfoFM9wU67a1LUjc
         hpr/2rcKEqJxE88YGPBg3CtZZYBfcmRJLlxkMuwiCvMdZsoF2xVeEYH7A0SqD2EwtCg4
         pTkls/YofXMIkDt5BK92jMCKaCcu+F1I9SmNhNMcmw4abSkYDwL+YLqzUyLuFFKkaEwf
         ZNHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=mCZ4cNxcZhD+p50DKArgbaXkdeNrEcBvNwVOp7PsDFc=;
        b=uDUScfbQKx+DNpKHoshkMH25KtK1pqNNWfxEoU4XAhN90/YtALQNgZPx9m4V/Ax5Wq
         AUMl+vsY+e7McxqehrREqVWKH6SPtJMeCsf4yBeb6vb2LzDGkZ5QnFiKMg/PbZAifR6S
         brqyF+c3RgHd+RxIOUcVqksi5x1hhIWW3snX4YZ28co9T5Wih7MQCP061li5z6SotTDX
         Xt0k+xMTUJUiWkhVQAFQ01U2utlaZexvoWVqHPQqot1TKFurLmhOzDJWbkkmCUQk3QtN
         rWgmHjOa2HRzF6+pXyxCbCb6GKs1Njc7k4HDXVZaZm73DMWfWXe4ya9SGWy4rn8D+SUy
         Z6mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JeM/b75Y";
       spf=pass (google.com: domain of 3fyntxwokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3FyNtXwoKCRQu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mCZ4cNxcZhD+p50DKArgbaXkdeNrEcBvNwVOp7PsDFc=;
        b=SmjQRhhh3VDSq/QaEGB2JTt6qOiZRusaTuUGEbkOIR1hNrmmkHYU5dx2OFSUPh5L1J
         LXjjZo5xK5Gw+WOxPHI+YlEVq0S3uI56VeTVpBU1hU5FbSlb2C7T8n+dfp+thME3UrYX
         S6IdMdvFKPnOAGrKUjxOs5iN6mEHYlNVZUoyRdn7nKmUXlHKTh8nK+ropDYjQt2z/ofM
         NLpKwmhaPLjwIXpqznVV9xs/NIsHcC+d8G/dgquH6x79sL5q0ZOvSwWSZ1JKJdeCrxsQ
         psEG9HPKv0vKXRcn2RyImlUo+7vCMVondGo9gF8bgmfb4oefAmBTLkEANiF4jCT/xW2l
         qAfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mCZ4cNxcZhD+p50DKArgbaXkdeNrEcBvNwVOp7PsDFc=;
        b=kB1Hg6v/biD0Zz+//VScIttmyHBHnirgl8xt8h3XkAD1516+VrP+vQ/aiHyfGlKAkQ
         etnzd3/prURK74ScC/xcBuuj9CXy4m5Y+ErU6qVW0ogv3g04KnFnbd8E1wR4Dd0dcLyA
         LpeRHMn+NTY4r5qnq00GfcmjXcRmsk1AQBNKn7YJ1KOWnPIyeebgnRQf6oZfKxSLJniq
         rpBBDKi04YSombuGb6nBli4qCWFu4CcO5j2SrstVhESU5xwt/dUNfmHSSiskdWI2qObw
         GlGsgBAw+qRDmW2sk41VzjYQtIlY5K4IcRW25ZQblrHHEr4RjYNGPkRrUUDTR0I6djzv
         4//w==
X-Gm-Message-State: AOAM5325xjR5aBGdBsXc1SsUtSxJabKHXflzZHknDEsfd5jjP7XP/cGZ
	REtPZjRWdH7HLGWtlIXJ4fw=
X-Google-Smtp-Source: ABdhPJyMip1pkkzvmPH6O+D/2U8jR8pz4Ph/FwAx7eK9GactKU4sj7MIYs8CY6i2ujzwVlKjaezW0g==
X-Received: by 2002:a05:6638:c6:: with SMTP id w6mr895678jao.143.1600987928789;
        Thu, 24 Sep 2020 15:52:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c805:: with SMTP id v5ls200682iln.1.gmail; Thu, 24 Sep
 2020 15:52:08 -0700 (PDT)
X-Received: by 2002:a05:6e02:f87:: with SMTP id v7mr808170ilo.212.1600987928430;
        Thu, 24 Sep 2020 15:52:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987928; cv=none;
        d=google.com; s=arc-20160816;
        b=C3CWGQRW0KILbs3QymKFv+VTSWe0EZG5rHHLmUPeLEu/yV3nlFDWSH2LkoMzbZL7bJ
         4FiLx5shz7YO/6sRsw1mzmRTzLO6YHHxPKUIn3z53CTYaLFckXzUDOKBbpX847xiWm0O
         k9h0/tkMGKwbNNRPIYlNYyvgYqB4R82+HsuaD3Fvj4NJuakfhfnonAweV3/6o2vC0x2U
         6JbqTSF6UtA6UUxyF3EMlgNvtEpwwRyZVAndaWqwi63CC4ngLmkFGeSNehDtwzsGUu+G
         imYs3uCO9WDSzcQh66aLhf9lNiR919ziGvyCw3jnOqu7IxDamBOrd2jUb9KuaYy5qn7L
         GPQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=wHymNihP2cmvV3L+Sm6JVmAu1rhIBofqol5fTdU44eg=;
        b=ISnb0sfc3saf4vkvFJaLRNpbob/oB5rTHCcP9vKt//bvhrUE29h6fms9r8M0VRBo9p
         3J/oGzxvWtCfOzUrH5tl6IUC0rsIS9tCzvp9ZF4ainF0h7Hu72uqSzl20+6nucgQWWEt
         FJnFBlkVwCEXBycalfneIGAH3/xkabYjZKt6yoyVVNhkIomkOxc7+YA4U9mxeohXfe3c
         ZxbPVc/Q07Ivh/gRDVaX8+CjgIqqVkpUFj73Whbd8+rRH6QaqtRPJIbJgJgpC1kG0gmS
         CLfyqnfTGVZbi2/8nQbHhK8nqXUn4F0ckuj3RHSRyrbz+umi3KiHoYrT7xOySmv8ds2X
         dBvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JeM/b75Y";
       spf=pass (google.com: domain of 3fyntxwokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3FyNtXwoKCRQu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id c10si29485iow.3.2020.09.24.15.52.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fyntxwokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id q131so666388qke.22
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:08 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a203:: with SMTP id
 f3mr1482755qva.33.1600987927725; Thu, 24 Sep 2020 15:52:07 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:38 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <42a4409413858c47677134b55c49d447bf9a8e87.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 31/39] arm64: kasan: Align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b="JeM/b75Y";       spf=pass
 (google.com: domain of 3fyntxwokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3FyNtXwoKCRQu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
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
index a4d1b5f771f6..151808f1f443 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-kasan.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -50,6 +51,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
 #endif
 
 #ifndef __ASSEMBLY__
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42a4409413858c47677134b55c49d447bf9a8e87.1600987622.git.andreyknvl%40google.com.
