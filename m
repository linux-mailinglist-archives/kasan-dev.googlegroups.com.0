Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPET3P4QKGQESEPRZFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 03C4F244DD7
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:29 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id f74sf3550826wmf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426108; cv=pass;
        d=google.com; s=arc-20160816;
        b=K54p5d5yr/LScz3F9sDxtyeUNzB1fq0AtjuFUS0/Ga2OWVmvauxdcYH13UOwAeqRDN
         XXbb5JbVuBWBeyw49Ys4EiJRJgPbULb2gwxICqLQbJFmN8gOH5NsWN8FvQzKLqBG6f0a
         Ist4wJw+mcPWX6ChNkMAe6zIgXXuB+zhPumq74KP5BRj3M4ONf/D+LmymZtnTWhcnpQD
         Iz5ukzzLYlnusfbx1CqqzJVkKnimffe2iJRVvEY9LpYtSPbrB0OdlpkHaxlxwfFYHPZW
         Nflw23bkoXdmrdyVkFbgNx8TxhZiJ2GF9Ui2Uo1RdnrYxtal4oaFQSViXS0/Jz4A+/ff
         kwKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3zLTVWHQfIxLOo+HxpV90gHuBwfKeZBsJsnYKcmunKk=;
        b=X5NkLEuMBSmLJVbqpJepVVpVb6CXlh8qy1YLyzuADDauGyQkmfy5lqp5cycBdIrOZ9
         qkS22T8lm1VV9/hJR2hFhrKu59fQePBvaH6JN6f/GOta4vmn6mzZqq/eZoSmBh+Jahf9
         GaU7Dttfm/bNWgC7xXT5awjcxM8PuNsuwU6XJ0nP5bvL/ATIErUSOkmjwSpYcPtffAVa
         fS6CTIZwQtGZ+YDU2PXIPrZKKOXfYgk3wFWFnzE494EUSkkaC86RGjPRNzcLX91OEbR0
         nXdP01ovitaie5l1/DVgUadi6LoZg+mgw8w2C6064ww/L7/OMpBPu2dmO3W7HNKIZaZS
         5DBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="K0McFcU/";
       spf=pass (google.com: domain of 3u8k2xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3u8k2XwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zLTVWHQfIxLOo+HxpV90gHuBwfKeZBsJsnYKcmunKk=;
        b=Aj/2MiPG9vGK4sSD7c3q1KA67bhNqIKHBUDaUXfJkFbJ6BJVW6Lh+qioRPznf5yskH
         Bjnv3QYC4NbqhY5TADOyEVHWvXi7huwEOP/9yqPLfKDAVIKhto/fKxULI9lamhXPO5t+
         QkmZslyF9wk6SAbwN3a5QpkAMhVjRpezdnwo8M+k0/3vykVp17keSoeBi+Hkban3iqD2
         OvPynAZpcgbBWqMd+GlYW61/x3qGh06ViNzelbOQtVCK8uj6rHRHvMOBTLuPV61gymgs
         2mVou1zBCVFFdh78DMxHWCAN7nzTJHWqkn+OT1PTCz6dPC2q6Xgb0PC2yS4B6/8wndy0
         UfJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zLTVWHQfIxLOo+HxpV90gHuBwfKeZBsJsnYKcmunKk=;
        b=HJ2wza7v4jg1kNgxqhr1n2J1IAR7pJetGjjvgsePHzoXdhn1qa6QeVrAzx9D5mq2Ll
         Rw8kW9aamn+qq1cw75uCeDOjIwYqDm/PcFlUt21buCWtnJrpmkWX5dX2di8sisudBj6T
         /AoOJ9z9ezx1EUg0poFPHMaVQ44IaT2EldHA2bR8Tg3M6piNTuyUFKxfuv2YEV4u446y
         8MrDB+4z7kbHdJuf0PfR+Cm2pePiQKFg12sXXtB7uwJlmdQhU+dvxcjSA3v5ybxME2Kz
         sL2iwsGlkM3ysUZc2SwORmtQsr0dCWJwFbFkyBxpiI40g/eKwL3ffz6+P5Zl/VbNDkhR
         qw3Q==
X-Gm-Message-State: AOAM531cEkK1vTCoCXmSVoqcddyqSULJZ8VnXObX3EM8/mLSU67C9obV
	g7OLx1C1EPu3bx7akO5/2Zw=
X-Google-Smtp-Source: ABdhPJz8WrFuxRPT2itA5rm0tcK5TmBISQTmcHfSBdLCa6hAQrTOOzA1pOwRbUVHLEbc/RyW+09FKA==
X-Received: by 2002:a5d:46ce:: with SMTP id g14mr3795080wrs.188.1597426108748;
        Fri, 14 Aug 2020 10:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:ed13:: with SMTP id l19ls350740wmh.0.experimental-gmail;
 Fri, 14 Aug 2020 10:28:28 -0700 (PDT)
X-Received: by 2002:a05:600c:290a:: with SMTP id i10mr3606989wmd.175.1597426107940;
        Fri, 14 Aug 2020 10:28:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426107; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/1ztw6ncXpkx9S2BuD3BsHU5YBcmsFL1YoxPXk+CgSH5IPkQaTUxnxBP3FnJDxMFN
         9TEeHF/N0HMzRbcUo6R6npUojfUwum5hBM9R8XvJwFpY6iCoPJRQjlY/NKmSE0jGVChB
         0mgA1hGm8O1DAD+yhJy++yc7x0UHevfdYI0xm91R94hSjdBZp2ManM6Pyqjs/lUes9R6
         OIHn6KybfOVrgY65bqbkWGgrXEDy8uE4C6wemOw3yLAA0MP9YNSxOWgYKxmiuc+wQxtd
         eRaTsG1WfT2YQPlRbFxBLTcQEaxpcP9KqJBksu84bDWxWCGYHgTAjbXISTLd1mtFb77b
         Lteg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=iIfWl4J1G8iITi93NOgHDi/s/4XpKw61QWFW+N1x36I=;
        b=AZtFVXg0obwnZJGgpysenXXJMr9nNPb24yAvGYShYz1gfUkhAjDrCW5jczhOyOjq8j
         JmDM9McHEYeKLAxinMyIIkYwpRmn5kMmSQORXlmoigxT+YSG6OWtAIMX4BXJa3Ashn3W
         2otlt6WaY1zFGkBad3494MmmjruoVW3h63S0yitQloMsTy7B71hDrc2bWkfc0/CRc0qi
         4gIran9UHkX9l48/6YnLXMuI72n7886fir4EGo4BHyyC7ihJRKTPmMWZOSLVgG75W7t0
         gpp4O8v4QyP4d1J5EtIN9NhL2BTiiF3efbdLdt6FIhHxMad/bGHQaR/j08Q9LelvE51K
         jocQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="K0McFcU/";
       spf=pass (google.com: domain of 3u8k2xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3u8k2XwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m3si496533wme.0.2020.08.14.10.28.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3u8k2xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id 5so3572989wrc.17
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:27 -0700 (PDT)
X-Received: by 2002:a1c:8094:: with SMTP id b142mr3616367wmd.59.1597426107618;
 Fri, 14 Aug 2020 10:28:27 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:09 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <4e2dea1d2163dc6f5a3ceb943f485b09cbd252e0.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 27/35] kasan, arm64: align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b="K0McFcU/";       spf=pass
 (google.com: domain of 3u8k2xwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3u8k2XwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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
---
 arch/arm64/include/asm/cache.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index a4d1b5f771f6..b8a0cae38470 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte_asm.h>
 
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e2dea1d2163dc6f5a3ceb943f485b09cbd252e0.1597425745.git.andreyknvl%40google.com.
