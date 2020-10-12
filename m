Return-Path: <kasan-dev+bncBDX4HWEMTEBRBW4ASP6AKGQEUH4C2UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id F14CC28C2ED
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:16 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id p13sf5324734ilg.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535515; cv=pass;
        d=google.com; s=arc-20160816;
        b=dag1tMnKx/HwUB9S15tTWV/PTmTsAgl+re9Ly/kffJP6ebCcaR19a+Mt0WBFQkqUGI
         TlMMGabAwgQiuwr2qFrohA8HCpYJ4rqCFivavgazgkCPns3sjtf2B3CVRxnl+UQPl1o0
         z6GHt22ENqFLUthNF+eaywDFDxKzN8X6vM4rbs6y3+KiIe/vNtD1yb5nySBjnwP1Z5vI
         mJkcWYORRH06nY/jMICQfSPTNDCGTvvWpmyw3uyXLeLXoxlA6QV3y3dwxApWbZqB9Ynk
         lmyjy/sPMlX2SAjF08vSDjpe7WPzn4Y0lkNq61fhDiN0VGX5uQzMPJD4Px3W7VPll8LG
         vvgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FtOv7PiopsMg1kZQH2y0nafi8bIphHsSe89ybhj9qBY=;
        b=AUxgRd6xWYSQLOe1ivfn+/ZQiDBYf4m4ey3vITH+XkSxrpWzCj4yhmA3UeKd7rDBbA
         IYyu1ZelBiDfwlAguqg4wQ6BLZs4UvEmp/zvaMVtpn4m5i5ZLc5R+IeWMcs4eLHwRzh4
         KK/OFeaHeDBnyvcpJiE42EekUHcAwHkpCbLAjWJXTN54/yxgMpzwnIO++EFGLJGTRvSY
         isTz6hgA8SWYVPEnv/IjkD9LF5HHlHt/2HkjFGij3w01/fGNOisUYk7u+Dj1lyihoXgj
         DqrS2ETrp/wDSlzD4NYD4BYyDwRfZrw/eFhueUMOYMhtur0yKuAqINIdZUZDyjJeBiq/
         djng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uvBp3SV/";
       spf=pass (google.com: domain of 3wscexwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WsCEXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FtOv7PiopsMg1kZQH2y0nafi8bIphHsSe89ybhj9qBY=;
        b=reRtlYy4AYss1w2DYfZIFjPy0gmdpNv8/SrGCyg7xFHTWd4GE8II5MKdbe7+tzRzmU
         TPXG/UGtRslYMjLzXS1dIhRpDMy9IW+rhBp1OSLXNVu4XzHyflIunSk2E9ReIbgdOrXS
         8K+B6qGd2va2NH6oMoV2qFIWPrsFyLXITFBSGAirzoJoeUrhWHfBusPsb7bBndMVm6xv
         ZPeQj11q82HSE1b9PmaHXbFp9s/HZPrPZUuH/3gq36CMIf448VboVVMB3pK5HPwCd2ou
         cXIIwbKL4GUHOzhS7r5kZy9ZVpHeBTXVL6qv2X85yvRI97sE9fG38+WlSNodPQ4SqheN
         YLCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FtOv7PiopsMg1kZQH2y0nafi8bIphHsSe89ybhj9qBY=;
        b=uoWs1SqbewTOnscdAkIGPiXbG7Hpr31rhDe7sJ2I0tAzE1zjejv9axhl4NyIK1G/vA
         /QNp7j9DEnQ5/ll6z2yxfjPdZ0MVak6f5VtrprOvsk4vXnf7kBwAML/kA+C9sc/F1N8d
         v9DTLBf12ZC6BYgJLcQkYx5f9j6ls749q6OhyhGTrYRixB2kOAiB5j+YB1DOY5CkIU3G
         oM/9AweirQtyjVUzIBnQ9SqX4O4lxxipc2BxX5Ih7TJdGS8qhR8eey/VUnUCe6MiBB75
         D8/nYNAF29Nmmci+Q3cpspyQJBjzB2u7FLVlkVnvV5OEbBEgWzDxUJ+kHX4KFsRX4n9G
         n2Fg==
X-Gm-Message-State: AOAM5338qAfMu28u0ADqZMtWQpH38g10jQ+sK2fQZ8GSeXGexIXBd9EB
	ZL4E9E7QDFfDanh0OmbepyI=
X-Google-Smtp-Source: ABdhPJwsdexvPt7mG3muUkuEhVEuVBLXAqOiB4kA1cFMWwvbPpadNQ+pYTJBtIKzYJ7UCn5HX6PegA==
X-Received: by 2002:a05:6e02:10c3:: with SMTP id s3mr512153ilj.103.1602535515660;
        Mon, 12 Oct 2020 13:45:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:cba:: with SMTP id x26ls1761342jad.2.gmail; Mon, 12
 Oct 2020 13:45:15 -0700 (PDT)
X-Received: by 2002:a02:7fc7:: with SMTP id r190mr20989473jac.13.1602535515080;
        Mon, 12 Oct 2020 13:45:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535515; cv=none;
        d=google.com; s=arc-20160816;
        b=mNyW9NiOerH+70G61/ktoSfDUQEwCxluGqNVr2GrJzAqB43o4jHWtqBIzwcaRWlvSV
         HppRkVY5F3n1KEcIThNdLep78hOYIJXAPYSCbNEMT9g+u2/4qbQSwumA7PEZV/Y8Rqul
         fCdDyi5d4XBLJH9ZVNTImhNd7m6FEwa8YOTM0Oq6+dypLlKnqW0EbFlyOy44w2USQyJq
         fYloLvCMqXcXWgoGMo2dlbqmMgF0JpE3aPsru8p/oC/YC5u7VFLmngmy1h8+00VkIaWM
         MXgLdioh+MBn/5XtF3iQSE6epbsZUhJ64Aq0SaVJp29BqFdVETs7kRezmzWoz44CSClu
         LzBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=FuufsF1x9ec4dgxq8sKlKc4MR/gScIEfRdtwwlGog8A=;
        b=OiMOYqbY99/owjFbii04skhfB3bTGZQ1jraLitbdX2CAALFUZFjGNSnG9t6Tw3OTy6
         7fxjGxLW/UiNiXuYxmDdbVvVKcFSBJmddxbBzC32/kNdWOsgbAbH3haTpKxasYdpotZ2
         W+Rk0j3p+Qz6b5iaAyZudX4qqHmfUqOcS8cvGdLUTJuJovCfclhMVOCCgMw2amL+Oo8v
         rpS1G8AcMHTkolUDTwzJZR1rUyO0SVPbQoYshFWYiGUyZAtChOSdZvle+2E91XQ4DHKG
         gvavJ50xJwkxeO0HboPgWNP4asXiOdiL3gzMdjyMowqhA2Nhk+bX/vsspN1OAkIKdb6T
         cvTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uvBp3SV/";
       spf=pass (google.com: domain of 3wscexwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WsCEXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id d24si1011765ioh.1.2020.10.12.13.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wscexwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id e19so13445115qtq.17
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:15 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:192d:: with SMTP id
 es13mr18205918qvb.27.1602535514492; Mon, 12 Oct 2020 13:45:14 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:15 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <67dc921f4720fdc5a33d747c9419a1fefb33e201.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 09/40] arm64: kasan: Align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b="uvBp3SV/";       spf=pass
 (google.com: domain of 3wscexwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WsCEXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67dc921f4720fdc5a33d747c9419a1fefb33e201.1602535397.git.andreyknvl%40google.com.
