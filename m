Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXMASP6AKGQEIZWBE7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A67FB28C2EE
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:18 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id v189sf2642220vka.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535517; cv=pass;
        d=google.com; s=arc-20160816;
        b=pV+9hz0/qFbuIqd6DyTjXpWD4/s60zHoyXGEBcmL7FbfYbvoiT3fThguNc2euD5oyk
         jCdlfPPE4xfxkQYYv1c6fxVeU6zxKtsYXDf7F/lzR6kEX5psrefZxbKi9xTuOxntt86F
         WaTGOeW3shBKq3qbqS5HsfUYHx6Dwz7Ws17SmkwdrBQWNqiLINmEWracjSIYzd7GNq8N
         mEurdF9E26sPwh+akacDSw/3s0GH0a66AIip7WaDjRyQm/RUq4wXMrzzrRj5i9oO6FnO
         LbFbPYYMD6+X8BviUvoKJ9KmG6hoTxkdWMkYTyID6RB5nufKiIFmCeZqznHfT94WgRs7
         eErQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fjwdASQ46Fd8MkVaekBHk5Y6UXhuunv+BPBj/Q5FcTY=;
        b=WA1z0iwrZAe/yLkcZ9xdZQJDJVf+phej7itPRviojvjN7J98TqR/uqudUWW8bMN3Y6
         4yPI81KxyXZtWmtQVZb7qmo0BMxS8+MtbQ8oXryadXYW6q5aQdkrUEOsMps4mhO+OPOt
         u5b4CJC7umVuQeBtjBSP0iH28WqoiS9WagRQ/reC5k9WjxZV84SpQTKG24ds6g6iAx8a
         mhyGGDjNabI9mD7kD2b1Sg2hZnZl7TgyNiKGq1jI1WXIGKkHxtb5PnfI0eVsbkC17hVH
         dBW1F8Kv0sEtCFkc7D8+skfQ5G/xhWyD5MJGzOX1pw3A0YfPpHE+p83g/CYQNb9S9w9Q
         1Fbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dcwMlfIw;
       spf=pass (google.com: domain of 3xmcexwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3XMCEXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fjwdASQ46Fd8MkVaekBHk5Y6UXhuunv+BPBj/Q5FcTY=;
        b=fhQMX3MZNPNpil1q/bu56ZHo18ZTt8XaV3n+YWTXIJ1gzbsw0NEHPwIekLsJvenWFt
         L65MKaS3wRgPEtaDPTwksfp+knxUYyvU+LEv2sod3sPfOnnnfC2GsDnK7ocfWcLzKgNN
         D2291D5SERDs0eKUFi31F70zTane+riMgQ8qu+xaggHpw6dHBMOun74HxATtldekc0Or
         z2+VcHw7H+lC7zU0On8ZsBZ3pKy+jcRVtmO2OMTCOkCshE3COYlNORfH0Jze7YCOT/UB
         Hc7TiS2sbfxCIS0X0BE3omR8BvIXgusPJ0egQ7Q0blPoT5KnEn4A5V73FedlqaAv74dZ
         JmgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fjwdASQ46Fd8MkVaekBHk5Y6UXhuunv+BPBj/Q5FcTY=;
        b=fKSfPhePIEMNMcIoY8naBSoBiPHduHiTEYGRyDvFd0SQV2ONsFY9Szl8fHUnfVkSBg
         /iO2QqImEMzL4YOlkJKKViN2wRUrP7qxckJTHXFgxbmLRh0/HJfZS3H3LH4oR2fKB/hn
         ZVtikp2z/35boesAAJgw0vkbTAQmgHyD5P7HKMqNQ1k0myL80f/edyaM41Yco1LrSGcT
         t2ok16CXAy1jOcsJXIroIE6gzVfl+KMEwV3Mhq1qbAagUiBgiaqDb8V0CFN1zSbw37vd
         nw5mEdgCDBP8pUD2WsFm4ecyTvnvAKcKA47N/AZkhh2egE5jhTFZGQJ3+JaHeSmcQplM
         qi2w==
X-Gm-Message-State: AOAM531qjJ+uLCDyZviWJhav9hxlXNFJze/Evs8JarGJQf3z/+6C5KxZ
	Z5jsi+xW4QJ58Tl5jRU9fk4=
X-Google-Smtp-Source: ABdhPJyvsECrXUjy4yLhbxMXHo+DhFECIU+hy1caKFBp+QWSvQ63fpnI7Pbry/P0Uh+bwRbhNH6JHg==
X-Received: by 2002:a1f:2508:: with SMTP id l8mr14218250vkl.20.1602535517577;
        Mon, 12 Oct 2020 13:45:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:23c7:: with SMTP id 65ls1145013uao.7.gmail; Mon, 12 Oct
 2020 13:45:17 -0700 (PDT)
X-Received: by 2002:ab0:1af:: with SMTP id 44mr10799744ual.51.1602535517115;
        Mon, 12 Oct 2020 13:45:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535517; cv=none;
        d=google.com; s=arc-20160816;
        b=SQ2CT5xCQ51lQzZ3BhPEeSkLG4mvstk8Jcw7udl0gIBSlxLWyeb97LDuywL8b0HmSe
         e7pd4mQ5SNlKm91XYsL10tsxqaODONHIhOaMUQhLRKkC11U3U6foo20aRtlkFx+OyBh1
         Wfc5WthaLPGn7/dUrxteTQYkXcSDOpKo1PmMknm9wgf8sySZD02h9WybPx0ZDLsqHKoz
         EgYebM2ZuSM0RpHEr71V/xL9AyG5k6YTI/0L84JUkZXe8PuXztMtr35tkm8f3MUP9ltm
         QEsES8r/EpVA/fJtJZ11FEDuCMH5Cvckx5JcoZPeUP90KFldfkm0cbYnMQ73Rcftma2M
         wsDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+SIWGAmnbEnD/Uogp4huNIPUvtkTtEb0B2WGWuwNKsg=;
        b=nPmrW1xyGn92oezQ60PDy+ArCgj1cyMG3VvqcYpHdBnr/ba44LOUbyQY3tDzFNh17a
         yoE+m/SB77lWFi3PQ97ZI880dGSMedlTZDp9AXyNnL91DWjgAF2DO0T+NL+3ZXArcGl7
         aStE5MY2XV4P+ZuG+yvz6/OLnumlxCl49eFdgfZ+DgZrhGJTIO+xTsdZsnSPIlqx3pS/
         C+1vxTvmxBjXSFynKScii+FtheZeFPycW7/rb2kQm9aeUt4Cy5lLAfpLcDgJwjSYUc0R
         7Caqu8Z5fGlFHT0+XeoW4emGrZr2CQ/fsl8/H3IgiLi8b340nPc49CHRvToBxsK7609u
         3WRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dcwMlfIw;
       spf=pass (google.com: domain of 3xmcexwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3XMCEXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id e21si1168139vsj.2.2020.10.12.13.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xmcexwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id y8so4707401qki.12
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:17 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:192d:: with SMTP id
 es13mr18206058qvb.27.1602535516736; Mon, 12 Oct 2020 13:45:16 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:16 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <e345a60b2ad8c4b7ea37d5b2d7186437a20ba99c.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 10/40] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=dcwMlfIw;       spf=pass
 (google.com: domain of 3xmcexwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3XMCEXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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

Don't mention "GNU General Public License version 2" text explicitly,
as it's already covered by the SPDX-License-Identifier.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: If0a2690042a2aa0fca70cea601ae9aabe72fa233
---
 mm/kasan/common.c         |  5 -----
 mm/kasan/generic.c        |  5 -----
 mm/kasan/generic_report.c |  5 -----
 mm/kasan/init.c           |  5 -----
 mm/kasan/quarantine.c     | 10 ----------
 mm/kasan/report.c         |  5 -----
 mm/kasan/tags.c           |  5 -----
 mm/kasan/tags_report.c    |  5 -----
 8 files changed, 45 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..33d863f55db1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/export.h>
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..37ccfadd3263 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index a38c7a9e192a..6bb3f66992df 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/bitops.h>
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index fe6be0be1f76..9ce8cc5b8621 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -4,11 +4,6 @@
  *
  * Copyright (c) 2015 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/memblock.h>
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 4c5375810449..580ff5610fc1 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -6,16 +6,6 @@
  * Copyright (C) 2016 Google, Inc.
  *
  * Based on code by Dmitry Chernenkov.
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of the GNU General Public License
- * version 2 as published by the Free Software Foundation.
- *
- * This program is distributed in the hope that it will be useful, but
- * WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
- * General Public License for more details.
- *
  */
 
 #include <linux/gfp.h>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 4f49fa6cd1aa..c3031b4b4591 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/bitops.h>
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index e02a36a51f42..5c8b08a25715 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -4,11 +4,6 @@
  *
  * Copyright (c) 2018 Google, Inc.
  * Author: Andrey Konovalov <andreyknvl@google.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index bee43717d6f0..5f183501b871 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/bitops.h>
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e345a60b2ad8c4b7ea37d5b2d7186437a20ba99c.1602535397.git.andreyknvl%40google.com.
