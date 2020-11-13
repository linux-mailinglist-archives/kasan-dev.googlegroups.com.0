Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMULXT6QKGQELWRAGSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 459952B27F8
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:19 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id h12sf4857621ljc.13
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305778; cv=pass;
        d=google.com; s=arc-20160816;
        b=ckcI+mu+qAhrTDvf159YXxtscDWUC4MPyL/at2CWrHq1lx1/ZmTHdS9IZZImiZY39T
         8NOkwTr03/WDz9YcVtkmD77rYjBoMKrbOA2q5q8O1Bq68kspB6zexLn20s8HHbhWjnt1
         JDbj+7QCHSJtUv6dzV7+MRoIi+/aib/yD6l9clKR820DHRtfcK/Up9UuhjBquZJvUKOv
         qF5U+CCetoCGTZ0/TUnwFfLlhToEKknxCWZdqwJT9+edibLql4DsTCfq5VtSSnbs11p+
         WZTxPUrBS9OAm3I1bx10V78xX1LzcVKO1s4EE9kZKdggfueW8Sjmo8npVkIfvSq4a5eT
         QNZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UYO3xkShtmw0tC814ElbCHm1ZxJwrqLXyRKoP77g8oc=;
        b=HPB+rX23XaOOsl0ic037PTMoksxeDrjuXg60DwuCL8LLmoTMrGaEqtAqEksuGX7c7D
         2r1c4Drl5WNTd7Ba8H7DCKvaDnBDkjGe9ti4W1Z2F/bo1/I9LmpwaJ2pxksJb5QV3P/f
         e7VEebgwyZsqCwXwPq6vBgqg67UQca50HNyHtOLzEEURVSTyikvKWt6gU/h1AL3iBW3y
         VUpAz/wrFvumtXjA/XyTz1qTbz5zpXso/7d5ba06CxfFLkgJXFxU61aNyInTUZHsnZTZ
         xi0s41yE49WW8SLEj44B5jP6RGT6eItnExwF90D6kASYaTsNl0hXrvQebrogcHMNHVQb
         9RYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZI1ZgW6b;
       spf=pass (google.com: domain of 3sqwvxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sQWvXwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UYO3xkShtmw0tC814ElbCHm1ZxJwrqLXyRKoP77g8oc=;
        b=cuOTKFuCO6vXHHIuTadEMOU864sQMrRxWN8uaF+B/4aBQK3r8iH9m0LitV7Ji/r3k5
         7KawCRk8geeKvItryC/FPjl7y/F6Eq12cCXB0FTWAUMNYgM22GiwQpsg7vfjo2uPb+nX
         GDjdobNV1MdOn/etE5YGDIinmcggRqYh32rIJoytMNGLePYzRLU9qHqLJLra6mmlYYCD
         prsPVYlbFOx0j4HZhta9YDAQb6/d3pxAY2kVDgvw1CSjmYu6Xw4VhNErtYwXSztonPQ9
         2Fblw47oc9WUZsrguMpVdaYqK6pn9/Uojwazhh2lHKxr0NJMGfuwUOWlVU0JDmQwX99I
         u4hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UYO3xkShtmw0tC814ElbCHm1ZxJwrqLXyRKoP77g8oc=;
        b=de3gbYKpXqp/RcD2uofwirhpmVuOSsKV8cjVQbQ5okSBSXqkIWCqGs+PAFCd67OYzk
         ywJypm3qrObREmH+EpRUK156q+b/yMs8zZKbnQ/LfHIRUOE6p8uTAFZ13rnyUAykTrCF
         Sg1G1AjVqL0OTSlqRQdgE6QNINqJESV7kcFWVDgsRjn8/kDUvOYiulhkNQq6i0RfalkU
         F4k2AQSB+KLTG5VgH4ey99kStf3hZPPtSjsnrYQnIe/wF2ahCKCBKTQjW9nMnnsDocSC
         YSINY060kgtkF4GoVE3umnnfIDLf5Pvri30vCUITPYbXH59iZHbA0st+9zYAY8b+fJDG
         7r/g==
X-Gm-Message-State: AOAM531eKXSnv1pJoXuGZSAy78a9MSWs7/Lforyr4s2q0S24h+nfspLt
	202t4XGr2KAzZGvJYM3mI2w=
X-Google-Smtp-Source: ABdhPJw4Ltdqxdj8zuNcBQwaSvgo3fUglDP4ji6IqpFfmjevOubyf7gmWxQDp6dPRWC5RRWGXI7zNA==
X-Received: by 2002:a2e:b176:: with SMTP id a22mr1966011ljm.391.1605305778668;
        Fri, 13 Nov 2020 14:16:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls5522101lfn.0.gmail; Fri, 13 Nov
 2020 14:16:17 -0800 (PST)
X-Received: by 2002:a05:6512:28c:: with SMTP id j12mr1653281lfp.599.1605305777653;
        Fri, 13 Nov 2020 14:16:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305777; cv=none;
        d=google.com; s=arc-20160816;
        b=YbDs8Cw0hwDjeh8BxNvOywawxmoeyhWx0KdV4yAqNbWNO4VCWQ2iE34ObEui1h2SD0
         7u8E5vZz5rxP5fZyE7s9Wb+xCGNN0zLWI5Cw83TENyr5TzH+F5rTHGNn3FZmlRYdKcPa
         BiJ3B9jPPm436xTxUa80geHvXwo7TORAyA7DKpK8RjP6fNvjpmWdM4xNpCfGuzas/lzw
         Op+lRgzCon4BtLRqRftjOGBFBdjLxkpE2Q+LhIw4e3yyMonZBvAwTIN/jwdt1x6snSxa
         /JkWOizrp5fgxU0QHHxCC7lSMbGyxCc7ALV7+N3U8KKyuof+apww5UmzJYvNRV+EttYw
         DzVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Dt7EU1/jQ5NZYnZflWzuW6PyxwAuYrm4Va7cUyGFJKQ=;
        b=op2IeTV/rtUpGvqLeCgSZCthRpva2+ozCPOxHB6uwB+gOLLL/WZKPH8g0L0iPgSiLX
         oBRQ+8ojQuk+WLLtuhuTLv6CRR9bBUMFjfAlPP/SqY0zEPhJAnHmKtFwFTZwQcxn8P36
         fUPzyyxRjr/OMgr8FkU+8kEW1jpXXHmFMutNB4tFNi/I9hldKmD0bd364Tjv+nf1B8HH
         N/R0BepcqaTU0LjhVafmFJSapiiYGZ0m82PEpbkAfOedx2jbYdYtNfSvwgMAoZac79yU
         bpf2/O0q+aRyO904RiehfpopWdFzNNGFlc2NTCTgpwFHCVNIcBo6ly2MlxSPpI+sbn7y
         kB6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZI1ZgW6b;
       spf=pass (google.com: domain of 3sqwvxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sQWvXwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o185si337000lfa.12.2020.11.13.14.16.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sqwvxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 8so3996149wmg.6
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:17 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2ecc:: with SMTP id
 u195mr4404062wmu.27.1605305777097; Fri, 13 Nov 2020 14:16:17 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:29 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <1c9b6aef43296292f4e756232b9a46d81b33d3bd.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 01/42] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=ZI1ZgW6b;       spf=pass
 (google.com: domain of 3sqwvxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sQWvXwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
index de92da1b637a..578d34b12a21 100644
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
index 1f45199e819d..d6a386255007 100644
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
index 00a53f1355ae..d500923abc8b 100644
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c9b6aef43296292f4e756232b9a46d81b33d3bd.1605305705.git.andreyknvl%40google.com.
