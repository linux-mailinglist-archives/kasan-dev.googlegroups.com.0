Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNVN6D6QKGQEAJSW4QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E0C102C1536
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:23 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id r3sf15037617ila.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162103; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ff0Ro2AinQuw1Wl4vo6JktZ789t3OsOYjlsom/uw1qVEr2kuylr21XhwUG473LA42U
         kPJIJIiJspwuMYq9N03guPVzHnY5jnj02iQJk1vPqOdJmQE+yPpXe6+S+jLHakvlL1Dp
         X9oIpxllzLD8TnC7qypOc7jCRb8NfeF4TS1xbQ3FLDuAUKIWy0AoVjDq05AX5ugBrqwc
         1F+8/NTWuNBUuaj4g9YSa3txpfdhDWNAgcKeAIao+NmkcSjbbsFFQVC/cPgqvr8SLQHp
         uswzklUBJq86IUhYpIBTFCy8mfTw5mFBQKG+58+Z4gQ3gQa86GBy20c3RsmdUnA9whWe
         Vkdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fq8vLUVes2Izrdqq7MlLXAMZwtTIwoSkTh5w4AtQeoQ=;
        b=FLKgy0vvbBPGukZh53h09oqn5cxaDsxl6BUR9I3Q3MDR4G2XcYsQsVVQnEUwgG6c3x
         mUW7qtJMEDhgjI9PSvDK48ZlK7oQOgP9uKPqQOKwiLq3KjzRjBm2JGYXPpIT+8vcyl4w
         mcoDiq95mVZmtTTn1fqqKQgBIC/k4o4Mw11FxdbeIIb9s3wbrk8LKMR7vJiMtzNtgxDv
         ly2cA/NUVdtPyJfBB1ZhEbHejLhU0Zob+3ixOd1cDq+T+ns0tD7eBmmlPH9uGDx651pO
         jxT4fCasV6M7YEWcccFzjA3EJuzA1z4X2+SfPjF+bRiR4jvcuudI3LuxnZHjE338G6ni
         Lelg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WO8sjQFo;
       spf=pass (google.com: domain of 3tra8xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3tRa8XwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fq8vLUVes2Izrdqq7MlLXAMZwtTIwoSkTh5w4AtQeoQ=;
        b=HXc6Dz2SPlgq7wpnVqvJPXxqZlJVuEXZY/oOdv225PgB9PI/lbBh28J4C+0rLFdavK
         pFs7HTBuJpqZRKnrkOJYX5DZDy8Ky3m7KHLsBiWDmC7VTLc11ozi7ucCSWOIcK7/81/c
         Pc5isE969nfxQYpQJD2gBf0mVWtCZeVwPLfDZxCp7pdWBv8LZsUsHpIQLHu3qCkP44Bi
         DFhm1V6/ui9J3YROiPno00BaOtcmGQzGEb28ty59izGZv9bYEGphqH0NNxd/qsl6AhgI
         +Wa9ZSnjBXOBXR6+G1qTugklMLPbC0Bto4NPAHemkjAbEEhozt1ICKe5LH1D7F/21eMQ
         iA/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fq8vLUVes2Izrdqq7MlLXAMZwtTIwoSkTh5w4AtQeoQ=;
        b=S21jNvyPEuaADZisO/tx5+lligDfCR+OkLORLSeE5Yi1tJWUfaGMFats6K2MQwojeJ
         XRXo259Q4gAWeH4EU+pmNHvCbxQUcgA23Tec4ErLbrT7O0GSoQXtGgUtA3NXFBTLz//B
         9QTuFbk+b2ZrNBCa+KRgLY86rTVFtBxsGxHfKckWvGBFo7NktLn6AGpCH0WAhIE638uW
         OqRS3sxVCxFrlfKrgBmGaCiHN+SPwaLxezOeJOEaNRpErHRg+xc4thX00CPTDTqwXW7a
         e2Jt6OgVQ3DvNnOPyh9dVEyIFIZ3jqw3tQxJ11cVMjjB7IEZSzrO0wD3r1xjNo4Gs7ou
         JJaQ==
X-Gm-Message-State: AOAM532rN1LL6YPeyET72A4WjLBX7KP4BB053MRwzGSV1N7W9qBPxte+
	aYl/ItWhalRG0NJMdmEJfaI=
X-Google-Smtp-Source: ABdhPJxbOoISC6R3RDFG09qM3jeIK+tLkNz8bMLGyVHKYWsh6qv67ESBth1lUF69BAw+gIAMsG9frw==
X-Received: by 2002:a92:d5c5:: with SMTP id d5mr1297092ilq.24.1606162102825;
        Mon, 23 Nov 2020 12:08:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:ed05:: with SMTP id n5ls927048iog.10.gmail; Mon, 23 Nov
 2020 12:08:22 -0800 (PST)
X-Received: by 2002:a5d:8986:: with SMTP id m6mr1257465iol.30.1606162102328;
        Mon, 23 Nov 2020 12:08:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162102; cv=none;
        d=google.com; s=arc-20160816;
        b=Y+5j1kMZkkdLDKV1L8PJ/U0kaNdwa/mWGx+9ZzadLJ4BtM1LSgKjiMPiHYDd/xaXmu
         /Tfh2AZPTyaYO1wR7ApmK5f5nrDGgH49A912Asmxm0j20NxNn3FSROUNItUHyPZo3Ud4
         /vSUVH+l6ZvBRt2MYC9S/Qi5pMakUhcFkSaBqDQ16PW8sia1H46rguWFl/jFJUv/jO5z
         IiqC24CURp9qDS7vxgKQt2uk7so3ra7TyWB4A0VlGo9HZFmxofVwOGr1zspuZ72TE8e6
         RSu5Qg2lP8Vf3c4s2TIS0vxVsPtGwjkqNLrHC+mJKyTcSjWS0ILcJJEojgrqgrGRwfyS
         E8HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=fJpKlB6WWj1wpKLf13tQib0s7UX5e/Vfu0b9nsfzmrA=;
        b=TdTSoonPKuk4YVSe3/rTSJByHFZRayaJ88xn44xdFlwZvWnMAF4bHvHrkiakvSpBqs
         DSzcchDuBzc8FK3Kc0ZWOV3k07dpXRaFq3kwuZyE9pSOpZ55O0mc+C3LMztAxDlDCOeR
         3F/QfRDoFOifLssRqouVCH6r+h0gGR21WatV4kxKE0eV0PafxftL/xSwQSgLv0eP9osJ
         lhPMTadljjDsww/CcvFqLQ1LKX2hNRUHO6f6BtYXDgQorSkWer0zXdw7LV8jQj+8EMuK
         9p8rGd1MIJNyq4M0Y0zGrsGbs7Xi5yCEL4MAkI6KgreaNWyqGkNxBdq3QtV0BNdayXkH
         e+cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WO8sjQFo;
       spf=pass (google.com: domain of 3tra8xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3tRa8XwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u4si700930ilk.5.2020.11.23.12.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tra8xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id n5so2411401qvt.14
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c18e:: with SMTP id
 n14mr1291542qvh.48.1606162101666; Mon, 23 Nov 2020 12:08:21 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:25 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <6ea9f5f4aa9dbbffa0d0c0a780b37699a4531034.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 01/42] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=WO8sjQFo;       spf=pass
 (google.com: domain of 3tra8xwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3tRa8XwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ea9f5f4aa9dbbffa0d0c0a780b37699a4531034.1606161801.git.andreyknvl%40google.com.
