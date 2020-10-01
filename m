Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6GD3H5QKGQEDU6J4FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CED65280AEC
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:10:48 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id n133sf51560lfa.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:10:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593848; cv=pass;
        d=google.com; s=arc-20160816;
        b=yZfm5duvRlnph7qFb8RvGzaP8IyJUuztLPufwd9QrgCjvvPTYsqafUJqbOo549mVFG
         xLTrv4mWlrpTxkKRl3PwtMeSU0gkT1Z06PI+gA/4iI6LgiAzJ5URVQ3XpxRJZGpZk5VB
         5BkZvfWii+1PUYMRQNSEHZ7Y0+kmpxbJ+xQ7fhP3aILZYsK+nwFOZETMlNWOJmgBo/Lb
         Nz8OGH9PGZGRA3rqaUXBDbS6R7bskwZWNw8dd8MKRYLPZ5Qr4crGW80r4CuEZqcdiyfK
         WI5L31jXuwd7Siv/5CjGp7QMSsy12IsQZrNkygZTqf26rBZK6UWvRuiUthaNuVRMl/ty
         0uhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zy/lbfhMq6fSbXL1WmDdjUgX2QCQHNv3AAoTr4HQU/Y=;
        b=xjg1lDhbNIz3tsBIIqh3urm460lBWoeOIOOsoe0E2AMrhcoIoXtB2DSOFMYf6STB1g
         8GoyPzo5QwgdrevJSSQUEP0mkPQ2d1RtmUCosDslzEzhYB+pl1gWD5nxLX1D6JYS52pT
         I114mnm7PuMOasTCqMFlsEoZui+KaPNHzaIOff02iuR3HFMHbxcTXJxL9Pz2M7XZRZCC
         ab4/mm8FFIC2PQNGAR6JCrN7PSPeT1yOX9Zm0J1a5iuvnh5pcsuKtgCzF3Hw1F9kwptJ
         5Uq6NqEbMRPnNVSJTNT4P7m2nqK+La/2sVs+N0iRLG/iPfSg9XGcvEJN6R6SHhmWgBxU
         Gymw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AWWv4sDZ;
       spf=pass (google.com: domain of 39mf2xwokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39mF2XwoKCZUzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zy/lbfhMq6fSbXL1WmDdjUgX2QCQHNv3AAoTr4HQU/Y=;
        b=iF9kcOG50iiAkL/7SMhorfURSd9a86E4kLmcexIBTfdGYVm0SgQvRubNwTkgiW6plL
         HEGGMdsSJAybLLRwYsxY0NdfRuDS2F4ZnmSba5qU41ubs4SPNdUSzPpajc74jY+16Gr1
         ONGRMtpW3tI3fRvM+chgR8l+L7Z+rlZYTJSqW4iANX+Snsa283Vy/IzNmNX0GNnaRAlx
         fF7X43BJOhY50mSpScAh9z7/hYzrqUvSghzsIBGwSHmDzRb3IaQdd30Aa5bHIZieKNVV
         3KkjhPoseC5oZaFwSsBWm/BgKqx0PeefWbkkha+JnYQ3cPe8ngTrdN0jGAyGBtVU9GT1
         +0Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zy/lbfhMq6fSbXL1WmDdjUgX2QCQHNv3AAoTr4HQU/Y=;
        b=aOZDBm4OY8s+HU/NphVTeUT11C+k5DxzFk9qSHu0RfIBpRLiQwMnnIZRaGOZpMpfXG
         UQeejazJmVvJuJnyutaPgR3RD51O0BgSAmWOPirP7TRK2GZ8/wDwnQ7DVZOCWoW0I9En
         P1BBdUNzrpFpy46ASgydXDfaKMJYhCoTpvwHNc+f+hH65nvE/htB023Q1l22cK8GAZ+P
         9R5p9xaG02UqNdNHX3ofLxAS0GGjBu/6K10JDugWNtgvaNyuFtckiKpHvOhiYy/lquJf
         bChwemaHIv+luWDGqIiH76kbvJPY6L9qFkxEK6zBLsKP+3/gNECjAwk+bvqiY1TetnGO
         mnyQ==
X-Gm-Message-State: AOAM532YKIVGN/4gf/1mH9U+FrXmIGVRUGDW+pqgQhJ0LXqFhOUz34Aq
	Kw58FL7vc+TBDLtudcrRR5c=
X-Google-Smtp-Source: ABdhPJzshRMU2VrcvLP0SvGnAPbiu0mhsk2Z/Ld1JL/vsnESscskCxaPhwzTGz1wl9/M4Bw47Dllqg==
X-Received: by 2002:a2e:9b15:: with SMTP id u21mr3280166lji.283.1601593848384;
        Thu, 01 Oct 2020 16:10:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls2144635lff.1.gmail; Thu, 01 Oct
 2020 16:10:47 -0700 (PDT)
X-Received: by 2002:a19:c7d3:: with SMTP id x202mr3891344lff.66.1601593847292;
        Thu, 01 Oct 2020 16:10:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593847; cv=none;
        d=google.com; s=arc-20160816;
        b=BdRRwU3CeBQlbOq7xS0jOwclHJhRkDgPHtlYshUbszkhI2GaI3cQWeIDP2DpvmPotz
         nGOOWjNFCcHt/rtPk7s47aln4bxrAqLHY3HlhkATR5j9SPDE7NaXjQlNEPsWNcPB6mSH
         MlxLsSPkonQayCh+V2p0llAqVfiQ/oGe3O9gAYMFkDL1A4BkWtlu93A6wUfzEU1QryZ8
         dM1MiyMfoNpB2GdwSkW/Z5jOfKFxh2AYjSMOzhwWuIaA9orE+Px4p0jbVLKCybh272EX
         oFVsrF62htVTDY/1p4Fjmeb1mH8/CWzWYmkVPVZ5GHviLfDaRI9LzdZinBaJgl619Ve/
         qSlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=H5RFba3mJUL9GPMJQGWmruVpmlYfNnrJ2Q5a3h16O78=;
        b=QBE4a0vbcWWoeJQ+OV3qI4yVNTtOzGnoY7QdzFBY5A4ISsMVxtLBnJZDKVSqd1FAzM
         1y1k4Q2b1w21+fEvKJUwFcy8LYNO/JaS+5G19Q6TgF0VsqJCqXgTE+bdwnwzDT2hPDns
         tacruWOcMbhFtsoIm3Xbbntkyvl2eU0k5+nBn/R2R1ElVUnEC6oNiXWZBJdQLr1+tX+T
         VpF9vG3wIKEuJtSZMOZmYVzAJe4YI+WfO3XRI31McdHhFv+7bCj5ElKPLrbvPETsqlCy
         EDwY8dXBTTa5BYlUpnBqAxt33KhvTipFnT6BXFaX4htfDMYb0kYjKFuaZKpnpuyrvc5D
         O4yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AWWv4sDZ;
       spf=pass (google.com: domain of 39mf2xwokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39mF2XwoKCZUzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id y17si207456lfg.2.2020.10.01.16.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:10:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39mf2xwokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id d197so25466wmd.4
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:10:47 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9a10:: with SMTP id
 c16mr2175130wme.96.1601593846859; Thu, 01 Oct 2020 16:10:46 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:02 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <c06cdd029d859d2bbcfdd9a033ce75c92547ec8c.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 01/39] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=AWWv4sDZ;       spf=pass
 (google.com: domain of 39mf2xwokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39mF2XwoKCZUzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c06cdd029d859d2bbcfdd9a033ce75c92547ec8c.1601593784.git.andreyknvl%40google.com.
