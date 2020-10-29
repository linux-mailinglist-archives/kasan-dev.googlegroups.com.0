Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2NO5T6AKGQE4Y3DMBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 79A2F29F4E7
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:33 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id w1sf1682854wrr.5
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999593; cv=pass;
        d=google.com; s=arc-20160816;
        b=dYD7sA4aju0QQ6N7gu+9aTNZsvynQAd7otb3Mz5f3SRi+Plnt9ETxDIKMHSex4u7nl
         8KcQZV/3CeCG85w3BWcjjZar09Chsc2NJRiQ/MTkwu5ISXtVcTmwK7newnYk30JAIAcU
         JaxSP0SsWIVw1FkhNu5e7iMlHfGoq7XTyKmJ5dcGXSMq/5A2bXyN6dvHd2tLANmc+kjD
         FYbkQt4Zn5TzUMbkP6gfNfnVvl6lHgI9+GvdCOPuqgOwPiYwOiWQNLMUlGoF64Au2xS0
         ucfzmxoWjlmECK8WS21CBfgHaKykLwyccqzN7KbXmhNMYQRCIndHMCPqy8dYKS1zrDPo
         TawA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ifjRbuRFDPy7gvCzVa/UPY+Yw3awqOZwWBugpS0bjxA=;
        b=Bw9xLIVMuzzoaXvbG7lOc6MuphCmk2FlX2XzKV/MSPelkPslh+GUnYqzEWJaAfmRRs
         yjZdeJNeRsUHcqdhF4pJRdcZfzNpgVzYXLoOcyfj46l87n1sLVF6iiZ3XoRd1XPU4r9s
         1HEFKc5oXXX2xzWgsEMeDWYoLmT8qzbIXKweSsDZrxfTkGjBgk4+6iaErEsr0aUABcXZ
         s1/yMaoNu89uVbIRzYsy1Ss1NzXQ/275tgTi1XuFRLl2XunsppzUK51YrdrEOadmcAnv
         VSJ2ww73WE1U/2KlB5Ctdjw0vmfG3IJF2t6x7+suysylBnG7jx6S+O2mbN9otegBZeHn
         nS8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v4GN1jBZ;
       spf=pass (google.com: domain of 3zxebxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZxebXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ifjRbuRFDPy7gvCzVa/UPY+Yw3awqOZwWBugpS0bjxA=;
        b=WTsrOZOd98CfTD3qlLUZn+hiyTMEEpR6XVWfq09Hqed6QhmnsOGobu9S6uhzlm1Mui
         4DH2qHnMVUYeAD0Q0XU6pWNjvQUhIEs0UEdBLiQDIJKkMt3I9gu6LVWG2FsdKZQXaf4v
         EEdPWzbpKIMrMgNDYntAvlwV75vU1zDDG3p2Hrmf5oibhZWgqvf4SVqsc13o0dlnJiqb
         r8gf1Kt4Fnm7pSGjSVROZ+AM4hz9RErJFcPpwkZmqYJqVeKqJouk8ueuc8JRzihnNOhu
         ZF2LSXqJKGE5a9SX8/Mn5bnDy9f8NRWkR7n53miyIyTSdHthTnTZDKyE2g1Yd9646jAl
         WBKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ifjRbuRFDPy7gvCzVa/UPY+Yw3awqOZwWBugpS0bjxA=;
        b=i1mgJz9Lzlb8Zu4jLR+FnuPBzJ1oz2uRFuVTJlxuvYUc+qllWOFSmhnMOzPLQSd0x1
         CdZRIK72rByXDu9cnVYiOu4YXyvo2xj0pGHkPX1vGROQUUz6ttfFJaWbcEsyVaZilj2x
         LBkPJQtmadHzBOiABCPnwwEfw037iV+GJD7eEa9bFfFLNeoa2fgfThLiYYIlPBnG0sj2
         okMDkFQ2kEOiNbwmK+7xN4u6Y20RB8usY99a+Pr2XZpYIuO3oBH8CXoGH6DURZVQT+F3
         I0o5K3YZxnHx3f4mtYmRCQK+K1X/ZWcBBYjUXCS6EE+t1xiaIB64qzpi0Dmw+4P2bvV0
         TW6Q==
X-Gm-Message-State: AOAM531MIWSmGHyAFWBLOII1k4UBNPThcASngTdUpPwbrnkTk9Djk97O
	xzbiHB967YfZxSaF4XU58G4=
X-Google-Smtp-Source: ABdhPJwcsTF7fwujJkGVfLZGYHVeyYE4HavHn6STOwTIAnF3Dgo0bq/mY/AZONWQFT7b6zUbrfRfPg==
X-Received: by 2002:adf:eec2:: with SMTP id a2mr8051531wrp.128.1603999593266;
        Thu, 29 Oct 2020 12:26:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c794:: with SMTP id l20ls2594569wrg.2.gmail; Thu, 29 Oct
 2020 12:26:32 -0700 (PDT)
X-Received: by 2002:a5d:46cf:: with SMTP id g15mr8061639wrs.342.1603999592377;
        Thu, 29 Oct 2020 12:26:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999592; cv=none;
        d=google.com; s=arc-20160816;
        b=rE3dQC21dOoa8bdyuwuCeaZCVsl7FQaP8VT1aJNnaNZxne1jTZkDOvoJBl3f5HADEe
         u+kaUoTW00/ORm/35lEUdYsQ0aT/ELQa+Adro1fiRRlGb5d8GovoH6cCEkI/oedIHHsO
         Oli2dOA5TzKZlxwoHJoOD4iDXpK8v5etKMDKxz2OH3CuDVSr8dhJMBaRFoUK/yFmYbTH
         w8+MksdftdazjQpAoVEqN0JHbRWsWB7LUYPRlgkOqBGij3jv/MpQ1Aqx2CC7v8ddZKxs
         6lbdV7wN5DtB8Px3CNJMvNUNZjK3HlE4Bf5BL4FAz0ydpy2EnG5iidnGulg+jETI7NN7
         9GRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=EAVCYXK+qwXTj64iW4lXgFSidDhKD1r7M09orz7ePT4=;
        b=a2w7o3ZLbLy84DUu37VNJL4flBmu5PRL2i2/CF3aMkgZbDuAOcXjNXySpchFOzql7P
         lCEdAEk7W7TZsHeYvW0sMi2pvVJEmB82MgehmrnUkV+RU78fBMOHOQszxVygTFPo10k1
         RkH89/A6HZlDuJcXwlSuhffvYzWi54/gLXCz5cYPD2O2Xuy1gkTB8e1oxpe0RuUTMF9P
         oRiikzUzMQCk5/BYjRDtKN7VnfhGDmf4ATqli5iNcjK9nKCziQea5eEKKCldc7xKn3gi
         4RS3QG9ke1Fpl/7IAmNNLYVA3xej5QqXOIsxFNhGPTIsHzpAEb1XgaQcFbvZYnlBXodE
         i5CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v4GN1jBZ;
       spf=pass (google.com: domain of 3zxebxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZxebXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id e5si127709wrj.3.2020.10.29.12.26.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zxebxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y99so1307174ede.3
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:32 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:c094:: with SMTP id
 f20mr5801944ejz.550.1603999591860; Thu, 29 Oct 2020 12:26:31 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:31 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <23a7ef2e6c268aba7f399b228b97a7a01f5037b3.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 10/40] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=v4GN1jBZ;       spf=pass
 (google.com: domain of 3zxebxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZxebXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23a7ef2e6c268aba7f399b228b97a7a01f5037b3.1603999489.git.andreyknvl%40google.com.
