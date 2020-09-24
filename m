Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTWFWT5QKGQEMAFBCKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C1AC277BBD
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:50:55 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id d9sf330032lja.5
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987855; cv=pass;
        d=google.com; s=arc-20160816;
        b=NBDwARR/0zKLKqPgpU6lhcQlLofuzQbgfGuvB2NXoAruPOARaJ+wUinFguBokoKDqJ
         lnk3BR9lnH/QFJ6gAiD1nrjPRqMjh5lgxPsqEcyYNk6g5k6A+blxgAwgpTdzIecfaH6b
         NZ1R/+NYB9MdYApvDfCSJnXy8TEhCPwH6u4YvQLvSivpCPETyB1l7HUM5bhDXTpMtmgv
         5Ml5Ayj9BP1JqmbFuMhrSqWzmSqlKwBAyWKmNzctlZmegBhti7KseNYDM1OzCy5sxQI7
         HZBcXDIfB7GCV8HiP6k3/NLL3PBzwq6MlNm1h5SYZNQXKBkUZkrjuQww6923ieSidfzM
         /gsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=q2HwnkDk+GZodddOWryJx56osWE5A/i2Ax26ZtRtCPU=;
        b=uYjMjf9iyBatriOFWm5ZaL9He1hXH2eQP0mmqkPOv+Oh65AJfGCgSL+uAdAPu4t90S
         /pvgH3So0FygEjm7RIKgFAg4H6IfGQkF9ATF1/MFB83Ac0Ort1N2cl9+WOdBTReuhM+V
         RiQfSvRMEP/02WO6M8VfwMt1kDvC0fXbwsCB1ysdwLdc+AVJWSgnDSYGicDkjOW5qlRR
         AAHvZyc33jLANyVldSb2ySLxeDRkOgLlBhLGVgkDAPzW8o6BXFU4DGdMCOg5ACcGqLkv
         BfoHhg8lxnXgNtVeTvAY94C0f+WDLbRog66/FxaX06qvh9we3jjgMGkrHYxyf3Qq052b
         lNVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GbSvhSb8;
       spf=pass (google.com: domain of 3zsjtxwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zSJtXwoKCcgo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q2HwnkDk+GZodddOWryJx56osWE5A/i2Ax26ZtRtCPU=;
        b=dpQns8RATN5nm5SHIcfwU6n7KtTUfKJAl/mpPgI2qDU7mNvzWxVr05HdBC3DefeaWW
         VHS0SOvM2XHLzyT+dSCN55isfaihF2e4gDrN7PRsro/0JTNdeSuEGXYhGWQyWHNM4BTa
         JtrRf2o0JT8pnbTILETyIP4JeIbyqnr3Y1oBEiNThCnaubNSkExacz6EGaDOUoR2qI/D
         Bo+8VkHgfCsG1UmoDyhwC0tzZCKVtKUY4kzFE6cR/pSXQ+MRY2HI6Ub0qSmVnbDeGmF9
         EpNp5pAAF5+Y6rhVe268UiTpgwv+jCISQ23vkdiwx/zpkiAUTVFvnjZq4oD+APTlrA2y
         4hAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q2HwnkDk+GZodddOWryJx56osWE5A/i2Ax26ZtRtCPU=;
        b=YsfWZYQd0f0fMX7aWHw5PWkTXUC6iaZOTdAq9t3twDjetUbWIUapRPak6vaDUft8RQ
         fZGH3NKXjNjPBkeQCkaium3/XKlUYROn0/3YiQuikwgfEBHBp/Sp9+btQd2MI5ekvVTP
         ISf2TfP+CqhsRIaR95jU0c2xfsjSZ3W4VHvqcKjO+v+ibND+DUrJXar4eOIeHwa0AlDj
         +jizz+p2400WUi0l6KAv+6/Oo4LippvxUyqjqAnhJbRQCZsdpENGgAWj5JgEaR2FMFRF
         9iGKpkPZPA5CTROdfbJjmroEJEel5ettEv0qe/pS3azICszYH0jq+8JC4LJnBbSNfgPH
         Dlfg==
X-Gm-Message-State: AOAM530bDX+sb+rYfF6LJ3hBOVij7nmIEmqqMsC8k7EK0fioNVijwxIw
	LultdwLzdKj/UUuI+slUF9A=
X-Google-Smtp-Source: ABdhPJymR45c0X5Q88w+gsuWx80OLj3OFUeVBjpl4HtOMcO1zVv8J0GiATxCoBC612CYPpb9laxxRQ==
X-Received: by 2002:a05:6512:3453:: with SMTP id j19mr382819lfr.92.1600987855084;
        Thu, 24 Sep 2020 15:50:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:86c8:: with SMTP id n8ls95590ljj.1.gmail; Thu, 24 Sep
 2020 15:50:54 -0700 (PDT)
X-Received: by 2002:a2e:9143:: with SMTP id q3mr404260ljg.253.1600987854054;
        Thu, 24 Sep 2020 15:50:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987854; cv=none;
        d=google.com; s=arc-20160816;
        b=C2SQr5P6Fqhtx9SxnFhNkLxjVE+xd+RnXkDcqIPdXUjw/D4lCy/5djJTIsOar7+len
         T36O3q9cKtedL2Wf/cubSp2d0wppoAhHJHPylhyLkGys1giIwcoB0Cg9NrDZMzhIrHsR
         0f1Y58tdbJOe4+Wq4fWCT31pB1cwIUKbkRPlsIbiSiMnjv9RYxB0FbpvUciudYcIiR/4
         JWYbmnL0OL1anmLN5/0E51Tb89l6EuoCEel+IegnoQ4q9NmLCdQxlzMgvofqu87QYFp7
         qtKEebt7dKBvhPnZKpcTKfcXgiHOWLQSzXeBRlB61DcCSnsiJv+IyDJDrRhIkaildqG9
         r8+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ZswYQO9674cQoHqiYfyFJDWx/WiHAi7fsHoF2eA/GXo=;
        b=XlYZ7NHgMZiVCcb/esTN4F/Zu6XSg0XCdNsE0/n5yREuAAqm7rJAY3WYWAeVz9zRjE
         MudhBEOMCxkGJ1qEqrWMIz7lIzAZK7ELPOIw66Ue7BCGab+dbc/cALv6/SZArT4E7kw5
         zjUn5OnkAnIjOtTNpRsKrT05SqGQ51hXUJRbUctfcdGOt3UBHgfMXTWOGQd6fBDdY5Qo
         4ZGJud7FiOi1mScOetRxbCQ+rUQtBtx2cL1dGdYPldMXmsYjXBakfWGTZjvu0H6k4iH4
         CUR9HBTOt/5s+x+arshUxF5zOqGP6xSb4I+709f03QwFk7MxUzlRHNHmU+zVDiWpfTHB
         P3Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GbSvhSb8;
       spf=pass (google.com: domain of 3zsjtxwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zSJtXwoKCcgo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id b5si17876lfa.0.2020.09.24.15.50.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:50:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zsjtxwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s24so277097wmh.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:50:54 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c4d9:: with SMTP id
 g25mr844467wmk.15.1600987853482; Thu, 24 Sep 2020 15:50:53 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:08 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <56eae03b7b8112b5456632f0c00bd42e7337966c.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 01/39] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=GbSvhSb8;       spf=pass
 (google.com: domain of 3zsjtxwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zSJtXwoKCcgo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56eae03b7b8112b5456632f0c00bd42e7337966c.1600987622.git.andreyknvl%40google.com.
