Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7M7VT6QKGQEFGXLYKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AE862AE2A7
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:11 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id i6sf6190767pgg.10
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046270; cv=pass;
        d=google.com; s=arc-20160816;
        b=FUInsVWF2jLTJS73kFsRtBoWIDuLoSmx5h/bnVac5MziMjt58/LESzqkjWtBAACUt8
         kIY9fG2fuDF99shXaXooO6McPs54zOGnLY6CoGTIv3NU8qmO9ZQIwOm+tCwDuh5rJ1xP
         dh08WTU8II96YOoPYRZvPbmjzqhNqQRnia7Ee6rw72WmIrgLjEeurpdn7gpADfkXOedk
         Sf7EUIgBRDc8D7UuhCYgNNkaaWbvLH4cpgkdngAhtcC+d0ICmO+LLs1aga6EFdMRDkm8
         T0UxiAaS/1R1Z5aLpQK8PjmRMM78zrJHJPb5bqoH3aE2AxsldOmGEnt1JaGJlI6bWx5q
         qBpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZfSvdtT9QQUNDalbL+MTtxZ+GrlCgILyzogp+yC3468=;
        b=NLegMQOI1arwJyf0KVDbfjcy3vAJnjBg9du06k9+A1hzlEYgD6JAUTy3//4KVgRHt3
         sYpoo0Hx0rNXjJKmPkuBH5EgenGh5rdXIzE54Cydgdp2roR7Ea0l12DJ4dOxEp37B85E
         I8aLRLWB67T8rVbJBcW4rZCunHdZ/EYwzH+WmulGSueh1RKPQQAv5R7oWxLTPJROf1gl
         QDwah2N5bLyuNy9kXTs2S353eF9n8epWplE8dGkCvON527zx+JhWiggkKKoJ4sbF6N7K
         D6IDEo6SzH7l3nc11/3GVgfeBMUKgnHrxoW7OEhEmLmIb7zWp7upuMsKJZOaU6rhNkvC
         IT6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OW/d993q";
       spf=pass (google.com: domain of 3_a-rxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3_A-rXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZfSvdtT9QQUNDalbL+MTtxZ+GrlCgILyzogp+yC3468=;
        b=XcJR4PNc1RYUO3hS3st7BNpCBhhj8zUaeIpGGUSeCB87DjgxRsUVUCfNF+c+sjcdLg
         IqZ0cU2gtZEm3BQdQwh4B2SRPOMidG7BQPRECN1Gk0WVduW27SbUgREdKOCAj04PL7TG
         EktRZGb3H2EwH5vzM7l4a4yIYuT/lCXWO15uvTcjZrwPz145B37PClyyuDRqVXe/aD4E
         DLjpi6XX7vuyYaEOYZfnz5VAY0/dO2QenuOatkPBsZwcj9HcbLptZ9MZcuSNIDBdgZVp
         JFrd6Zg6znVtXx3zt7qKpf6/6HdWbhuuQOUeSBswtrhBPPBZkKyFDm8lq9Fuo2W/VDx6
         /4kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZfSvdtT9QQUNDalbL+MTtxZ+GrlCgILyzogp+yC3468=;
        b=Fq6+hCwgK3iuj9iHicot9aM9n9FqKRQ85VKWXnPbFxRDBzpqy6MqQvO9aef5O2iCBN
         NSbB6M3KCostODyuTp46eXQh0q4WwgZki4Byz8bAw56a6+flHcl0u5MKUPUpDhtOL+ln
         2+j5znKdzyEbuj1My+DUz7G0YY0lOKc6OiFg6xUWw9pZYlmUENbeRQEya9otpmXtPYgB
         cAmkBiAcWyKd49alpYG2WyyLv6/eex9hZEZVVazv8nwcYKH20dNu7s66/+fnk5pQOweY
         wF+IaxnWIznfiG7eovwiIkS/utkA99vJk0kdhj+uwtqNrvJ/4PsfR6Y4AVQpujQ90Gfr
         h48A==
X-Gm-Message-State: AOAM531QDgUVmUSySSLiVAiNkDxGMF59kTgiRF1SrilSFrQQ1HghHgij
	/dQpZOVAXBAJU18Je+cgo54=
X-Google-Smtp-Source: ABdhPJx+DPjSzjXBK5lb86ohjWIbgKJOIJx9txFQTeLS2FEzFEmTAQ5jXo9lyaH9FzSl5ICTfXp9/g==
X-Received: by 2002:a17:90a:d486:: with SMTP id s6mr261805pju.115.1605046269877;
        Tue, 10 Nov 2020 14:11:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d03:: with SMTP id s3ls2771445pji.1.gmail; Tue, 10
 Nov 2020 14:11:09 -0800 (PST)
X-Received: by 2002:a17:902:d3d4:b029:d7:e936:7651 with SMTP id w20-20020a170902d3d4b02900d7e9367651mr8545301plb.57.1605046269349;
        Tue, 10 Nov 2020 14:11:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046269; cv=none;
        d=google.com; s=arc-20160816;
        b=JFPMmPtxFrSdDblVjImVBjPasflfF0r1miecy+e+Fy2wUt7/WX5xjQXNpsbn3z+r82
         kJBCBAC48YCZQ7tBPLJBArM8Y8ACjjhpsMEVrXE7gc+2xKRfqNI0MChCBq8s9eOOcdqi
         8i8vtNu84bStwQMiktOX0jODFSFlGjC0rW5+t4ZCPlVBZ8tILoZ0J9+VGDCmmdDAHgJH
         EJDcUuIfOVRtMnBEjn5nz/d97xWSJmKo2w4NeiOUtV8oggt2E3125MpRdlWO8T4iIMVg
         JOEfgi06nH99h9bvq1W0vFw2PsB/wqCASQCxfDFoZDDOffXscstfg0aLToTVaOgg6yVg
         vdCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=WeR44QGUklCpbQR1zDrK0pdbRnj18sDGWIyeDhpbDFs=;
        b=xhTfroUQc7WrLjbtVL2pSIxz5vtb1Yl8xDQ8QIYAMTPRtqY2TtE2SMMYx5WRR3xxzd
         9NpK8nEhTzHZKODpTZpE8X8KhuKecnLDafAByNo+3EHGHwF287J4Djos3YFO+ibFrv1A
         s7nwoJ1W0iRo+OYi4QEwuo6peEDsL8g0VDfsF6c64oli+w7YhHsHZZN7CpO7yJpHvS0A
         jdbVy9mI9xK6E2D37XiY6IDGKjnM8ijXPq47Kq4yeakYYl9Yr9eVNSkqPsu0wz0RWw5x
         fRN/F6uirP6ZKkHdBngjbzDO40LS371YbCgzPnR6y+WoW3NCk2dT0H499lAjcJYqcpws
         2/+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OW/d993q";
       spf=pass (google.com: domain of 3_a-rxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3_A-rXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id i4si357895pjj.2.2020.11.10.14.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_a-rxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id s9so204141qks.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:09 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e65:: with SMTP id
 z37mr21969980qve.39.1605046268416; Tue, 10 Nov 2020 14:11:08 -0800 (PST)
Date: Tue, 10 Nov 2020 23:09:58 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <8cf064ae41eb86697bd3aff5adf6b546d05351c1.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 01/44] kasan: drop unnecessary GPL text from comment headers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="OW/d993q";       spf=pass
 (google.com: domain of 3_a-rxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3_A-rXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8cf064ae41eb86697bd3aff5adf6b546d05351c1.1605046192.git.andreyknvl%40google.com.
