Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3HNRT6QKGQEQ5OWFZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 414D12A710F
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:10 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id w16sf14058780ply.15
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531949; cv=pass;
        d=google.com; s=arc-20160816;
        b=QacxX7tfRohpvTCozFQ57MBuuaQG+zTaxg8zDGQuf9oqunWqzqlELcWLsRvWdW4csZ
         MK7zpeUpR9U+XnBgRS3v8XFJPB4jw+YhAxVVWhTbVMJreAotN9Nuf66e6Ez0ElfB274A
         E16/sFt05QT/szj7tfo0+3Ly+NqQsB/N+Fha0/G558RWeN+SLjoVU7vOYrzUalc2vxhu
         A9ibemruY778vCA4BxyiBiiWcAuATwC4QNyLguWEEE8hm1p+WpcMCejrnB0wwvHHqyA7
         qYXrHcQ0OcEMINU2mnzj3P0lzhUeS3GY+4171EH52nB4+s/GDWejmaYyEpQxBl6ukwXZ
         p04g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=J9ZyJ6P74DRoPn2PyL6BEPa5tjU6diLrfNMk1BMVqag=;
        b=mTCbidugPMOQqB8gfgvdwGsiNEW38oUJafhvEbxLR2V5/5CzT0qt7vA2caJMUjQ4v8
         nS7Zbp9Z055o+k2TOeSkLZ+nijHuQXvgwdV/csVviDWZ3DIAc9KCEGSWyIDpd5adn6dl
         y1qO5MxtPRLE/gLWQTGexSRFEoLwEFnqSRPuwEUKggYcMrnNdh5lcZ6X+3/BPnlnZl/v
         G78L8/QFOiLP8dDTIrHvx5As6mFu2qR3eg4RSKOlcfafL33vuW+cjGRNAj3basX/ckPM
         Vx7VRMyOX4zL2GESfN0x24jWFDvhbLu6WJbwRtxGTXzhbyPExTDZGTm83F39TY3i5eEY
         BxwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vfRlFfDi;
       spf=pass (google.com: domain of 36zajxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=36zajXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J9ZyJ6P74DRoPn2PyL6BEPa5tjU6diLrfNMk1BMVqag=;
        b=JKRWo4E3HVonDNrx34B7nnPLJ3LfF1v5Lsn5zUBE53l4bqR/wBoP+j08Ilp4vetd1v
         bZHADG2+w9NlvCOI+MYlTx3n/HnuYKNxuLGxf+L07PB4KZIAJCWdnozEqU3hqF41vq6T
         hOmFMqhaGToMzRstnObksqbCPHQbBUcnkLdnuDXwDUXcRZIhQJ3XyDmk5dP9CigKY2wX
         bE0UZZ6QhZ50IrOdrRKz0N5LD+hWhRwMeySKfVoQg3TCIxm+hmrHrHoFXSPyjT39Ot0Q
         0R+3u4o9OVkT1VhIm48axXs1iITgpxh3NMjelteOr7LW+dnL3jlQo7I1mvNhcrnHHLQb
         rMeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J9ZyJ6P74DRoPn2PyL6BEPa5tjU6diLrfNMk1BMVqag=;
        b=G58eszKZTO8Xk2/zy9BiHxHWOW2o34XiSoNgZvdebVcksyisIcLbnC0sJ4ZbdQy05Z
         tATHYeNhNIkHlB1ufvVfGB/vn3ne9y++pOzDrRJnaLx3TZUGWlDt/waKtd5wpUmluQuY
         90miWRS365ezVt+GY90nxnx5FpT38Xhax8zknlzNn3Hl17RxdVSsuJvO/LrduGvXlpqm
         MmFOBZOO/lc1d3Y/AreaWdVKLuMkkTh/PBXIWGsEvAp+gbvzVMWc4riWaIJllL8SpT24
         1vR8Uc5iqNkmKyO3DH+f0KOT7B7zqqo5731T0YFcCpN0ag06+qDy8sppCvFAsVGbJyks
         U0MQ==
X-Gm-Message-State: AOAM533sd3AslMu7qWeWJjurnTqXk0mCHgRKdyNr1Pcd0Ss1NK6ccWDk
	sh9yiOU9Yy1RXl9W8oVtSxk=
X-Google-Smtp-Source: ABdhPJxO1timxVqAVSXU32fEuwVbrZCuOOsaFFQgGZyF87UDx/yFPzqhQHUQ2x9ftOkWqZPVsm5QJg==
X-Received: by 2002:a63:e:: with SMTP id 14mr306849pga.426.1604531949020;
        Wed, 04 Nov 2020 15:19:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f601:: with SMTP id m1ls340116pgh.4.gmail; Wed, 04 Nov
 2020 15:19:08 -0800 (PST)
X-Received: by 2002:a63:1c21:: with SMTP id c33mr302156pgc.161.1604531948456;
        Wed, 04 Nov 2020 15:19:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531948; cv=none;
        d=google.com; s=arc-20160816;
        b=qxSgO44toffsswwQbu3PuAq7bQJ5XFnUX26hDTQgNLt8720ZTMck51TJZO+T9wmdOh
         pvQo225oQ+G2j4zN5Im2SZ3hpxXKsY1uCG+vejOWVa2s7TJVDocpRwSXoGzvFWetlmmJ
         JQxqDYaodptThbYuSNksJp7fg1IRfzwwU7TJhpagnYTZdfWagNmeJRUPP1wt4Aky5HWc
         ir3yeUt78eTkxDdHl47hCv9pGSMbbO7lFYlSnvNDPAp3llTT6Tx9snBEupJHM+RONoQi
         G27A9PZLiBT59I3Iy6sm5cq37xiFm/zl9DzG3MfH5b0HthdLjAI/KmK77KDQuIIBpuj2
         oZOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=EAVCYXK+qwXTj64iW4lXgFSidDhKD1r7M09orz7ePT4=;
        b=qJ1ihfRiQsO57yQFCuTJhbvRfwK0D2VDNmKAuxpllXPYUovwSbybycejrQG1p3G0DX
         4/5NGeGJRGXGgNnmhvYcbR5VW809QY7938UGqmw7T6ROuBcaIqFcN7DLNkXTCBjE/aEa
         z2sAc80i/0gJEgazptUnnZ25ioWHwDA7p32E4cGLQc9qryfx9mah0maE4OuhzWga433Z
         CpgjFk4r+2/3Nz/YRoVUaEUd96i6pzuiT/yUK/W+wsPhCIEKcu8O+925PH9uanIYDf6W
         Rsh3peCdHOxpX7fLmIQcH3xQKeHXaAPlR/vTs+jAqEy94l4BffFdtLM/mUIGX5KuBo7n
         4xLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vfRlFfDi;
       spf=pass (google.com: domain of 36zajxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=36zajXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id ne10si172266pjb.0.2020.11.04.15.19.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 36zajxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id t13so13847812qvm.14
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:08 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:40c6:: with SMTP id
 x6mr284828qvp.20.1604531947585; Wed, 04 Nov 2020 15:19:07 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:16 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <d443ab06c8726f117b1e9e5585e6954a40c6a323.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 01/43] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=vfRlFfDi;       spf=pass
 (google.com: domain of 36zajxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=36zajXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d443ab06c8726f117b1e9e5585e6954a40c6a323.1604531793.git.andreyknvl%40google.com.
