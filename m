Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNW6QT5QKGQEYG4ZZHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C54E26AF50
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:39 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id m199sf898096vka.15
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204598; cv=pass;
        d=google.com; s=arc-20160816;
        b=XZHsmj0rL1UseN+vv5v3ty2BQL/wra/2Z/Bok1WOMZ0oRYH80q8VOzOQ9U3c/5v363
         QIpDhyN/6+a6oerpVrIhXYupsCCjsFySBK5gdfZSdHa9id8+Xgi0sLQMQsRmy1LIbVuc
         wCY6lYRZTqLH+kSUYqjtFDAlDRobt53jirq00w3wGrPQbeVbRJRp+VA+WF7BMCjdYr1Y
         WD6B0yvrldCRQ1Fka66Oi6WBrcKoR2IcmjurJPhUsaoZVHEoMcMIfXPPqtYu9pdzFp9C
         VobnZq1dcZ4gnZ+gjz8l1nSHrTq6Xtmk99Rnlfs+a0t56V5KuL1Tuav0JLsyxMS6JGfp
         wNMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=w2UnVJq2jiI6z08MDDJXp4RDvc5A3enDXxZ/AM1auY0=;
        b=vRExMJBQz54a10y7ePxzPNaRoOfnZ8mBMD2rS90JiQVU+TBisDgKfT5vpi0T7l+xv8
         QiaHwZmF4o16IYrtKebsASFVqG2a6bfrgxyiJagES1ZdForpRO76sR+oClULu//c8vNt
         84Sny0wYaPDWl0jy9EFrEl5shnDKSVFyVCPkS54la+YsXrxrjDrtQOpDJ8Q9kft540n2
         dZeTaAmVm5l486uiOquOWLiMXmM8J71Xm0mYbikS7pEpcioc6Prty9mUa8slS54+IAHT
         MTzx9LilVR8jG4UxpMl1IOqo/IxyJk3ZNRWYXtJzc/Wzy907KBi/+y8iOQeu03q73xII
         4AIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dSJTHqOZ;
       spf=pass (google.com: domain of 3ns9hxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3NS9hXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w2UnVJq2jiI6z08MDDJXp4RDvc5A3enDXxZ/AM1auY0=;
        b=lF+3Z10Vofkpqnr+8Z4/JtOiTki+Jvz2+dzl+ZdkwHI0q/VQF32JXUS3IfNzu1eDFj
         aVP4uUs0BTKUt76aLJcxPIvbYnvHs+veO/GLuRrD+lc82f/tzSaXc5nahW16jQb9NATE
         bzoFjDW40ZbZyf1QAhuIfeWN4HAXRTnANclUG15rASjYU9vT2vDaO7Rv4ocgAPm4w9Dn
         jIQ9bvn5KW8O5dAhMHaFEcmUKdGQwbP+JepF+6tzDCdpr/BJOtvEpwS/6qpyJIcjQ0Iu
         UAptYV2e2Cxfy8ocPqk1q6wzol0j9BH9NAc+A+58sj4HKKIFhvgBk18WOnL0uHPy5hXD
         fXPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w2UnVJq2jiI6z08MDDJXp4RDvc5A3enDXxZ/AM1auY0=;
        b=nYJJg62J8nTcgMK27NzepfbwXkkXzl+QTbfR/PdE6hOMBE6GzMXnJg1WiDWkZQozRG
         hPqEAd8pDwytm7NIoy4jqTWYFL/DncnhTPlD0IbXztt4vxOp91Y31fB6YJI52I4sd+im
         dgqzn7wIDbH6W6ibmtdbqZjBrz7XdIrP2vbcLKQ6XDc0mgPJpGzBkbuZSseZtJ30/kN7
         RWloMDRSxkw38IvdPDhmVx1r0Yapxp1v6vr306Uc2XmHfsaF7wamCFYBV2mNmldRL2fv
         Nt+AcF3wuSI9n5u8twqDQ41Qbai5+xumYd71p7wrt7a+QAlObCDevbLATCT6BGj0L4+1
         y0Ag==
X-Gm-Message-State: AOAM530kPFjKR/VFRHDAiSkzDDRcMAQki7i2l2MjyvHPp5bdi+7t6LBG
	tw6GaF34QDJLfQTGO209sRs=
X-Google-Smtp-Source: ABdhPJxJTjmnuLH+ONw/8LCvUFQiRblh/fZmxTgOXweOrn70tua+rmIppHVdMA4xVAClJbbkzMOVLA==
X-Received: by 2002:a1f:b486:: with SMTP id d128mr11767783vkf.1.1600204598331;
        Tue, 15 Sep 2020 14:16:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ce11:: with SMTP id s17ls17636vsl.11.gmail; Tue, 15 Sep
 2020 14:16:37 -0700 (PDT)
X-Received: by 2002:a67:fc48:: with SMTP id p8mr2891534vsq.53.1600204597753;
        Tue, 15 Sep 2020 14:16:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204597; cv=none;
        d=google.com; s=arc-20160816;
        b=hDcD843Be26cXe/4HnCuPPyAJBCM2jBQYKiCbhmWO9EYwPNlC4nBWZI5dU5cOvslPO
         DgalkCauI6EqkF8Ub1LqACXeYw94erM8DrXDUB/mIZuHkDr7nU1rTj6OlArqxd6vDd9B
         T2Q5Rd9f/GGYzqRDoKU3dQWVZId6li5MevZVQKuY0wtOnd9Z3rQIefi3tuzmsqHiM9PZ
         xgd6ekUnSHZvQ4hNTt8PrKTvs/h8FUWFRRqpFOdQFDMwzqKyUpBb3pKf71N2vGIYWwkw
         vNJrl7YoJ2JtK62J5ZZy2CaIOY6jMKMgT7exEEkbq3ECBaGA9gNhlunkIbg5E/kdrR7H
         1wdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=rBEpAT9/SFMGCMSd5Os7EsFNXqLe39zVSJtjGGUatVU=;
        b=exbP0uN0DGtZLt8O7bL1VozhX+qugvrKff2MEyKtKTyq8p91UZeqHk/UOEaF6dCz0V
         hQjK6hMXY+7LNatKHRXzweC5KSAL3fa4K3pw+7rYFJHGZzOyL4WFATYqLuD/rYL1Vdmk
         uawlyNT/Yitg1mfEuiz2GGvhHuFZPp0OXKCWJs2dbMwJ+uzecFtq163Rf8AkbmCS4VRU
         EFkvgmrKMaHwZretlwH2hddQH2D7MB+mgviGexqGO0587NB65prrOXecbxXj6yfECGYF
         7snRNqipMtQk6rehAygFoqTpWi5KhgTFDtWt2zWcKD4pcrFDY8V9wLo02Y0ENlH8ZSf3
         cciA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dSJTHqOZ;
       spf=pass (google.com: domain of 3ns9hxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3NS9hXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id s11si746486vsn.1.2020.09.15.14.16.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ns9hxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id dj20so3140557qvb.23
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:37 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:58aa:: with SMTP id
 ea10mr3757654qvb.58.1600204597332; Tue, 15 Sep 2020 14:16:37 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:48 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <b154864a1b17319c865fddd01a4bca5aaa73aff5.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 06/37] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b=dSJTHqOZ;       spf=pass
 (google.com: domain of 3ns9hxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3NS9hXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

The new mode won't be using shadow memory, so only build init.c that
contains shadow initialization code for software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I8d68c47345afc1dbedadde738f34a874dcae5080
---
 mm/kasan/Makefile | 6 +++---
 mm/kasan/init.c   | 2 +-
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 370d970e5ab5..7cf685bb51bd 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -29,6 +29,6 @@ CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-obj-$(CONFIG_KASAN) := common.o init.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
+obj-$(CONFIG_KASAN) := common.o report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 754b641c83c7..20f5e1ab8d95 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains some kasan initialization code.
+ * This file contains KASAN shadow initialization code.
  *
  * Copyright (c) 2015 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b154864a1b17319c865fddd01a4bca5aaa73aff5.1600204505.git.andreyknvl%40google.com.
