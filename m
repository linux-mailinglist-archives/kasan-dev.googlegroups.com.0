Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFNAVT6QKGQE3EXA2OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E34832AE2B6
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:33 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id r15sf1104777wrn.15
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046293; cv=pass;
        d=google.com; s=arc-20160816;
        b=isWDPJd9ijQ5mDR/gK79dHY84Iic2fuQ4BVOhbGipJm+9Xcq97cCfH4s4B7BQrVgrC
         BVb5l+A9DkbJdgy5WRuMKOYTWxOcF7sDxVwXb9YhX6CL2rXohpJ8lbL+UrpOrxaLaz3D
         ERl3UoOUkIHu+msrQe8HXO0IWjTIJOiONCXY3QZgJF6QTBv4sKl5BsH3aHK1vzTVVk3w
         cP3RBDMIvdBh5jhQDeg6HwH3EVjkHYEqpNkus6bGn2I1DfCLJ7ZFD7xzj6eFgZ15w6A5
         hcAL/q9tiWw8LdOVNBJIt8/ISGACI0j5b1vrM/yzMYXNLY9B6JLLYO9eSh37LMBuPsLh
         pcFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=DLxx9kpqVpNMl/L3XyXQOnSyGNOP3PvPvJfCLDNMF0I=;
        b=ht/ep2HPt+PQ8YGoPH+KZJnrvgaZh7LqY29EJSUEUaFNGXeV7cIN/nXfRaW6TNpUpy
         VF6XElHl34YZnfBqdevrOrSsQqAMRfa4//ErqMqvEJoZf3oHWy+bsagYz6y6m+YXTi6L
         pXoCxGQqCbPcVQkCZAS3xSfd8Ecgi//k7wDLgIFY/3MRDAERQAVVk6+YRpW3RC/8NHeK
         VYio6p8G3x13PhXmaRRUZ5mZNmo1T707hIZ3pycybVq4z4sxTJgUEOoeIE3x3t2ephP4
         n9Me2NKhuRjn/CzpAuTWKGZw3jl3LoDqCwITFGxO3SFmHTbAfwDBvkgR5pKnMZWKHxkm
         1Isw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F2II+MEb;
       spf=pass (google.com: domain of 3fbcrxwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FBCrXwoKCeMFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DLxx9kpqVpNMl/L3XyXQOnSyGNOP3PvPvJfCLDNMF0I=;
        b=o7zp9vxmSRiC8+h4OzisEWe3Zk0VhBN6TEiOsaPKZOsJTtEvGLozwZ6S43JXCsOeX2
         KVxgd+ejLJ33ahlg+7sHOuoRVZKlcCM9Z5vc5EgDo6WEUGb5pKOVdwzooijrzFhgbMds
         Ka2mpj9YRV1Cosnj3te2h7gw+9B5mE4U4TW3wjBpu5uUzZKAIdi0NcciZ7kTZrSeQe4h
         IjJdqBl5SMYFeTNfcnwG7+LUxeFJrOY58QPFbDAjN3W5NYNmtkYD9qzmmERt9N++/WQN
         OFcve9sokz5DOuLEZ+bNsZEdLD8DxmhsBvsg+lWj6h8wyD0sTSusxQfDDVYtR9zuAgFH
         BEqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DLxx9kpqVpNMl/L3XyXQOnSyGNOP3PvPvJfCLDNMF0I=;
        b=PpDokKaKy5+XalYWNFwBVjMWJi6CXxDAWTAHCm7TS2PKS2x416vl4aWzqnw+0pTzJp
         +/XuPyBPySK9HKJyfeKB/KgbAx70JbyxyCel1qDVxAEODqY8U7+SyJXHy0L2PTZuGT2i
         S88l0Gk2M8K8J0Ox5CALI96/RFFT51fP9G9W9Shs57wFPcArcAK/VqodEj1KadHFffJw
         DfhpdWskhhvSKAFoJE9HXCGMH5gKVCdZvfa1kibMsiGLIoA0BCdkHBsRoLWfUpjG3msy
         m3BrHnYdEz99Nt+Z4+CDQTjoC5OmB0mcfRCnmxylhPObjntcX6OwPpR7RSdkM+uYEbRf
         flfg==
X-Gm-Message-State: AOAM531YZx2fqbFl1byxmVzzObJ1FR3H5w1GluFvMqV2d0/G/jDqjRVx
	7S3lYLzwZbK/vVoKYW2cen4=
X-Google-Smtp-Source: ABdhPJwW9S9cH7JeGEVljSYkgPhBnl8hRsfq8mKT++shS0VmjYLqPXT/7uL20H8DINlvpSVFUrz8pQ==
X-Received: by 2002:a7b:c772:: with SMTP id x18mr226376wmk.185.1605046293660;
        Tue, 10 Nov 2020 14:11:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1bc1:: with SMTP id b184ls210398wmb.1.canary-gmail; Tue,
 10 Nov 2020 14:11:33 -0800 (PST)
X-Received: by 2002:a7b:c05a:: with SMTP id u26mr229413wmc.159.1605046292938;
        Tue, 10 Nov 2020 14:11:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046292; cv=none;
        d=google.com; s=arc-20160816;
        b=SDr5ZGSgmkzU1/++TkUgahlasa2WvRdCcsxZpJYXpAk8nFy+9v768lNXtyg06rAA+g
         tsoh66h+V2AMpfDNv6cnfYUaiQLgWTuDpvnhmAB6rhp4TRHy5RZuA3hTEFoh79jTfKdU
         olsWif1EdJs/D+/En2ewG5AnC/PeX6K3CRjbtk2fvlOhlTErYbOecfNGbd13zJ3aYwY6
         DJ/fXX4t2rmCuUBQWqrVLo5pzKa62cVDnyE+pL2gpl8YNG9951brbqSpG/M7JSWDxkPm
         /khok2rSycwIAUXHc49apgvzEUxSz9ezppqabKHIvvLFIlzcs1kgaDfcr+Us6NX8bHiO
         lxjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MhFr117w58FsSht0PRNFWn6K/+nJJro/ruUDoZHnt9k=;
        b=SzbUf5k83o89624PKvIAjMlsVapeeQGSliniYMhhP2r//YWE0hX8bJ/ztvWB76uOhc
         kefOzAozrtusqDvwJMbgOdk9bSwYpJKd2pdFhdz44A1JMu8mvjljU3RR9KBkOvKI2dmy
         eF8jT0VJynrkk0B0lYIIvIO2RieQEOPx52gmxG/LbHrDbHoPr+5VsdhqtNvI6cfKYq4h
         zV4GLBDZ3uM0hhwHsH/0NX95p6z3+N1g7YaYCa8fSRFKX/3tOt0Wi8rZ9vWcniuJuhC7
         AFCczPxwotLQwH5d9HWWgyt/V9e0UU1AayYoh60VesSji8pg4Wr6lHCbxguNfUI6UGCx
         rbEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F2II+MEb;
       spf=pass (google.com: domain of 3fbcrxwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FBCrXwoKCeMFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id h1si1231wrp.1.2020.11.10.14.11.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fbcrxwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id w17so5432417wrp.11
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:32 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6484:: with SMTP id
 y126mr211278wmb.141.1605046292476; Tue, 10 Nov 2020 14:11:32 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:08 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <37a9648ffa16572583a7513323cc9be88a726eb1.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 11/44] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=F2II+MEb;       spf=pass
 (google.com: domain of 3fbcrxwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FBCrXwoKCeMFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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

Rename generic_report.c to report_generic.c and tags_report.c to
report_sw_tags.c, as their content is more relevant to report.c file.
Also rename tags.c to sw_tags.c to better reflect that this file contains
code for software tag-based mode.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: If77d21f655d52ef3e58c4c37fd6621a07f505f18
---
 mm/kasan/Makefile                               | 16 ++++++++--------
 mm/kasan/report.c                               |  2 +-
 mm/kasan/{generic_report.c => report_generic.c} |  0
 mm/kasan/{tags_report.c => report_sw_tags.c}    |  0
 mm/kasan/{tags.c => sw_tags.c}                  |  0
 5 files changed, 9 insertions(+), 9 deletions(-)
 rename mm/kasan/{generic_report.c => report_generic.c} (100%)
 rename mm/kasan/{tags_report.c => report_sw_tags.c} (100%)
 rename mm/kasan/{tags.c => sw_tags.c} (100%)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 7cc1031e1ef8..f1d68a34f3c9 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -6,13 +6,13 @@ KCOV_INSTRUMENT := n
 # Disable ftrace to avoid recursion.
 CFLAGS_REMOVE_common.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_generic.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_sw_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_sw_tags.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
@@ -23,14 +23,14 @@ CC_FLAGS_KASAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
 
 CFLAGS_common.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o shadow.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o shadow.o tags.o tags_report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7b8dcb799a78..fff0c7befbfe 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains common generic and tag-based KASAN error reporting code.
+ * This file contains common KASAN error reporting code.
  *
  * Copyright (c) 2014 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
diff --git a/mm/kasan/generic_report.c b/mm/kasan/report_generic.c
similarity index 100%
rename from mm/kasan/generic_report.c
rename to mm/kasan/report_generic.c
diff --git a/mm/kasan/tags_report.c b/mm/kasan/report_sw_tags.c
similarity index 100%
rename from mm/kasan/tags_report.c
rename to mm/kasan/report_sw_tags.c
diff --git a/mm/kasan/tags.c b/mm/kasan/sw_tags.c
similarity index 100%
rename from mm/kasan/tags.c
rename to mm/kasan/sw_tags.c
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37a9648ffa16572583a7513323cc9be88a726eb1.1605046192.git.andreyknvl%40google.com.
