Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEET3P4QKGQEY3Y2RJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 4394F244DBD
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:45 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id b39sf3509706edf.15
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426065; cv=pass;
        d=google.com; s=arc-20160816;
        b=UIOBoDRFGbYAksSKfQrc3sxvhSOVbR6NklCXhiF/0D/wnIRBC1TtzX9OLHLlStV8yV
         Dp/uKFOgV3MOcJT2guYWQNyzJC5Xo17IIOWSsiiV4rev5REwQ0GSJ6pNktSn10NUyW4l
         MKuTZMZjV0mAisOt/TPEmOpHir/QadVlI8Oq1bdx5fUxwXvfebr19uLghqHnw6DBey0i
         G3uZLpOR3Il3YpZoxNpC6lprJy1kpRP4Mn96JEvBC8Vpd3DAxJnAvnEXWIZKnBJCDQXN
         W+GPWbFNBMaJLypiYqhAz9/nwYVdMTiOgQis/XcS69O3KvGAT5x/2CTYkRrdNYvJwdwX
         18xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Fp8qzE5lLn6MgaRKh78uTAE0DYXmZxRMS/6Z2FD7osY=;
        b=tMP7868qagfVjrZI6I0fgCVLbZx6gT8yoJMX0iPuI5xCm+0aeUqH+CiHBBxZlpGkcr
         KB8RbdMLcjpCdk5tu0SalbxL8xFE7YSX0/sO/2FvaLL8dc4/cUS1bvl1G8AoMU2fm6Nt
         hLFYmgU6ThFVfATNz9T/iuS/YQvlzROdX+z8gxSHp7HQ2xGwMIEPHLXrwto+ditQR9vP
         C9Lh8VvVg5IrfSUkICkyo+qp0N2oDvvPUr2dZ8pgXTCHVkGe4yu2LwieuRfpLoZJY4vn
         hihPqshl0/npZP3hJMpUx3AUkod3f04lhLGaRO1hJq/n0mVA7rfGG3e+fiDdAaZ7pAha
         knQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pPcBQTWc;
       spf=pass (google.com: domain of 3kmk2xwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kMk2XwoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fp8qzE5lLn6MgaRKh78uTAE0DYXmZxRMS/6Z2FD7osY=;
        b=XVnBCen6u4d7mTxcvX60TAdd3rhQ3UPvv5O0cBDMcAb3lXtaRzTj/wZhw4waKBjq0y
         Ot0SR319asEjaWaWrhYkuKrZtOaIo1edwmcKCPde9+eCF+EFzgQ8Zhk/zxQxQ0ajJ3kU
         8lfqKkb15oPo2yjcEMIEGUtgJa+03UmKEgoE/4IliDJUaWF7hJ+i2LZcGzY8yjJ7HzEY
         t5cFu5TENUnsFOJSg2QpaQ4gxCMf1I8Ps9LDptF4/E8h1cjj75OXB1GnyxsOh4dFkHbv
         /AjclXtB4YBtXmUQR5R2TskduytWnMzetKo+qRofCxBZ80/8mU6yI6tSq5KrKP9QMxQz
         2QNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fp8qzE5lLn6MgaRKh78uTAE0DYXmZxRMS/6Z2FD7osY=;
        b=EW1HzNoa+gRRukuRog9z7I0bbVWCObMYFd7pIaQewH2LeFx+BlY/J83qA6tghJnWqU
         FG2N6qR2l3SHXV+zrlJmgoFm2LTL34vqxw4KmFQwN6n5vqTC9IMbg9u4OCqs8NCvv7/b
         RJvFGg6M97lY11elFIt3QDqLItgC0rZNBhRiNyeuAG4sHkdkAEtlfLuXxgGi6yY/Zyej
         ZJuYRrp4NOtqM3y6VD3w6gSUfK4YZazhTsQI3UshhXxxDhMOBq0Ee3LbNqvfyZJlGYLp
         2a98MmqWKu/Dn/90kFXNmH6OSPOVjFQrHCzVc2JwqVQwJ1rUfMBFY4PKvXQ55jEZKMME
         w+eQ==
X-Gm-Message-State: AOAM532KvDFplhdsxOHUosAXjCJmQ+1D47I+z2ZzumzlzthRNnvlywzr
	ye7Av2vf2KzJaKpOEhJi0t0=
X-Google-Smtp-Source: ABdhPJxGonuWhRnwDhQPb2vpZFyDfG5DNPTxcMqfbPJ2pG2lARp/i/FmCdlxFy/APcQf99GfQfPZOg==
X-Received: by 2002:a50:f311:: with SMTP id p17mr3402165edm.37.1597426064982;
        Fri, 14 Aug 2020 10:27:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fb86:: with SMTP id e6ls1077528edq.3.gmail; Fri, 14 Aug
 2020 10:27:44 -0700 (PDT)
X-Received: by 2002:aa7:c915:: with SMTP id b21mr3349144edt.17.1597426064504;
        Fri, 14 Aug 2020 10:27:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426064; cv=none;
        d=google.com; s=arc-20160816;
        b=pvR3r2fNspO4pa6bAR1aXPPMhZdNdJ62OeL0QlKHdR5THC5ntnJ8Lk+QXVuKNkFiaE
         ImeVD41954CZtuwg3i1H95BnwDY/u0ASOhQWRSUIFOOnhxoHXtoaaBOwVeUP3y1Mbh7k
         DkzhBod0eg8hlTFqo+kWYsKM8oQFtaczUAARFQBtUCHy1PIBkeUB7euU18NJ85htgBxl
         8fwetFkMG5OKnFfCuFqTS/opEyalyp0+GiIS+Bml5FEUunpH9Nd1HT4YmX8CQEDA7q4Y
         0xR447zeR3hO5Einct3GJtJJZR6KT2BueE5cS/ABiPi6DQsFKd8e03UlRniRT9sAWAYz
         dMWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=np+YjQo4chu4bS0e//GH8nyclC7wFRenYBsdsyZN+zk=;
        b=ZJTVqjUPUP3ME8x5raGqa/OaRfWKRrml71GpLnAQYj5rU3z19D6G9lRo3qgKm2qRZP
         yVq/fvqORFadKIaDxVTZ3ay1oeUJ2NCybILPuiu6jZSOH+Eibp3XkLKJE1wSaNwSSryh
         wOo1XPCkXodOXCQnZCEg0e6hFvtz/VEEXU1xyLVRafcP6NP9CG9cBb/cRyw+ufVOHpVq
         p108I6JDwT2lUJNgcc/wnk4a+48lxeEK36pCZr6HqRleEhUOXwoy7EGjAH7smYLHmPPn
         gqIq5HL21AtIku1LjFkXxEB/Y+Lnem0UphfTq4Oa1dfgUGD1HBqbxdtDZ1RjLF07GAoR
         MoRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pPcBQTWc;
       spf=pass (google.com: domain of 3kmk2xwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kMk2XwoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b6si417613edq.1.2020.08.14.10.27.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kmk2xwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w7so3576855wre.11
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:44 -0700 (PDT)
X-Received: by 2002:a7b:c8da:: with SMTP id f26mr3553163wml.126.1597426064102;
 Fri, 14 Aug 2020 10:27:44 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:50 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <c628647bade1a8f80dca858b0c0fba74cfa08271.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 08/35] kasan: rename generic/tags_report.c files
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
 header.i=@google.com header.s=20161025 header.b=pPcBQTWc;       spf=pass
 (google.com: domain of 3kmk2xwokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kMk2XwoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
report_tags.c, as their content is more relevant to report.c file,
then to generic.c or tags.c.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/Makefile                               | 12 ++++++------
 mm/kasan/report.c                               |  2 +-
 mm/kasan/{generic_report.c => report_generic.c} |  0
 mm/kasan/{tags_report.c => report_tags.c}       |  0
 4 files changed, 7 insertions(+), 7 deletions(-)
 rename mm/kasan/{generic_report.c => report_generic.c} (100%)
 rename mm/kasan/{tags_report.c => report_tags.c} (100%)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 40366d706b7c..007c824f6f43 100644
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
+CFLAGS_REMOVE_report_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
 
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
+CFLAGS_report_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o shadow.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o shadow.o tags.o tags_report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_tags.o shadow.o tags.o
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7c025d792e2f..f16591ba9e2e 100644
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
diff --git a/mm/kasan/tags_report.c b/mm/kasan/report_tags.c
similarity index 100%
rename from mm/kasan/tags_report.c
rename to mm/kasan/report_tags.c
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c628647bade1a8f80dca858b0c0fba74cfa08271.1597425745.git.andreyknvl%40google.com.
