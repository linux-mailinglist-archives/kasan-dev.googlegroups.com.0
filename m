Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR4LXT6QKGQEB5KRQSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A6092B2804
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:40 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id s16sf1608282ljm.4
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305800; cv=pass;
        d=google.com; s=arc-20160816;
        b=BKsY/5SzBoppGL28sMA1dUg2E4m4CrR6N0qCN+ANe0e/0uVF8xkmlHkixEMcIfn5ZH
         WlwNxN1rl18r+WG3NtnlQXXnR4Ef8WnfTC3EqPsxCSJH17C7kFH6twtErfVJmW/1SQu3
         IjnIPxa+J4xaogc6AVWDX7UR/M//zNuYxv9pZm/D/Z0m90fidlqNiswh5T1eiaOFx9wg
         AwSu+S4jq55RaQFuqtZsuZxCDeQow4RWbjU0IpXEhyosFtVdfr07pmFvled0RQzA5vtQ
         HqxXXqybc8No+Z579RIMzZiH0yjsOzqaKbxSjR/JWLUf7L63LWQ3dafe9n6YRJ1IfCYX
         NbKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sHXfdzWXAlmRzQrUNtZnWCshh7Amtl3E7Mqc1yqpQ9Q=;
        b=kk57Gyb88C/dNDeOJ4Z/7BWqAT50NMCN4D4i0ygMuflEDQ8MGjeaQFaniXLtO5xP6h
         ab2f+E/bymK7F7D1xAzBf0RndVD392ccfPQaF55GNN/jKgCHQtfpSLPFcOC8xtXTJUi1
         pF0al9JT06MiZFGPKGjqeykTsb18SOraNq1KmmxCwDynvweaxNYLD9AM/pSpD3OBGWk9
         7KvqWlxkWXg7qm1mGiE12oaNz8/Na7qjzRjG7SE4f6NxDumyrhje1Kr/vsx9ENg/v8fI
         hYkyEQ1BgGaMh+LcKYq+fyThShGuArTiEmXgQiAJcY2kFdwcD1tGbHwMuuQDD4flWYeW
         /gpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ANnqD32l;
       spf=pass (google.com: domain of 3xgwvxwokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3xgWvXwoKCZEv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sHXfdzWXAlmRzQrUNtZnWCshh7Amtl3E7Mqc1yqpQ9Q=;
        b=TtDV5Vy2kTGzqsPc8RbSu/0DFyjQ4NljXZWBg2jQJMV89cRzfDITRrjNziW2ClZrvE
         3KtA51n9vHr35XUFA9uJFt2GSJ/sAjyruc4oNoinAx7dO8zFbROh2qNDFfdK3UTfJo6T
         bWWNCo+s0dG5DLNwobgRUwZVgZPbXujSfIa7aH0UN2BLaUymitZ0Rvah+ttyB/MeTr0q
         rtRjUD2SjdxTZeUf3uCzJZUJmIH0BnPzd6FIpww67EyL7kuDnEb7VLcUXAzLRmt7NLEb
         NKzf+j/WY5z3hjwPSxNEY9VVQSTHdpIEGl4Qm7uKGsJV9Ch2Ct87rIzhMp0QbtCC0zFY
         CSVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sHXfdzWXAlmRzQrUNtZnWCshh7Amtl3E7Mqc1yqpQ9Q=;
        b=cIVqugk5cs1bBnjlqk5V5e27EedKOmbPJ9vDnPDaK/t1Fxm5wAFTwep9JGMTQoTGf9
         gUwdKt7h2Xwqu1o/m0SgPIyZjWDMuM5HK6WavfGuWduJ9Vl12h6+dJlrCzF8efmH1llC
         RW2jqKI/+QF7N/2lt4lRoHVobx2jbvs7LaWN+6HmhS/bYx71xkWGGZQ6QRmbxSfkKUFF
         Vx1lqaahkA4yrL1hXOVDjOFgHmjsnigW3yUP5btlGJYKfrKZghHCBRLFC2wPqsDQvYRf
         MUxyx0+0YZSRyyNQUwnbWZBKR9EshnPl91d5pgSKLSeXOLevnylHTgvrIa0Ym45a6Waa
         rgkQ==
X-Gm-Message-State: AOAM532lUyT2Ai43kwN4m6IW8Ch7v4IWrDwTTl7sH6CddScCC5rYh1pd
	cSU0LOsR2QCd7lOcKqWqBrM=
X-Google-Smtp-Source: ABdhPJxiIcgzXdj1bZlRgVqG0btcOEwc1QZIEQaAeKQzKj21q/+VAnS3iEQHk8gOITTjRwyCi6MmDQ==
X-Received: by 2002:a05:651c:118f:: with SMTP id w15mr2072611ljo.225.1605305800153;
        Fri, 13 Nov 2020 14:16:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9908:: with SMTP id v8ls1495323lji.1.gmail; Fri, 13 Nov
 2020 14:16:39 -0800 (PST)
X-Received: by 2002:a2e:90da:: with SMTP id o26mr1753006ljg.354.1605305799126;
        Fri, 13 Nov 2020 14:16:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305799; cv=none;
        d=google.com; s=arc-20160816;
        b=E3/KMOcc2deDHjuohcCWq6Qj7oPsPCHBMYtl6a9D3opeTH6/toJjGSWgiN6EdDhBA6
         B1IEuCl8wgk6+02+Wfom37venB+EUn20orn/HzukQevL8Wm8D6+HZwh98eWPaoIoQbLI
         uje0RITwrkPMirRg2gr4KMTXRi3FG76u7DIbbv8gInhR8pF6zh8cliVue75lDbM3vcJq
         YarmonPrHls9APw6oBOtwfbZYtG219LV/6EoJSviFytdYb2CMQi0NmAaC06YdlzU6ptX
         m2Wz96T8yt+qwBY2b1+tx9nUNdLVYbWPfzWjZz3LO7njONZnXaHrzNkWqft7ssTE4OGa
         eIYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=12r39HYL1Y3hE4j5QUi7EFyLiI15fmV465I+oq9RH80=;
        b=GWHAzF4YsVAyanpEGvJnhZuGCRhP9XMGWYctfXWXmVO+sgCEzDwSepEhRk6uCPmZxq
         rp/381vWmh6xS2M9Cc2Z+7KcKGBZZO0mlJv8vw5n8dfOtJwPDnK10OQcxgy1oc0Ouad7
         btyZnXyA8vRgWuT4Avn8uWjhSlGuOAFRug+IIClmnglMYidtCP5lcSt5esk9TmF0kmgY
         W8QdEy0naHd04jAK2TiA6b3AgLsJ8c4TVu/JcldWSO/QQa8fXlZAecMvk+GFrImwh0ez
         OtE3Pe/BaEEV9dYV7Hntp1Nrz+HuSvbvxWdFi/a96ZF6n00n/x8vuqLZ+sDD561E06hQ
         O9ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ANnqD32l;
       spf=pass (google.com: domain of 3xgwvxwokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3xgWvXwoKCZEv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m18si350872lfr.11.2020.11.13.14.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xgwvxwokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z7so3318077wrl.14
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:82ca:: with SMTP id
 68mr5801946wrc.332.1605305798473; Fri, 13 Nov 2020 14:16:38 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:38 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <0904c29d9001fa5f87516a65eb62f47bede026d2.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 10/42] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=ANnqD32l;       spf=pass
 (google.com: domain of 3xgwvxwokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3xgWvXwoKCZEv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0904c29d9001fa5f87516a65eb62f47bede026d2.1605305705.git.andreyknvl%40google.com.
