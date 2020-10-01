Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDOE3H5QKGQEMU6FRZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 385E0280AF7
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:10 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id m9sf59551lfr.11
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593869; cv=pass;
        d=google.com; s=arc-20160816;
        b=oJTQhrZaknXz6Ptbh85Vh8HO7DNwy1LaSzcnsud8o4SZ0V/TCGd+Fm1WWmCs2JVYhA
         DHn86mqc7pqJP8KG5gAvIVw4ku45xcNP4G9bFucTZGQK+DevZ6cSI52atZA6p0ABvZNO
         eahd/72XUlrCCj5g3fkigGMsKwKEsevPyz2SK4M77mSNOYdhzv2fLLh60Z5pD5+12NDB
         Nm6tWN64WwH7J2yooS+KDS1uZx8CH+snSXtZq4FE+bAZR4On5Yg51ZX87+XElUuvblhX
         KFRsreh+hpKrgU4ZHRZ0jLqkbJoVCH15B2NyVFYgT5x1F4+heHZxBj8JapvzXe07Ef8E
         LEVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=gipm88NeLAeFr7Rl+VBrb+0S8mc3jNsqDA8DQzks5Io=;
        b=Ql1U1d7VO4CNHjLnYjUtVvoVHhhtl/SGOoURa7Modqhcd06Y0NgV4s0vGYhNTtL9U1
         qUweeaGp365ZpGuNsKJSvskWfKeSB6hHI7RXRwxVzI0+2fK1FVXiMgZa5UHl/grPvCmz
         T/OrnSGTGswgDKwpGvMLoVzGlULtIBJZGr0mJLFiLQR2Szx+30Q654WbDTS/YDoLA4w3
         hS/9Bzn7zS7lOdH+DX+MCBtYQbdB4Ecnm6cB9cLiSDXsxUSr6cGO024EExKD76ysfiCl
         ZJMz5/t1wC8GBgB3UZINZsigktFbd2cZn8zEKQ76hNdAMLRrRsRlMp9oUfTD05EGSFl/
         JbjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pWNfjvS2;
       spf=pass (google.com: domain of 3dgj2xwokcaslyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DGJ2XwoKCasLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gipm88NeLAeFr7Rl+VBrb+0S8mc3jNsqDA8DQzks5Io=;
        b=KNsywQ2He4IhBswL9PhMcA+SX3BGoLNvXL9iycYYmjzpacdO9zwH4IfInL+E2h+GDK
         6yG7G2YKKnsVT0pcGiBw+Xmm1HVlA98h6XT5HKmZJWv4i8TPCodgBob+44xTOeZa98W1
         wKNcVjq91EKRnezH0CB5Zbsm/mR9dXkZLqnVfKK2HYxkKNn5W+mw+Mf0CzpVSl+bME5X
         UHkcPkk6OPYKlY7HFQcxxBJF4t1w2DPzwMJIDYIQF4qnQ/douwEayFJ99l0B6zW+kANm
         xoatiB0JJMWYkvciWG2yHokV9+kfpw3WvHaVEU878eQjAhU8S27MpFXDyxNEkyfnm1QD
         Ld0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gipm88NeLAeFr7Rl+VBrb+0S8mc3jNsqDA8DQzks5Io=;
        b=JBwnVkN1j0/CwnmSLNcDOjzp/f+UyE/jIOjlMalmWcXY5bLTh6WQOmGjFrfClu4kI0
         Hf4xhwDVaSYhQKzmUswwIcnspM2uaTuShtriqtYH39pqaSxJkvicCvFCKRDf88vhms6R
         3+n4M3wkmi61h+IMC+UPCtd14GQ3uRiWXxPF2Hvr2s9IyVRHBjnmWMbPSRvML2+kMGOf
         4C29dsp1tpcUdaKknae4+45zQVShlzaJw8TGqQVAsRxINc2Ulew7lFwn/+No3YOSztpn
         jakclOzJSAMjDf4jbfWyzq7wxS0F4hYB88aldbmY01lTQuGK0pGioBGE0/imVrMCcLfD
         nkfA==
X-Gm-Message-State: AOAM531bBEtVJwRyN8urUHZE6FShNEDzFzV84JflmmZ5Q5pSR7+OwKOB
	uz0ARFUlizGeGCJ3u/OESAw=
X-Google-Smtp-Source: ABdhPJwp1Gv4PpqZYJGAi9mVO3eI/Bmi4r3PL+0Hd5pRiz8JQrQvPL8x8pOLkQkdQ/rN9QhxhKIT+w==
X-Received: by 2002:ac2:560f:: with SMTP id v15mr3868130lfd.550.1601593869755;
        Thu, 01 Oct 2020 16:11:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls2140325lfn.2.gmail; Thu, 01 Oct
 2020 16:11:08 -0700 (PDT)
X-Received: by 2002:a05:6512:419:: with SMTP id u25mr3655431lfk.81.1601593868693;
        Thu, 01 Oct 2020 16:11:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593868; cv=none;
        d=google.com; s=arc-20160816;
        b=esSyQ0r2boLSBOM8ngJ9wW05RWDrgodC6xkSCMY6bEll2OS2/ICzPI78nNBp/g/YeM
         HEZUz0oQCUMQ56mNHfoTAUfS5j1VknWAfMc6+eZlzCdVpE0TAud+2YDJmWVqb8EDJXcs
         eycLZZhiNn9r80QXqthl2HIU6/YrPyvn0VK9Y8V2BRkQqh4RGbPP1rtONPWSNYZTin2a
         0rUefBpPFm3gJEC77Z1EzYbU35opKsZ5bOhLF5vK3ezwXxBgBLVlqZ267k3FFaVWu7cJ
         44DhbwjWxC2hmb5SApIl+OMNRLVBX1eTqioTCn4kjljts8j9ho6JF1HFbnFU5iaZHVDs
         GP9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=i+WwNt1IAATvZAz+iP/g9MRNBvWviz+j8TK22xvBHcE=;
        b=OGiOMWzOvUSpEqLR+p+cjQgtthWix8kQx0+2nVUZ0HalF6Cb3tNj43/7JBvRv2bX/h
         Mu9lUpZy8YV6BF+vNFMSYVt8O2sYW61Xztm7ItCQKT2tVDCrC/oRsFqq+tkqwNw/Z9ab
         26jAnjgVbc9r1fWMUK0COU38yUL+W/ZABTicn7hYkXALNa0Mj89jwb+f20EbuQf9EaJV
         cERrq/CIbAf66iflXXVsK1dltDhPNA2Yap4vXmTajZU+9+OXK7uC6tpEwqVmqcHPvL3j
         a8p17PngpWfFsEVWEEQ+Yu7F633AyduDyfutLMzgWqFFxF5pFuFCDiON+09Mxih2+ZEl
         AL5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pWNfjvS2;
       spf=pass (google.com: domain of 3dgj2xwokcaslyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DGJ2XwoKCasLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y75si166802lfa.3.2020.10.01.16.11.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dgj2xwokcaslyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f18so115572wrv.19
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:08 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4683:: with SMTP id
 t125mr2378858wma.110.1601593868069; Thu, 01 Oct 2020 16:11:08 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:11 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <55e2c7b8f77b324a24fceeb9ec8c96aef5990f6d.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 10/39] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=pWNfjvS2;       spf=pass
 (google.com: domain of 3dgj2xwokcaslyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DGJ2XwoKCasLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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
index fc487ba83931..5961dbfba080 100644
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/55e2c7b8f77b324a24fceeb9ec8c96aef5990f6d.1601593784.git.andreyknvl%40google.com.
