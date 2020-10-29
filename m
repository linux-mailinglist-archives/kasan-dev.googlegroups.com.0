Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAFP5T6AKGQEQMUZZ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id A9C5F29F4FA
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:57 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id h4sf1668387lji.6
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999617; cv=pass;
        d=google.com; s=arc-20160816;
        b=EnOB9ZBCO+LudwlzSqcoEpY4sxoCB7qpSlqb9zDg05ouLKl33y6yxm+kWV7hMADYyP
         Vd6dWNmq6qo+pxgoZ0tti8EARqmtq3ASex6PPr3LAPlNKVrkfjO4SfI6bQ6xOuIyvlYn
         2O69kHE+68nYdd7e7OysJgastFPWibDYDTtf+FgtTqGdQOs1WxZAWyKV7SjAGFoUjSVn
         NAG4TTqk+SCFI/o/y08dZI1VUB83H9OINUM0OprN3Acw+NbpLWPhDAHla4KcIAJgpZcW
         R34ostFttUiYT8XRwwo3ae+x2VHglW+hftePmlHfa05Y9x+27FyRktM3WuEYpOrA+QNb
         AG3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=XXILB1RH81Om1vklwzXOKa9rv267jc9Tt4J1dQvWaQs=;
        b=BjGVW6k78EClpdrInAgYA87LeujOUCPwNvtK555UK4qCP13VwuAxGncEt9PdeRqNqg
         FFwqxOiMJflJflfYsyC7RX8zMkp6LnLcMhDEVh8RAZ0tQiJQZBfZqJ+K7ClBxOi9IpFe
         olAWgWQAWdvYra/XF2uyBMfSJfmaNT9/Njme2ohzQ9bmbSkg6MznI8MpZuIl2rDWOAO3
         JxEQYtiEG9ORASEZ/47q1wyV9mXEUA+5L3WBLfJv3qVkVi7RG6Y6URYutFIJZtDyJtL4
         vV6xcmtBAWcSlKdadbV9nqj4IkPh3IJbRhJbmQQRo7m4QIgTdHR7aEfGKZWt2bDg6ueT
         yVIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TypyGCZV;
       spf=pass (google.com: domain of 3fhebxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fhebXwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XXILB1RH81Om1vklwzXOKa9rv267jc9Tt4J1dQvWaQs=;
        b=oHhlak8WRydMUJVtrB7nmeAv+BQrKIWF3F9ECWoyNRypOANwbTeMLSeDCqv0L10gHS
         hGoxF4D98OR5WhX8nvYmFiQk7elaC+oJuGHsxtcL0DPrtLuYNqiSWj9wW2DwhXCimqJE
         0FIh486utvZaGeo/4V+Ikq50HyShRM2Hzjd9UE+eC03YWHchiNnLum/fZ4mm/P/We1dS
         kO22DryBgCGX88FFgT5N3E1E16AJpvqX42sX4wyLS909kzy1xJvs3I9fZx3+QXZ3eYSX
         CCbfhdBaK4izU86TJO5exX0ARcB3ooU3pE73RnijRLK3llxGJTgD38IgPXZSWTgWKgJb
         e+pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XXILB1RH81Om1vklwzXOKa9rv267jc9Tt4J1dQvWaQs=;
        b=erULBUlT7Gsxy0rNcEEtt63mnLpbJP1W08BWSWU/5qRka3+5bs2hEc0q3Pbwx9XjMm
         qL4NLi41T/C+5mbCBYAZQwMPHcI5hxlQsS0fHsBqyq+ouUDJeRcyzjnvhOR3NSsGA14E
         1B434qH0PRvGc6eo4/OIY/w97RW/vLLqB7IE/krjpzDKlTv5+l0VEySodRtGbedxB0+I
         evEONxNjsJzA3DfIa02eVKUJgcdjq7GvTlQ+SJL7gJPMKw4qUhVWU/NaEd1MalHA4KN/
         1xxwLAbfXFfnA7lQUjSwyM8S31Saq5TMD5ntjsZHOp1nGhvxLZRgAq6kyCc6x5TtdzpR
         5v6A==
X-Gm-Message-State: AOAM5337dKeZmTheabwaGmZyjpT67Me0dU4XsXBKmKvc0Z72N67ZZMlv
	1kNOQlOA6R/dPz8UxJARSZE=
X-Google-Smtp-Source: ABdhPJxaDKpQxQ5Fstjxgd3C1xJqM/nyNS5vldhkmEjh0/Bs3MAQTuq7yr+tyip66wpP6HaEpjqkxQ==
X-Received: by 2002:a05:6512:3127:: with SMTP id p7mr2391850lfd.101.1603999617153;
        Thu, 29 Oct 2020 12:26:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:546b:: with SMTP id e11ls2397840lfn.0.gmail; Thu, 29 Oct
 2020 12:26:54 -0700 (PDT)
X-Received: by 2002:ac2:5294:: with SMTP id q20mr2335418lfm.538.1603999614717;
        Thu, 29 Oct 2020 12:26:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999614; cv=none;
        d=google.com; s=arc-20160816;
        b=vjwbZNCbmXtNBOhLjDegoVcrLZLyKp3PonkMLfxZso+ehS/mXexFJMtB9lLXhyxIaE
         2qByJoz5yrRBSDV6zbu+/UEng/ItoRTZJ90wXhxfW88aaEC5tTTaUbGMx86/k6IrQd6X
         t7kK4RPy31wMvcw/IKntzQCFTwsSpI55/KLlg+jsbY8RX6mZcOTrYI8OGwwVqbBFuEX4
         qaoT4cACo4PQhmsaHs0mrz70q6NNak76xxSPso47B2YYiw2uEpX3iu5G3lY9GjpyLUNR
         k2CbwHq4YNbgvDvACrCZHn92ZkxHlPSi9ug28pNR0xkOYHPZE1TL8ZsWnDQSPGaOv6Yh
         q+1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=m4Rd6JEchDCdHagjRChT+nQsGKSwHG57Cfn+FHFZG50=;
        b=MCwJRMHqhFJZ2dB4Ck1cJXtwqGwY62OB75kAuP7/U/Kr9YomTOFLmaT7Ac3gyuiO5t
         j57g/BYb6z67899nUVMEKIElM9TP81UUj+vJ6ZCZxl/htIWnizImdObBjiPEG7IzDgR2
         hAG3vwXjtnbeKXpXJKvsCqZaWM36jcwxhPCBSUVq/IyX4aQRdqAKVWBVicdWDhXE9dDH
         xItoqafJ2mxl5Kl12xNBeT3XGYzw+zUWt93rMmtVHNMF/IxNpjUsJHkmTBMzozopo6yG
         MTb6E356q8JpE6JAoC6ErLB0SuSMl/mWNSIyF/RaJDTiA903pGnlDFiAO9uoT23tCU6n
         3rUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TypyGCZV;
       spf=pass (google.com: domain of 3fhebxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fhebXwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id p1si91133ljc.0.2020.10.29.12.26.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fhebxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id dk5so1610003edb.20
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:54 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:88e5:: with SMTP id
 d92mr5743773edd.145.1603999614173; Thu, 29 Oct 2020 12:26:54 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:40 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <89d996d23ed399e02142b3ea459a03dfcae40d6d.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 19/40] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=TypyGCZV;       spf=pass
 (google.com: domain of 3fhebxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fhebXwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/89d996d23ed399e02142b3ea459a03dfcae40d6d.1603999489.git.andreyknvl%40google.com.
