Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4UASP6AKGQEGH6B47Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id E895228C2FD
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:39 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id h5sf3882703vsr.6
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535539; cv=pass;
        d=google.com; s=arc-20160816;
        b=W1YHFAU9rRFSVKd53ob3ZCyCyfxx5YjXCppj0ZmIFOnAYAKNu3Qw87I2Uh9GJDgA6j
         4462wHbc5PdvTpJAWtbVB8IJ6z9Vxa4u+pJ7bhxzazlX1Rj3EXl/KhJhDAQtqwxUDCOv
         8wGSzyEgQl6tzC4FJw/8w9QAgKbA26v0O6b7LjgKiveZZcx7UtnZ7pKlp3kmzA0yoSGA
         tF6ySn+qsUU/HR75LB+7svfjk3z656P9iDr8uB21qRvOTiyo4B7BNNea3JBJnCeukMN1
         ywkNzwlFHFVBFahpxj7PUZnMRuYaQ/XwyYTA7uNyqeks02ppfY2J5qh2ZDXHKeatGQ36
         rjKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=e8BA1Idxd4PYEeNIYHP/4sKySNdT7V3jO8v1pAB/Xx8=;
        b=0HZR5R1+xiI+Ny0RbFRegra9/O9LlpKXbOov8ohr5Q7GOqmpeBUT+5DVQh/3/x2PuY
         Vl8PfAbKCzZ/PsqRxQ5Yxld8OHnIF7QqhGegnd2q1XCqhhfR9J4wSYYGWSEAdYSBQLww
         qH7vMjOzUGe5z0X/KF5ospYHIg8k5z2czoHlzdnZRYmoFWlR1r3w4RNkQz+G5xbJHrtO
         olAhbMLcCJArLO1iAzC/oDssmKThL+Vh8/tTou9I6rAzaij3CCgOQczFmkA+H4HVhQmT
         KOdEkLMT3RJlPRPF8PxBgbQYyggwn+oNreHt0mR4oAARHlxMMWv8XAdE5eQvDDGjNIfv
         FYHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="p/7hfliV";
       spf=pass (google.com: domain of 3cscexwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3csCEXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e8BA1Idxd4PYEeNIYHP/4sKySNdT7V3jO8v1pAB/Xx8=;
        b=o5Wrfa6kQga9q3JYRcrz+fSTjYPKwpnCYbb38gOFQAS7X0mIkfHbUVaXB7q8T1Atko
         cK9Mem+NGHrdx+RKlqAeef0bcdQutmK3rSjzGGhyxh4L4Y6+KbN4qu6PkORDuNLxI41P
         3IDdQOQpjxAUcOt+TOgRBThqTZhg7eB9fVELDcnpAjaIAW7TpqbEy1kzYmHwf8FxfaFv
         THrTu0knTiJZ4VK7S/0QPvzFjUqbsXxdlfRYH+cCfrWs1IjPQzoC6ANFhraR7bM5LvBf
         kCjZns4vyTnGUbnVDXxxKWF8mKlPJCg7yDY4hotd4eo4Xp370JfoGSiG93HCoeu14Tja
         B8VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e8BA1Idxd4PYEeNIYHP/4sKySNdT7V3jO8v1pAB/Xx8=;
        b=G7omQdeWw59k1feXhEFivW9EGlvkRkSondMkOIEgdw68gNsUfiUCPAkJR7KejUmli1
         xfW1xgdJd+Is9B6pPF/v6Hitj1c1kuCEveJMkYelZUYY2daAUa2uRx5KgY/pUByD8Twv
         cNqAvnTvW/P0eKljS0rYYtxD67k0t3Ymeco8yUkpEf3sSIL5kXlUcsGJ03BZ/P8LwYV8
         PeZ/iYVU2D9yjfDNmlWl9s7Qpfp9tdWoPhJ1e/OJk+IAWnYlfEsEZfh91/WoGODyU7UL
         aijM/rTV+MIZqL1N24P5AYSvR1TOdh1tLeUyf1Ch+L9ZMnq82e+rId8mDKY7fzLBc0f9
         ckQQ==
X-Gm-Message-State: AOAM5317SYopV3HK8CABEeSPZbarWGFO57HY7bqPxlexqfEpWy627B7V
	XIMlMD2C/xeEvW5hQUprGao=
X-Google-Smtp-Source: ABdhPJz7qVjyYI+C47BjHB32Z1X5uhA+eAveNwtuEyL7q2uYMYGauX7LPQ1zQ6EuFLkHTmCe2yCH2A==
X-Received: by 2002:a1f:9c09:: with SMTP id f9mr1000537vke.13.1602535538979;
        Mon, 12 Oct 2020 13:45:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:edda:: with SMTP id e26ls2031274vsp.5.gmail; Mon, 12 Oct
 2020 13:45:38 -0700 (PDT)
X-Received: by 2002:a67:fd64:: with SMTP id h4mr1201034vsa.38.1602535538499;
        Mon, 12 Oct 2020 13:45:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535538; cv=none;
        d=google.com; s=arc-20160816;
        b=KvR2d/oTTrnDJZ+QWpmGtZ0WnTUx5AZiMlixMdYxXanYJtbg+WL1is+KYNoA3sbO9p
         gC7xCJVlWz/lqks0XlOq+6gJFzI4BsIOuE0rzLQ8/G9JKcxZRC8Qa67A5zh8AlQtTu4y
         2cfUz6W3/jZxYEakfZuANjxkOgIyHQAQ9AErLnZ6p6U+rnCJ+HITNwOn9T+cmbFt2mEv
         Be26eGPXrcLgR/AK5X/WVnHxBSPjyM+1tR6yGB0Y9uHkrobJ9S/we/e+s9HsPYpD7PDg
         shIo7iTXB6N1wf8BsYT+lPxixv0g9ietTa8c2oKDlT5ldT1CJWHkTVY/YtdH3GlQpXO7
         ZVWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=41Vl357/MnuT0PAxoBH3hjpV8+7JFQ9o+WDzcoWDr24=;
        b=QT2vZuUDDP1/fJVaUlw/nPMRWLgp0ilSW7IuOMCHmpXl5V7kwGJ8s8js5X12JvByOy
         P2IsFyhzU2sqWPbkIQouztsUKReOaVsrcQHuQjGj3mWhcwLs1kREadZg2I/8spMpd5iJ
         L/foVzjMCesQ2YkmFtrDfed/txGBHAbDSIwmYp75075ArWQfR5XHHxh0bxbx2KFV7dag
         TIdB1Ggo22GSJmyQhDFX2ZS+aOOe9B4c0dwDDE/gQwdMIWIDVA+03pBfVLXxvtopNFHg
         TKlJwBIdsqhx0zQvxVWSSEpv//MqDvKg8p3FaBDlzolY1CrFzEJ5340IqWsqUSn5/RKs
         XXMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="p/7hfliV";
       spf=pass (google.com: domain of 3cscexwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3csCEXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id e21si1168139vsj.2.2020.10.12.13.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cscexwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id y8so4707401qki.12
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:38 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:8e0d:: with SMTP id
 v13mr24646235qvb.51.1602535538096; Mon, 12 Oct 2020 13:45:38 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:25 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <9a603d75bebe17810dbb5e6e5e001f3243be8052.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 19/40] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b="p/7hfliV";       spf=pass
 (google.com: domain of 3cscexwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3csCEXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9a603d75bebe17810dbb5e6e5e001f3243be8052.1602535397.git.andreyknvl%40google.com.
