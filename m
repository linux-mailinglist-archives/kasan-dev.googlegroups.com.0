Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOW6QT5QKGQEKZEDZKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D272D26AF52
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:43 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id c8sf3712039ila.20
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204603; cv=pass;
        d=google.com; s=arc-20160816;
        b=aueGGcUscpvHlASxzgEaHtCE8ZLNWEVYB4Z2hnhIGE/6Jylrr1ccJpqc3NJ1oFHQUu
         GjTK82FdqQCCkM+JfLxIxYo+qsOGf3t+8dpeiB1bD/Hw9jL8dgTzibh0k0CSxEB181V4
         hQxVCwLz6RXLjh6a8/wkKXHxAOylC25nYUufSkVIS9oKCkDpHw7XLc5e07UnzzeyoLqK
         w3+gpUrkbvKkCupXxYOl/Emnq34eph0wc/DZbP+TTNapyHBne0AFuwZHAFSUW50krH0p
         mPFQFvVl1Sz8mglA7t4tdy1DooDcEQqjjU7Wxusi//wsNLOr2CSt2xZdcdIpYBC0Qgjf
         kyFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=aSDU7HFW5WKstd7Di8KwAL6+DkVk4eMd+BLWLCGJMIM=;
        b=Z733iNUsdemAynzkx9bzKx7lOF94BNmnp66KvJBqSA5bwc2oAN3eS/j9RPB3q6vCIU
         CUovQ/cY5NysBD5xHnLZ3w5/srpztqlWEkZsJu3GLe7WuO67e0TkuHP8IAdjCrOqLaTx
         byovN3bILKNPoCxAPRArc8PjsfpFQJ8tJ5qCxKkrCcnOX0EYhuxta7fX1XRl2X/JEjGz
         VzwH6M/WaRyzUdF8fqHh9HjBsJPwH6243/H/9Nf3+o67dLGvcyZ5Baj/6Lfw4FY89rFE
         bJjGgXXwo0K4c56cWd0HMpw5xA2Bao/5LeIE6EL50hVoxOFYSVZaDBEbaZpQ0PmjXWNX
         KF5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X1G6wMyZ;
       spf=pass (google.com: domain of 3os9hxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3OS9hXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aSDU7HFW5WKstd7Di8KwAL6+DkVk4eMd+BLWLCGJMIM=;
        b=qEZpszMpliVP5plnNmLcx9AZjsi68EDIX1R+pEPmuS1RY/tXDMBAt0R0vaL3rQcHaH
         2MvUukclPCcJP5bC7okDNupRh4pAsIaC6dvfV31voTdBHxaN/hhEMpcBCWHGiFYvgvEW
         FJ5OyO6VJ8P6cBHHSKR8hGzO1Gwv6JOt8bC36GP/4AG/wHMXan7TbepQ5DHGVL91Zuyd
         3mWU0wAg3+/AgrkwRbe0vuVJQgig7jWsNzGx/Ze/oXSDv2TPuhr5QgznldkKS54xQ58A
         Te016HwgIYHqBU6EUqnLrjBTV8Xsy8VT+ewqNflq+6hICNDeootpWYHaViCeZGOZG5Fw
         iv0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aSDU7HFW5WKstd7Di8KwAL6+DkVk4eMd+BLWLCGJMIM=;
        b=p8AaCTb/FokCb3T7lBxL40C6w2PBeIGlrkZjyR5RvLmP92MgDr0c5xcx5Jad2PZpuX
         p13iKF1xNzl/srhy4WQEnlt6q4ZhMfQrgCX6wZ0TXUqLpVKBlJL8cb52fCaUy+tMcwWG
         ALGHKqfoP5aV9t9RlhbiwagRpV+IyYBuuBTGBF8wqJQpGw0cO+qPOtpIXHCAkX52TA0/
         PwZrU1W3Y/LUL1CZNVKOQfZ6A9+0oXilscYP8tnS+fTWMjYBVTCbfpwr7Y7Vksav+PoO
         OB9KxZXR+9LLykTkiA4RTZE5NMxtaypv2BPye824CcLZoQ+6F0KaEGRF1+FDGQqnj0sx
         D1JA==
X-Gm-Message-State: AOAM533Yk4OZ5A8XbYCpHTMyHqLO1GsBofmYFh3LMdy2y8LD7al8ibc3
	zDACDWETfZvLHaGHHl12PhQ=
X-Google-Smtp-Source: ABdhPJxE1E1i0SrF0bQtTcE+KVFmJbq8mcXZvukamIX39ptOJg1lnvI6R2rYuU4qJh72OJWY2Zjesg==
X-Received: by 2002:a05:6e02:cc4:: with SMTP id c4mr11705448ilj.152.1600204602904;
        Tue, 15 Sep 2020 14:16:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d68e:: with SMTP id p14ls13384iln.11.gmail; Tue, 15 Sep
 2020 14:16:42 -0700 (PDT)
X-Received: by 2002:a92:6b04:: with SMTP id g4mr18344718ilc.192.1600204602521;
        Tue, 15 Sep 2020 14:16:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204602; cv=none;
        d=google.com; s=arc-20160816;
        b=CzQjK81g+lP7GaF/h9zu+HnCUhDmm8LLh5iwt7PSsVYJLfak/yyBZRSDg9ly93u0wH
         cZuUel5Xp99DWya9bhYN5TAWwXPbgx6m6jQQSFW5hMGjS95MtI1jymxvb3oHEWO9nIqK
         e3H3Q/q5Fs6ZeT31gsk5Jrt+nHqllcC61SXyCCqdQdT5cFpfszfJ82/FS9bA0xoqKrDN
         1xdwSt4e9cYDQuTLhVSaHJf1ZiZnrn3aYyorWuZpQGJ4MzRTeMz2/iuTsaaHy9LBlAgB
         D1imxai4261uwrW7mgnWU7Z3rarzVgnZ9buvWO5GeQVF4u0ZQGcwQSAXIup1bpc+3TVY
         Hkvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=lWHaJYmPEYXJBP/uBzeOe/Zb1P7kD+TOmnHXvVDLg6g=;
        b=RBfovrhVPhAqF9JkpK8L1qKNnZIQDi4c40/PELChIQmbogE5krLc6vPTscCc5YQay3
         kXspkXZh/n9CI5MVUCC/abQEkM41TBRIC0RAv6NBd92rfCKnr+iCZkDde/hYbbbowHDF
         yqNkfHXeTC8/nCQ/HyRK5xbKkHSDJPW2bp+Ymcw0McPmtiyidlZtXokGDLTMxIpBVit1
         y6UxZkQmyX93WCeXeLR7PUsnh/YFbNgD+3zt6lHiQ8L3wXPbGhgIqRZs9YiF3zBuYeWR
         t0eKHogUSUAw0O2b56lbdGhWZDwYh9cOrIc0nMbLnWw5oWREb1Tj/ZFGN33p/MdE8Z0d
         wmJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X1G6wMyZ;
       spf=pass (google.com: domain of 3os9hxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3OS9hXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id q22si740113iob.1.2020.09.15.14.16.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3os9hxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id z27so4029922qtu.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:42 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4891:: with SMTP id
 bv17mr20207397qvb.27.1600204601843; Tue, 15 Sep 2020 14:16:41 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:50 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <fab8d524fc2dc5d01c9dd047c497f3e9cee483cb.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 08/37] kasan: rename generic/tags_report.c files
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
 header.i=@google.com header.s=20161025 header.b=X1G6wMyZ;       spf=pass
 (google.com: domain of 3os9hxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3OS9hXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: If77d21f655d52ef3e58c4c37fd6621a07f505f18
---
 mm/kasan/Makefile                               | 12 ++++++------
 mm/kasan/report.c                               |  2 +-
 mm/kasan/{generic_report.c => report_generic.c} |  0
 mm/kasan/{tags_report.c => report_tags.c}       |  0
 4 files changed, 7 insertions(+), 7 deletions(-)
 rename mm/kasan/{generic_report.c => report_generic.c} (100%)
 rename mm/kasan/{tags_report.c => report_tags.c} (100%)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 7cc1031e1ef8..b2596512421a 100644
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fab8d524fc2dc5d01c9dd047c497f3e9cee483cb.1600204505.git.andreyknvl%40google.com.
