Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS5N6D6QKGQE4ONLHDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9502C1542
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:43 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id y21sf99491wma.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162123; cv=pass;
        d=google.com; s=arc-20160816;
        b=dwqbkm9COmAGHqA9HTDPpJBANz2RU9MicZSl7BZIPz0sB3o8S/dECRCf2Chnj5EOJi
         8FRfFzei1TeNfR10JBiLhtjtmyktvjRc7n5QUoziTiv2RtP1SZtr/FiGzf69VmS+6mf8
         f2KP3P/F10cfHE/yrlLP6vMPL/9dlPtQ12lBo3kVmO+BtXTUY3wu8wlj5LXRFKZ2IjWS
         EOO0kC+vkrz03qETJR4a1/Urz39l4hOLfZhJXXhDHHfE6uKrrYj++tzLiRRkoBVA85Zt
         +cPO1V4zgcAbXqk/FVqSwy7XAmpGhNhZMqukTkpo++HZi0FSWyS/Kn+opNPrmg+PcIvS
         pPvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=CCiV3TlHr9ZyEskYxJ+JDhMkLZJsuHDBTO5CE6UeRZI=;
        b=K5bNZ9FhN60dHG5PHhFHaKueAcOdjdyWQ/nnNH1/G55Uf+2etkwwMjCD+4sVeU1bua
         mXKMtiTJbSe07A3wRbfAoKZmJ5KyEhbt4dFdy+4NDGuId9JEsSWyxezJxLiEsr18Z4tW
         8nAtreo9Bl6FSXNQgMosdn62WaFsDgZjPblX9s6keAoLMMYJh8cw6KI8iJQXNdyCfYDi
         lVyNQNhqidgCe7Hd88J79l4gAOeZakKk9K8ptLTv3JlOt4V2uGPYE+KYEoeYMv+w/5hc
         x2plnWMiuf8OtHY+/eJYDOiIxKu0folAFZgjI9ERYrUPbqQXUGioBFyRneyNTel3vhrs
         nIUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MMrmJNG3;
       spf=pass (google.com: domain of 3yha8xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yha8XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CCiV3TlHr9ZyEskYxJ+JDhMkLZJsuHDBTO5CE6UeRZI=;
        b=MYwF8ZtUyg2Vf7f41HTHVskI5GX3RZxJVdWLO+jO/m1nAFYCPaC9HPJhCwKdSuUCPH
         T/xD6jZm/PoPIU9YxUjigMJ4bZ9+6KgWgQxTebWknGzxPRd0IuQZ69WWtvYdhKVZVJc0
         o1YX+2wsv7prnfwBNn8AoYruP5r0f8Iqn9APwQupYOznSDwRrbAMR+eq6NkeALBR56lI
         x2A38cUER4STpUJlg4ftV3SNOZ/9y3kBaYAsnJh4A3G/hRyPwv8cLMvSsXvxogcR/z0C
         nAD07LJFONe5RA+VVg/nv44oOw0vgGRTxkeZ6mmM9z/wrOfchv1H/Z9a1SQxPMrt7+PU
         D5DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CCiV3TlHr9ZyEskYxJ+JDhMkLZJsuHDBTO5CE6UeRZI=;
        b=UBxWDxNm55Tojtto/jwt6WONcR8QYshnNJ2HfuTr52jHNZTDnA55nlMRgbPaR3Pja+
         qvLIPfRDS8foORrxu3VGnrM863mwaYDWsM7xa0v/ax/59deZPlvnsBnqTZFuLhOJiVx3
         yr8ngD0SrjHVUB7uFX1H6iTV4ywxNde6NyAIMVSDlMoDMMQsp0dNRZPovGdpJoQl5ptT
         8H5PE4hzH/54okFMAuUVasbDDuBFrIHdQEFjR1QCZUuohGraWguoxHqjK89/g02k7QME
         CMjy4t9xpS91wYLDSR/9DjqvKkuvFV/61mPXkNaJ7ucIbn0a8/cl18hK3cw9KXswZVid
         M4gg==
X-Gm-Message-State: AOAM533OffoleXlAE6HYQ7LYf53Ts/E2TAEqaCKbbDMSHni4kqA4R2t5
	i2w0jrJZUusbgkJ2bt8SUqw=
X-Google-Smtp-Source: ABdhPJxvULZ1tJhlQr5ODtd3STZYLxkHrF43Tty2vpF5B91L6VIvJcv+m7iqX+jCdMHWgJtxLbu0RQ==
X-Received: by 2002:a05:600c:218a:: with SMTP id e10mr592866wme.73.1606162123736;
        Mon, 23 Nov 2020 12:08:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls8972922wrc.2.gmail; Mon, 23 Nov
 2020 12:08:42 -0800 (PST)
X-Received: by 2002:a5d:618c:: with SMTP id j12mr1462623wru.182.1606162122860;
        Mon, 23 Nov 2020 12:08:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162122; cv=none;
        d=google.com; s=arc-20160816;
        b=DIkHLc2bm6+iOUee6WJqGPsFsdEdwUcFuXFubZK/xVHiih+C12F06MuRZ1aHujZgCU
         y+x+xu271+s9vpog1ZxGXdvX4bu05BvQIj155ZsmIO6EHJXz1pAA1KVsJlIVIbSrbDss
         fvHbTAf6X+porWFjG5oCKLtSzKNeFsQsKtSfLDYqn6Ujjt7JiKA6tpji1pdTPIAVoaUl
         d4DJJQLLUO+kJOKvwFvOkKxy6kUj1L0K9kU1xk3CYAbcXYkunu2wZYWC7ufhskaR5CJl
         WRXyfyjTclhNZcSd5GeZbdxKPva+9LaAqnAHT4opY9eRm6pQRMr8O0GqVi9Qqj6W/lPa
         rP3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SaAeiXzxxrxPHQMFzx8S9oOteptS8gJenWmnYcdr5qo=;
        b=X5RHh3/7bib/No9z0TxHkNnqOb/298DcMl0SJkmEQe+jMNuAAQG1apY1iWcbLZA1gs
         mrBEctoB4wlxIzZhcYQxjmNNIiFQwy5PyHsjwKGGT3Js5xEy4X90cZDhpXOzLz/lhfmE
         NxGJ1bIEFzp/Adj7OLZNgMBjEV6j3l/arhoGEKiEEhg0189JYvaoNWZ486zolcucccuz
         HGPsKho0AHcIv9p37Tl0pVEmwo+C9EIgI1eQH+GT83zRJDvic1kK4FIACteAOf4KtFjF
         tthG5ePoUbRkkLT1XVAJF/r/1wwVzYPyW+2F1CHUbzqH2LZ9ltwMS7saVgp5xDP8lB1N
         DZnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MMrmJNG3;
       spf=pass (google.com: domain of 3yha8xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yha8XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m5si13420wmc.0.2020.11.23.12.08.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yha8xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id q11so1496905wrw.14
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:42 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:1cf:: with SMTP id
 t15mr1483556wrx.92.1606162122457; Mon, 23 Nov 2020 12:08:42 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:34 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <a6105d416da97d389580015afed66c4c3cfd4c08.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 10/42] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=MMrmJNG3;       spf=pass
 (google.com: domain of 3yha8xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yha8XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6105d416da97d389580015afed66c4c3cfd4c08.1606161801.git.andreyknvl%40google.com.
