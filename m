Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZGFWT5QKGQEGFM36CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D542B277BCB
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:16 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 6sf311515lju.22
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987876; cv=pass;
        d=google.com; s=arc-20160816;
        b=s9ZcYYGdEk8Vm0d/S1bnQ47U9bYrg6DaRpEbyyd3Wzkp65O4TmX+1Is+MIluTE5YII
         LakUj2/3BPbPdSUuIL3DXWduxMo5ofMMWuSFTAqaSiBjoLgL5iYiEDs7BgL8vmcOF+Lf
         m0l+GqmWemEqLVikCxXqVux9oPOD/Ro9cktMHadP2p5htki7zu/HIpPmneUXXYCYfwCC
         THs/oVLb7xMdbyyzWV8jusHokSD9wSilmx2RSjjdTQIqDuchk6C74PQguqTKs4rg/zZ2
         2LUMx3tEp+Tai8iTly6mNDHCueS200Ac9hBlxmMGlw+o1ZMuwqKbGNshJPL5cSFUUAF0
         lTeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EvMSZ1TywnZj5dAhpXByNEx11boJ3zZevP59oGtsbHg=;
        b=tEGB3XAtfte33+D+gJWCCVjXrV4bd4orhLqpWf9EuMRB70LRFwYRDwxerrfan/0I2y
         t07KVAFkZL7ThubGxYcsdJ4LNH56IYIYQ+XkQZ82uwNCKhdsAs+dcdM2s7kK47uAHGqY
         JPtHrJWRkQpcvBOQvaGImxVVI8H74ubq7H/hWpZZyXlt/fA94VlQFOJHMFb91ifT51AE
         z8xEeMsikN3R5Rhyy2/OQa/Wf4sN0DLxpD6P5FVkzt2/6jrqEVH83GNnEe4keHvwYvKj
         vI5fPJ53Vl2fx6blYex941TEmvOCONmX8I56t7MtmVPK9NCYLPwqP+9CMVKp2XGMZkEk
         wNFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BLLSjtVl;
       spf=pass (google.com: domain of 34yjtxwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34yJtXwoKCd4ANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EvMSZ1TywnZj5dAhpXByNEx11boJ3zZevP59oGtsbHg=;
        b=nhrTk8GR4F/JxaAHaidebiX3zO7rAhmJd7AGfc64jLNRi0sSo+mD3L58SGQ7N0A3B4
         FI+4VD5kS67Xm77RoBUrZDyYhCw08fiZK7kcp9poPAlzTWEZ9bk31QgYJd7yYOVWnELq
         CVKN7DR46NWlwteHFalU1eU9G7eG5afXWYVAho2C7dIQamugbqrDhiJ55pnEUKlWuW4k
         Df1Ajeg8hz4MlMu+lgrGJUXprNXfGvwthPPR/7Edq0xe6bHDKGPlvMACIMcfBVlgqG6/
         NTZhXOqYolK+jJtoMmMmNGMtnbiE43m4TnYOB9/YyDdYDNHKM++9nSJ/KwA0H7GXPUoa
         l0nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EvMSZ1TywnZj5dAhpXByNEx11boJ3zZevP59oGtsbHg=;
        b=YqXSZQ6oxgGJzGOvCUM3E72jgW4xd238aF7KFPh9wy3W0SRxwuAx1jkiqe9W3i3s7E
         A2W4WjH0fwwq4X39X+XKSRsUTTZvaG8Va+zY2m3qUDbt1M3Z1cVTaofMaOUR2UjoAbIS
         NcQW7IhpjCVPr/klKFOoyn7wY4Ox/2ugDg0wuJT1D86vYoA8+wWGxlpXuOs8HsdiziRd
         RRkeYixj5/ouA9lpwN/Thflq5fYkn7XKDKGxuYquDKEjnPWRZROoHXLuzo2FCtoUQa1o
         LY2eMpyQ80JHSaIIvhizjKi2W3zcQU0qXsr4WnG6oAc/R1hsMLvZiYOL1Kzd5XOmLtzt
         JkcA==
X-Gm-Message-State: AOAM53266Yxhc878zNyDD22LdZqcPSzp9HEnAKaAZZV62KazZX38rfU4
	XbJDMWWNI4jTY3pMx8v/DsU=
X-Google-Smtp-Source: ABdhPJzTL46QkoG0QtbMYYOyh5IgyNt8oxdzMsoa8HFz2pdgo2T9DxPygePkpHtdfDjC1rm2cbG9qA==
X-Received: by 2002:ac2:5a04:: with SMTP id q4mr386156lfn.450.1600987876382;
        Thu, 24 Sep 2020 15:51:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls252505lfn.2.gmail; Thu, 24 Sep
 2020 15:51:15 -0700 (PDT)
X-Received: by 2002:a19:8316:: with SMTP id f22mr365914lfd.239.1600987875364;
        Thu, 24 Sep 2020 15:51:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987875; cv=none;
        d=google.com; s=arc-20160816;
        b=eSbIOxuEnLxdZgMHx0wSXa7kmPDCwP87Vl9j+dCuHDY++ToRzBLeJ9A1MeBfPZ6q4+
         c7nWyIYz5ySsbk6P5MblCmL7k1vhxOOXDrDzAX+1VQEGo+ZkRFtLZwNpJtYdk/RwgNuR
         pTl1SyyDdFEfYxIVpNVksZvIsuAUb/CMxnSkBZbv8tr7kMUVklNWj9jDvBza+ES/cRKx
         PVeM/vPpKd/gLzkFa2zkKD+ZBhl+co6KoyDPKDtZHBvvOCZ0lbdKVdribsycE33+Y2/9
         MAdDV3K8f4vnIOnvzdg3SIup3g0N8dHsmI7manbvl1/2AB0iGC6GaLWGmH/a8yXhg++B
         Pi7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=XhxjFPUAzCsFTqwRl/DMEAkFODrqtlmMsPGn1xe7/7k=;
        b=eQaNLYqnX2/XG3fvgclqYr+8l3henoNijj8kefcNv/j9BmadZG5EEL33y+nlzi90HY
         XBO4zrSP5CEmEz0yJiHz0YUw25lvPS9vEL4PPzmXBld4o5qflbcKUoufpI50jGs0QX9c
         w5oCTdbjiPR66fU6kn0spWwL1hf8cy+4E8aJsOfcChiGVfcs0bZ/cM88AiN6Dmi2lu4u
         7EHQE/Jrq+/6TLTzuFSX9Bl7diTWEhB7/GmgCIHwr9Y4ekztf3Edh+nQNiIzp3qwDEj8
         Bv8cQTQKfneTAx3KeN5uWcwRdS7VaD6uuy7AgBoEg3soi1ayjBSKEzHJBRxYtsY6xogP
         EH1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BLLSjtVl;
       spf=pass (google.com: domain of 34yjtxwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34yJtXwoKCd4ANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r13si22491ljm.3.2020.09.24.15.51.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34yjtxwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s8so281590wrb.15
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:15 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f5c7:: with SMTP id
 k7mr1238189wrp.246.1600987875081; Thu, 24 Sep 2020 15:51:15 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:17 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <da4fc136c8cb6a44200dbe5bff4908f8c3835ceb.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 10/39] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=BLLSjtVl;       spf=pass
 (google.com: domain of 34yjtxwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34yJtXwoKCd4ANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da4fc136c8cb6a44200dbe5bff4908f8c3835ceb.1600987622.git.andreyknvl%40google.com.
