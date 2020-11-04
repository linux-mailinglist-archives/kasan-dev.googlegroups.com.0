Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBPORT6QKGQEAW26LJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id ACE5A2A711E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:34 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id 2sf76644vsv.17
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531973; cv=pass;
        d=google.com; s=arc-20160816;
        b=FXa4+SNLcDLUCcfAYD+Jfm+qxtWileb5EFCMA9660gKhBVBFovZO5W09V6k8T/hJpG
         MmtgXJaY6XeuW0/js9ma3ciyjsOMRTl/4ja83hbHJz7Ck7xNiHxIMzNRuBaqf+p0UxVy
         z4t+gL76KXjglNbdhqMCTPUsfNdZv1TdYcQf92LjRNzUnnflUiNUZThhxNVU2F0jFeFx
         LjWlXrkkf/xqWq7t98ajHPap7I7haiUIJHRLhjndWXj4leDKe3uW84U5xGQHA0NLgxyU
         NJunrtnjf8z6u4seiyrI041v/Yx18iEtOsYZ09/faVh0NKj/97bsQmk51kull3JOxmnC
         Jx4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=lVLB1m3FpJvli0J9c1OSUoaDBjjb2gyG1nd+pJBB3Bc=;
        b=frXKX7sOI2mTZHeuuTXCkctZXumfI7fvBnduxYzHUlSEZx9pEXhteFdQE3mOMF6nSj
         CPcusIa/tALG9/MJZ/GjRIgao+nLvNs2vTppIcioXnoIofJUjvGRE0pe1nHOVlyglbqj
         fhRaDRJAEs1x9UJKe5CllKJy7Gf0CabfhD1e83e/YIk60dum9t6Jj49FCf9ZlKzG6gZe
         JJun/th9xnNMjQhMsYGUwfPKNSglZGQo9fFlw9b71TJ4c1jeXaMFSFD7gwsCe4YgqXE+
         bsxuVP9SP84O2ml5t0XLvlEWB1L3Qz9Q6C16/45V0ZMLePN1gpiM30+c+H7rUNQZ4+t3
         GhzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HMlGt5Zq;
       spf=pass (google.com: domain of 3bdejxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3BDejXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lVLB1m3FpJvli0J9c1OSUoaDBjjb2gyG1nd+pJBB3Bc=;
        b=CQFlB9Qde/xKNmA7OSkpl7ij7djoLRkIWF23UzxS1y3JJYOSErqPtHPwdWLSpfMg6H
         Qd966H96vwLTBba3qI488G4qSzkXcBldhh1cMqARGbHnKqhJsp9o0hZv2BRMpqZgN9zr
         dFeaQHWD6RVJCmcwS2GvBe3sLqtCdXJtZQZiM3acvf29rZT/JEiQcRDnqzZ1S3Ui19G6
         mPV16xfDGbZM6f160jZeVaSfCvzRrcz1Yf5kRveO7OeddFSkMYXYNxEasD71hvC3LPwC
         mWgukfC8gkOYZf6eN9BrT8L4N9XbyUR6mOAFBXRb8+9o9mAZx9FolP/7J87Y9kFbf9o+
         pekQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lVLB1m3FpJvli0J9c1OSUoaDBjjb2gyG1nd+pJBB3Bc=;
        b=YY3LL5IvnKsh4wDstxPJEOzYC+EgYprnYErjFGl2SN1EWGDhvkwRTqFWLduz/D5X28
         THmQ179PJzPDdu1eThdTSyqX8Z1l0BFwiZi3s5cb8u80fkMya6y3mMi0WOE2mnVhSgio
         d2dC5SmOC0wnKRaNduTuXjiJZTJPex/eoG/piCIxoqjDKrNRDObN9BKpb/AR5DjSc03X
         5PdBN8Lk+/yVFCxs8/FtMF2asPm1kHCsiLMhf8ZW853hpKnF7pLxQ+JlEa0BSQT7Gk3w
         QbDw5N4GfYOduxxHsI8Etl8CuPmb0+k5cVxmNZCC0tUsw7N6Pqy/ibuT+pvL+DPNQUjL
         6dtA==
X-Gm-Message-State: AOAM532YszXUpYFstFKkwys6VSLPEWpqexf/SzHBP3WKPkRikZorGB4+
	+q4Bh/2Xek6Sr5txg/S/S7k=
X-Google-Smtp-Source: ABdhPJy4R69G/zjXulAaV8f4Nmk1YPT7AbuQZ9eup5N39FXHT4KOUY46Vm1YDUGygUVbTUBDns4dww==
X-Received: by 2002:ab0:290a:: with SMTP id v10mr134722uap.94.1604531973777;
        Wed, 04 Nov 2020 15:19:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4ada:: with SMTP id t26ls251373uae.0.gmail; Wed, 04 Nov
 2020 15:19:33 -0800 (PST)
X-Received: by 2002:ab0:7117:: with SMTP id x23mr148373uan.36.1604531973308;
        Wed, 04 Nov 2020 15:19:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531973; cv=none;
        d=google.com; s=arc-20160816;
        b=maEAZJtDjcKaI9KuKv804ECIxjI/yvFXWza9o7EbFIFYTW58pXCL+67cA2UFecUUNN
         N02e57R7APqYu5q62evWySJam1gsKX6n8EIJQIJR38aJ0oxc6xY4yFzT1iFfoeSM47Si
         WX2YyEU6AOujvj9JMaAlY5KqaA+TO8+ohCWXuWT3pVu0amMvdcM+Lp5tEidvFOHGjlif
         SofBShVwulMq6YUIMdyAKSxAFtQYOQ6YFMq7aG90kWaXIGc8+CGB455Q5q2YeuM0RVWq
         gkdMk2ax3mTxP0v030Ey6a7efx+p1o4GlXPhR7MwGYQ4q3Pccb+YFj6g98BUCAZEzabs
         qOZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=m4Rd6JEchDCdHagjRChT+nQsGKSwHG57Cfn+FHFZG50=;
        b=jV6dzRgGdC+VGZpGlyAN96TkFBr+NaY4b+UiZoavCAYVrxqS+043I8ZmMlKKImRGxu
         kxgxnSkpkVIDg2T3gPxwT/LvbWldkYx2b4gV/5WgGH5dy+zIr06TpVTQz8FW7/s0WpV7
         ivaZAUOE8466O7lirQb+g0e/+g8gDwmnQrfg3Yf7lh9qhWgeg4SfyHdew4mLlF/IhoW1
         urShzsxrgBBv+8EO7qVJtksNAG8QLFi/mVYEzF/+oq0yPa3JJncMoprwLj0WrWuUSHHd
         9F9UuklEMDKotn17cK6UjLCYpFzGdZIJ70gKAMObNB5EIsPJj90QslTbtT3ekuMx/b1W
         MSZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HMlGt5Zq;
       spf=pass (google.com: domain of 3bdejxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3BDejXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id j77si195483vkj.1.2020.11.04.15.19.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bdejxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id k188so14554883qke.3
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:33 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:fd4c:: with SMTP id
 j12mr428967qvs.22.1604531972889; Wed, 04 Nov 2020 15:19:32 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:26 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <f96f9536025669d9f178fc11e5df983632c24724.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 11/43] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=HMlGt5Zq;       spf=pass
 (google.com: domain of 3bdejxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3BDejXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f96f9536025669d9f178fc11e5df983632c24724.1604531793.git.andreyknvl%40google.com.
