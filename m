Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWO6QT5QKGQE4PTEWAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A9CD126AF5F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:13 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id a81sf724389lfd.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204633; cv=pass;
        d=google.com; s=arc-20160816;
        b=ObMY8In+HcKrWsX76FL5OL8ryFhdMcsAGIy0FzIHeeTmGAFevrAgbnuHey7EXT939f
         D6zKxf29do64QrfNkYD2G24J5gJJuF3cibDS+lYT3zKvKK6ggBXTYsBZvjP+SZ1nATLw
         Q1BR6am85a9+U25/zvqFQvFQaSPQL/AfUQuXmItzpbGEMpmgKKNNphR/cfF3goCX8DGm
         dGi9A/ECHrlMbR94UlcqndFnd80QsTpLBN+1exmiXjo1Oi/FG/0zsiidbKIU9kE5ofsY
         pERLypJU7OSxSwNvg/8sITjze5nkgLJiX/rVaL30zb5PKivtWcNY5RKubmx+hGOn9TX3
         1tZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jt9L61f90vPmjDW22IuCxDUgjIwkwXZdgAHGt24ZpG4=;
        b=bGx5uscUVVUhM6/x/dTzoyBUk1N6l1hmXskSNkJ5U527RTMrBYgzWEtHmUsbRBWiMK
         AGTIZdN4Vg8rIzn40qNZQeK/vmYPbxm8QgVdSqhzADPtKb3ReHHMy18YkPOfotr6Gn/0
         eel6p8whujV0ySbzX85BVpIxavdycdLqDF3+cRzmYa8TipjAePHqXq86EmcQp1epupHX
         Zjlkx2Z2fHBf4pWtfwumRUzhPmziCf9j63VHcGBI8ex80GRxuBn7CaLeF2b+Vci9XrND
         HMYw1RKAke4i0f1KyU0vnGnT34jttD7IdgLeMrrroZBOQ5gJDXjVlBlBA5hqGaEjauw2
         FjBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ujKP7f36;
       spf=pass (google.com: domain of 3vy9hxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Vy9hXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jt9L61f90vPmjDW22IuCxDUgjIwkwXZdgAHGt24ZpG4=;
        b=hlXlpkp8GKsdpcA0Vdg8I9ePCTXl7fBj5XbTrtrjeLYSnAFn5KYoStb6N2brJVP7wb
         IytcyTRlRe3+AnZEeGQ/TS9hetAyxxIe7DLq5atrfPMJkuEVFEKR2S7Wp6rr/YZtpiRu
         cNyJLqX9Pc6cUuHT2EIDPaO/226ZEoA4P6gWGVRocuilLIY1Tp2ecs1NZ9qdcYiDIXJM
         N2EK2H8nH/iuR4TTSfY74Z3Gqxqmd3cYnEtLK3NKQtB74H8JRH2SJVs4LBfM5zHxrht2
         1TFPyNoR3VPvAnmy/JAwUzZ62AnhUZvbn9J6UHiQ5WSHRhgCbHDsNGEzT0fFxtZiekh6
         FhmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jt9L61f90vPmjDW22IuCxDUgjIwkwXZdgAHGt24ZpG4=;
        b=GFtzRFTVES34Fh4t3zpJju+NjdqD2cDVALcsnruALiX2iyhw8F4Zc2y+qvdSlRHyFN
         pxSHwjEkHLXS6H+J/DnWn5zftL9czTvcYHbmS3/SM9iNeJIEhfaBJaWUMbcC4PMSPxnw
         aJfx1lHab6XdqN3T/Akb3WjydaWTMz8srSR9YTZFxTmVXbt3OFiVPhUySww4Rf+Ih80A
         jXP5SCdVPtlImJf+SRVLC3gWsgYlIN9sc/oXX0os8bx/SFBqR74+EVnj3PT1XHknZynN
         YTGBIJrieu9xuknzeQ6cHT3Yevx+ymzhl11ID9R3c2peR8hahjAVB4q33alyfZJ5VfRd
         IQDA==
X-Gm-Message-State: AOAM532/6K/88s+GzshErCMB2daEl740EjgPq+F69Ogdh/KQgQoPSXnB
	NNMiXxhnoZjp2wXSRCSjaZw=
X-Google-Smtp-Source: ABdhPJwdTxirxxATl+HQnFhrw/hUAnoxYvs38NYiHdwvFs24IMs1ecnVB6a4CMHRPK9j23CUoP3MDQ==
X-Received: by 2002:a2e:9d98:: with SMTP id c24mr3969398ljj.281.1600204633259;
        Tue, 15 Sep 2020 14:17:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:93c7:: with SMTP id p7ls52657ljh.11.gmail; Tue, 15 Sep
 2020 14:17:12 -0700 (PDT)
X-Received: by 2002:a2e:3210:: with SMTP id y16mr7839116ljy.417.1600204632212;
        Tue, 15 Sep 2020 14:17:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204632; cv=none;
        d=google.com; s=arc-20160816;
        b=gr4H9Kfgjiu6+AXezp6rnSjy57lfRpgalwZ9b/JqZ1lZSQaSLsMUX3onAnXcq6GZwP
         GU4xTTR6/NmkVonX45scczc3blW/22Iw86xHGWR0pJlynyP+OgC2468S24WnqKh8ErF3
         embcDzpA5SxHSCHd0cXNcKIbHqpnjbPNvGDgHUaZYDOAOcUX2xJsJcy80/uipVfa0/q1
         mZoZap0eWU58DX1qtkRo9urjiI+MaKMJQ35m8TD4Bx4EpQi2RMcA4vYMuvXnTSX0zwnm
         qA9f1+IhdAqJJhF6mpOug/Yuw+m9fcoYMgZCtAgUgmYp6n1xkrrkEIATXuEkfymfECGi
         Gzpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=esxSXj6mlAjehqEnyoU+Xpp5A2AelPI+Y2Gwz7MtjPo=;
        b=Czn06sq370lrTVFplouGeVwiw/4emHlGwq9EA4VjdgFQfgJTN84pgbxGQqZkT9l/OL
         mttOiPe2r0NqlbSeebugEoCoDMa0TsJ+fJnwhTkWzw8jQ4ZK3AvdgA+fkCEVTrnFKezu
         vKMmVZbWoKOvaHAawXp1wJXUCsfyLa9tvPBu0IeeGhYNTqCan1r3x/y32SAtT2K5n5tp
         wW1WQ+/HFKDCLylVh3EyVKO5+PJPr9MX/9E/F+xXZl10ijQQyjgbghoAPNzA2BhAlsfE
         uebW9itp6TulD7fYpn7miL1mUR9AgkVvNoRC7N2KD0qnR7jakIavhAQe+2RqS5bfU2IK
         V6xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ujKP7f36;
       spf=pass (google.com: domain of 3vy9hxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Vy9hXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f12si566847lfs.1.2020.09.15.14.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vy9hxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j7so1707023wro.14
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:12 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e256:: with SMTP id
 z83mr1249442wmg.33.1600204631443; Tue, 15 Sep 2020 14:17:11 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:02 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <28d17537bbd029104cf7de4f7ca92246449efa50.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 20/37] kasan: rename tags.c to tags_sw.c
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
 header.i=@google.com header.s=20161025 header.b=ujKP7f36;       spf=pass
 (google.com: domain of 3vy9hxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Vy9hXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN will also be using tag-based approach, so rename
tags.c to tags_sw.c and report_tags.c to report_tags_sw.c to avoid
confusion once the new mode is added

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I922ab246c5903e8ce3dd3766b923aaf250599850
---
 mm/kasan/Makefile                            | 10 +++++-----
 mm/kasan/{report_tags.c => report_tags_sw.c} |  0
 mm/kasan/{tags.c => tags_sw.c}               |  0
 3 files changed, 5 insertions(+), 5 deletions(-)
 rename mm/kasan/{report_tags.c => report_tags_sw.c} (100%)
 rename mm/kasan/{tags.c => tags_sw.c} (100%)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index b2596512421a..0789f9023884 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -10,9 +10,9 @@ CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_report_tags.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_tags_sw.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_tags_sw.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
@@ -27,10 +27,10 @@ CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_report_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_tags_sw.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_tags_sw.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_tags.o shadow.o tags.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_tags_sw.o shadow.o tags_sw.o
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags_sw.c
similarity index 100%
rename from mm/kasan/report_tags.c
rename to mm/kasan/report_tags_sw.c
diff --git a/mm/kasan/tags.c b/mm/kasan/tags_sw.c
similarity index 100%
rename from mm/kasan/tags.c
rename to mm/kasan/tags_sw.c
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/28d17537bbd029104cf7de4f7ca92246449efa50.1600204505.git.andreyknvl%40google.com.
