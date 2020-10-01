Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBWE3H5QKGQE6Q33VSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id AB92C280AF3
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:03 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id j6sf195708pjy.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593862; cv=pass;
        d=google.com; s=arc-20160816;
        b=ASCugTkK1LHEP8pNtc8X+vwqirqB9wUkH3Wxl7/ymZcMhkXL57DAcXljHycSlp+Ewh
         na333nhhSTWkidlPiL02Dm+ezLAC2K2o4iULl8MgQ5Xw7Yss9yOs51xAz2nncjLQi2OY
         UKZ2ptbbcC574EH5koLF1/dlbft1vxgCYR3Z/4jk8ElgOcOb/CJwcBh8m6jGotCI8Z3L
         sz9XRN6SR0ioHrQGi4HEgrlE9yN4z/+6KOAP3VVp3STWl98YTjW1RfqZfdaQsGFLStRP
         xtBzwP0WeFSq0n+IuQ8Ue4S/YyVjMcweZBLIv8w9Ok4bf0I7AS7IZWCK8BaaX6/esuLo
         G1iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=C22wxw2bibAoZ97d3gw+MdOT9aCY6GZI0vgPjmemsFs=;
        b=doQEkf+fnG8j1CTRgqRw4PD7GH9GhwHrrIGG2yBYlCwzam5/VMs9Vkl5QpgxzJE2gC
         xuHOKMtd+THme9Q5TgV/osfM9SYPa/JLwVH2MIpSwchUPh1PQAN19fICNP08Sj9D+xm3
         GJ0HSz5v9ynQyS66wqxkBtXsdWKz246ZEu/pipZB2vqTBVKQV0Z+P4OLQE0cEJyy+x9E
         5xCLG+onoHnPyh/Iub3c4KrJ97BtAawAUme0XY91TuGL9gf8qz+rYDyNsmxqy4Q99F6n
         Vt14YpmJI6GPKya+HVd7wnzB54R4UsR3dN8O0XCKaAdt0YjrQ7ZqK95ZnIcUP/aTQE4g
         9vTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VZjFuEKc;
       spf=pass (google.com: domain of 3bgj2xwokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3BGJ2XwoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C22wxw2bibAoZ97d3gw+MdOT9aCY6GZI0vgPjmemsFs=;
        b=tNpIGcYBHD5IGFNevz6xBKuyH7EVvPVp6fDmXVl/nTf0cOPvsKNPg6R2EGnpg/6Gxr
         CkIYFFiIVU8sXjm4NiQ7VWweTnneP0016pS3M/ssUpfRkmmlBwPCfsx/Z50dLEaTGN2l
         3Uvf7SkPk6MNm2UiU5LgJtsInDjL0NpB+tp5Egdnif5q2FLUIy4f4SEqos+pMMbEZ39o
         sQoh0jioz24iZkUx1dIdwWLlKb3lKXmUBARZfxO9Y/ZaxhgnluH+fXd38ZD6zbixrGab
         6uwX9uU5+QqCjK4nf2LgP2OQUZul8blwFIzwJE/Vs3sHaYjUlNINtVm6jYdXElUldgUY
         lTfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C22wxw2bibAoZ97d3gw+MdOT9aCY6GZI0vgPjmemsFs=;
        b=YQgAuvby32BG39wnlJdfYnSP0Mt8NMFXDq0ctoMmyEMHwjEbMtRs0k9mH4ZK/aV/AN
         W56bzaAQIQ962fi7SyLjoMUdgou9i/NPrYeaZGRyATuz+Aa4iVvvhF3hM8RQUx25DkJq
         3+3eTlfZXpnwR3r+RqTGOBtj3tbVn6MeD226eJ2cj7ZNv4PerovQqUaUxvRGDxPNCYmS
         us6ZdMEm8uLT5MfCSZybcnZoU0+YQmFa1gODuw7XNVn4bN6XOBTsbQHVZfIJ4PFI0LaJ
         7fyoGS5HNmzVki1e4fwU8pJRI7zks0tkUI8dAJBrkTIi9oRIgv7i4qyRNkDxthzxRexB
         93oQ==
X-Gm-Message-State: AOAM530/MIDqgRcyBdFSdKJtgSX4bsuKJDu+uepxfOG9y4PgTSNDyrQB
	msrhHV99vwlerKKZg/Mj1l4=
X-Google-Smtp-Source: ABdhPJyiDdvgfL6snZL5S0ejPmXqMvCKqJKheugB/7c8t2Bh0QTiMNoS5OAjqNoWSbhBQXOlZ/VKDg==
X-Received: by 2002:a63:5fcb:: with SMTP id t194mr8444766pgb.364.1601593862347;
        Thu, 01 Oct 2020 16:11:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c7d3:: with SMTP id gf19ls3025835pjb.0.canary-gmail;
 Thu, 01 Oct 2020 16:11:01 -0700 (PDT)
X-Received: by 2002:a17:90a:b942:: with SMTP id f2mr2232683pjw.196.1601593861758;
        Thu, 01 Oct 2020 16:11:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593861; cv=none;
        d=google.com; s=arc-20160816;
        b=fV2mByYuefi7JWK7OFfWvJqLdm5hsiEvhIqOv3R9HcoRs+unOAmB5x5pdPmXAJwcAH
         VANmQUZyvIYxmSNrhQCjb+2glr1dCFeU39hGiFxrwe8XXu9p8HSdBqb9TCdfCKJXK+rD
         R+QJGqVxB+rqk5c0bTPlZCA3+aQT25R4U76reWDF07ouweWvoXJs8WeAYRyw4Pu2Rp39
         8ciF8l7TzJeDE0aMhjJrb/CH+len9y9gFJDpqWisa2dOjUDuqJDBhrS841f9uRlh0pjA
         Y4LIyO+pK+wYwHIRnvlYPpIZpjoy9rkG1WQnp/rWH2bngQt9LviCOaCN8trPo/OFdLaK
         LQOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=w1E5zxU5l/CeX9umqlaBwf6hqmnsI5Vdz5NunkaUR1o=;
        b=yrKoiP8gQoiVcP3gih5M1jRHOJR4EoetYMOSoF3675Et/G9809LH3PlER9rnQIEruj
         Wr2x39hFN4/rqxqNu6HoiXmZgXbNGfUdq5TV97kVr5aD4yE+02ZM2iD8jRwMKqboixJz
         NFn8HMF4nQs2PbYx7fzfGOPtmcj+7y8gnVcHC0j4ATOvrI1vwmEZzh00C/0P5jsltb9C
         KzcwwBLZvcfu6fD4v38waCugymkLPm1vPo4wgAg194fqXBB1HG1oU4sztSlmGvtQCfnW
         lLrLQnyDorV9nl/yBQ/x8130qkYWZzjgq95t7dR7vq0ssIx8udqCoSSJiXBeC0lhWfS9
         dFpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VZjFuEKc;
       spf=pass (google.com: domain of 3bgj2xwokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3BGJ2XwoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id i4si294996pjj.2.2020.10.01.16.11.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bgj2xwokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id u6so90492qte.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:01 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:abc5:: with SMTP id
 k5mr10210842qvb.40.1601593860931; Thu, 01 Oct 2020 16:11:00 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:08 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <d00def4a099b54e7aa68f4bd2068a3d99607f787.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 07/39] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b=VZjFuEKc;       spf=pass
 (google.com: domain of 3bgj2xwokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3BGJ2XwoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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

The new mode won't be using shadow memory, so only build init.c that
contains shadow initialization code for software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I8d68c47345afc1dbedadde738f34a874dcae5080
---
 mm/kasan/Makefile | 6 +++---
 mm/kasan/init.c   | 2 +-
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 370d970e5ab5..7cf685bb51bd 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -29,6 +29,6 @@ CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-obj-$(CONFIG_KASAN) := common.o init.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
+obj-$(CONFIG_KASAN) := common.o report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index dfddd6c39fe6..1a71eaa8c5f9 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains some kasan initialization code.
+ * This file contains KASAN shadow initialization code.
  *
  * Copyright (c) 2015 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d00def4a099b54e7aa68f4bd2068a3d99607f787.1601593784.git.andreyknvl%40google.com.
