Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRFN6D6QKGQEZPYYENQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 41AA12C153F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:37 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id n13sf1515473wrs.10
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162117; cv=pass;
        d=google.com; s=arc-20160816;
        b=qXo+qBqVxYCYO34VZoIwVJ1LhtX93k37g98uH31xXtAonvb6nTKI6bSOw1PATTPIg3
         HqqlfYFC/7EsyCGVflxHQ9wNo45g7eQAc5sHusFC7xOhroo85UKUUxQ7itDotsnTEW8H
         /JV82hq5P8UphJakMgEuIxAn7af4MFhLM25/ogrJObAhQUVZfj7QPv66c4LGpw4JWRQ/
         Sfyr1X5xfqHc7n6by7h4qH+3XkMq9s1Bq34mkN9bNr7Teu/JPlo2h0x5JEZJPqjuq1u7
         T69F35hL4YeAGRPblaKRNQvM6Oa507Xk8krbExpdVt4PD6dgFLDnCIradLuETXwOIyUN
         /ZDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=L2r4zehz4DPD0dCsCOQI5p2ObSGy8GjPs0m6OfKHDxY=;
        b=CIap/JAQjeCerSVjXAC6Rx/LRxrQro3jIAu+562mtCs5E631ANjTlHVGYJKMzwR3ey
         6U8dAbxHr6jfK4nINpimP5xfQUCcNppviIrJUw/cnXN5QMEFe7czgJJGHOV16ze/4LBE
         FNmllx3/wcwDliMlK9JHbOOb75XWXFJpoHJLQWixzVcCCuKRx+8ombqSLpvIr4lZvHQy
         i7OG5olptRqqHYsp4gJOI9KgRFOEzg1lZNg8eO6EbNkG+8UejvwO3CpHG0kR1usow8vV
         Rcp1VlsXmjDTH5Y+m7WjZ7c6ser9N583TO2EniP4WfDNVaq383tpLXk6lp4d+MpFFvUN
         1CcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WY7HnayG;
       spf=pass (google.com: domain of 3wxa8xwokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wxa8XwoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L2r4zehz4DPD0dCsCOQI5p2ObSGy8GjPs0m6OfKHDxY=;
        b=AlRyBfVFyResBhqagzAb3fFiVwZfxu3NQNZ3pdi4Io+UMzCg63l/ApmFYu4p/UXZBS
         WKtxq+Vscjy3WWav9qmLd+OHzH9HBlSCylRsg7FEA4/fA4TrFJla+mTSJlS5RoZICp8Z
         bGlPall6iktyyUdXR72THEExLFBABh+bsuGtClKXvXkRTJCUdXerRb6LkAyJz21HTXc5
         QPU8bJp+foJM9y6yWViXl53cAxkeIPsM/geJSK16fWnJGCOblSq+34TKMcjYuoz2dT34
         ANc6Ucf3dj2weReoFW4pywJynQUnInsC+L2wrOLTeXoNnx3ymu1Cp9GgzYIZat0fyBHx
         s3jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2r4zehz4DPD0dCsCOQI5p2ObSGy8GjPs0m6OfKHDxY=;
        b=d4oNDCthjxfC/oBR4u/uuvY3C0FKtSnYR64W2ZnKiIO5Bhs2KC9VpQNTjlsrnyGdZv
         PsdHt68TUsOegm7nF94k0jXl2K1L9oBSd+uxz6iFheN69lEXphvOn9U0ty4vLdalDRDo
         8IGgHbZQekzRhvxIeeW6vOnG14tMz0XPI6vEbFyjkkUcS8qFe6jVvHKK9+XbbR/PmlAv
         vwkHDQkwmQ6swubMKH/yyHwe2C7JAi4YsARSbPBJgMcSAco0N7ob8HOXLsil601zlUnz
         c9O897oI6IYD/PqjR1qzm85wEnLi86ue0N//USfJuMpBq55EQe5G30rJl8LpZPXCnaXu
         Av6w==
X-Gm-Message-State: AOAM533CqI5bIgJnnz/JldfkIRug6lWoc0lUVlIfRlKVHrpjoPLNTnZy
	GqLM5UBJ3eGfWEFV3Kb0O14=
X-Google-Smtp-Source: ABdhPJxRhjkQ4LOOI1ex5qic566UaPOzsjK94V/Px1/R97BaGGxgAaURR8aOuHtcZSoMRskaxzA32Q==
X-Received: by 2002:a5d:4f90:: with SMTP id d16mr1480773wru.292.1606162116980;
        Mon, 23 Nov 2020 12:08:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d14:: with SMTP id t20ls159208wmt.3.canary-gmail; Mon,
 23 Nov 2020 12:08:36 -0800 (PST)
X-Received: by 2002:a1c:4e06:: with SMTP id g6mr546582wmh.119.1606162116069;
        Mon, 23 Nov 2020 12:08:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162116; cv=none;
        d=google.com; s=arc-20160816;
        b=p/qo1QEMxjQ5STF/5QF4jlvop5WVVs/aBFZgBHCliCkHGrF7lVQ6mTBubO27/zftE/
         01xuCFoUPUn8ERkH3o3kBYwyRFu1bgC6f2+LFZ03bYzmkXsGptE8IcgBG9SaVo8vqS9w
         BjRWkzpIOtdsThZ/Ti9VJiemsNNkEeLWDSEVLMrW8EUY9wuvwlBfk2f1BHp4ISiQL87R
         LO2YGufzt5suGcX7R9H2YmV5/3tXA9M4ROL6Ev0WQetmWxdzqzEFSLZF3YKuyrZypeA6
         9kpXngJp23echLwU4NfxgmReVUfxgvn9kzaZfF3XnNqq2aig9ng02SKHW4lnZX3wHxZQ
         O9aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=L10tW/D05wNgm0snGrZ8GYs8HuV/uyjC1rIZlpL/xjk=;
        b=jfc+yGCpQQGjGLcEDgyTpAjMy/+6mz3rsX67JPG0Z2Y6x/zS54h9RGwU/sK/P5ZEoW
         wtBKLD7K3J2Y9YF64vZ4TbQvYKDqqmDoBXtyw8yfS4N34AatMgLGgMtt5OlacEfC470z
         9fzrF2766rm5SJ5wxKdB1IbnsuiC5fjx+FljI+XfcGGohn+YxK4IJbYMwnKKX2nVBt96
         uUVc+38iZ0lNdb5hH2DJ1okAUzKfTsbK9qi/G//137FpFfDy+1JyR+sZhOT0jB17jt3y
         dNJYuf82KOwm3RNyxWrwiim5fBLovXj21YE/bJajUrx/aQsADl5IzIRyLWSCauiQAdP8
         3+QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WY7HnayG;
       spf=pass (google.com: domain of 3wxa8xwokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wxa8XwoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 3si219689wra.5.2020.11.23.12.08.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wxa8xwokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id k1so6224096wrg.12
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:36 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4086:: with SMTP id
 n128mr617585wma.68.1606162115754; Mon, 23 Nov 2020 12:08:35 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:31 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <bae0a6a35b7a9b1a443803c1a55e6e3fecc311c9.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 07/42] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b=WY7HnayG;       spf=pass
 (google.com: domain of 3wxa8xwokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wxa8XwoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bae0a6a35b7a9b1a443803c1a55e6e3fecc311c9.1606161801.git.andreyknvl%40google.com.
