Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM64QD6QKGQECHZ6FRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id DA2852A2F06
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:08 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id b6sf10704564ilm.6
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333108; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nt+xYdpWP11GbvgC7dbQa8inwbLyn+IbZ5SJkuQMB35T8BSf9bQgs2DWS+fJCw55Fg
         2oRmDfn1hBCsGzKQoRXQv7kcndzXgI3m75+eOTm9RpUpVyOyoQhJ6GisIPb8GZ7j+T1l
         Xk/f1MKHiHm3nMQzA2GEd6RUhf8nTwEEKMl0dM16waHvldIHG9c/+EZR4OfEWRIRIVgp
         +BiK63KIROPhq1JV87E8PdljQrVJ9xcZLZIiNUHwhIhCCTa2d/+sl07dL9i894sBuVFZ
         ilPfW8k5aZKc+OGjF+DebNZols12ME0hGmy38Cre7MoNm/+FrNS7Umovw9XVFT8xSvHU
         Fw+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vndJInDeQyPxNpDh6j/P5ggZyCRBfpoBzyBziR9lDAc=;
        b=PA84cSdX4eERVM46wD3zONfiNVOeYGzMTxMUQ1cjVeCBmmGZgdfaHPWfiqeM32Vxay
         0MQ9a1C/PQ/DIHiGNYcIsymZYqblZkNg/xi1M/+UZYBQs0jwUXtagzGXZzq4/jhYXTlQ
         RctDp0UOFbuSJZZ1AL/ap8PxLOgO2qBC7iVy85SIBg0iwJD14fMBLGKFt1FG5H8fquAC
         zR5qSKdO7K9FKV2FmV8JTfMACPKD8FvfG2UnwkU8A3btZzMrXWHBgXTIHp7ImOsBa/jm
         MzudEkuRia4QClqNdnasAaapsuP956ALAFFSw8IYJUvzhPSwqLxtVBBO/pJlZroDcBmZ
         b44w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HVGBfoVQ;
       spf=pass (google.com: domain of 3mi6gxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Mi6gXwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vndJInDeQyPxNpDh6j/P5ggZyCRBfpoBzyBziR9lDAc=;
        b=PQxo/93H9LTrDO/7/JIDXD7NKIVQwjI6xgUtYtowaq7LlG412tHRbN8AFiGAUkhGMR
         J1n1y/CQaDDouAR0XtIrOcio9KuU8jEmJW+nSkFSYLanIi55hFXATdFKLhW1E7I+1JG1
         j3YuX16uhPrJPR7A2KRcd/59b3Ixk3Z99PHIPWA+6uNEz8VCSa5KC/zHxpQB0NAdGLO3
         zxiir+vtD0Pn1ZcGHJ63YVTcvWIRUXsITNY+961QyuJHR4QqvA+ZwqhXC91iGgaJf8sj
         Dsf/9z+OhsPVmLhIWZT9VoqJ7Wd4dJu+YF+chwpxjH3qFL/Nzk1anTWs8vIDkWQmCpYp
         imww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vndJInDeQyPxNpDh6j/P5ggZyCRBfpoBzyBziR9lDAc=;
        b=YmtOtfRhoUYkRZlIgFpCbGIa3Qo6FwZm+xdyP5TOaenc0JjhBniRgMXYYvr0eywPSM
         QRnpRqaZxmkCy/DbaPnyMBo4H/map4y6GTDtP1JFpFG9lhoIGber/nOHGzVRUdLGglve
         hSTQL0BNB9z+tcp/fcNBMkwioI6ZkleSs350hNOzRExdIszxodlKeosiu4O0b0u/SwiZ
         md0ps5Usm0/jgoxy/bBaSlvtDXjXQXh1ieM3/GW8C+nZE2RryWMF0v87i0wOrEzuVTzN
         ZFVEs/mG8WFQuWEw3zpjXBwiB55d9hu2gcic+w13jctmzfhF0bI6x4pvVZEr00zm1czt
         XteQ==
X-Gm-Message-State: AOAM532BUDdyh+SNmrrxZj4KRs9Ub69yutfIVvgw7A+OK7+1mLjoqfvW
	vmYNsBES6EDjnJYjx0JxBkI=
X-Google-Smtp-Source: ABdhPJy9PgGo66HYhEYSyYmufGCUHVYloTCVhEr3VrZtPL7QUNB1Vm0Pc3wmutKgAuOMa/XWqWECVg==
X-Received: by 2002:a5d:8a02:: with SMTP id w2mr3236855iod.178.1604333107835;
        Mon, 02 Nov 2020 08:05:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8154:: with SMTP id f20ls2002555ioo.11.gmail; Mon, 02
 Nov 2020 08:05:07 -0800 (PST)
X-Received: by 2002:a05:6602:1214:: with SMTP id y20mr10736656iot.190.1604333107500;
        Mon, 02 Nov 2020 08:05:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333107; cv=none;
        d=google.com; s=arc-20160816;
        b=VqLs/M5DoxgXi1BhSAwneiiYeYa5oLrOXE7SXZ2hWuQCYrJM2OuvlUEUapPVwlDeRc
         LnWJ+7dXku3Y/Rxa3kWFceIMv5Wn5MzUAIiNbj7qnjP5S/JPWhaMr+5MkvshnPxWeXbD
         0udSuh81Y7WMxXXE1n7h7MR3pEtEP9CMDLQkdv79o059OH/MDkIbK1bu2+PXWV434k7e
         Koi1j7lKULvxCuq7U/QJ7HXQlImrRKz3NJnS7H4MtAJXG4inxf8xseyseJ7ajBbcfoag
         c3swBQ1ZPQ2d/pnyldu8zgaXKPgpLaPgKlPFFqndqziB5U4pyDSjdUHHmwHhoxsGHTWl
         pJoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Sy6BvWdNS0zjXQiflbFd/HmI5xZS6ylM1lYk0zN7bgc=;
        b=qwD68MFXCb4vtqLz/e2tq7ixd3/uYmyRFksMl4uCCMcLQN/OC311A+FgU3QyqzZeza
         sMIzIx6YLo9kyN0hVeLg0jNoyJZmtv+jeqNXlr4Hqc8WiSUSwHav70721OxUf2hPQESs
         fYTkPr0AKKWgMv08TYddE5smiPW8KjnV502jrJQBuH1q4El0RdxbMk2P2X5V7iOUlGMu
         dipkcR0Nru19uxF0WsBqM5WZQ02ZVkoMmYYfLjCf5UAQxPl5XjD1Zl5Z3za0iDXINYsQ
         PImMefw39fVgrdfYIRFIAz7Z6qgDnRQkctNGLw+TgCxW02hkWpBDWELQRiWwvxlqSKTw
         M6XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HVGBfoVQ;
       spf=pass (google.com: domain of 3mi6gxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Mi6gXwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id o19si868053ilt.2.2020.11.02.08.05.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mi6gxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id z12so8339312qto.4
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e585:: with SMTP id
 t5mr22207546qvm.6.1604333106950; Mon, 02 Nov 2020 08:05:06 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:57 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <83f76fc92ca8c7f1a037356d11b6242ae0c4beef.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 17/41] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b=HVGBfoVQ;       spf=pass
 (google.com: domain of 3mi6gxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Mi6gXwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/83f76fc92ca8c7f1a037356d11b6242ae0c4beef.1604333009.git.andreyknvl%40google.com.
