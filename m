Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQELXT6QKGQEVYA46PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BC1C2B2801
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:33 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id w5sf2409852wrm.22
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305793; cv=pass;
        d=google.com; s=arc-20160816;
        b=c7zNrg+7EZ9LBDkUeGU0KWrNhsGJfa5v7Qh7XaonJuXcxo8Q+dEexsxQ3PvDVQwH5c
         38oPri8ZAmywtNwyECcmeeUQ3oEbdATUHukXIdEHyyiFMkP66/CeaD+RXQKJKRjnKCTP
         u8z9f/9r53wNhiyMHoIJiWM81R9herdJiu78OWz6EpG2Qs2oVh3+Wy2wMVWojLPRK6+v
         KEPL+sWQp0BNLSy/FgDcpSelM1ahjdpz4Og4zq7ItHMUes9+KdgaSEqt1bla6LyRHyhG
         GWGw72UDCH5XqGujcdYJ8VsCpWDIueetcTcpQg0YPL5E4ulYJ1kBPlGjKYUguXBGShFL
         +Y6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fPJzro35vJvacBenGRnf8UBeFjIi78NkD4dLHfUR+nQ=;
        b=BLLaNO3KldDAbG+bwQUkj13hfIJtfVpJGN8/vnBfdzgIuoX8zV3me30JDhZOOJnbab
         6ylIPP5yeYhTA8qtP81WxoeWt3wuiEe3q3FWyr0AjWO+CEgrCVCh4Ve+QaSisLeVfgnB
         dmsHQFt/PFCNDrODhO5exJrY05hZSlj+apuI5iP5myNS3cimVmENpwzgIILlhb+3R+iy
         dr2Zw3l4iM3DHkiFbqt0wIx6lcQTnAKU1wmR6nE6Lo9cseW2RrFnsp24KAZO9wj0OI0V
         2KvrN989WCQa6LUYJePHW2wndOA6XAC/RgQjTv1TZNpLHak90t+GL6CqYvRlv8kWb0kp
         an+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MsQn79So;
       spf=pass (google.com: domain of 3vwwvxwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3vwWvXwoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fPJzro35vJvacBenGRnf8UBeFjIi78NkD4dLHfUR+nQ=;
        b=B629eJcXgG9WplNmHxLi14piQ5CNFcZHEvkKwn32JjJFVrWbkrxEyV/ywpmhZjKZet
         82UW6u7IRyZDrlOd1Jd9k5sXfYWoMeCHejtSOdn0jDEZYzp9JG/EtX9c1uv/MGMK0ag+
         bugmTV3Daj9o8akPJnsvQPkmTup/ccXB/Bl9ZBilQyqssIsmLNQR9fki53O7qb/gBshj
         Lh5ls0TdyY+6wKcSgM12h9omJVlpK1wYYuEGl+il/t9y70ZnTbZZCCXAJV2FQDDlnj9f
         AiHB/rGsGeUqFkAAJlQfLRknivKco1AjzOZffbhO8aBCE6dtw7YlHdT2kCBBT/89UJY9
         fKbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fPJzro35vJvacBenGRnf8UBeFjIi78NkD4dLHfUR+nQ=;
        b=hHIS5q6GeFFIRHdNrI0K9RQ2ujuYG4mTm0pg55onNJ0vZ9OtaY2JfZCAPUpFuH+Rh7
         IUTB2b+k8tYZeDdgZgXDLKtUxCD6Gj50XJAOJ3eZX9aStvy+jjEufS72MIN4wEoREDAq
         q5CBDmnmwmo/9iPpWnAhhaLH0VZx5ngCHvv/tA9nU7RMY2uZK4aX3sLdYvUHfu901vk+
         OXZAlbh3eIz/N9VVFB4Lkip37BBvlkAiEgQGfDu4bufKu20SSe5JJKHxdfjXAHhfPqZQ
         dGELfoO4ZzFwVQ5ZDyi3V/TCBMe1JXJya5k+6WmrBylVXg3MBB4qnoKKyKk+j/Bic+8S
         kf9Q==
X-Gm-Message-State: AOAM530OaH6kGvGBlZQcYr/HqDUr2HslUzKgu7ThxIWs3MDWlPGqYhRH
	cHTz7k4iXCv4WspahmtMwlw=
X-Google-Smtp-Source: ABdhPJwCAQH6vcaSwaM57FOGOgcuBLXz1S7KPHH2lIh8I4mKPNytBSOtp+eo2bZkQ5XkXblI2RK9Wg==
X-Received: by 2002:adf:dccd:: with SMTP id x13mr6408885wrm.394.1605305792860;
        Fri, 13 Nov 2020 14:16:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls7244553wrc.2.gmail; Fri, 13 Nov
 2020 14:16:32 -0800 (PST)
X-Received: by 2002:adf:de85:: with SMTP id w5mr6191992wrl.90.1605305792051;
        Fri, 13 Nov 2020 14:16:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305792; cv=none;
        d=google.com; s=arc-20160816;
        b=C5BH853mE2EB8jSYnHag3yTDPw6AGM2Z4i+8NLm0TI3BlNH48LYCpymFMJl7Bcy7RF
         uuqstTQEGtI/hB7QUR4JKOF+9oY14d1vRADcMRJDDZIPhEJsWklGvT1o4gVN5ASQCaA0
         bP+yG3hd6uBE0CWQnyVH0f+pDxzGe675lq2lN6wiplaN1b9F+IS9dbvSQtGeyCAsGsT1
         IEDW3+XfkEA6+cYVBppEUMkVoBrcJO3dY1nhbCpnaWo2wzT9mqD7Egy97C05dB0+7Ten
         6K3dIonJJU943Fy7zDTgcG+36/1OKOi8FEE/sc3uYM0qmZmV1I2Gs55OoCpidBvupSOB
         c4BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=XIXqMdSsmfBQs1yd8rWpQ1njkvR1OEP1mN24itzZ0z8=;
        b=s1NgDvtTAW3i52p5iNM1LGu3rDP46WiEdKUoJPaPl4SN8p2G0BnxXJ4MbAakmlrkxy
         n+88v311DyqALV5ZygucN1UAtIku57RH2rrRhQZ/EPDVYsVA8769wGjkMlf5kZzUpBE6
         PsslMCS3GeGeGd1S2RuZIafUFN1UMY6qCRJUEFJKqKs3/yTGlJWf5BJKt1K1hwpPyZQu
         DXSZo3alnBccdrgMfPHvoOeB2GIdRwosBrcZ6PcGeWjN2zC34/1f93Yfryzu718HOxsG
         QfciIFVNvAAq8v33ldKJjKALFtQGqhxuprxbJhcBPxJkmgE10PZlu+C6voY2aoUVXxQq
         4anQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MsQn79So;
       spf=pass (google.com: domain of 3vwwvxwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3vwWvXwoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id p16si230827wmc.1.2020.11.13.14.16.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vwwvxwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a9so4855768ejy.22
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:32 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:783:: with SMTP id
 d3mr4903651edy.168.1605305791570; Fri, 13 Nov 2020 14:16:31 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:35 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <a1864343953031cddc2cca424d9b7f50ddf971d4.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 07/42] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b=MsQn79So;       spf=pass
 (google.com: domain of 3vwwvxwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3vwWvXwoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a1864343953031cddc2cca424d9b7f50ddf971d4.1605305705.git.andreyknvl%40google.com.
