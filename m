Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7XNRT6QKGQEURG6E4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 017642A7119
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:27 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id p6sf76833ejj.5
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531966; cv=pass;
        d=google.com; s=arc-20160816;
        b=JJcXOMJjJqsTdBQ2GqXDgDSE8Mf5mzdJcHxNWujddasa8Cfj5W/0TaO/oPwrJvwGrl
         yGcm0V+e9Ea54iz+OMO27m4DpXESqGEU7Xzin5SCHdq80FG4TMG/JuDHx0araxgBkcaE
         NjGjTeZfBK8wbRnrPcdb2aloSxb47sOSsowXrQrgFTrun15P4+tsJPlndQZE7RvB51Jj
         nLo7OWgj6sOqU76UJB4XMMC5KLjbmIvZEnGCb54awx82mj1pNDzOZ3QBpv2UepcARb9h
         IQWDNq/iHPriT2dJl60D4PeEPQNELsxjT86Cs2a4RxOnGSZh2q1F5NHSibD1ysmrNwSE
         uHaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=aIS+p1UzES93sKnIEtI/GojCoDl31wPR/PqTN+maA0g=;
        b=b8WaERbqeguQyaKbnLV+0ecROPRKzkDtRSOog1Ocbh9UdTZTuZFnULfVT+m2/q1036
         RP3hccJGx1U0Yc/o28lTA7ZlnQmMC1dA6yHOG5u2gac7NvYnigkeFShZVdzs3cNpsfx9
         ROjSdlATBGdvVooC1czOTDvDEyk3u2iAEvHuQ2zrvKYYWOagAm1IPzkfe/EwOJEYt5HG
         UeyYzOG6f856e4gn3DsQqHDn3ElIfkPzjoOujb+ripyj90zMDg6JRNLrl28T7cJNWqfj
         TxOU4p1zUMkpXUgDb61blDJxkDxyrCE7vPpXpv7nMewCnYNNSp1+kq9jC8FhNck1LX6A
         QYtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oVOf4hGd;
       spf=pass (google.com: domain of 3_tajxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_TajXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aIS+p1UzES93sKnIEtI/GojCoDl31wPR/PqTN+maA0g=;
        b=LCJ2QxbCk4eglKw6hWJXQR6G7+2JGQNVmB9yv5YDPKJt/rqmdVTu+TxfW0hCJOtB4J
         FTy02QBtw2B+3IzboQpSCkIneD9x40G4icnGilEGw1RHTxsaNxyNOUYZ5N7psyII9Hnm
         C8852hTvWuGVR2GqPahnGwIGW8NU+EwoAgZBS4xVCK7Vc1G9MY8zNKXb/UvHfbbxc024
         Pj7g0nCW5yHxqlb0eHn2NPxZYIbXX3RzM3p9/j10nYhmii/vvo3l/JpqZtNiYacnYKYf
         xJ1gAOM9a2rJe85dALFNbBd7cejgKbmzkvetaCAjBMMEL/0FZ3n3JlUFZH2IDOWMrbCy
         j41w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aIS+p1UzES93sKnIEtI/GojCoDl31wPR/PqTN+maA0g=;
        b=oNlQg0w8Z65WzbP6GhYHepLXKV9Cit7tK1QjZhwAXxjIi+BC9PYm1a8aFbFwYPdaso
         JStl0Yworu9CeMm56dcO2P3hwJfusi2/8m6oSZmTeUm6awzq1+qgNOGtO8o+nCzNPQfT
         1GIrprUyv7iQH4Av4BsYu+YkAlFblcIoyi0SO+rZ7NeplcWaJqhXHHU0/abYCKDNwk/9
         jTzEFiiwLFrWvThGeKRHG6eCmKdMSVfjQJX6M3FQ1PoFTxJMOVY4nZEqSIhCndUupNEG
         MdkMD9RnXEXXfcr2Eu4yRrkpwhip7j8OO2lFBJZiIYaLii2XL2jc/hXd9smxFpLlGlxN
         dBaw==
X-Gm-Message-State: AOAM5332Uqfg4J0nQrhgxMjBybsheD3xiaZqQI/tql/48lkk4y7le/h7
	1Bc+dra9oJ+mmU6OtSjUSOs=
X-Google-Smtp-Source: ABdhPJzf6xONQVtPm5aa8vN94xBjlOZ6cj2Tz0MN/aeKqsZZK0I3gGXyijz6xsWDv4PefL2qV2NEVQ==
X-Received: by 2002:a50:930f:: with SMTP id m15mr209625eda.112.1604531966783;
        Wed, 04 Nov 2020 15:19:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c04e:: with SMTP id k14ls4120791edo.1.gmail; Wed, 04 Nov
 2020 15:19:26 -0800 (PST)
X-Received: by 2002:a05:6402:22d8:: with SMTP id dm24mr177975edb.69.1604531965900;
        Wed, 04 Nov 2020 15:19:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531965; cv=none;
        d=google.com; s=arc-20160816;
        b=mUrb4gU/eZkE24eqRrCUWeedy0lRPc5y339LotOmwXc9OM9NrgC0y50Ofz76vSWBH2
         uVH3xuwCQYD8FjUJRhz1qqViEECQjTsJoLMWjNVWzj1aoBTRDDngE30+TkvFoFcgW/u/
         6kZkJtB458hlROJpyMrJ0o7m4+lrmJcUwsLt5R5Vtb8g/BgwqZFQx0WATlftkbjv4ms6
         wPHVx0at5RDvjH57ez1lSq9V9Pe3pC8UviXVI33N5lssViaEABmDW6GdM+EFR5bKtxyA
         0lvTyaZ3felfPa2wK94HAGeiNRjHrJuLiy/C66yper0wf+cY0/SbV6LMuJLdesQStBBY
         k43A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Sy6BvWdNS0zjXQiflbFd/HmI5xZS6ylM1lYk0zN7bgc=;
        b=HcHUTqdQHKIoV+6D5zodZw0LQpowBqhsidS+lixhsNqFdIsOG7oQunOO72w/X3smfb
         MUy1vNxVzpOSQkx5+3KhTm/by/V9wPi9xk4WmBN19wZ3tj7UNUX1LwxkKgINQFCMQOrl
         ppOxlwO3VKSkrpAx4R6DzwcioqfxeEl7lIN8brcupcNobhh0oG2X31+4bwZ/hAs2ovgb
         YiLr55ISR+xBsjDq6Zmsvbo62NO+XpzNFFDy8NZ8Suni7pf8CLVoYsL8ds6js7JEtLhi
         cHb+Rp+X9IH1uLnlSz862fyELYKTzHha4Fjjhgleki3+CBIbAfl1say8W95jrpIWWhlE
         TN2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oVOf4hGd;
       spf=pass (google.com: domain of 3_tajxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_TajXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id g4si142221edt.2.2020.11.04.15.19.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_tajxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f11so38597wro.15
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:25 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:309:: with SMTP id
 9mr83914wmd.80.1604531965449; Wed, 04 Nov 2020 15:19:25 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:23 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <88fb34d65d1ff22472a9a2ba6758203ce1bcfca9.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 08/43] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b=oVOf4hGd;       spf=pass
 (google.com: domain of 3_tajxwokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_TajXwoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/88fb34d65d1ff22472a9a2ba6758203ce1bcfca9.1604531793.git.andreyknvl%40google.com.
