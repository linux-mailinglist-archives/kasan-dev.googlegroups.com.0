Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDVAVT6QKGQE7C7PB7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DABFA2AE2B2
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:26 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id x16sf6158991wrg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046286; cv=pass;
        d=google.com; s=arc-20160816;
        b=xerhhfA2RsXJx1Z4SivfeU9wRHcJKCnEanXPw3Jlj4MI5JOzhzdHgXtSm1FbPLgl87
         eq9ssGTf3fe5jEyMFuO3cZL5oQXvinf/o40TnhAdbKt04Cwl3/540iiHIH24LV0yLq0A
         ZMx9r2zJAupXEPZCxqcv6QiJK5A+Pl9YmtBedXfw6gDy07MjXKWsUHQ74rrad5lDV8bA
         UQS7Spw7a5IKMGyg/sqgRRzw0rndlgjR4y6fcXFKS80/ZYo/Mb3EVQVDtno4GiEpfWQH
         Dimc7JyI9ehGnN6WViyCVQqKYDlCH3pUXLNq6IVg5uOQBESsFZM2RviCMjxGN/1/6Z5d
         VulQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=H7XXoQ4tdVCq5CB/SBmtirzvSviBpu2W47SdJsEgOH0=;
        b=kbzjuDKcUmuC6IpEdeyXojLIXFM9iaWoxzFKHi6iQwVjJHcH4G5cHsio4B/Bq/86EH
         ZPKLfonsVV/hTjZ9C07P1ci05xjus68ObaGTUP5O8nOU3B5FJYoBTSUOOnn3vg+9RohY
         6FFQvWm2DkzXcovzNvfMqy6ztVMeFleKsvOG5kiECDpzwni6kePDJlh5vgTynto+WudI
         ErnIqeF996SeuHnTVlvgAoX908NaqKn0Rtp6KmnEzxJg/nBZuaE8/4qJp3cj4fU5ZVYb
         HqThWVjvPanxYKIrGHNoumcmlIdj0jScC8+sk/NF3cpG1h6QxkjHCgd0cW2D+CDEorjn
         eEnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="l7Hc/vzP";
       spf=pass (google.com: domain of 3drcrxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DRCrXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H7XXoQ4tdVCq5CB/SBmtirzvSviBpu2W47SdJsEgOH0=;
        b=G2MzbSLXUlDaSeWCEIhCIczbgnRRdecDbYqmmg1kW3qfk9stuasEvRruQgRT7H2PeN
         ODJg61jBsVX5+YXubHKU5Przo6bGa1Gqjw4D9PoGGQ04P7d/5F5CF5pLiJfTbjCPXQ+Y
         RrpKLWesikWCnOr/GyxLYEKV9z0klzgoZ9CwviqAcM78NPPYpLhyZQQNSsqtkj4+vJoh
         3blYXO4R3Wx+FZUsHdwGJJRWQRna9/b/osCZSHeVTkRDe0NEnSLkd5kYWRm6PNCK+Ltd
         nnEIOpBRpmLFS1I2N5PiEEIpDtHas0vuD3qty5fRpArLnUE4H8yRGbi18AqAqrvUEb7/
         QY6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H7XXoQ4tdVCq5CB/SBmtirzvSviBpu2W47SdJsEgOH0=;
        b=TrYtpU5tG3oiSsLByTG0lwO/BWK/1ROOeebugsqsfRAfLKR3i8jb+hHvGtl2QpeFXm
         whKRjTv3qRDstk42r7Ilma/+FoJnUayLINbNCQ/83hwdhnc3H/afgmfR6xbaYwkP8y8O
         m9J6BrEkU1xfdKlsue2hfMbTi6OLL+z0Pmme5nS4nGBiTqs+fVQM2s10zYMKaepVaOO2
         LtHq+1JGZdffXapnH6yOVmn3Wk1SNPPqhaIBrcJISLyCXHsDR4AHPJUVMSGo41rRyyDd
         oXrPeGVwzM2MTinI81qyXVM32tQULyue0lOJEAD9eyQiLBCs5gxgIAnhADLrhAXrUwxU
         ZqQw==
X-Gm-Message-State: AOAM531t2IrNjNL4rzGPJXdSaOMNNIlWyHmXK0oE0PA0ygcNmGEnTo6E
	BDu8dh4Cl0/k5JjZaZj0eKs=
X-Google-Smtp-Source: ABdhPJzLdHaRf4Y/UsLzIsO6V8HqUbUfW5bV9PDMKwscUEVcnCWkVp62/7pKgG0r2OpVcmpgp2B3UQ==
X-Received: by 2002:a1c:e006:: with SMTP id x6mr236660wmg.107.1605046286666;
        Tue, 10 Nov 2020 14:11:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5417:: with SMTP id i23ls212220wmb.2.canary-gmail; Tue,
 10 Nov 2020 14:11:25 -0800 (PST)
X-Received: by 2002:a1c:9916:: with SMTP id b22mr246323wme.105.1605046285745;
        Tue, 10 Nov 2020 14:11:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046285; cv=none;
        d=google.com; s=arc-20160816;
        b=o1sAewR6zkxeaLTyeZWRT5BzmICRciegi73VS9PK9drLStqyqmSDi5MAt2LcZon0bj
         I5XeUH+8YUREWG/aP4tRO69Ni6pp9MU6JrfSJeq1mZakFEluwOLtrlS28DouxTfVCtV3
         exJa/TmFZkfjiAl1aqb9qMUndUD+X+NhDyeRrazyPLw21CfMVkzbRED5Mfq/xKclCnKo
         RvGuQURGfB63VnQIT1UHIvtBezeEx+c0TvVPQCFZ1wotH89uPmEwPXfZSAE9bOTP1LWs
         pTSQACXDzr/N6V2OY0aXuswN11EXQuktuBSApzuf1O849+rmr3R7a7jD2o6rsuSiN4Z3
         OTZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=6f9VU8cnKdC26HiWZCbo7yiQNGjM3ZLFH75+rhjhEuo=;
        b=y5TOsCQlzJVt+sxynvgFnKwzqXgW7aqx0m6DZGFwTw7vdRHx6sBkIlM1+bxmkpbgWz
         uTchkwVPRkdPuxAR1LPxPteORIb6GfbhpvnVyXboU8bkh4wbaOpUsz0FRlIhpHambkg5
         PnAC3fN5FZgHiqFodYzw3HRxH408n3iv/j0owGGLoRMH0G7SqQzCN6MipnYnn1PZs/wS
         cHUspeESKU/0VA+7MUZRXkH4DVNgyES6OHXa+5wVFqb/UJ0t4Jleihd4ildZpODmOax/
         k4lkP8rAHsMLdwEGwdUj4zHxj+MntGsLLNDA/r5VPkkxdSR/5HLju9aopbfByvorfiq4
         nQ5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="l7Hc/vzP";
       spf=pass (google.com: domain of 3drcrxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DRCrXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id w62si2476wma.1.2020.11.10.14.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3drcrxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z7so1850008wme.8
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:25 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:a5d8:: with SMTP id
 o207mr283775wme.0.1605046285365; Tue, 10 Nov 2020 14:11:25 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:05 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <8f1316319d050f2019e03dac28a37ce1dd5206db.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 08/44] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b="l7Hc/vzP";       spf=pass
 (google.com: domain of 3drcrxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DRCrXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f1316319d050f2019e03dac28a37ce1dd5206db.1605046192.git.andreyknvl%40google.com.
