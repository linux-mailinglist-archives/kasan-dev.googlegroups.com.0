Return-Path: <kasan-dev+bncBDX4HWEMTEBRB55O5T6AKGQEMRCQPEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BB9FF29F4F2
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:48 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id d41sf2347747qvc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999607; cv=pass;
        d=google.com; s=arc-20160816;
        b=LSSVXxM+1VF0CvoJ9pZOAqdFDj+uIimYJ3+Zq1R9dA684+82cNEkTKOAUf6I2J6gk4
         8FosWHhffZ707V3j90laxn0JHmWvluoTXqAsOBuanL6epGtUE6uryWnlgimTGvr+f6nq
         HUA5vtSoRdiOlZKeTBo62dKhVdHNZgrgEjYlcRQEJFUp2a5sKOgTNFOCKXwQ3h2pSlw9
         LNTpb74uf042jDqnNCeyJOmhpaa0/KiMWjxapw/WpGENA5sVJrv38ArJ5nPPEl/5lyRc
         xlpKRWbY6uS5hKa4AZboF5HCkHeFi6QZftetK8SM81TzmIgd6XGgiXSDFz4AWW97OBKr
         y6VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=h3qCaob6FS58XlTi8K8liqX2m7OOVO56TlLK0zKoG4w=;
        b=NdwJe6Qi3PssAp/Tp2bxiRM4+LARDSPrnoDqWR59NUlUBGPok16WtI1kMP6eLRZjFT
         7UydXVTc5BtGefaJ2L4RBU2T8TEPUfg2psLgJ1hSRwVQbX7PSiGhoKbVzWAtOauX1lbQ
         SYCoYeSeFIIWY8V2h+s+aQ7ao1QwX/twnFRqDJWiUntDID3Tug+8WUHdrWK71OHqRtSJ
         tsUr2Ef0ugiy4tUWSwqlfvX61QjkbdlAUSXJm0Py/wABNwPALpOIaVWdMOf4lORAqrCv
         Kwc8wh6tpofF8XHpEdMnAtpFUbX3Rdik3FteN21ker/GPfzoPJd8QsdFjL8l2SkTMMqy
         cejA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OW/hMHsO";
       spf=pass (google.com: domain of 3dhebxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3dhebXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=h3qCaob6FS58XlTi8K8liqX2m7OOVO56TlLK0zKoG4w=;
        b=QluWFPDWw/CItiBIVA3cug53nqyzY8K3bh5Or6l6KoJUnE+IFxsbpGH8S9NSF/784T
         cbpKAfAh83UxgtlVu7ZGpNfdMPICNtgiJ9/Sk1wH5zs+tpg8bJzS+mSqNJ5EzjvXareO
         wbN7J9pIxS6uaE6xQQua2+iht/bIO+Y6UcV9ZtxiGIcpazu/3LGMgS8uQip8VyHYVpLj
         mRCf3pF6XTMpBNaIoZpX3H+dqer4wHBIT3AQ7sbOGfozMtiXxludlsBH4I1nBHUFlS56
         WcL5QZxLwd2kZgrqOjB/XiPc8w5/KH6PUYZLTam+mazEhbd37TB8f09C/Yg6ptT7EgJZ
         m13Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h3qCaob6FS58XlTi8K8liqX2m7OOVO56TlLK0zKoG4w=;
        b=ZDgQyLlp6wBIZwAcPIMUF5JdXdUW4x4yrX+Uiz15T+rG+zBoeDtBrSAF9+dV4v9on6
         Btk9p+yj4RKl6jUtbup8mzxztqVjTL1jcDg+S4eXwU6VCaKOPTGV+MBep8KrvwlbASUX
         u05xd1SyKeAg4ioIdJ5VDpHI16WkMCFfEvJWcHBkZOPJF4d/36WOpQ3c3jy7epjtaHD+
         iHB2t7m8yN+8K60NSRv+iNlko12HHdzAaumsCGF7ZVDxX8BjYF6mcU+zUMWvSk9EIg0J
         Ntug/m7nhH+Id9hqr320ttrnqbdTp+wINM3VGRXR5HrbZAQ+MtkRclN8XaG84vqbyRzb
         IOXA==
X-Gm-Message-State: AOAM532kQeQHUnOtUBsTHIuv8a5UavCQ6O3mJDsLiPJW0WvHoFktUHse
	TKYqtdQLa1f7CAbdqGdlr+A=
X-Google-Smtp-Source: ABdhPJyfMo62dhhOBA1kum1Hkm/jsPoO2W5X9Y6QP+FjeAhvV8jXKpMdjlp9i4spGtXAsu+M6fMBbw==
X-Received: by 2002:a37:ac14:: with SMTP id e20mr5344994qkm.183.1603999607869;
        Thu, 29 Oct 2020 12:26:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b44a:: with SMTP id e10ls1001330qvf.8.gmail; Thu, 29 Oct
 2020 12:26:47 -0700 (PDT)
X-Received: by 2002:a05:6214:125:: with SMTP id w5mr5599451qvs.3.1603999607354;
        Thu, 29 Oct 2020 12:26:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999607; cv=none;
        d=google.com; s=arc-20160816;
        b=IHAatOrokVmlCzTPYGwZmTK9L5cR+uy+q7WRv3CoVxIHs8l3uE9rJho6or6AfIJjhJ
         wx3SfUoDDCPjrDm9PH3IMc6/YYEg00V4fvgLh3Or2kgaIA1TNEpd6/gm3jIxQyZSUVrC
         O25j9IceZswICZ71omvRZ1vmRczwv4c2z7efyMTQPCD2SIrfo68e/u6vymuqsdW8OP8w
         +V0JOv7jOKzT/acEgOZaUp52782U+JTJ9i8qrTmoxmoApcGGW3ZDCYEIOgkR2DEcMwZy
         D6UAAQRG0dDtYqSHQa5JbgnwB5xLX+nzMghuzkuKZ99/m+K/rpRZHj6BiGUv7mxDqAQY
         EsDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Sy6BvWdNS0zjXQiflbFd/HmI5xZS6ylM1lYk0zN7bgc=;
        b=pJerWHyN02QlIzb880/diQthCmW6TK2cODpEU3qOvD+AKHPgPUEPhBAVZbKpZmkts6
         psCSpESJUoCto4/SsM4ZYP09FCvYC+evVuyVj70NJsqY3AMJIjkO5DO6Gu8E3Ng5Taqs
         h4phpoQOmN9fDDyLFB8uXtvbtb3slT/X1hDQj1x7O+pRAUW46pwa3/zdeFQAhT4ZlLKO
         c8mRls3zBpxnAN4b3kZ9yp3hYnqdHmrbGRjs2KH/6SkNveUg0R8dC9FIHPpbZZRU30wV
         Tb4LDRuTdvP6rbowOOhIUFDdlmeIovwTU9vCoyOOVLEL6tkm0MXnr91CVi/HhtN7iUC8
         E/2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OW/hMHsO";
       spf=pass (google.com: domain of 3dhebxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3dhebXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h21si181801qka.7.2020.10.29.12.26.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dhebxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id h23so2014342qka.8
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:47 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4770:: with SMTP id
 d16mr3853281qvx.61.1603999606977; Thu, 29 Oct 2020 12:26:46 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:37 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <a3625b33aa83c107820f241b3acc4e30a155c0f4.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 16/40] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b="OW/hMHsO";       spf=pass
 (google.com: domain of 3dhebxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3dhebXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3625b33aa83c107820f241b3acc4e30a155c0f4.1603999489.git.andreyknvl%40google.com.
