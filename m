Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVF2QKAAMGQEHSR3GSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA522F6B1B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:53 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 139sf4457385pgd.11
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653012; cv=pass;
        d=google.com; s=arc-20160816;
        b=U2r79kIJRFgLXdQzO93mahBnrRc6fhhy+mI/NaIXCtFsgjtGiCssURaBFkHCDrw1zR
         O8PH2/JtvgrNXs6ghlTXLEpG/WoZJluBtOOYoST6tV00eam5hcTOvUkTMjkIZ+fblT3C
         U3FOPL8AUED8D3KbUao8gSGx6oxKiMnS3MmNWqb19bETOfFPmp31eKGxeh10MErCfgiA
         3S8gtUKPXH1z7qsC7LdB6w75og3sRk8L6hmTk0CnpNJCXQIFa9jICEU4QkB4RamJfLpK
         6pa5+mvqDk2J/EbeMnQ6UT6KjmnMv076fP9p01tx3fgd/YNV7IfD6nLSGfTdpJKGbZbL
         09hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0srZJYNRBnFlmg4vqCd2yglXYiiCQRgU+PT5895SjWE=;
        b=ED1AwbVHUoOmWH88zqoJOn2UczHsZW/te8rloqyhayL2cIbOsPBvfogoqI9xIsvnJY
         CPOTDFDFkpC8PNQrBbhmnnHUB5P+nj7aV8EItO0s0PIEajcO7olffwio1XJLbCRhoEC+
         DNqcaduHBsrtTi6sFmGj7ZZVDqjFozj8Qd7KgHPz7Ld9IHkOw3Sl5bpVDnjMsMlcQ6hR
         x/ZFREdnI2GdHrK/wuGsZDFnqStSGFAV60wXmj7Nb8YTWIMtRygKSFQhBiy43USm8VvI
         mUOQN1DwBfwNEecJ5iXO7LhLPoeoHba2Jp+zNBgzUXJEQyzjtjh75F+7v9V4jw8gfZvf
         +h1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cC2ei3K/";
       spf=pass (google.com: domain of 3up0ayaokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Up0AYAoKCZUzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0srZJYNRBnFlmg4vqCd2yglXYiiCQRgU+PT5895SjWE=;
        b=hN3fQ2lFcovYORwmQU9jEEIjxcE++6S4hYXKzIOB2URluo4Jmg8C52qbSLUVcL7KYj
         D2s+htdkmzge1jOCQ82oAGxLCGchf/yV9BlY3zLG8YXvCkZ6i5E/FMWNyU1bRXojGpCr
         FMY+RHaSNNnVGyJGr77krHbxNM6EPMpHRdqV8mYyL0CVfjeuZD4sIMDGQoGLup2CW3MF
         t76kJUHfmKaHkono5WaxlJaoTZ+4FaWBJtPvA25cnxhrheWXVF+i6TDkzqMLgpK70NAM
         p9FTE+aoluqI2wjzXwAbILb6vkzovns7eocDdKJo/KDWxqsU9B7Q32bQ+eXuwqIbsmc+
         dc7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0srZJYNRBnFlmg4vqCd2yglXYiiCQRgU+PT5895SjWE=;
        b=JAyXuli1I8bcg03Vu2HTnoaPJgboDb855T6AtcsrkzrF+T3GlBE5+STp8OySl5r3Jk
         /qZGCmajkDX+jw8JKm0Ebofdw/QJrsoUuZQwk1gJwyAJDft6DaoG52xwcuFuHPrBNzPD
         4aHaVUUA/wochFoMp18KUjiHQWpZobtrE5KkBieBNc4B4q4JsQeYNMKB0MRoZaEgHAHl
         mIR8bBXyRj4+lWc1yJm+Fewgb+vx4S1WvffGhPd7q71d1LBAagH7EU4YClKGXo4j+a96
         yLtwxghr0yOjhmiORGJWtXw+Vjdcdk8SfPDJ8wpd4lbQuAmsyqZVqKZfJONKRYShN1gs
         0lYg==
X-Gm-Message-State: AOAM530ssj5c8eu72WtBdhUH1/CEM309jefOlAd9JY6cImxtdhXFSkYO
	3bauD4xKtorowtGbabfwet8=
X-Google-Smtp-Source: ABdhPJxaOaJuBx1HMt83+e9N2j+9oopVo9mqGLTjnD1jl54om8dkGDz0IDqcdNsM79E+9b1Izd/BTQ==
X-Received: by 2002:a17:90a:4107:: with SMTP id u7mr6512884pjf.163.1610653012222;
        Thu, 14 Jan 2021 11:36:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9550:: with SMTP id w16ls2514538pfq.0.gmail; Thu, 14 Jan
 2021 11:36:51 -0800 (PST)
X-Received: by 2002:a63:4f64:: with SMTP id p36mr8887145pgl.374.1610653011676;
        Thu, 14 Jan 2021 11:36:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653011; cv=none;
        d=google.com; s=arc-20160816;
        b=nvuYvkCWz2EZp9K9F8dHqQ/QKPHquYdRyEuksGT1qPd6y6ZfolyhDJnxIX7Ar//0AX
         1rpjq2Dz5o2XGMabAeRySAqwSYoLnEDU6ZllnTj9mIqsirMGPpF7f+SFsdfhzqxDFE+6
         +cUJmCFuDpuuqSXsi9wh/dQfvZu8ip98REg5ntFAC14lQvWfDjOc35DcVtjF9eKSMbmh
         f+UGRmZsbFjfJ7w2X0dgjyWFj61FMyV3NUtVmgvwUQJ0qgXcBJABtd2Kiudg9fYdYekK
         AscZxEIoVAKApc9Scl/Lgiog9ARLMoBHv/abZMTHQ9s3Q3XGmuYfONZfmIn1KmVGKnRV
         G62Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=HQul2+mx68GlfTrevBbbyn+9Sc9/a5lDU2srZLIr3Ck=;
        b=DGgekHwrTm31EN1vsAuZJiUzyleWWgDJyZPYrFB2iA0bMTW9/gHCecUUX3u3GL6UDo
         Gys6YWgyteWKfVXrGB7jI799W3Lkp3oumwr86B1zxXdSrgmxFt2u7QulD1msT/tyxJiI
         urM6SHbgtswCpug4fptAtx+kPgWPRvT9ZbS8Vnr3ijoEj+JLN80fm0mbtAYHA5bvxvGc
         f6zSzHzKmH4kkbazxf56z7vbMW3bDuiyLXcUtzJpJKfjeitrpaI83OyNdSTFp5WWM9UG
         vXT58hJA6+lHEpQymk9tAlxNE9oka2esAm0On23QcZ3qSr/N33MaGmh1HuERAXRMNaIx
         4oiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cC2ei3K/";
       spf=pass (google.com: domain of 3up0ayaokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Up0AYAoKCZUzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id jz6si160832pjb.1.2021.01.14.11.36.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3up0ayaokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id k12so5305571qth.23
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:14ee:: with SMTP id
 k14mr8494029qvw.36.1610653010781; Thu, 14 Jan 2021 11:36:50 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:23 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <008f7320e7155cead8bbae07a92ea0140fb4fc7c.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 07/15] kasan: rename CONFIG_TEST_KASAN_MODULE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="cC2ei3K/";       spf=pass
 (google.com: domain of 3up0ayaokczuzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Up0AYAoKCZUzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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

Rename CONFIG_TEST_KASAN_MODULE to CONFIG_KASAN_MODULE_TEST.

This naming is more consistent with the existing CONFIG_KASAN_KUNIT_TEST.

Link: https://linux-review.googlesource.com/id/Id347dfa5fe8788b7a1a189863e039f409da0ae5f
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 8 ++++----
 lib/Kconfig.kasan                 | 2 +-
 lib/Makefile                      | 2 +-
 3 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 26c99852a852..b25ae43d683e 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -374,17 +374,17 @@ unmapped. This will require changes in arch-specific code.
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
 
-CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
---------------------------------------------------
+CONFIG_KASAN_KUNIT_TEST and CONFIG_KASAN_MODULE_TEST
+----------------------------------------------------
 
-KASAN tests consist on two parts:
+KASAN tests consist of two parts:
 
 1. Tests that are integrated with the KUnit Test Framework. Enabled with
 ``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verified
 automatically in a few different ways, see the instructions below.
 
 2. Tests that are currently incompatible with KUnit. Enabled with
-``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
+``CONFIG_KASAN_MODULE_TEST`` and can only be run as a module. These tests can
 only be verified manually, by loading the kernel module and inspecting the
 kernel log for KASAN reports.
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 3091432acb0a..624ae1df7984 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -192,7 +192,7 @@ config KASAN_KUNIT_TEST
 	  For more information on KUnit and unit tests in general, please refer
 	  to the KUnit documentation in Documentation/dev-tools/kunit.
 
-config TEST_KASAN_MODULE
+config KASAN_MODULE_TEST
 	tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
 	depends on m && KASAN && !KASAN_HW_TAGS
 	help
diff --git a/lib/Makefile b/lib/Makefile
index afeff05fa8c5..122f25d6407e 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -68,7 +68,7 @@ obj-$(CONFIG_TEST_IDA) += test_ida.o
 obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
 CFLAGS_test_kasan.o += -fno-builtin
 CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
-obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
+obj-$(CONFIG_KASAN_MODULE_TEST) += test_kasan_module.o
 CFLAGS_test_kasan_module.o += -fno-builtin
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/008f7320e7155cead8bbae07a92ea0140fb4fc7c.1610652890.git.andreyknvl%40google.com.
