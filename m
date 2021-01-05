Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ672L7QKGQELWFEAZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id AB35B2EB289
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:20 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id q10sf460433pjg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871299; cv=pass;
        d=google.com; s=arc-20160816;
        b=xmtntUjyDa6SA7kcdQx6d8c8I7jBIf5L9aQQTBI/MTxw+dUrq7y3sdamSFbXoO+7jR
         E3BmTPbVhFsxf4tLNeSxvz9e+UWAo9MpBk+lewY7yjzF98iTUJll09B19nkb+gZE4W7F
         Mz+x+W1IXt2Z+Z5vlSrYeOtB1mVSTdlc0xF76OKcXW4REcKTLMfyDWHpuysW29DM7X0o
         G5DNKh32vOEWW7vNm7f5WZbgwo4p4vSxPb/f55K5q6iVGX8eOpt+T7mGlzHW3DrRboQG
         gQ4lXTJ7pLzeICnvI7TLjgs+Qf6Bqp08g56LAmWfyEG6hIgrUeHFLVNpQHA3Lrq3AujX
         LuWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qr6XQ49qkwx+Ky+gj9pyzJ2T92lJW3U4aYvgz9ciVe4=;
        b=GHvlAJTX5zznXdA91vQCXfKg8CD/99qijnjQuZTgWmgnjFy0OugSBRHscVrMhVe0OE
         dvqaWxPALOb0pIAuAby/BuQXbcnMYOb6IY9OTfAYsUcCOHA87WIDSn6m5DdNeeNGas0u
         KkPGD3pokwph+mfCWlPpEcP1Sql0kPMyh3q3z3g5MYxGrKfQG99oUSm6lLZWTmLISLoP
         klALobRZVtv7M40T09XQMXsUwBfVeIMqPnk5jMqNKNnFy4RGsflXYKIBieDIXtF+nLWu
         mnHrvRia8Uuew8MMmUbAYV15tUmLUjTz+n1sm56s0rxGllySgfwpN3BMEJj7QsygYWtK
         bMOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f1nlOcJ4;
       spf=pass (google.com: domain of 3wq_0xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3wq_0XwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qr6XQ49qkwx+Ky+gj9pyzJ2T92lJW3U4aYvgz9ciVe4=;
        b=P0xAPieZzckqkWKkZGq2joekkKrJ2MQ9r3ZO4tyF5kYLZXWr3vwhWYcZJMuJKEhtaU
         /1tGKLbnE48TWJTsgWT9iSwmr3efoyzenbPQVfVKtuzzIXxFo4ixnvR0C1C9Os2y5aL9
         V39fPZ4SC7dkvr1HpnCECWMXmvtIo+enL5kLq58hTDJAV3iqaU8AzgjB6ZBmR7OMlqr8
         UywYbfpAPWb6slsPIqJNqTortOGY1T2E0wyiN1/5gURgEjeuTzW49B23f03oUponrZK7
         qsI1EmLuagCGT0RxAjlJcXOyQzfE6pRRfxkJBxSyWGClZWnjyP1Dxc+PpS17+SoVN19O
         qsvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qr6XQ49qkwx+Ky+gj9pyzJ2T92lJW3U4aYvgz9ciVe4=;
        b=TFNGjUrFwPjqa6+jpnJFm0C4ps0SB5y/7opKmkTrdgrxwMx70bmbs3e6ngZmKudHra
         TaphzkNPFP3xOYs5f2O3BScGVBEi/HGXAj0PPdeMOOpqbbZgwgalPmhb9k+FYg7Ck4dB
         QMI7NIfzcnXPDmPglyb4rrs2QtXzwOJy+imQzCxhv+o0a+Sl3gpkUTfA0j2+NCH7NQgW
         +IBVts/S3Lc5+Dm2PQAsV3q5SJo9m2P4sMgWUNRXZntQ57aWxAk3McdRsxSH3hLtjfRd
         Q393WUgTcarr+nFvzUcJk5hMrVY6M9ITuKV5chFiLykrWPjcButucC5d27uNqtNAu+Tj
         iygw==
X-Gm-Message-State: AOAM533BDW1NropmXAp21mQA8I2FSowQwymJt1Vn0z3B8f4pNJ3NzfDH
	0hj0y8ldIOAeV4QtKXWA+60=
X-Google-Smtp-Source: ABdhPJxpRpaSQnkY82N23wpe64+SUfQmI9NmOWfRGVR2VNymTRKGwbM6NaKSHv2GN/3SwSz3op+MIg==
X-Received: by 2002:a17:90a:6842:: with SMTP id e2mr497976pjm.190.1609871299321;
        Tue, 05 Jan 2021 10:28:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a609:: with SMTP id u9ls178334plq.7.gmail; Tue, 05
 Jan 2021 10:28:18 -0800 (PST)
X-Received: by 2002:a17:902:7e85:b029:da:726a:3a4f with SMTP id z5-20020a1709027e85b02900da726a3a4fmr459246pla.65.1609871298764;
        Tue, 05 Jan 2021 10:28:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871298; cv=none;
        d=google.com; s=arc-20160816;
        b=LiNP8yvhLoqmIrh5WXBHfZ4knsc9nJQkINYtXJiWkOXS9nph4m8QMfwbAuDqEzCXX9
         JaUgZbx+uazA5FWBIPXsm4QVhwD8ypTERMCa6uhQpJY2rq2DSyw0gC/TOJwEObyCZ2F0
         og4zdSwQkbE66aU13x3b/1Pc7yh85Fl4mJINH/I7a9FsVCBjcs6MhR5KyJjQEg1qQ6GP
         r2ecaF8v5pd3Df1aLTkjl+j439mBd8Y2WWdUMhY3nLKlSSt5ONFdt4ZnybEuEr708MB/
         +2moGwguqYyr7JHGiyKQVuWEjs3+qlHbNUpZ7PzEbnQsk7LYdbDaSjz7Io9ONwAxggLl
         vvAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iDwaT/3sgxFRaKMDSbTZTruUt2fPWaZ2OF7Juvdk9+4=;
        b=R+O4B3PkuOXrx84S/aLVL4afB/VJhXDQXpg1e/dQWQvEIEKnP9C5NYTwTF/dqhWreP
         nif87Tqrpvec4If6M5Bii8qSFnhB2Pn1JXryUxEwBUgz4C5HrPx/PraoAw4wIbqe1oK/
         9ntnT2xdWMaYHuE7s9UWEMLS//VUVJwe80ppOnZ0li92JQ3I7YOcL7V0kEim6mNaElOG
         hZkYcaEek99gVBatx1IfkQeQDpXHytgnGW3lugXefW6cRfGXgT+I4LzNWoPIwBb/lWaN
         ODyRaQ/tUI58ruhi6HaGgIPIh8HZgZO2gQscxmopPDrcOzLvBxcY7UvcSSZzx1o4WpGM
         tiIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f1nlOcJ4;
       spf=pass (google.com: domain of 3wq_0xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3wq_0XwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id mp23si362908pjb.1.2021.01.05.10.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wq_0xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id f7so419573qtj.7
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:18 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:13e2:: with SMTP id
 ch2mr693457qvb.57.1609871298143; Tue, 05 Jan 2021 10:28:18 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:50 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 06/11] kasan: rename CONFIG_TEST_KASAN_MODULE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f1nlOcJ4;       spf=pass
 (google.com: domain of 3wq_0xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3wq_0XwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Id347dfa5fe8788b7a1a189863e039f409da0ae5f
---
 Documentation/dev-tools/kasan.rst | 6 +++---
 lib/Kconfig.kasan                 | 2 +-
 lib/Makefile                      | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 26c99852a852..72535816145d 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -374,8 +374,8 @@ unmapped. This will require changes in arch-specific code.
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
 
-CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
---------------------------------------------------
+CONFIG_KASAN_KUNIT_TEST and CONFIG_KASAN_MODULE_TEST
+----------------------------------------------------
 
 KASAN tests consist on two parts:
 
@@ -384,7 +384,7 @@ KASAN tests consist on two parts:
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
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl%40google.com.
