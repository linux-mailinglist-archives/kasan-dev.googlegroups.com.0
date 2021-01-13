Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLF47T7QKGQEQJEWSHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 95BE32F4FCA
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:04 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id g16sf1199477wrv.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554924; cv=pass;
        d=google.com; s=arc-20160816;
        b=gutb6AcLhOgsFeGoeS9TfIZD3g+8xc/DJD4fYkGQ/wfgs84WFKLteB3XlP0xWx789J
         vc5Ls8jiXo6H3NiYGxzy+8PUsxRaFBSLajkhR7lG/v3G4U/y6/Dv81n0fGFKa/BpgM/9
         QyLyvIW+egtIGjaVzBwep9CYkAz6K7EUz76/BQ1fPFCYKFf/RBGr7Wl2yinfIKQy89kH
         mq7ikmde7NoR9VYAzOKmDoz1VMFS/7mmi7tk2vnQEXnVasgct5lZloZ7peUwPcvGg2kB
         dNhMTvcoEd/xUYVJtzkg6Jt7hHgHME4A74LXwswzOXgzBcrKpok7WUnOLfXVWCnJc5UH
         yd3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+eMNDuEI6lIlIMKtmuZsFa7ChFQ525S7tJdryYjqHh8=;
        b=Z52cDo5zemiCxN1+BDXfKgof6DXm0qTGf+dkVhI5JOkjVL+x3sDw7ZpFHN5XffOh+q
         5TWSmZbSDloBhQzevXKgmiuP4ckErGY+0BjpcJHcaqipUDPgfIrutXJyT/MsxfXXn9tL
         kUnStwiASAr30xLrJV1ZHs3p9DaAFZ51hZ4PdvGMN9Z+72VJ8+NgJAlo2pFVjsu2DZmD
         JDo/vYeG1aLpQ6LfktxOpkBk7B9Y1bG9wSTYIdXfsRaetvMVxoE370Vys8gatiEvm1xf
         KB7QVznvd5yA86a9EJahp6EROQGbQKLjNGKKEu9vjraYoFAfUFRx46aPJHoEz9HyWNqb
         Rx+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=alLGIQBa;
       spf=pass (google.com: domain of 3kh7_xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Kh7_XwoKCWkHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+eMNDuEI6lIlIMKtmuZsFa7ChFQ525S7tJdryYjqHh8=;
        b=JxNzNwBjpePgxDLs1ZYoTa9pLtdig8qX6B/Widy6IDFA8MCn4WHREQfGdH2JJOg/cq
         mT5kMTcnv+v8qmTWKsK5crAdq+N05wlPIcKXJWS9FAwlqF5e5cbFSGQxR8M9blJt6h3s
         QP7ZzDBPn5hX7q+h+JPdRygFqQOE0FFjMU4YGGEbY+QAojxgVfIaHFvmeOXMwelwviV4
         MmsTQbje7tPqSKr+y0NAVXKAvRhIFkr5C62GmEKqmGR7u5IBC+ZGXQzyo7wFRS0X9LbS
         orllYSQbBGTMIt6dishEWEVpvjF8V+I2vt4D3Z5F0b9CAeXic1c3eIl0RMwt3DkzXiNP
         O8gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+eMNDuEI6lIlIMKtmuZsFa7ChFQ525S7tJdryYjqHh8=;
        b=H1Gjhw42h30UZLx74FjLYGYRXGU9Z32ymLuMLx/jwTLgEboQ6uyk+C0N13TDN/TkBC
         dhMQn1t+sdSx1rBj5BozZaE+yVPz23XciuZU/jOc60JwVi/IlioeGKe1ONHMC6to2ckt
         0jhlySAz6Elqq9Kin7MRCpgjDVS+igRkgMAEvgMLZJw9TeU5byT7rq3n1SXoGJMNmaxL
         g6otwPfb2lP8RxRRMp26dr6QIUmquUyMXpT0DTyD5OoZVHvVWUsMpDVmk52vDH652Bl9
         cZ6WcyJFH9elehgl+eu+VnHck2PiQOrQEvMJVjpvi8sm9rgwjwoxEbNF19gmI3iFiM/K
         z/Fg==
X-Gm-Message-State: AOAM531nsUDpN/BPKpdPBS1ti/Kn+OXNxNOZzle+nPxEI2Jt3TtFZgGE
	e9FtIkI9JoM+j2bQv6oRs7k=
X-Google-Smtp-Source: ABdhPJzVb67lvwJqm36C85tOBFjIOe/LQaP/O/dpMNQA46V7b30PjOV5xyWw4SPtCre+I4awdwHNzQ==
X-Received: by 2002:a1c:4c14:: with SMTP id z20mr10357wmf.149.1610554924425;
        Wed, 13 Jan 2021 08:22:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5543:: with SMTP id g3ls1704661wrw.0.gmail; Wed, 13 Jan
 2021 08:22:03 -0800 (PST)
X-Received: by 2002:adf:cd8f:: with SMTP id q15mr3335354wrj.79.1610554923579;
        Wed, 13 Jan 2021 08:22:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554923; cv=none;
        d=google.com; s=arc-20160816;
        b=KZfAGke6OQp02vva6VF5YR5e4sfiPeu3olDpNfWB65ks+kPxH7pM4YhOLs7lthlR/E
         rTsgA9Ge0k68DbdFg79Gy37HQfVAETzFfq2hR/e1tFDEHZNp11iXEHhSQFTl3wNF1AmO
         4lKKhRc2a8OiBezS42Q3BfDOWIj0yab6C+tJlymjEjlZ9U1eqhODbOFzHN+IedzxNN8n
         z7uCPcluZ/Itgndfkp9EpQAWvjydEXzxAPSH3Eu0wqSdr69n1/3WzmG1CaCmPYh7s9Wa
         WXjFPZxz8Wh3gb5cmIBD802CzXHq0E6CZdKMMaOQsBDQIsrigEsPNNPe07UazksVd/Ec
         xZfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=HQul2+mx68GlfTrevBbbyn+9Sc9/a5lDU2srZLIr3Ck=;
        b=R/fo/OG4Q65kpM7l+2Mp/8/a8Z6mETDTChg2aOcucxzehlfBW0s/uHfeT+VizWuds1
         PBhVpDpJZtCW5gEmNMl7n0zujKwmkqpJeAfZtx58mH3cqTlsovzbrttq5mCKCzclz74T
         vf9lt8RxeYjmdnDcsTNJDwcj/I8Ud3dYtpohkV2NSvA3MigCcB51PODkhc0SnHjCER2N
         +a4HsZzZ9xPtDWK779FL4of64pi/iO5Mi7wzD1Dr/JU37N/vOHsa/Y4Va7H4TiiWPCJd
         5SD3xwW07Vsfobt/FAotBMymaZMgXwwGAVg+NI1yffqqvqk3B7wyiSJZCZvLl5KbhfOG
         DBKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=alLGIQBa;
       spf=pass (google.com: domain of 3kh7_xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Kh7_XwoKCWkHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 7si122822wrp.3.2021.01.13.08.22.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kh7_xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id g82so1027597wmg.6
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:03 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2c89:: with SMTP id
 s131mr21058wms.0.1610554922915; Wed, 13 Jan 2021 08:22:02 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:34 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <68fab13282d1fde2dcfac859f34b9470db5f0e4c.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 07/14] kasan: rename CONFIG_TEST_KASAN_MODULE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=alLGIQBa;       spf=pass
 (google.com: domain of 3kh7_xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Kh7_XwoKCWkHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/68fab13282d1fde2dcfac859f34b9470db5f0e4c.1610554432.git.andreyknvl%40google.com.
