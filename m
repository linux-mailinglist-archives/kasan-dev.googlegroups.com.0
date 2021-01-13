Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6NU7T7QKGQEKX3XIGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D79AC2F4F74
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:06:17 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id m11sf1050689ejr.20
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:06:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610553977; cv=pass;
        d=google.com; s=arc-20160816;
        b=A4orkl5ml8uB1pwdaD5Ief2U2PY+Hg5Ggsm+oaZLf/ROekhdMygcu4iTc3wNi7uv1d
         jGrEv3GgO/mIOdfR+u9IBTnMN187EfZC+9SX22ulPaxDyjqpa9nXXVRPD7Hs+g6/bxYq
         x6RzX2rCrrnbygv5Mw79PdlfnLrjwaL4G6z2PD+1J8av2QR6WvvMOFn6JeqplRvbJIFW
         5Y33lGEIh/G2EYJ833Q/pepwXlvom06SYlGphN73ft8rPV7IBiz+mZNU4ngAawHQqTyu
         XRFB0zN7OgOUHGlcvOU9l+vCsA02kbehnJg7r4qv19USkXar06um+IX1+4VhV6oyv5X6
         48+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=2jW2WIZXYXuiTwxg1TUjuL1Uvmbgr/ka4JpL8Fx3k1M=;
        b=AuRJmle/8uhQ3FrA/e9vmFqDoVmp3EMznoBhgAyAzWwCSR3ESy8ZUza27vlLREmAAl
         QwNK4qGcXfJyrlkACrvTC6wn9hTWY5nad0dnABBLOCu4nkhZ1G/ghzTmMGBwJ/n616gj
         PkEF6GgTvzypGK4k17fJyYlqstG00OwIn+oNm8duNAt95szQCI5KV0KS95ioGee4qt+O
         PvdRS9Jmn1+BogFkRqlXOweVzEAb6SDSWHZIYrhO9YX9bfumQF56FVT5tDHR0VwMd+U8
         dKyyLNgdEhpkMutTmH5KM2dEGurctQk/yzLcOkYqa1ezT516tkeaqT9NPCcYO4ZkoTyq
         L7Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L9Ti1u6m;
       spf=pass (google.com: domain of 3ebr_xwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3eBr_XwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2jW2WIZXYXuiTwxg1TUjuL1Uvmbgr/ka4JpL8Fx3k1M=;
        b=RcMGNuLhQZwAlBail2BAAMRs91ZuWLfgEAQFxMWUONFopNyiO28GX9IogIQoeWlPbX
         rDaZQfspqoo0CedOlHC+ZgZJz/EpwRZxulJFRqpmYMc8a4D+ldy2zDlPR6WvIPrLq9Uy
         s1gJmGglngjaEXLWFcPpobRoaKoH+TTEuYoqXfOqNHCZaE76zT+3Y5I7YKy7y0wG51z3
         BoT3ZJxl7/4Gf8pYktK5Mkdqgs9hEMiJH3Z8zzGxfwJ5BdXvduik20oBNVjpa4FVnpuT
         ShHubClFTJpNsyjikCHR1icU/Cy5GuSWDj9y16thbges1lZ5VSuEio2mM5r+hZVePLmr
         5tKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2jW2WIZXYXuiTwxg1TUjuL1Uvmbgr/ka4JpL8Fx3k1M=;
        b=EFhSMFwAKOgVxG9EwRiv03nLLhzJsclyoat6zgfTXxMUhWa22VFzOndUqlVEEbDbPx
         r74qzbo7XAAiE01q80O3tsVxaw4Yt9vYpe3cUep2uqi4DWRHYhtnfOVJdGpiaxSTU9Qz
         pCqqJ4PRt6qTE+nU/UAJB96yFgaTjVFOkjm19ctnvCqBdVQE5jfm0rqcsmYc0OUV3SZu
         +Si+9r2QzVDAo3YiCj9aBsggiqTeiYTi14LmyFG5b1/3iMfeoBlRCKfJMyuLPaBXwtGS
         S3cCVSTJMQNutx8eqJmZ1FD9tBIwD3gLu42m4zLlePF5CP4LnVfAVSN8+9zSlUgmrFyf
         27UA==
X-Gm-Message-State: AOAM533Z9jktSvqTNjwbEOsWF25a1RiN+JnJcVXGVBLgvNvGRno+2NKm
	FDMpd/b349UwfFxcCgIrxA0=
X-Google-Smtp-Source: ABdhPJxjbPU17/pRAO3KJ4vGRdVzKLG31zAuKMvtttf/josP1sQzH+ACHA0EgCyfLEFasmDy67fKqA==
X-Received: by 2002:a05:6402:1d3b:: with SMTP id dh27mr2413894edb.238.1610553977663;
        Wed, 13 Jan 2021 08:06:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls2937270edd.3.gmail; Wed,
 13 Jan 2021 08:06:16 -0800 (PST)
X-Received: by 2002:a50:b586:: with SMTP id a6mr2353044ede.206.1610553976644;
        Wed, 13 Jan 2021 08:06:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610553976; cv=none;
        d=google.com; s=arc-20160816;
        b=c8/F9YRR3Voa9XgxhMVh41Eb6RUekOFu/eSBgFEmDGMJfdQaUpd6KzIdxBkYoWMmLt
         lIobmMPffUjz5Rn1ZvFG5CrJZQLYO14IeAOBuUOP68jOjxY1ctQ71c/NYf9PfDrv/o0p
         gk97aHmXDXk+F9+Eh00amSwrh9cKxH0XS+Z9zlVIgsEDhACHFTtjLZFrMqbLe65W6R16
         xSMCm2befJFKZkTxrf0AvPP1MwoBzphwvqNbsoEh+2vsg2g7DhIX8EhqDoNMQRDK8/IA
         u/XeCCDPVYsvKpSwqyrh+cAbOVw98yh5QycmJOV/u9zfFGo4RZTQ5VctpPwgQk4YH51l
         Jmfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=++heMP95hiEbtq4vG1X57rPsH+Ed2fmWnBvi1eFQ51Y=;
        b=HyBAUD4KMl4mxERsTGOtMyWxExtYHsy5PcPiaLHCTUvRGTFWbviRr05peFwbmucbvU
         rVxC65PSYKbl9bqF0UNc9f7X7htx7GZhzT1GfgUC82uUbe5ZOZDvYN1GUFCC0aa0UXS3
         YhfHG0+G64+AmU4sBxbBeXHsCof18dLVKPjq2/4ZuV6ESm2Q/rQBQLsZTCtc1qm1PjjM
         K6qV8iDcwqY6tJSQmCVORmAGQmy53FRxEZ7diXamhizE9TfHhojqCT0yTDgMODEjHB8O
         9SouiHZkHNi2/CadxkImO7elxuuTKPIeD3eriZzStYVFbpe5gOu4BhQJHykepIqHi9z+
         Ht3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L9Ti1u6m;
       spf=pass (google.com: domain of 3ebr_xwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3eBr_XwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id d2si149115edo.5.2021.01.13.08.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:06:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ebr_xwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f21so781193edx.23
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:06:16 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a17:906:f9da:: with SMTP id
 lj26mr1987310ejb.467.1610553976214; Wed, 13 Jan 2021 08:06:16 -0800 (PST)
Date: Wed, 13 Jan 2021 17:05:56 +0100
Message-Id: <20210113160557.1801480-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH 1/2] kcsan: Make test follow KUnit style recommendations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=L9Ti1u6m;       spf=pass
 (google.com: domain of 3ebr_xwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3eBr_XwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Per recently added KUnit style recommendations at
Documentation/dev-tools/kunit/style.rst, make the following changes to
the KCSAN test:

	1. Rename 'kcsan-test.c' to 'kcsan_test.c'.

	2. Rename suite name 'kcsan-test' to 'kcsan'.

	3. Rename CONFIG_KCSAN_TEST to CONFIG_KCSAN_KUNIT_TEST and
	   default to KUNIT_ALL_TESTS.

Cc: David Gow <davidgow@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile                       | 4 ++--
 kernel/kcsan/{kcsan-test.c => kcsan_test.c} | 2 +-
 lib/Kconfig.kcsan                           | 5 +++--
 3 files changed, 6 insertions(+), 5 deletions(-)
 rename kernel/kcsan/{kcsan-test.c => kcsan_test.c} (99%)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 65ca5539c470..c2bb07f5bcc7 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -13,5 +13,5 @@ CFLAGS_core.o := $(call cc-option,-fno-conserve-stack) \
 obj-y := core.o debugfs.o report.o
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
 
-CFLAGS_kcsan-test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
-obj-$(CONFIG_KCSAN_TEST) += kcsan-test.o
+CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
+obj-$(CONFIG_KCSAN_KUNIT_TEST) += kcsan_test.o
diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan_test.c
similarity index 99%
rename from kernel/kcsan/kcsan-test.c
rename to kernel/kcsan/kcsan_test.c
index ebe7fd245104..f16f632eb416 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1156,7 +1156,7 @@ static void test_exit(struct kunit *test)
 }
 
 static struct kunit_suite kcsan_test_suite = {
-	.name = "kcsan-test",
+	.name = "kcsan",
 	.test_cases = kcsan_test_cases,
 	.init = test_init,
 	.exit = test_exit,
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index f271ff5fbb5a..0440f373248e 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -69,8 +69,9 @@ config KCSAN_SELFTEST
 	  panic. Recommended to be enabled, ensuring critical functionality
 	  works as intended.
 
-config KCSAN_TEST
-	tristate "KCSAN test for integrated runtime behaviour"
+config KCSAN_KUNIT_TEST
+	tristate "KCSAN test for integrated runtime behaviour" if !KUNIT_ALL_TESTS
+	default KUNIT_ALL_TESTS
 	depends on TRACEPOINTS && KUNIT
 	select TORTURE_TEST
 	help
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113160557.1801480-1-elver%40google.com.
