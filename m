Return-Path: <kasan-dev+bncBCJZRXGY5YJBBC6ZQCBAMGQEWBULI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D9C6C32C3A8
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 01:40:44 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id t69sf16883882pfc.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 16:40:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614818443; cv=pass;
        d=google.com; s=arc-20160816;
        b=IjW/+t0JCIZi58nDo2iIbFZTpKHAt4pnsPALzZe+EuxlOuy0jqvh14esIfZzVQ4qDn
         vZFTMIEyCC+oNGGEHuL8R85PeqezokuquQPbE/Xjv5AG+zVBozRF9kRVc2qu8qzKhuOx
         egAOGWDb7Zbqz5rvyhREZAGMMg4mDsGFv0zO0rKKkhUFRXRmhhECM49c6mtBP1Hq+K2u
         rpSeJ0IS66/jjKhWJ/EzlYqcQPAaH4P3BlqGZdRG2Am24oggrKuTr2mAF1db7cJqQF7l
         UtST6fvAQPpMKxu0jKgjj2TqURPokIWJ/6e2HcjXwYq3o4eIS23McY8gr5w+5lHXC012
         d2ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=XsUTAxMHTKHjqQow88t/6SdYacskqDrDJQhulMR3VMA=;
        b=Lj7vNGEEkvxsw2DLfU7Wr12Xzq4QNb1XOf5FfOPY9NRT0N5U6ClXwrdL6Mdt0N3G7C
         y/34tBtnwPyKmVZ9kcUqw64c91VWndSbiox/X423vtN461OHhr4aq1kZ4SAuG5VQkNwM
         mD2+6ogujx4mkCogdy1a2HH5nDFpQkXS7nVt2GaNjM/QsVjWPIhuc/tO5HXesysuMfCJ
         BU48rNdKZ7GSleaDZ0cVaa6WtokTWpphU/Q16BaLN5SlOVTUFWqqw/XN4dYffar5939y
         1l8OqJEzewvaadKtuSTatrL7rC5EKjYkW3UqGN+0/Xd9f09Kuhg6PQJxyqndjDo2yaRM
         QmoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kYaxQmGG;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsUTAxMHTKHjqQow88t/6SdYacskqDrDJQhulMR3VMA=;
        b=RrcPjOsvcIlyt6TULmWhKDckF/sxrFE63yVpDAM8hxf4cmDJuQnqCz6Hc9IZkA9+ks
         SE7XyqckFvxmxHiY3H67UKhKeAHex9pRSWMGY7JkG7bi2ljFA/kmxyWoyIIYStaMlY4I
         LsaF0KbHXmL7cI7L17K69yNu00vfmGBpz85rV4WzJ6iH7eEPWgisLdGO0dpEdHSfTIzq
         q75lYs0jPzH/5y2wQfMVPziwwbdtq6op+PZpPKGqoLt5hFT4sdtbjeOWo/gEuF8BhsSf
         d3ot1hnFQ6Rb7m6iG8yTZ6+U+T+s4WuHEFLvIKg4RBQva7Xgunjm4ukLm1Kave5t5ukf
         X9Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsUTAxMHTKHjqQow88t/6SdYacskqDrDJQhulMR3VMA=;
        b=bFhP7kzoVdTbnYx8XCd9a7gPXT8Bgl6HMuN6W5zbr0Zaa0z3tUFs6TNyHv5mJk0SGa
         I1zTPruKZa7v8z8ZOP049vipArfZKVocBFbW615V6sO617vLnRFP2wV7B06/Z3IuCDeQ
         DisKv74EtkQ5u4qzEhmotTF1b3yOeThlrf9aUg4Whw17ZieZO24kHVRE4vdiGA+CSIig
         CBKSm1hXolBUMtwV2pOs6l1ccH6LHLLqRcZvEs38K7Jm2yK3k4/CMbj8MnRhOP+90nqw
         tmP0J2G29AYnWiCsV+aix0WZInJCx/b8pQJ7XfyQEOKzEW2f0LXhQ8FbpsGR5rcWvTFP
         aaPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qIbJVZG3mTffi9QdnYj23phuLzbNDV+nKuxms929uuvffg8YX
	kjvI7wIoj4tEubIFbrMt/Qo=
X-Google-Smtp-Source: ABdhPJw7SHubqlqiZV01QXNQE0PHLt+PRVx1eZxZYqu+uUH32OsPrsnKvzFAVeV+SqMdwGBlZIh8iA==
X-Received: by 2002:a17:90b:b0d:: with SMTP id bf13mr1696233pjb.7.1614818443307;
        Wed, 03 Mar 2021 16:40:43 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:16d6:: with SMTP id y22ls2166460pje.3.gmail; Wed, 03
 Mar 2021 16:40:42 -0800 (PST)
X-Received: by 2002:a17:90a:db51:: with SMTP id u17mr1676525pjx.194.1614818442798;
        Wed, 03 Mar 2021 16:40:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614818442; cv=none;
        d=google.com; s=arc-20160816;
        b=Zqlj53uViLLglTkxiXNguFMCV6BHiLXF3XmxglIv3T22LU+dPuHq31ll8h8W4md0Ez
         l2/MX0nrV30E2FWcQ8JFSTMoZwgQo+arL7CeoWbOmBlW6sSX4vwSP0jzQF7dTb+0yDJn
         ZOHCZ3M8Oom4KTXx0hjN7oIK72M5RlNAQP6WohZtpZkHVvTurpr7E6kXZ8hjHtReR7Fx
         9l04VKn530clJJOFsSz+NiUOBLbOPjvDt+1hB+bfoBYgzM6qT5o5V4JeJANn7aCjEo0e
         yAznV2fcMzmrp+1/pEf3i4Vc+Puk59fbaVg7JHeeX4OAQZvUFjR/tCjCZk+iHLIyA2wW
         LIEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=aweubVhZEF+5k4Xe7uXTxfd0kULEVsDbXVeTGyYnRt0=;
        b=ghapCqDO2SjHbDD8VcGg2s7orYE202uRKJp5794D4G4iGCx7wW7PBbTmvlhOBW4tN6
         6atopdwiACRAfgXOt4L/M7mN0J8liUXURy5J/JSnK17yjLMUzxtgGefzTHDhqlt1Xgfl
         FGa6U6M5G+/k23GVI0glNX5KMhYxgmXWh42qeyaK7bNUsEVlUbzse4V4nQHgA7HaW+is
         QHZi65eNSDHOGnzs76OvPiy5Mjbn3UndbCNVBIBway2tDfX1qBkt5ujR00M2+C/Z57xR
         UmjM2i96OyEsR1nhDW/UpXYh3c4tFKGCmLNxSFaRQmp34/hkkm6p/RAC27ZIEWM8Nw2p
         Nf+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kYaxQmGG;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e200si217596pfh.3.2021.03.03.16.40.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 16:40:42 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7BEFF64E60;
	Thu,  4 Mar 2021 00:40:42 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 2/4] kcsan: Make test follow KUnit style recommendations
Date: Wed,  3 Mar 2021 16:40:38 -0800
Message-Id: <20210304004040.25074-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20210304003750.GA24696@paulmck-ThinkPad-P72>
References: <20210304003750.GA24696@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kYaxQmGG;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

Per recently added KUnit style recommendations at
Documentation/dev-tools/kunit/style.rst, make the following changes to
the KCSAN test:

	1. Rename 'kcsan-test.c' to 'kcsan_test.c'.

	2. Rename suite name 'kcsan-test' to 'kcsan'.

	3. Rename CONFIG_KCSAN_TEST to CONFIG_KCSAN_KUNIT_TEST and
	   default to KUNIT_ALL_TESTS.

Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/Makefile                       | 4 ++--
 kernel/kcsan/{kcsan-test.c => kcsan_test.c} | 2 +-
 lib/Kconfig.kcsan                           | 5 +++--
 3 files changed, 6 insertions(+), 5 deletions(-)
 rename kernel/kcsan/{kcsan-test.c => kcsan_test.c} (99%)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 65ca553..c2bb07f 100644
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
index ebe7fd2..f16f632 100644
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
index f271ff5..0440f37 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304004040.25074-2-paulmck%40kernel.org.
