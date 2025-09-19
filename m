Return-Path: <kasan-dev+bncBDP53XW3ZQCBB766WXDAMGQE5FWQWGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 98770B8A1F5
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:08 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-3667d52cb6asf664041fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293888; cv=pass;
        d=google.com; s=arc-20240605;
        b=gA/o2uJF6ZATVQSjFQV3MHy8/9D2k0FHtTP7nddjHuP+NONzH6HO0T5YYexQMfRmZq
         BU2vZeM1SjazRsxRQSQ7VLNp/Jm4h4SGKtNsQRSjIhvJWU30uNKtTlf5IHRoPaojJUYL
         b17TwfOvxQhyaz0RaiRzsowX/h+tvVePM0EHSPdd5a1jlXeZWZEwFK+0I7Xsd481lpmh
         pjT5Idurb8alxvdJmg3AT0K1/RtK72L+lg41rxMq4SB0XYUN7qucDaCxeQqiMvDS0j6P
         kzUqE9UO7bJLP1a6tHKeED3RaAQ/MZwq9vE/N2j01J35hOfsTmzL8t4WlgNTJDUAnyOC
         yoaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ke4cm+DXTL5j7Y7wLciJYtmc+fwBIahb5Wyk8kv9xVo=;
        fh=g1msVwro6pMuCOql+74w/PSj0xFLtix/Z19Lpwa1Tjg=;
        b=e1+7S+cZklms8fiUZTwLK3m8IM2oaqMEDApIYWdDToaCk6shX1IrW3rVP1iVoARTtY
         SG3t/jQLtiVVcqwU6G2rDi89mQamqew6lLboNsHvyEQUXXkOznvwefZwrS/NlRAMQitZ
         jNqPs0P5imVNlBSj0lCZ0NRDEwVi/Y7rMOSjV2p9gLy9d7Zrznaax9JImU2UdZbqqUM/
         GC1jpufgk95BIGKfGi2v6ICGH/r/pCtmj4mfb/kZ0RPLU70M/CTyv+sfXHurgpxkRSA0
         5G2BeeMADMstQraE96yejBqWx4zt0ZKX6N2oytblAcxmgqLmaoSByiklykofTkTlXmQR
         961A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NzLM3GbH;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293888; x=1758898688; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ke4cm+DXTL5j7Y7wLciJYtmc+fwBIahb5Wyk8kv9xVo=;
        b=FbEluyfuNcYOep3pJ/xFS3GolReGO6gP1HLGzcAaB4AohMxaiuYbJOlI9uSJuk9JBS
         wy2krh2DnXrjApCDwx5i8Pe/mHFMUGLlwfiLbHYPtyV71sDKJM4Jj4s69mZBXNlxG38d
         RSKgW1v4x+jpYrmeQYLqckusFB/kdgxBQpcoMlHn0UACg0/Y82m/3AKJtjnyYa37yxKn
         1QDWXlzkVqmC66jk5WEsHRn837Lc2VWjZzl67sCFex4wJ/GDyezrZdU+kJfVzF6LYEWH
         6EG9gdrnm08E1fJQyzRrasK0pPn5dgbzyzVCobUR8dBKkdy6ZyaPIjysBvJEebiFO1fN
         37og==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293888; x=1758898688; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ke4cm+DXTL5j7Y7wLciJYtmc+fwBIahb5Wyk8kv9xVo=;
        b=c9rjEkFwAfAKvSxSvDNUTTvC60O6ME255lYoxDOUnAcP1ol/D7kFJu3HWakw3iFYIn
         6VPCnMN59QVflD70E8kZwHs8/Pokk1A0SPFGiKBXg16PovREkw/V4zbpjh+hAuGivwcS
         CU7E6mAHJnMirLDAfMGG1eCpTMZMHViA5gBY38jMGWBY1px3u1SrtbgFcHRGchVs51dg
         VUWLrw4AYjC4wRd95dWf5/FCuMo+W2BbW0GCbT+W84SAFBPYrvp/cyFJyEHNUWE2OYcd
         GtSv2UPNFgSuCoJN7gV0NcDtMr3PtMNBVlGk7Bm46hCuaML+1bi7HR6fAbVC8UY+2q2u
         U0jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293888; x=1758898688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ke4cm+DXTL5j7Y7wLciJYtmc+fwBIahb5Wyk8kv9xVo=;
        b=CWGWlmwnS9904sQNE5xQfZPOz7yZ6qWbA68eT9BM4IIaG7v7psc66RIW8Kh+0Fiv9k
         ixiFlYK5qSa4tUPV+5Iotf9zRuIcwpu3s5xw8DqFYQ7mbkJ71az1YTBHNQk5bAf3KYAC
         uM9QglUBNxHmLaGRBRrb3JhbmbK9BEuqjdvZZsWimq8efbzOLpACSzqQVkZy4Ucgjx53
         13kS85rbr+PuAB+73tHa7QaKczwVavTiBVGblb2+betzKrd/kfleTbDjOq06j1y5pVuV
         OHxtnmXxXIOZAhE9aXCf67MHMQYtVUg34LWtZDvjedYavSt0USMztHYdHHnRfNS27kaD
         i5CA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUjzYYvzyGf9EyQAH1g3aZtwbNWx04mH00VlgZx/+uAmUrldSIqbRLuSRPSi+ie9vkl0ultaQ==@lfdr.de
X-Gm-Message-State: AOJu0YyKiOB06p78xaRv9WF9kOz+P7ppN3/eKzmc7CntPbdtcYTaDsTF
	X2DbfWh5x50E31CfC3df2TxVsH8G/ORoJUOOq4L8k/P7w5VuRIHccheG
X-Google-Smtp-Source: AGHT+IEX1F/YAr8DDj3qI5lp+qjwW/VY8/9rPWhqkLjNQ/5qU3q/iAzqpjbi389ZvSGfsx5xSqdK1Q==
X-Received: by 2002:a05:6512:6502:b0:57a:71f0:5da9 with SMTP id 2adb3069b0e04-57a71f05e9dmr692267e87.3.1758293887780;
        Fri, 19 Sep 2025 07:58:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5hAp+HOq/ZbofluY4qZOG2lkDh/k1N+h/TvTfDbKNilw==
Received: by 2002:a05:6512:24da:20b0:578:b22d:b290 with SMTP id
 2adb3069b0e04-578caf908c1ls721601e87.2.-pod-prod-09-eu; Fri, 19 Sep 2025
 07:58:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVu6HlRQ4pWsXRHMS5LbbyG3s5G5FAWRpAOm2LB2qFmEIXSnbiH1TBLk9QEoEf32y8n88vrx3TK+kc=@googlegroups.com
X-Received: by 2002:a05:6512:b19:b0:578:93a8:81e with SMTP id 2adb3069b0e04-579e05b97e1mr1511070e87.17.1758293884328;
        Fri, 19 Sep 2025 07:58:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293884; cv=none;
        d=google.com; s=arc-20240605;
        b=fwH/5P5yuBtT7JATa2UcXpWSbY10K2qVdh9QoIKd3ktdD3scjK5qwD7XZg6PXFmIOa
         F/XimvgZqQ8ttQf27g+ysGrJspWeaQ2B0Fih+aASPJ++48IHx+ggNwvV4U6PaIVX8W0k
         W5u15RoglJ61jm90XVbV0cdcu0XXEVg67WGBPN+RwJyg1qv62vXu/8ee2SfdDzLbV9Vj
         21obqPVk9riftyVMof3/gWBkECpQtrS1wP3qwzHdYXa/klJJK5BkLI1Fmswj1EPPTgdI
         tXVhFhWj5wRlnNtT0iog0fGiLHpDNIeJowZ1ks6cFcxzjqAVHiDa0wpv+NbS3RdyQHyD
         nljg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eBXsJ3eFBRBXMY0OnOP/8+Wo598xHcjcSo7yO9rMMTI=;
        fh=6sUT4DbGVKsOhQH2nBFSszLlmWSEx6rad6xZkFznNBU=;
        b=O7HBmSgqTLu4AKDWpWXCsXo/p1o+rI//T+MI5HnYmQmTgv8G8Om6urAlxUl41SzUdF
         05o+ZLNOjULKYju0q2qSDVfyYBcshZ2kV2082MyvbynZVo5Bvx23+eu3QMy8Hd4XTsA6
         Zpw6e+1+S3XUSNwL8MdfkqtxBIfmKnCWY5vaiZGhRC15ldPxddomkCeMWqp6mARCWVfn
         H5+uRvtE9uKgCQpXycuyEH9F/gMnBwxq6Ke9HMUgqYlBUbaVeOdswoiBndSwrKLAZ/u7
         VuX/detuU2SXrOINRLtrzn7O7ZqF1nTB7GZDArv9sVo3dR5GDb1tCA2K9itYVgapN3nO
         knOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NzLM3GbH;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-57aa85bd5d3si33208e87.4.2025.09.19.07.58.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3ee64bc6b85so946467f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqDeS/ZQ4sgEagZRqgMpQGePOfndUq4FCqimtL4rbEcDsAQs2UnCbU4yMmb4FdSyIydLuRBRGwyP4=@googlegroups.com
X-Gm-Gg: ASbGncuojjVOCSfJYoj1ZZuCP3guP5nqv7RwSBz9V0WhtoggB+ID/77MjZb2pawg1kC
	ADrpbv7d7N7qidg2Ds7xm841IV5xou1sLDIHuaPc9CVyYCJq7w+qx36QG2npmY3h7ShL/QGz/Et
	1hGXPm9AyqQ1ighUw2L7f7HpaCkoGvxfvdgmLpNRt3Oux4GqjoRGdnpYLkxpC/tw3JQcrXHP3UO
	A8GcA6ToYIgLXSI2/b9+yhCSCBj245x7V+PaF4l8a/aqUPYeLGdHKaQ1M/4fuGkQzK0zJqerjF5
	p2RPRC6NgYRNqt+tunRBSpVtMdIlbRlnYoMMz/t85uiohFzcSoTBwQzmw7/nBEcvFfWBqn7/xE0
	HlY3GVnig1TRluPkXsXErr1H2ggGspzOb5ROhJyiQXl4jNTWhjpeitS7xLM9wE7MBN301Zszxa4
	6+REyABm2GAMSpP9U=
X-Received: by 2002:a5d:524d:0:b0:3f2:97a6:db6b with SMTP id ffacd0b85a97d-3f297a70589mr290499f8f.3.1758293883676;
        Fri, 19 Sep 2025 07:58:03 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.58.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:58:03 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v2 06/10] kfuzztest: add KFuzzTest sample fuzz targets
Date: Fri, 19 Sep 2025 14:57:46 +0000
Message-ID: <20250919145750.3448393-7-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NzLM3GbH;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Ethan Graham <ethangraham@google.com>

Add two simple fuzz target samples to demonstrate the KFuzzTest API and
provide basic self-tests for the framework.

These examples showcase how a developer can define a fuzz target using
the FUZZ_TEST(), constraint, and annotation macros, and serve as runtime
sanity checks for the core logic. For example, they test that
out-of-bounds memory accesses into poisoned padding regions are
correctly detected in a KASAN build.

These have been tested by writing syzkaller-generated inputs into their
debugfs 'input' files and verifying that the correct KASAN reports were
triggered.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

---
PR v2:
- Fix build issues pointed out by the kernel test robot <lkp@intel.com>.
---
---
 samples/Kconfig                               |  7 ++
 samples/Makefile                              |  1 +
 samples/kfuzztest/Makefile                    |  3 +
 samples/kfuzztest/overflow_on_nested_buffer.c | 71 +++++++++++++++++++
 samples/kfuzztest/underflow_on_buffer.c       | 59 +++++++++++++++
 5 files changed, 141 insertions(+)
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

diff --git a/samples/Kconfig b/samples/Kconfig
index 6e072a5f1ed8..5209dd9d7a5c 100644
--- a/samples/Kconfig
+++ b/samples/Kconfig
@@ -320,6 +320,13 @@ config SAMPLE_HUNG_TASK
 	  Reading these files with multiple processes triggers hung task
 	  detection by holding locks for a long time (256 seconds).
 
+config SAMPLE_KFUZZTEST
+	bool "Build KFuzzTest sample targets"
+	depends on KFUZZTEST
+	help
+	  Build KFuzzTest sample targets that serve as selftests for input
+	  deserialization and inter-region redzone poisoning logic.
+
 source "samples/rust/Kconfig"
 
 source "samples/damon/Kconfig"
diff --git a/samples/Makefile b/samples/Makefile
index 07641e177bd8..3a0e7f744f44 100644
--- a/samples/Makefile
+++ b/samples/Makefile
@@ -44,4 +44,5 @@ obj-$(CONFIG_SAMPLE_DAMON_WSSE)		+= damon/
 obj-$(CONFIG_SAMPLE_DAMON_PRCL)		+= damon/
 obj-$(CONFIG_SAMPLE_DAMON_MTIER)	+= damon/
 obj-$(CONFIG_SAMPLE_HUNG_TASK)		+= hung_task/
+obj-$(CONFIG_SAMPLE_KFUZZTEST)		+= kfuzztest/
 obj-$(CONFIG_SAMPLE_TSM_MR)		+= tsm-mr/
diff --git a/samples/kfuzztest/Makefile b/samples/kfuzztest/Makefile
new file mode 100644
index 000000000000..4f8709876c9e
--- /dev/null
+++ b/samples/kfuzztest/Makefile
@@ -0,0 +1,3 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+obj-$(CONFIG_SAMPLE_KFUZZTEST) += overflow_on_nested_buffer.o underflow_on_buffer.o
diff --git a/samples/kfuzztest/overflow_on_nested_buffer.c b/samples/kfuzztest/overflow_on_nested_buffer.c
new file mode 100644
index 000000000000..2f1c3ff9f750
--- /dev/null
+++ b/samples/kfuzztest/overflow_on_nested_buffer.c
@@ -0,0 +1,71 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * overflow on a nested region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
+ */
+
+/**
+ * DOC: test_overflow_on_nested_buffer
+ *
+ * This test uses a struct with two distinct dynamically allocated buffers.
+ * It checks that KFuzzTest's memory layout correctly poisons the memory
+ * regions and that KASAN can detect an overflow when reading one byte past the
+ * end of the first buffer (`a`).
+ *
+ * It can be invoked with kfuzztest-bridge using the following command:
+ *
+ * ./kfuzztest-bridge \
+ *   "nested_buffers { ptr[a] len[a, u64] ptr[b] len[b, u64] }; \
+ *   a { arr[u8, 64] }; b { arr[u8, 64] };" \
+ *   "test_overflow_on_nested_buffer" /dev/urandom
+ *
+ * The first argument describes the C struct `nested_buffers` and specifies that
+ * both `a` and `b` are pointers to arrays of 64 bytes.
+ */
+#include <linux/kfuzztest.h>
+
+static void overflow_on_nested_buffer(const char *a, size_t a_len, const char *b, size_t b_len)
+{
+	size_t i;
+	pr_info("a = [%px, %px)", a, a + a_len);
+	pr_info("b = [%px, %px)", b, b + b_len);
+
+	/* Ensure that all bytes in arg->b are accessible. */
+	for (i = 0; i < b_len; i++)
+		READ_ONCE(b[i]);
+	/*
+	 * Check that all bytes in arg->a are accessible, and provoke an OOB on
+	 * the first byte to the right of the buffer which will trigger a KASAN
+	 * report.
+	 */
+	for (i = 0; i <= a_len; i++)
+		READ_ONCE(a[i]);
+}
+
+struct nested_buffers {
+	const char *a;
+	size_t a_len;
+	const char *b;
+	size_t b_len;
+};
+
+/**
+ * The KFuzzTest input format specifies that struct nested buffers should
+ * be expanded as:
+ *
+ * | a | b | pad[8] | *a | pad[8] | *b |
+ *
+ * where the padded regions are poisoned. We expect to trigger a KASAN report by
+ * overflowing one byte into the `a` buffer.
+ */
+FUZZ_TEST(test_overflow_on_nested_buffer, struct nested_buffers)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, a);
+	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, b);
+	KFUZZTEST_ANNOTATE_LEN(nested_buffers, a_len, a);
+	KFUZZTEST_ANNOTATE_LEN(nested_buffers, b_len, b);
+
+	overflow_on_nested_buffer(arg->a, arg->a_len, arg->b, arg->b_len);
+}
diff --git a/samples/kfuzztest/underflow_on_buffer.c b/samples/kfuzztest/underflow_on_buffer.c
new file mode 100644
index 000000000000..02704a1bfebb
--- /dev/null
+++ b/samples/kfuzztest/underflow_on_buffer.c
@@ -0,0 +1,59 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * underflow on a region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
+ */
+
+/**
+ * DOC: test_underflow_on_buffer
+ *
+ * This test ensures that the region between the metadata struct and the
+ * dynamically allocated buffer is poisoned. It provokes a one-byte underflow
+ * on the buffer, which should be caught by KASAN.
+ *
+ * It can be invoked with kfuzztest-bridge using the following command:
+ *
+ * ./kfuzztest-bridge \
+ *   "some_buffer { ptr[buf] len[buf, u64]}; buf { arr[u8, 128] };" \
+ *   "test_underflow_on_buffer" /dev/urandom
+ *
+ * The first argument describes the C struct `some_buffer` and specifies that
+ * `buf` is a pointer to an array of 128 bytes. The second argument is the test
+ * name, and the third is a seed file.
+ */
+#include <linux/kfuzztest.h>
+
+static void underflow_on_buffer(char *buf, size_t buflen)
+{
+	size_t i;
+
+	pr_info("buf = [%px, %px)", buf, buf + buflen);
+
+	/* First ensure that all bytes in arg->b are accessible. */
+	for (i = 0; i < buflen; i++)
+		READ_ONCE(buf[i]);
+	/*
+	 * Provoke a buffer overflow on the first byte preceding b, triggering
+	 * a KASAN report.
+	 */
+	READ_ONCE(*((char *)buf - 1));
+}
+
+struct some_buffer {
+	char *buf;
+	size_t buflen;
+};
+
+/**
+ * Tests that the region between struct some_buffer and the expanded *buf field
+ * is correctly poisoned by accessing the first byte before *buf.
+ */
+FUZZ_TEST(test_underflow_on_buffer, struct some_buffer)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(some_buffer, buf);
+	KFUZZTEST_ANNOTATE_LEN(some_buffer, buflen, buf);
+
+	underflow_on_buffer(arg->buf, arg->buflen);
+}
-- 
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-7-ethan.w.s.graham%40gmail.com.
