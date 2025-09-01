Return-Path: <kasan-dev+bncBDP53XW3ZQCBBIU227CQMGQEQB227PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id DBF22B3EC79
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 18:43:15 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-61eac95b627sf588393a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 09:43:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756744995; cv=pass;
        d=google.com; s=arc-20240605;
        b=HzPkjJFR4jcL7g5MFIra55NLWFzeTIdq0sHKvqsQLrPgD856M9S9wUxINV/IVffNNE
         tTcgOj0ZflerR2IbMRD5mu1/FvWaMJvbhP/32HmNZTzVUrNifVwBGdR78yBW+SAepiar
         cphCB7BaDpKkMgqrYL8Z+zokNlNhm9ZN9GUyo53YIYtuZmtpUOMHpGXNlSBZBZdpV2EY
         vgYq7LbLZZuZeGzCPm/RCAqYq1UwLEEab31+jyJ3O62Q6NLOY2J1/OVIPEAfqTcT4r9R
         KzfiJXeXgVfBoUXJujuo8HqbTcU1baiKgbhP8bQOk892DBxpxQvomkshLqDfmvNUQBz4
         5V8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=3Lxz9sRQXH+nkdeFPnoEsn8buzYQNHzzB1J9HgtB8g0=;
        fh=U51hAbX2c9WBv0hUfGa+/er/1WojDTl/mkHJRxRr200=;
        b=fr1qleWU4//0reIesSDDQwX4Rt3BmbEmiMgIe57j05Ukgkaz43rYbNmMkJNyGyfL9B
         kYrFDzLOq2+auV3p7LdDD1/fq3bDnSAH3IA8dWyYJ/jvJpFMKBmEOEkf5NupJ6zRTZ3y
         9lxCNm75zJkXWaEWKgCNORlQxZebJuh9aJmJtwAKPrisNl/cWt4fotiYpTP1hyZTv2vh
         Oq7IS8daPWFLFFbKbCXcZbU6ut8SXD6npkf+J9a3+C8k2YZE6YHyrxyNWozw1DAHeI6f
         TYCgh9V/vJN/W+nzhhnxEWvoy6yyMAQ7P+UWZ8Y676mZxm5Vd7gyoZctQVg31hnGIZyx
         wOyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QvYIVLvv;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756744995; x=1757349795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3Lxz9sRQXH+nkdeFPnoEsn8buzYQNHzzB1J9HgtB8g0=;
        b=b0vROWe/XaXIDasO5RefNNYyxYhWJ413W+Ag2WvwQ/PR6qMyNzqZftO7rK4xDSerTY
         p7Tfg7PaXaTVDcQJrE43DIB7/oaqyiuM7lsDf7HV2AK1I+Y/+6CJdtIYeo1VFP6Mjx6Q
         CAVuyiY0+fq0MjfaceC0py3WhrpwhEewN7CYAy9BDtF2ZTx5tZ25kWfiZM7KEUVtLvkQ
         ysRGatEei88OAmo5gAV+Qxt5M4sG77LNf6zyRX7YMWwnw2lU1YJeaL4WUyFF5iOgiHmv
         uJ3XjIibShUjzdqdO+TH8S19PDX16kMyd8V/E7KMHeOWXDQipvIIxts7h+1YCPsz+jFD
         v37A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756744995; x=1757349795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=3Lxz9sRQXH+nkdeFPnoEsn8buzYQNHzzB1J9HgtB8g0=;
        b=KjHS9x3xgaof/t8jyo5kv+tLOLC5csLCAeLmoACVU5lbSE4bW8zWjBMbi8bscwl3+U
         s6jH8D8m2NfguQR9BNhxcp2OC/d5ENx0TlXPt9HOyqVvShGaOg0zSD2Ubm4mNacj7LEi
         tJtidGUZACsqtX1aFwNyBYjIDbtm/zvuMZN+Vcnj7Iq4lMyrwhmtLgekH+4kAgi3Mprg
         nKGQ1kt0q9fguBsXSW1K5YINGLrn7dlVF3ADwh23FsjaZVKj1Dc8SA1kqU1hJLonxChn
         vwOeFSQUIOWHfImIEf+D1WswmD3k9Moz4bs3p+kTrNEoO79u9LzntoeVK15r1Y6vbUed
         W+4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756744995; x=1757349795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3Lxz9sRQXH+nkdeFPnoEsn8buzYQNHzzB1J9HgtB8g0=;
        b=VAtSRcSD60STxYvJ52AOO3wXxBVSpP/3dWNuMUs7zWmvGTHysuROwBhLMLpuTwMK5E
         YfJG6LFSKRn5/mpanwmivR68nKEVXTW07TfOMQRPAuBYAR167oIHsU76YLdfyJPwgAFB
         miiUxDkQXiavVAZiYGdYNmSr0MUqvyRLAtR4XPSeuNputdz3WReuVFKj8LpvxIFJRNEL
         oq9pSf7iO+6P6qzNdX1mRnDd8Fl7P4t5SmXlrgJPUtiCPdkDDo1SlBk3sYeI4KWMwkyn
         H96xgx5L8oBXb4QFRLQS0ijxN9B4vWTsGJNc/bKfdAIMz0YWy8Rp7gQsRGQibbrNE8aA
         D3lQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUEwXOrINxxPnptAN57a0mIpwq6hCjQhDEmVQsGwGGTBFVs/4fOT/xsnSKfCQC8wzlmt8y4g==@lfdr.de
X-Gm-Message-State: AOJu0Yw3y2ouZeQR2Tcq+ltyHRxbXAdTkHLYMXlmEh2OSCS+gG4g7H50
	K4OWwd1xbUqiEg7zgjippxCMhY6LQysa7tKyHugFaUWfKrHJIE5+64dq
X-Google-Smtp-Source: AGHT+IHlf4fgvFm2DmmGQ5jYQ7IClb8GMBCmN275B/QODtq7iQvYQklLL2Q2NhywUfuY+1Pvb0Nkmg==
X-Received: by 2002:a05:6402:454f:b0:61c:79f6:37f with SMTP id 4fb4d7f45d1cf-61d26c52981mr5720908a12.20.1756744994835;
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcy7KAw9pFxxW1Pbj/IXtV0WDYSGHZ/6WVlTBm7tsjgJQ==
Received: by 2002:a05:6402:2055:b0:61e:8fcf:91ce with SMTP id
 4fb4d7f45d1cf-61e8fcf9280ls1650203a12.1.-pod-prod-01-eu; Mon, 01 Sep 2025
 09:43:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrxFbYSFAVSC3k7rnElE6KjBTJS3QJAk5h+szvq+iz8oxnDQhof5p1TUvKMqXjTv+50zER8NXcy7k=@googlegroups.com
X-Received: by 2002:a05:6402:270e:b0:61c:29e:db04 with SMTP id 4fb4d7f45d1cf-61d2686a7fcmr8568358a12.6.1756744991614;
        Mon, 01 Sep 2025 09:43:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756744991; cv=none;
        d=google.com; s=arc-20240605;
        b=j9VylvYYOoSP3wEGdflE5byHVgyRnEs+J0GTnzS6VIYlOPdQ50WHB1DGoutCPzcXRt
         dx8Zzw0nOL6F/RrDSPXaKCcsmWFPBO+SJaOXbZs4anof9dmsuFef6N2aAuMEZFAQT5ab
         9eKz5j5H+rEtAJi6psOEp0znSciPpaLiSJjLLu6FMGBdhPOhCPP7Epwhtnm8plfm3NR1
         Mp9PkZwbDf2Z8jfDJEp8IrgUvIiMMl9Ol5dRFPjNBMzGdqiaP+54Wknc1liqlzFuQHb3
         47v86L1MHvfqx4DfMuvGdyFmJ6MbfKAiFCuPpndJANqVvoeoNmAqTtXQvAyF4bsh468i
         vYQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JMtkoie1PzFbZ/9GVFEn9qZYkcpNtvbFVewJfLAvroI=;
        fh=tg5hkomGEj7DcWs3a1UD30YWUde2YabkkPtI2BhKTMo=;
        b=AWpd1VT9Tw3ORAKbeLOmE3UVyjTEzjT2WiePLCv8j5VtjEUc8fnYYDNr0Pd6YSWOmk
         UCw3vpoeaKclqUMBr6sSnuOZwGQ9h37rPsp1aMzF5CvuRxxYRC26Xe9bGobPWrQlKNpN
         6FY7g9sNaBhKJ+zevCwBGLePAhTVZU3pAbzbq7I4Axjuusbedry0nT0CbO+EeHWUt4Y3
         dxkPpE12+nAEsJNDofXzMyRPT5RfX3Ix5E7LOtuMkJjzpjjYYijtnaIgnBLZUgDiBnIb
         tRGotyuj4raMh2JHDpzfqpiQhaE+yOVlMOXpJt/IQw94k8L6g0ZULjFUII31uupTwOM/
         WrGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QvYIVLvv;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61cfc4d0266si236328a12.3.2025.09.01.09.43.11
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Sep 2025 09:43:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-45b79ec2fbeso30644855e9.3;
        Mon, 01 Sep 2025 09:43:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUaOHyTDnk7NZ44uI1PuqTA39hV9tl/beW+erzDEii/RSQovoNszQ6YlIhq1QvgukuT4wNTJ4dWBZoI@googlegroups.com, AJvYcCWtnxfOj7/wK4Ho2EbqpB/d2lRUrR0u10SVkMoY72aZ1ltaLbnYJK3woLlL/SnpXlZmx6JXtNP5fwU=@googlegroups.com
X-Gm-Gg: ASbGncs1gyyvmeoUKvTQZDf1ZBc9F//vm9nmt2b5IPVv2aEmxuEzTlGDnCRVDRNLZUR
	tpj+6gT9KHsKClMoPms+9P9UDoNWOXI/uyEwD/JfHQH1Iq235+waRKRIlMdk+JIvh07OdOK3JhP
	oiC/oRFH95pg44sgs6phU0Y185VWELzZ9bW/5D4OkmliJtodc7lAM7HlLqbqbEK17sH0yhy+7qT
	jt5YunyssZWe9U84TAw9M2to85XtaLnCj0oIBC+TGJ+HdFbXjAj4zR9sxHMOJ5axQHUKLHMjLrI
	L+J+vU3YTE49XLrVbsXV6Hmo3ty57wu/FPH5MqvJ512xPSvL9LQ8D8Eh5zloaPAg7GB7gqVemS3
	nPJ9vnjQZYAcBrYlUIUH9Z3BHnZaFSzV/ArGn4cFKLlyuZ2z7LG75cTDsUVr+3uhkYKQJO5cUt0
	lyI2kg2tbrwVyRkp9rBQ==
X-Received: by 2002:a05:600c:3b8a:b0:45b:8935:16bc with SMTP id 5b1f17b1804b1-45b8ee1788emr25495035e9.37.1756744990976;
        Mon, 01 Sep 2025 09:43:10 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (140.225.77.34.bc.googleusercontent.com. [34.77.225.140])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf274dde69sm15955362f8f.14.2025.09.01.09.43.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 09:43:10 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	brendan.higgins@linux.dev,
	davidgow@google.com,
	dvyukov@google.com,
	jannh@google.com,
	elver@google.com,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com,
	kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	dhowells@redhat.com,
	lukas@wunner.de,
	ignat@cloudflare.com,
	herbert@gondor.apana.org.au,
	davem@davemloft.net,
	linux-crypto@vger.kernel.org
Subject: [PATCH v2 RFC 3/7] kfuzztest: implement core module and input processing
Date: Mon,  1 Sep 2025 16:42:08 +0000
Message-ID: <20250901164212.460229-4-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.318.gd7df087d1a-goog
In-Reply-To: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QvYIVLvv;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add the core runtime implementation for KFuzzTest. This includes the
module initialization, and the logic for receiving and processing
user-provided inputs through debugfs.

On module load, the framework discovers all test targets by iterating
over the .kfuzztest_target section, creating a corresponding debugfs
directory with a write-only 'input' file for each of them.

Writing to an 'input' file triggers the main fuzzing sequence:
1. The serialized input is copied from userspace into a kernel buffer.
2. The buffer is parsed to validate the region array and relocation
   table.
3. Pointers are patched based on the relocation entries, and in KASAN
   builds the inter-region padding is poisoned.
4. The resulting struct is passed to the user-defined test logic.

Signed-off-by: Ethan Graham <ethangraham@google.com>

---
v2:
- The module's init function now taints the kernel with TAINT_TEST.
---
---
 lib/Makefile           |   2 +
 lib/kfuzztest/Makefile |   4 +
 lib/kfuzztest/main.c   | 163 ++++++++++++++++++++++++++++++++
 lib/kfuzztest/parse.c  | 208 +++++++++++++++++++++++++++++++++++++++++
 4 files changed, 377 insertions(+)
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 lib/kfuzztest/parse.c

diff --git a/lib/Makefile b/lib/Makefile
index c38582f187dd..511c44ef4b19 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -354,6 +354,8 @@ obj-$(CONFIG_GENERIC_LIB_CMPDI2) += cmpdi2.o
 obj-$(CONFIG_GENERIC_LIB_UCMPDI2) += ucmpdi2.o
 obj-$(CONFIG_OBJAGG) += objagg.o
 
+obj-$(CONFIG_KFUZZTEST) += kfuzztest/
+
 # pldmfw library
 obj-$(CONFIG_PLDMFW) += pldmfw/
 
diff --git a/lib/kfuzztest/Makefile b/lib/kfuzztest/Makefile
new file mode 100644
index 000000000000..142d16007eea
--- /dev/null
+++ b/lib/kfuzztest/Makefile
@@ -0,0 +1,4 @@
+# SPDX-License-Identifier: GPL-2.0
+
+obj-$(CONFIG_KFUZZTEST) += kfuzztest.o
+kfuzztest-objs := main.o parse.o
diff --git a/lib/kfuzztest/main.c b/lib/kfuzztest/main.c
new file mode 100644
index 000000000000..c24350eb1fca
--- /dev/null
+++ b/lib/kfuzztest/main.c
@@ -0,0 +1,163 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KFuzzTest core module initialization and debugfs interface.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/debugfs.h>
+#include <linux/fs.h>
+#include <linux/kfuzztest.h>
+#include <linux/module.h>
+#include <linux/printk.h>
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
+MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFuzzTest)");
+
+extern const struct kfuzztest_target __kfuzztest_targets_start[];
+extern const struct kfuzztest_target __kfuzztest_targets_end[];
+
+/**
+ * struct kfuzztest_dentry - A container for a debugfs dentry and its fops.
+ * @dentry: Pointer to the created debugfs dentry.
+ * @fops: The file_operations struct associated with this dentry.
+ *
+ * This simplifies state management by keeping a file's dentry and its
+ * operations bundled together.
+ */
+struct kfuzztest_dentry {
+	struct dentry *dentry;
+	struct file_operations fops;
+};
+
+/**
+ * struct kfuzztest_debugfs_state - Per-test-case debugfs state.
+ * @test_dir: The top-level debugfs directory for a single test case, e.g.,
+ * /sys/kernel/debug/kfuzztest/<test-name>/.
+ * @input_dentry: The state for the "input" file, which is write-only.
+ *
+ * Wraps all debugfs components created for a single test case.
+ */
+struct kfuzztest_debugfs_state {
+	struct dentry *target_dir;
+	struct kfuzztest_dentry input_dentry;
+};
+
+/**
+ * struct kfuzztest_simple_fuzzer_state - Global state for the KFTF module.
+ * @kfuzztest_dir: The root debugfs directory, /sys/kernel/debug/kfuzztest/.
+ * @debugfs_state: A statically sized array holding the state for each
+ *	registered test case.
+ */
+struct kfuzztest_state {
+	struct file_operations fops;
+	struct dentry *kfuzztest_dir;
+	struct kfuzztest_debugfs_state *debugfs_state;
+};
+
+/* Global static variable to hold all state for the module. */
+static struct kfuzztest_state state;
+
+const umode_t KFUZZTEST_INPUT_PERMS = 0222;
+
+/**
+ * kfuzztest_init - Initializes the debug filesystem for KFuzzTest.
+ *
+ * Each registered test in the ".kfuzztest" section gets its own subdirectory
+ * under "/sys/kernel/debug/kfuzztest/<test-name>" with one files:
+ *	- input: write-only file to send input to the fuzz driver
+ *
+ * Returns:
+ *	0 on success.
+ *	-ENODEV or other error codes if debugfs creation fails.
+ */
+static int __init kfuzztest_init(void)
+{
+	const struct kfuzztest_target *targ;
+	int ret = 0;
+	int i = 0;
+	size_t num_test_cases;
+
+	num_test_cases = __kfuzztest_targets_end - __kfuzztest_targets_start;
+
+	state.debugfs_state =
+		kzalloc(num_test_cases * sizeof(struct kfuzztest_debugfs_state),
+			GFP_KERNEL);
+	if (!state.debugfs_state)
+		return -ENOMEM;
+
+	/* Create the main "kfuzztest" directory in /sys/kernel/debug. */
+	state.kfuzztest_dir = debugfs_create_dir("kfuzztest", NULL);
+	if (!state.kfuzztest_dir) {
+		pr_warn("KFuzzTest: could not create debugfs");
+		return -ENODEV;
+	}
+
+	if (IS_ERR(state.kfuzztest_dir)) {
+		state.kfuzztest_dir = NULL;
+		return PTR_ERR(state.kfuzztest_dir);
+	}
+
+	for (targ = __kfuzztest_targets_start; targ < __kfuzztest_targets_end;
+	     targ++, i++) {
+		/* Create debugfs directory for the target. */
+		state.debugfs_state[i].target_dir =
+			debugfs_create_dir(targ->name, state.kfuzztest_dir);
+
+		if (!state.debugfs_state[i].target_dir) {
+			ret = -ENOMEM;
+			goto cleanup_failure;
+		} else if (IS_ERR(state.debugfs_state[i].target_dir)) {
+			ret = PTR_ERR(state.debugfs_state[i].target_dir);
+			goto cleanup_failure;
+		}
+
+		/* Create an input file under the target's directory. */
+		state.debugfs_state[i].input_dentry.fops =
+			(struct file_operations){
+				.owner = THIS_MODULE,
+				.write = targ->write_input_cb,
+			};
+		state.debugfs_state[i].input_dentry.dentry =
+			debugfs_create_file(
+				"input", KFUZZTEST_INPUT_PERMS,
+				state.debugfs_state[i].target_dir, NULL,
+				&state.debugfs_state[i].input_dentry.fops);
+		if (!state.debugfs_state[i].input_dentry.dentry) {
+			ret = -ENOMEM;
+			goto cleanup_failure;
+		} else if (IS_ERR(state.debugfs_state[i].input_dentry.dentry)) {
+			ret = PTR_ERR(
+				state.debugfs_state[i].input_dentry.dentry);
+			goto cleanup_failure;
+		}
+
+		pr_info("KFuzzTest: registered target %s", targ->name);
+	}
+
+	/* Taint the kernel after successfully creating the debugfs entries. */
+	add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
+	return 0;
+
+cleanup_failure:
+	debugfs_remove_recursive(state.kfuzztest_dir);
+	return ret;
+}
+
+static void __exit kfuzztest_exit(void)
+{
+	pr_info("KFuzzTest: exiting");
+	if (!state.kfuzztest_dir)
+		return;
+
+	debugfs_remove_recursive(state.kfuzztest_dir);
+	state.kfuzztest_dir = NULL;
+
+	if (state.debugfs_state) {
+		kfree(state.debugfs_state);
+		state.debugfs_state = NULL;
+	}
+}
+
+module_init(kfuzztest_init);
+module_exit(kfuzztest_exit);
diff --git a/lib/kfuzztest/parse.c b/lib/kfuzztest/parse.c
new file mode 100644
index 000000000000..6010171190ad
--- /dev/null
+++ b/lib/kfuzztest/parse.c
@@ -0,0 +1,208 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KFuzzTest input parsing and validation.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+#include <linux/kasan.h>
+
+/*
+ * Enforce a fixed struct size to ensure a consistent stride when iterating over
+ * the array of these structs in the dedicated ELF section.
+ */
+static_assert(sizeof(struct kfuzztest_target) == 32, "struct kfuzztest_target should have size 32");
+static_assert(sizeof(struct kfuzztest_constraint) == 64, "struct kfuzztest_constraint should have size 64");
+static_assert(sizeof(struct kfuzztest_annotation) == 32, "struct kfuzztest_annotation should have size 32");
+
+static int kfuzztest_relocate_v0(struct reloc_region_array *regions, struct reloc_table *rt, void *payload_start,
+				 void *payload_end)
+{
+	struct reloc_region reg, src, dst;
+	void *poison_start, *poison_end;
+	uintptr_t *ptr_location;
+	struct reloc_entry re;
+	size_t i;
+
+	/* Patch pointers. */
+	for (i = 0; i < rt->num_entries; i++) {
+		re = rt->entries[i];
+		src = regions->regions[re.region_id];
+		ptr_location = (uintptr_t *)((char *)payload_start + src.offset + re.region_offset);
+		if (re.value == KFUZZTEST_REGIONID_NULL)
+			*ptr_location = (uintptr_t)NULL;
+		else if (re.value < regions->num_regions) {
+			dst = regions->regions[re.value];
+			*ptr_location = (uintptr_t)((char *)payload_start + dst.offset);
+		} else
+			return -EINVAL;
+	}
+
+	/* Poison the padding between regions. */
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+
+		/* Points to the beginning of the inter-region padding */
+		poison_start = payload_start + reg.offset + reg.size;
+		if (i < regions->num_regions - 1)
+			poison_end = payload_start + regions->regions[i + 1].offset;
+		else
+			poison_end = payload_end;
+
+		if ((char *)poison_end > (char *)payload_end)
+			return -EINVAL;
+
+		kasan_poison_range(poison_start, poison_end - poison_start);
+	}
+
+	/* Poison the padded area preceding the payload. */
+	kasan_poison_range((char *)payload_start - rt->padding_size, rt->padding_size);
+	return 0;
+}
+
+static bool kfuzztest_input_is_valid(struct reloc_region_array *regions, struct reloc_table *rt, void *payload_start,
+				     void *payload_end)
+{
+	size_t payload_size = (char *)payload_end - (char *)payload_start;
+	struct reloc_region reg, next_reg;
+	size_t usable_payload_size;
+	uint32_t region_end_offset;
+	struct reloc_entry reloc;
+	uint32_t i;
+
+	if ((char *)payload_start > (char *)payload_end)
+		return false;
+	if (payload_size < KFUZZTEST_POISON_SIZE)
+		return false;
+	usable_payload_size = payload_size - KFUZZTEST_POISON_SIZE;
+
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+		if (check_add_overflow(reg.offset, reg.size, &region_end_offset))
+			return false;
+		if ((size_t)region_end_offset > usable_payload_size)
+			return false;
+
+		if (i < regions->num_regions - 1) {
+			next_reg = regions->regions[i + 1];
+			if (reg.offset > next_reg.offset)
+				return false;
+			/*
+			 * Enforce the minimum poisonable gap between
+			 * consecutive regions.
+			 */
+			if (reg.offset + reg.size + KFUZZTEST_POISON_SIZE > next_reg.offset)
+				return false;
+		}
+	}
+
+	if (rt->padding_size < KFUZZTEST_POISON_SIZE) {
+		pr_info("validation failed because rt->padding_size = %u", rt->padding_size);
+		return false;
+	}
+
+	for (i = 0; i < rt->num_entries; i++) {
+		reloc = rt->entries[i];
+		if (reloc.region_id >= regions->num_regions)
+			return false;
+		if (reloc.value != KFUZZTEST_REGIONID_NULL && reloc.value >= regions->num_regions)
+			return false;
+
+		reg = regions->regions[reloc.region_id];
+		if (reloc.region_offset % (sizeof(uintptr_t)) || reloc.region_offset + sizeof(uintptr_t) > reg.size)
+			return false;
+	}
+
+	return true;
+}
+
+static int kfuzztest_parse_input_v0(void *input, size_t input_size, struct reloc_region_array **ret_regions,
+				    struct reloc_table **ret_reloc_table, void **ret_payload_start,
+				    void **ret_payload_end)
+{
+	size_t reloc_entries_size, reloc_regions_size;
+	size_t reloc_table_size, regions_size;
+	struct reloc_region_array *regions;
+	void *payload_end, *payload_start;
+	struct reloc_table *rt;
+	size_t curr_offset = 0;
+
+	if (input_size < sizeof(struct reloc_region_array) + sizeof(struct reloc_table))
+		return -EINVAL;
+
+	regions = input;
+	if (check_mul_overflow(regions->num_regions, sizeof(struct reloc_region), &reloc_regions_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*regions), reloc_regions_size, &regions_size))
+		return -EINVAL;
+
+	curr_offset = regions_size;
+	if (curr_offset > input_size)
+		return -EINVAL;
+	if (input_size - curr_offset < sizeof(struct reloc_table))
+		return -EINVAL;
+
+	rt = (struct reloc_table *)((char *)input + curr_offset);
+
+	if (check_mul_overflow((size_t)rt->num_entries, sizeof(struct reloc_entry), &reloc_entries_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*rt), reloc_entries_size, &reloc_table_size))
+		return -EINVAL;
+	if (check_add_overflow(reloc_table_size, rt->padding_size, &reloc_table_size))
+		return -EINVAL;
+
+	if (check_add_overflow(curr_offset, reloc_table_size, &curr_offset))
+		return -EINVAL;
+	if (curr_offset > input_size)
+		return -EINVAL;
+
+	payload_start = (char *)input + curr_offset;
+	payload_end = (char *)input + input_size;
+
+	if (!kfuzztest_input_is_valid(regions, rt, payload_start, payload_end))
+		return -EINVAL;
+
+	*ret_regions = regions;
+	*ret_reloc_table = rt;
+	*ret_payload_start = payload_start;
+	*ret_payload_end = payload_end;
+	return 0;
+}
+
+static int kfuzztest_parse_and_relocate_v0(void *input, size_t input_size, void **arg_ret)
+{
+	struct reloc_region_array *regions;
+	void *payload_start, *payload_end;
+	struct reloc_table *reloc_table;
+	int ret;
+
+	ret = kfuzztest_parse_input_v0(input, input_size, &regions, &reloc_table, &payload_start, &payload_end);
+	if (ret < 0)
+		return ret;
+
+	ret = kfuzztest_relocate_v0(regions, reloc_table, payload_start, payload_end);
+	if (ret < 0)
+		return ret;
+	*arg_ret = payload_start;
+	return 0;
+}
+
+int kfuzztest_parse_and_relocate(void *input, size_t input_size, void **arg_ret)
+{
+	u32 version, magic;
+
+	if (input_size < sizeof(u32) + sizeof(u32))
+		return -EINVAL;
+
+	magic = *(u32 *)input;
+	if (magic != KFUZZTEST_HEADER_MAGIC)
+		return -EINVAL;
+
+	version = *(u32 *)((char *)input + sizeof(u32));
+	switch (version) {
+	case KFUZZTEST_V0:
+		return kfuzztest_parse_and_relocate_v0(input + sizeof(u64), input_size - sizeof(u64), arg_ret);
+	}
+
+	return -EINVAL;
+}
-- 
2.51.0.318.gd7df087d1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901164212.460229-4-ethan.w.s.graham%40gmail.com.
