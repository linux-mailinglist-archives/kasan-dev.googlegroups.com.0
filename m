Return-Path: <kasan-dev+bncBDP53XW3ZQCBBJE227CQMGQE72FXA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 11FA6B3EC7D
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 18:43:18 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-45b883aa405sf13572145e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 09:43:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756744997; cv=pass;
        d=google.com; s=arc-20240605;
        b=W2TNk15csYCfVxlbL1DKrK44cg6H7uYKRTNV4zaAIT0jUCvEeKTwcTn3qEDz61cl8D
         Hzh7y/lXB8Nj6Uj96nZoM0F346Q9Ch3oyVN/LRyEJBalXeZVrKrGpVFCFaPWWv+nnCZ/
         GrzL6oTin2oGUPOg/v6/m6I6dDK1BFkzpVAGKiTZTGtRbFfnMQ2XThw7yujWoFMcQw6x
         MQ58XE6RpgT9j7zF/3ACe7C1TrD4Ew29Gt6WOWV0eypOAH2Gb86T69Q6xvnZ0kikRP/+
         hLslCaxi9C9Ugs3w17OLvVa7p1KcrF+CTe9KYkJBp0f7xDg86X+H9GnCpZyIFsKNXI+t
         bHqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dukCdijJJZ5PHBHPLzH6bHorOfI4sidvAq9gDxUkEFU=;
        fh=szvch2/D1X9zl5Gnu/raq+ZukoRJkC63F/EKDZt7kng=;
        b=b9+qlCJzxay/hxNDO/MUWagjI5aADkGqCT4dErSqnY2X5GuMdj8RaA4RVItCWdLgwi
         r3sM8DDvnasP98dhVrHQhVtHG7wbJw+oY++SXyc0pGv0V+23NbzGxOcS22AGrXSEH8h7
         77Jmaz+tO6ALuVlOLcSX8uNWhBvsIgeHhZWYVQW8zf5r7128NXpvcYhhd/zq6sBVHDQj
         wUnI+fGZw9khxX/GU9ELgLj43f4NT2UJlhvTbqYAlpolS1/JCzQPeQLaP5p6vVbg7NOX
         wzCJHZ6qLenTp6KMKeiA2KzAokKasELV/79N5fkGLL9WuyXwCQa7Oqm5/XUP4emu9u6R
         suxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eH7RGex1;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756744997; x=1757349797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dukCdijJJZ5PHBHPLzH6bHorOfI4sidvAq9gDxUkEFU=;
        b=FktWKdu2HZuztTPKAW22/WPGiva63jUwM+Sdpcw+l2NNbrK12OfnxMyuBxHgUC7EKG
         rExD37RnNB8bEv8mbWHfYBWV+AnIQrX2nnvQ9xVlOV2MVtuujqoT0/YNTrnrTqcLyB7b
         Ipyr6QhXovU7J+3yXHMfKVOE34RzBUBYiI0bPtsSXOtmy5+ujruaYt5N1+9Z5Zwubtvu
         V9kwAPViRd+ZN0+R0XGn89WdY3ShrrNzQMWw9U/OIXhACxrFRtDaPuAjNOVvc7xirwca
         7qn/+4bJ4bC/VxIr+riLv0c5LOHLZEh7JzxGo3KfX7uZNRMQxu9NMgq1afUV9CvGFV+/
         CPMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756744997; x=1757349797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dukCdijJJZ5PHBHPLzH6bHorOfI4sidvAq9gDxUkEFU=;
        b=eFUE4LbuMxrJ6wEYvfVs/e3ABy7bVLNGIqzwhOHENYBJfqK9uWKFnTq/FJQdan814Z
         erzDO9wlvv4pFg0lzzIZ0pce3pZ2c8vylvjf8jLo0+JX2tZpd9G7gzbzt+dnzHOllcFJ
         ovKQ6ey9mVN723G8aptxPKiPR602PK4cZznTuy8AB3dxZHV1xcjPJZuF2TCNaAcaTXF9
         HV/Sbi1vGE5yY0UoEm6YySSAa600tgVh8uRDZXjzVmoNyBofEfwd8c0/lMPoGmydjm5S
         G44mig91Hj7OTPC9Nj2Qew71i5kxVwaHe+gNOgdE7c1KEA+r67il1MxwyZlo6+UDzJT3
         EQjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756744997; x=1757349797;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dukCdijJJZ5PHBHPLzH6bHorOfI4sidvAq9gDxUkEFU=;
        b=IUZ6Alwi46ooKYRZGDgUM/rUWQYbfIP4P//Dy4h2cn7QccC4PTlPIjCQ0DBJ6kLPKA
         UoODSARQMtBOdTys4rqRg0IUgHTSv1EOV1c6aZD+2lt+3+/7HvdUkhtwrEiuC/O+557F
         j/OSJXG7tV79UXlFJBO2CMh4ZcKKwSd19d0ZgHVi77AIvA89uMJo9f0HRXTPk0uhqM8K
         IpEI870NgeONqNEyezghWFu7Q8S5SjUGwYFU/QIx7tPyzndltjI0Wd+PXbwDd4tyDsY2
         ad4oAENs2GDOhyMZba54KUHX2+ffgo+haYlC85BWnW+FhdrUu6W0ggy3wHrz4MZq8B3g
         i0ig==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDUN0CmQlasoD4eadK/6Nf9ewqZlGfkxFS9V1lZZGp9CKjIRH7mRM9pE9maVbLhY5GCmgLhA==@lfdr.de
X-Gm-Message-State: AOJu0YzXB4oEqGZWqq65nvLGVLm7t7Eqj07eXp8r0xlKjQWKk4gXIVdM
	k7AZ67vvOOUX+f1N2F4HF0E2sRvprI/VNHAY9kIrAWnP6w05ylySeHrV
X-Google-Smtp-Source: AGHT+IGyT1FPC2OQ33egpeq+cmA7rzmpjrIMRklk8Qpz1tvt7NGLt9Cy2kcKpJDrx2SR+EquNt9wNA==
X-Received: by 2002:a05:600c:1914:b0:45b:88d6:8ddb with SMTP id 5b1f17b1804b1-45b88d693a5mr57857545e9.37.1756744997554;
        Mon, 01 Sep 2025 09:43:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdMyqe/+pYgIEOmZGzShRjOsS35M7c4wXenGGNzjOZ1dg==
Received: by 2002:a05:600c:3b9c:b0:43c:ed2c:bcf2 with SMTP id
 5b1f17b1804b1-45b78cb2f26ls27476205e9.1.-pod-prod-05-eu; Mon, 01 Sep 2025
 09:43:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqoHP44jORLdv3NdA3MKLHGhaZAZPhncxy43ufCYeRqXspXHaFB+yXuI5flzmE7bCSIrOYzjuXQ/A=@googlegroups.com
X-Received: by 2002:a05:600c:524d:b0:45b:8a10:e5a6 with SMTP id 5b1f17b1804b1-45b8a10e833mr55377445e9.15.1756744994550;
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756744994; cv=none;
        d=google.com; s=arc-20240605;
        b=CZ3AYaXctoN5XliTu8539m6af0BVNDKZICWM5RLJFk+Xguq1KZAdpIM01XA22NdWE8
         esxhB02LY/jiFiz/EogA85eeaQ4lF9K9sWI9UpxlyUNyK9p0VFf4BQ0q4cGmnMpMJ4lN
         q5DDe9MLgQzRDnbYIOurvOhj17RpJR/YlztRsAv/rzNZ6HYOJfoEkPca/b/yWAoSzo8i
         ydwKfXRKIL8UsaFGF/Bj9NSjVuneGFp2S2Sqz0LAux6+oF92M8lZC55z4MCSQN7C8uOl
         tcVpMPbMDPki8RYjuiDxAUy5quBiPqrS9tR8NqJOPepwJF84KGm00P0PGj9jtBd5J+9j
         LBJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ApDGjF4qZlhoSmK2tdSzupo+2mRrDnKfGsOkf1zOwN4=;
        fh=Vpz6EJwJ9u3nVFqc7DOslxY3m2got51INX7VJq2sgBI=;
        b=f8sUJHEp8FJ2iOzdS1C8CVAgo2nsYI7Rvhidv6XOxPSLavlBXnOCHHfptffHKan2TP
         6mrgrVrwIcgiNTxAC6pA7INddDm8PP1QfM2/CBbJzNNdhHsmkVzpcBG+C84yAXzRCgHH
         UGLLdD6Z0KuDs7TpI3Ak72TkSJh55+QaU3OBRgdrml+bJ1wCv+1dJ3b4j+yyCCZU/R3t
         CDqHNxRznjmvtNv07Nw1KsWdwcmQySnFeoskZqY5kbIADZg0vaauLt/smr69lNZza/gx
         imz8YDJxdsLTpxTgiu1VpJfu0+TGZyVYRi+7/9+6XQMqezi+gTuVoS0k+ipHQs3X7K3p
         OUNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eH7RGex1;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b8b916d49si1082135e9.0.2025.09.01.09.43.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3d0dd9c9381so3105317f8f.1;
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUY8vyiZwb1uuUeBDmfFWmR4UlZlqLH8tW6Him1Yh/CblVtSvwhAtm9PzYYkub97P6Q+rSRNO0SoAOg@googlegroups.com, AJvYcCXwSarc4kcTfiQj1gZH1mmVAKtEbdkNkDAZYLPMbprQmCI35L52l6S7nkrJwltjpbPA9Vu1iLjXg5Y=@googlegroups.com
X-Gm-Gg: ASbGncv5lB9b6IeEFsJjddH9PZ72RIg9IlRSgoMZg36N1Tub0c9ncE3Arh0fuFc8wiR
	wfF7vV/cONR+JbsDd4Z8vKiHgaX5LeCEbIvjSO6oQrUjDJAlPUv1j9VVKCRSzS2F1uGdtwaEBp2
	bh8Xx2v8xAtgy9IOSBD8Ea50zZP5BeywyS5oftEPCU2u+MB2PsM09h3TkfuUoZxhXDhhOhNeczf
	NZSiaur2fSjYMxGbgprC6H/r/elfqAYGPvUtiQscPi/cTK+DyMikCMycF9xuu2rgIYTRPWJ+WLg
	MD+A5QV7zn3rg7iXT3yz9e+Tr8ct0tmZhFgagHB3GqhiFDBE1qjzWCowPc9jzs4ZKPUvEn1WUWZ
	zzybu0/TLKKQWNXdKgdJYeSGIcT45TM0yu+NIr4FLuonty3OAkraVNOq/1lMLIAyniWU8S8Fp+L
	b+GwmneWrYRXuiZE/yr+mZxWbjhRk4
X-Received: by 2002:a05:6000:25ca:b0:3b7:9629:ac9e with SMTP id ffacd0b85a97d-3d1df34d63dmr5448037f8f.50.1756744993978;
        Mon, 01 Sep 2025 09:43:13 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (140.225.77.34.bc.googleusercontent.com. [34.77.225.140])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf274dde69sm15955362f8f.14.2025.09.01.09.43.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 09:43:13 -0700 (PDT)
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
Subject: [PATCH v2 RFC 6/7] kfuzztest: add KFuzzTest sample fuzz targets
Date: Mon,  1 Sep 2025 16:42:11 +0000
Message-ID: <20250901164212.460229-7-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.318.gd7df087d1a-goog
In-Reply-To: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eH7RGex1;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
sanity checks for the core logic. For example, they test that out-of-bounds
memory accesses into poisoned padding regions are correctly detected in a
KASAN build.

These have been tested by writing syzkaller-generated inputs into their
debugfs 'input' files and verifying that the correct KASAN reports were
triggered.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 samples/Kconfig                               |  7 +++
 samples/Makefile                              |  1 +
 samples/kfuzztest/Makefile                    |  3 ++
 samples/kfuzztest/overflow_on_nested_buffer.c | 52 +++++++++++++++++++
 samples/kfuzztest/underflow_on_buffer.c       | 41 +++++++++++++++
 5 files changed, 104 insertions(+)
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

diff --git a/samples/Kconfig b/samples/Kconfig
index ffef99950206..4be51a21d010 100644
--- a/samples/Kconfig
+++ b/samples/Kconfig
@@ -321,6 +321,13 @@ config SAMPLE_HUNG_TASK
 	  if 2 or more processes read the same file concurrently, it will
 	  be detected by the hung_task watchdog.
 
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
index 000000000000..8b4bab1d6d4a
--- /dev/null
+++ b/samples/kfuzztest/overflow_on_nested_buffer.c
@@ -0,0 +1,52 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * overflow on a nested region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
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
index 000000000000..fbe214274037
--- /dev/null
+++ b/samples/kfuzztest/underflow_on_buffer.c
@@ -0,0 +1,41 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * underflow on a region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
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
2.51.0.318.gd7df087d1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901164212.460229-7-ethan.w.s.graham%40gmail.com.
