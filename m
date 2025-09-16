Return-Path: <kasan-dev+bncBDP53XW3ZQCBB26OUTDAMGQEQZ5SV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 60623B59183
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:33 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5717bd64551sf1882998e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013292; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ix3PenbuMCgGt06ueeKnKLg9yC7mSBz08NfTYypsErC8azknxgfN6/AwePfhj/+beU
         LVw/osn6k4O9s8wwjFDsRnsqok0IPrraiow7+AJQ7+OpsaemwmzCaH36UvEe5XyZAxKN
         ERjJlElnvmvGr/dMGlQPRoy8EQ298WF1EYEV1wvZSk/pmNafyA3fsy+XOzn3if2LGqMg
         fSVbZRYOslcqWpP55KXoZyVaENs+bchgUfyLM1P77vXHxyYpmfr2iNpNLs2nD5vh6Peg
         1QAXKq5GEVqVuWK7FnEYfECQCwpxuwj8fb7NvrcbfZPq6Tlj3rNFxDWf/LigMCEON/Dc
         UIMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=I/T2Cu8nEqbXIU5yPBSTjWaGezN+lCIBkMcTe8Muut4=;
        fh=feTal/xbLiC6eK7Q4LgRALVwTYBVbhZOa7V5aTIaCZ0=;
        b=K1DhxzGTX3QQSpPWv0Tqzi82kfHsq3aSDN1g5xH/bdWkp+X+hjRb89A9JKYAtdROxP
         kbLKIJVbbcNVUOlPpnGm26tQ7GnwKV4UjXJ967fZY7xCQ4Sk1v4EyllG4L0ux55WESQW
         SAsh1Zho6H6guXukFpUIUgsjZZvRdthnT0dx4Hus8Jq17/f78WybLi8tndd19HoJ0aHt
         VPPCZHY6BM61cxc7hHKXb1wZvncpDdmtUEQke/UsJ3ueEotb79YIcnfgp0Uvv8LX7NTE
         694rebiopUPDwXLtLamLGc4TJO5QIyNGBVjujnxizMLKpVNOhhx5JXSbDB4ifqAh+3Lu
         UU/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cjZjWZiO;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013292; x=1758618092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I/T2Cu8nEqbXIU5yPBSTjWaGezN+lCIBkMcTe8Muut4=;
        b=Dju/tsgicK4O+WhJivYW5Wr89kRHX3nestmxvXFPJWV756kLpPBhB8cVcec/zpQEtW
         cf0XEED3WHo7Zf4Ru+CnrG+KWbfAEFFpoFo91HyQUo4SImFzz67KsKcpIKMhBU1UaJPW
         FaORfAlOEegwJSa/ymcXvpJqTMQBXsPV45VopFSkZMRMikzQezwCRgN086WbM88fdikQ
         UdAwDi/XpQc77rBYyB0YF2IoQJ+NR26s8Ekm9w6rKH/Ejc4cG9CT+OyuSPI58tRPfFN9
         QUSMlBMSKjgzz1Y2nn2ovb4wvotgiAnAvpp1e97AtSSTAxbHiIBh5iDTVouNczaL57XJ
         HRaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013292; x=1758618092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=I/T2Cu8nEqbXIU5yPBSTjWaGezN+lCIBkMcTe8Muut4=;
        b=Jmt3Kyz1h7ZnAXqK2IzPf6qz0859nL9NOQ6gH7O/pT0f2NF9fHQuEN4m7WdX2oVR/1
         OmRLB0yJwWMger3lXw6QHgxAScLh5b0GaeRz+p0rW626s1vjgo/HKcv9oSIqGPLFLo69
         rlkWJgZU8UDsFUzY+sLU1PwXP6lR0dhsYGo/ErI/jBmeKcJlF7ZPhCPY0Tk+7evG1oxC
         xlkRKOo1BlBPCFIIvx9JEX0fgweIi47o7NAQh+r0qTZdOUUypYMgHZN4R17+Wj9lPPKj
         SkUx9UZ3Cej4bqSTMC4cg6oSVGaegnmEqRhfSxy4kRqHlwWLbqNKnJYo+OjsBYSS7SuJ
         BW4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013292; x=1758618092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I/T2Cu8nEqbXIU5yPBSTjWaGezN+lCIBkMcTe8Muut4=;
        b=XySM4n9bWvNa0OlBzfTtpKxVJHolNtpz1H2//meJV00lDMqGxaOWpDDWo6QzprimoN
         82/Obk+nQIpKT4vGsv1ctL9BnrkesW68YrDJMFRtcnIjaPaxObmTwF+8q/3D2NKVme5a
         7R0Tmo+s8NS+TPraf0YMhtSljlM1CcGlft7MdTx+FsanNK8CWzNMiQogM0XWAdoMCyFB
         6505ZOntD6q7JS067PDhRE8gLU/QGtvQ8JvcuGt/8bedeUaJ5/1hfJp0BDtm9dkfSupr
         rhAS/A10xW4WJVu52Vj+3lyDtt/B3mPt9C4xCsx33FB27i+c4999Kq6TV7b6gbv9MUrL
         kHZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOZGvbWEzJ+kRQlyy6OO9lVg2fqeZL9h6SyHUG0o31Fln6o+yjr4rePKzJWtwBu1PGN5jXSQ==@lfdr.de
X-Gm-Message-State: AOJu0YwWd+X8BQC+IoNWwFXvGf4A1M6qByATtv2kBlnaiNBHgMRHdPwl
	uVSmtx9P5SpcsUJkY9gK9HkFb//ZT2f2eLvlcD07ePBfofDx6Sqj/NAP
X-Google-Smtp-Source: AGHT+IETDyeqYi14ZVUzdfgAbhDNnBG91w30Pjx5bQ6DfBj4NvUdptUlsd39uRkN/eep1Tr7owEwxQ==
X-Received: by 2002:a05:6512:20da:b0:55f:4760:ffeb with SMTP id 2adb3069b0e04-5704ebf9ee8mr3316658e87.49.1758013291968;
        Tue, 16 Sep 2025 02:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd51A75UkBz0M2vfSEL2HK6t4fIWBzICoWD8aH84EKrF0g==
Received: by 2002:a05:6512:4288:b0:55f:457c:89b2 with SMTP id
 2adb3069b0e04-5721a578edbls601368e87.2.-pod-prod-02-eu; Tue, 16 Sep 2025
 02:01:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJ8WLyiWMiTKpx2HiiiU16fMMqUKm0rWcKa/HaUo8oyNkMIFht6XlkNQyadTJFuDTifkAPm3Ryu9U=@googlegroups.com
X-Received: by 2002:a05:6512:79a:b0:560:827f:9ff6 with SMTP id 2adb3069b0e04-5704fd776bamr4120278e87.57.1758013287943;
        Tue, 16 Sep 2025 02:01:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013287; cv=none;
        d=google.com; s=arc-20240605;
        b=LosQBm6TISfbCibTCAT4HE+m0tyTWWJPra6aGzH8OyMO0IEgHLMuIzClRfoG15iU7f
         xcQYkD915YdAh+1j5hy7IFKSO7kd6GePs6uaqKYw+bxOKXD3YgVQEyRAUJFk0vy0znLa
         6bdMfyvVHK4uFx0llOzH9w/A+G/53DiWyhykTqmNVXcd0lwH7YgvhpfEgoezg/BJCW7S
         u+vSFZwa/SNHdtKp1NxZI1U7/B7UR84VquNdF5GvY/b7XBy3q5pYvMPjzc1Ib2W6Z4Vl
         I4zabg6/lfC1AbcnndM+lObLu+46V6ATp7CyydHSbHbCoKSsPNUyA1cXQIRBIHTRUM8u
         hnHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eX0GE1tFaVdaJ+X5gME1f6NzrpcsI0lAH1DHePnNN9I=;
        fh=CginynbuJLR4eDF3XBg0MAgyH2e1IUaeeuY46DbNwpI=;
        b=ZqNKoVJF5cN+6NzCaCc4cWXA2JtRAq1tEHkS42ft8fVoPptfcSHnt4is7avD3FFm7P
         HiRTG8beCE20ct/QfF7v5+lQRDf3/RzjXHQXLjnbZPcyZOp/KPN01WeXGvacVFiHVFGp
         d6o/KQHe6s0u/qSr5vthGROM223bLH0d66DIpIxTuwqxhQtVdh6eu0L4HYeZwIB92N2t
         IUnFcuRlissP9XM+M+j1No+viFj4K5P05ptl4WFksLEwAPD5k6A82zpy0WeZZXeWL03w
         ZRNhCb26g8+wGbsqnzCa/9MQYKzsSE/LZJviJClpZBBkcpKs3hy7yQWl57RMGzxPALtT
         bFPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cjZjWZiO;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3512a98ca2bsi1938831fa.5.2025.09.16.02.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-45f2cf99bbbso13174505e9.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXtkIoED2P9PJrBi/IG5R/XdWhIwqTLI77ICpGuudItSumG9br2Kz91Xj+w5KA9uinjZWxsaB/KP7M=@googlegroups.com
X-Gm-Gg: ASbGncvThwNUaRmvMFY5fu73kKRVyOVb28tX53qWqyylvEJlFZ0SqdN4/LsbhIeXi/k
	0a2r9wPynGFFIjhkOrmyKLFXjMhGXhEUZl28G29Wj1PJ2L6IURrQXtUNFdw2JfRfNuWwCNH4YRi
	UI8k0/A18vzErnxC66uO/Li77lu9nPolWXZRQwXVFkxfF7hrl82cnDQ2XFtM9Ou95G1ylNM4Wef
	iEubdbu2lCbFY2B++9Mqy7ViiQJMgjCSHqazsll8yxsWkZ37B1l9VfujcXd++x40Lq3juSCiYmY
	NlR4QVrNqUZmgQ7FRhS8olpWCrXT+IIpzdBtAgELzOhLgVQvSo5tu+1STeDu87eGMC4/dd5M86V
	VruMf1qwzmPayisseHg/7c1iRsQxN5lTMyGrwr/2dqndTXWW2x/D1ZvowMfu4xg0tlfpRulCUqi
	jHVoQP7GZWM9OTRHK4IIYyHQg=
X-Received: by 2002:a05:6000:2001:b0:3eb:86fb:bcd9 with SMTP id ffacd0b85a97d-3eb86fbbfb9mr4536453f8f.12.1758013287060;
        Tue, 16 Sep 2025 02:01:27 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:26 -0700 (PDT)
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
	tarasmadan@google.com
Subject: [PATCH v1 07/10] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
Date: Tue, 16 Sep 2025 09:01:06 +0000
Message-ID: <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cjZjWZiO;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add KFuzzTest targets for pkcs7_parse_message, rsa_parse_pub_key, and
rsa_parse_priv_key to serve as real-world examples of how the framework
is used.

These functions are ideal candidates for KFuzzTest as they perform
complex parsing of user-controlled data but are not directly exposed at
the syscall boundary. This makes them difficult to exercise with
traditional fuzzing tools and showcases the primary strength of the
KFuzzTest framework: providing an interface to fuzz internal functions.

To validate the effectiveness of the framework on these new targets, we
injected two artificial bugs and let syzkaller fuzz the targets in an
attempt to catch them.

The first of these was calling the asn1 decoder with an incorrect input
from pkcs7_parse_message, like so:

- ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
+ ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);

The second was bug deeper inside of asn1_ber_decoder itself, like so:

- for (len = 0; n > 0; n--)
+ for (len = 0; n >= 0; n--)

syzkaller was able to trigger these bugs, and the associated KASAN
slab-out-of-bounds reports, within seconds.

The targets are defined within /lib/tests, alongside existing KUnit
tests.

Signed-off-by: Ethan Graham <ethangraham@google.com>

---
v3:
- Change the fuzz target build to depend on CONFIG_KFUZZTEST=y,
  eliminating the need for a separate config option for each individual
  file as suggested by Ignat Korchagin.
- Remove KFUZZTEST_EXPECT_LE on the length of the `key` field inside of
  the fuzz targets. A maximum length is now set inside of the core input
  parsing logic.
v2:
- Move KFuzzTest targets outside of the source files into dedicated
  _kfuzz.c files under /crypto/asymmetric_keys/tests/ as suggested by
  Ignat Korchagin and Eric Biggers.
---
---
 crypto/asymmetric_keys/Makefile               |  2 +
 crypto/asymmetric_keys/tests/Makefile         |  2 +
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    | 22 +++++++++++
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  | 38 +++++++++++++++++++
 4 files changed, 64 insertions(+)
 create mode 100644 crypto/asymmetric_keys/tests/Makefile
 create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
 create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c

diff --git a/crypto/asymmetric_keys/Makefile b/crypto/asymmetric_keys/Makefile
index bc65d3b98dcb..77b825aee6b2 100644
--- a/crypto/asymmetric_keys/Makefile
+++ b/crypto/asymmetric_keys/Makefile
@@ -67,6 +67,8 @@ obj-$(CONFIG_PKCS7_TEST_KEY) += pkcs7_test_key.o
 pkcs7_test_key-y := \
 	pkcs7_key_type.o
 
+obj-y += tests/
+
 #
 # Signed PE binary-wrapped key handling
 #
diff --git a/crypto/asymmetric_keys/tests/Makefile b/crypto/asymmetric_keys/tests/Makefile
new file mode 100644
index 000000000000..4ffe0bbe9530
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/Makefile
@@ -0,0 +1,2 @@
+obj-$(CONFIG_KFUZZTEST) += pkcs7_kfuzz.o
+obj-$(CONFIG_KFUZZTEST) += rsa_helper_kfuzz.o
diff --git a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
new file mode 100644
index 000000000000..37e02ba517d8
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
@@ -0,0 +1,22 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * PKCS#7 parser KFuzzTest target
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <crypto/pkcs7.h>
+#include <linux/kfuzztest.h>
+
+struct pkcs7_parse_message_arg {
+	const void *data;
+	size_t datalen;
+};
+
+FUZZ_TEST(test_pkcs7_parse_message, struct pkcs7_parse_message_arg)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(pkcs7_parse_message_arg, data);
+	KFUZZTEST_ANNOTATE_ARRAY(pkcs7_parse_message_arg, data);
+	KFUZZTEST_ANNOTATE_LEN(pkcs7_parse_message_arg, datalen, data);
+
+	pkcs7_parse_message(arg->data, arg->datalen);
+}
diff --git a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
new file mode 100644
index 000000000000..bd29ed5e8c82
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
@@ -0,0 +1,38 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * RSA key extract helper KFuzzTest targets
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+#include <crypto/internal/rsa.h>
+
+struct rsa_parse_pub_key_arg {
+	const void *key;
+	size_t key_len;
+};
+
+FUZZ_TEST(test_rsa_parse_pub_key, struct rsa_parse_pub_key_arg)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_pub_key_arg, key);
+	KFUZZTEST_ANNOTATE_ARRAY(rsa_parse_pub_key_arg, key);
+	KFUZZTEST_ANNOTATE_LEN(rsa_parse_pub_key_arg, key_len, key);
+
+	struct rsa_key out;
+	rsa_parse_pub_key(&out, arg->key, arg->key_len);
+}
+
+struct rsa_parse_priv_key_arg {
+	const void *key;
+	size_t key_len;
+};
+
+FUZZ_TEST(test_rsa_parse_priv_key, struct rsa_parse_priv_key_arg)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_priv_key_arg, key);
+	KFUZZTEST_ANNOTATE_ARRAY(rsa_parse_priv_key_arg, key);
+	KFUZZTEST_ANNOTATE_LEN(rsa_parse_priv_key_arg, key_len, key);
+
+	struct rsa_key out;
+	rsa_parse_priv_key(&out, arg->key, arg->key_len);
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-8-ethan.w.s.graham%40gmail.com.
