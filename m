Return-Path: <kasan-dev+bncBDP53XW3ZQCBBJU227CQMGQE7JUEQTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 62A4BB3EC7E
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 18:43:19 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3d160b611fdsf1483207f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 09:43:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756744999; cv=pass;
        d=google.com; s=arc-20240605;
        b=S4eWXSa6o1iK4bG6+FWB0BcZ3NZS6rYhzYoSKqXkuYVsQmGqxjr5dNriF4dq73gza+
         xYNQ3BiCHXXVG9r2HfKL7BA3Oowr1yjHv8akTzNJIPDAc+0zKZ3K8dTP7XmsYKYYW0uY
         jDeNigowk9KYXYjNTqpcfNYYNpqW0KEGqKmN6RRCviq5i5K+s8Hqqzf+NkK89bxB2K02
         j3x77gl+ovoD+l2tQH72c6c+HCubfBnaGPih7SkHjtzX2nMnq/Ys2YwMcOUf3PlAw2Gj
         yTgWwX7J97GiiPxIpP97AHReKSKfwk1/oAQlHFokd68LoLvGuZcDuwovnKRD4r3Y/btK
         aEUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=tE7qnQu2KLSVzyhnjDRDoqgCMNYeTzMl9+2BMjLguwk=;
        fh=HSii7nQtohFB7UMK2pz379VYdDTh1zIN5s5AnT3H7cQ=;
        b=FuiEpea4JQR2jtiL03NtBQFA5m1i9Cm8z3SyQelmygd7Dwi1VRO3vQPwI+ZNiNJsY3
         ha7ac0n58gq+5H72zrPNlEKCCxbGJ1xK91qxoBeyqa3xhybB8e3n1xfwcewSH9t1zTLN
         S/T8BiEg/ZqemkR9f+ASfIIjw4SvCAsMlM13gS4erwy7PrSWnnFUP4LaTcQeam6su3EF
         8k+y80VDCPIADRNlh3VhMKDxPYXojfu4VifP3gNLrxxeS7M7LkIQgYGt600K+/njmEvc
         1IaXNFJwAyEHtXVpQNxcTTN7BCYFAnWdH+qmUKSLCsFBvzm4EfnMpJiOUR/+gqJskdMt
         IYwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bpBwLepQ;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756744999; x=1757349799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tE7qnQu2KLSVzyhnjDRDoqgCMNYeTzMl9+2BMjLguwk=;
        b=ATLgSJYqvsZrWSyfSJ9ebW5tP1GrrIrtQokBPjD+xvY0ywMbxk5RLBYoqAq0YeOphM
         eoExYOXAkJN2W5AWV9hz2QtTx1g76EBsyiwOyBS0lFRjZj06wmJQrN6ozuGqy6rpedya
         lz/k0pMw83IjjyvIplMsgG6O71kcAZOL4cY7mSiMLxIjIzko4c2iamRCDuWbKI9P3HnS
         15mvvoyKeElaZUsz7vox4D51wf/HzX3OVTbxAHnj/VTep8eg6bC6dlPluHn3DtjPBvVN
         AbBt87kOO9/vJTWdlAHeWs26M5rWYySGG93heqf5HIS8JQ5baLhMGYoYl1BYzNk9Jb+c
         KVRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756744999; x=1757349799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=tE7qnQu2KLSVzyhnjDRDoqgCMNYeTzMl9+2BMjLguwk=;
        b=PUG0GYLQd9jnPImmLCAlfa61Tp66cCipjC461lxxo2C1MNsaRV8YzuX/lqKbcnzpaI
         Klcoxa4VC6nlm0VdmNhc3zU1O7YUo2JgY7dTInv7aX5SfeXL4oSOJczjFJlPqqhSCqzs
         x49qbat/7Ggxw0PPPTN/dKNNfKM30q5MkBbmB6R7IfgO20X4eItdcjKxWcHdIHZGlLtc
         6vSrFJyUSyp3PrKgAthL48bAu9dHjYDpEqnNoXK71Me7oHeYJNWh7Km6vHZg5WMI5Wpt
         TsIJaQ0SLGdvn6a5KxZiXYL5A3P9Fak0H5xLrprBBVt3miaiR/oc9+a2+67QMDE6WGPg
         97IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756744999; x=1757349799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tE7qnQu2KLSVzyhnjDRDoqgCMNYeTzMl9+2BMjLguwk=;
        b=ToddGiE0LNcJKuEvURzI7udGzwWIbrWsvAXgWwSKvUYFAaK4SySV3kTe7+qAyzGpip
         etSjiQZoJ5NEA7UxQSNO9zxKWzrZUKNQKk3qdMRZIZRV/jXDxpuerzpoxnj1v4elXuMi
         QU0riS6wbE44lG8mlNGka0pkPw9QWDj63H3TCg5cB1piiFSCWzdbbPQzeePqdkWOA4Pn
         qgQI9cqgQdZHZnt2uLBZghbwCWIhlg7t0P3oyUM5Iq+bjL2MFEjnsIZyMOWGzC4/nZ+e
         kVjVTwBdPvG+FNDtnO8cGayZOh4vKlWklE8uJupfcM6oAcOsxj6/GsDT6Xg8tenEUcvP
         NkvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW91ruJrMMgUH822AZN4/gSVsRI1hujGbFyI9MrNc18yE0+7zkLCE4bX9Svj28UCUSZ8DszzA==@lfdr.de
X-Gm-Message-State: AOJu0YyNQv468sTV4LcwzUip69UcmyzH7iALFhSt7gMT6z3Dcy1epgmA
	spR3SmxLLyXnAm1JQGQGs08AK/2AL4fuEtsZ3zjEbaRVt0JAPKlGP9uA
X-Google-Smtp-Source: AGHT+IEAup+LfUvO19biAYSm9Gtdl0CXhPCDYEmJqfvq/Wr6ce8nReC7eUa5Hcm1IdFQIaOBdx4E8Q==
X-Received: by 2002:a05:6000:200d:b0:3d6:7ae1:aefe with SMTP id ffacd0b85a97d-3d67ae1c171mr4445016f8f.12.1756744998763;
        Mon, 01 Sep 2025 09:43:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2y5RhbyrzWsjDYt0EhUbVM6rCeWG4e9gd+1QcVuPd7A==
Received: by 2002:a05:6000:2005:b0:3b7:8a12:d1ef with SMTP id
 ffacd0b85a97d-3cde269d5aels2598782f8f.1.-pod-prod-06-eu; Mon, 01 Sep 2025
 09:43:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX80vPSmlxxnLGl6YsOaPTI2j+/khRm0lbCvqkHF5huAdJV0Vve0dxWHl6n+i30NNtOkkzO4IixIO4=@googlegroups.com
X-Received: by 2002:a05:6000:200d:b0:3d6:7ae1:aefe with SMTP id ffacd0b85a97d-3d67ae1c171mr4444855f8f.12.1756744995643;
        Mon, 01 Sep 2025 09:43:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756744995; cv=none;
        d=google.com; s=arc-20240605;
        b=N0x1tVfH4YVepG9OSA0RdBwlw65ilsBJpVi7Oo32MiFz9Mih7nHfUYmEo6WEwXMoZH
         56c5pb1uFvRnv93Wu5OdZltgVUgV89alc/fmr40VwGjNvcJVDOnJ+P/N6wzoBRN801Zu
         fFL9u9T+bwKB6PRrH7xMWJmvgJ5u477q52NF6S+mkqy/A1kF+udZWe+SktDS6DCWq6kD
         w92juhcgQgd9uYjrArVxzbb0EUKdlOVVyJ/S4BL0FwvihnhP6yUo7VsOY3lRNNTyiFk/
         h4SEbx5JClCOQB9AmxMTXKNj45M8CX0wutZ1E7q5Jj7raIsQeaaAhuxw7FCYTg4wbAnU
         8Lmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IBvpSqbqbG4wFXeR5v1aPOZCpZfQ+jFjNgEJ1TDAElY=;
        fh=2GcMZ/hvz4yDR0eMK8Nxj/9frEsTavDhziTjf9iWQeQ=;
        b=YjnH+GW+Syqr7iYDUQdr2UJfu1UOj1zkNDP94k4mHrKhMLlYET6AVuSn0C53Yp8B2+
         bNfP5LRn2UUwRq3110Q+jvYF4XHApJwhjt59sJBGyLCpHCssY1EGzOipWGxTkpiJiuSY
         U0kBiF1JD3NQHEbvPGEoVU56nWqXqdECJVs16nfMFKmZ//M42YIdpBvJZT3qu0NqDfiL
         eiSE6v1qD6CAWUnVwZy1PtNCa3GgdgBxSNkiyc2tg+/yhALTEZPoUDcytlA3ZRZGlUEX
         GXfjDdxhz/HnjcVbHVjf93KlEiTSxP0KlLOOeQVTuJWZwTSRJLNCzxrMxe5tE+SDIj1H
         LizA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bpBwLepQ;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3cf2883c69csi142991f8f.3.2025.09.01.09.43.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Sep 2025 09:43:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3ce4ed7a73fso2303137f8f.1;
        Mon, 01 Sep 2025 09:43:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPfWIG6UUlZI2vFxJm3CoS244fMAD1rpZbNC4Tf5xEUaW96sldV/Mxx+/lVSdIWBpRMwrtzst38yoq@googlegroups.com, AJvYcCWb4deGMm2QqYhRpN444HMF0j3C0BH7V244102X87EH6xRwgsMZAwetE3o0H1TK4qXLZxZruDq8RQ0=@googlegroups.com
X-Gm-Gg: ASbGncugfVgWsPdaKqck7X5dXUNzJBHWvAftY3pnFJPKY2EzL/fE4lcPjlnj8fuqUrX
	Rx4bCGOalLsuqQ13IyFatcTC9SYvZj57JTsYuo4Uzeon8712MsqdiYATs2ul1WtiKnjQz3cY/EE
	BGcIvDSiB3U9Y/+FWz+q9F+us4GDR9FqUyH25NgKcWiZ/WAy8p5qoTolEOP+4E793LrzxcIzu+B
	GvH1PTjUr6ooCfYNd16pJy1n7+H0Vcd2pcYyDVPPagr4P5Kmu8CvSv9E6L4xGyw92vBvtn/PTr3
	inn7N8eFhNr4wy0yrvshR9hQ94eiyt4CtXGxb3dbyqj1i/cKbuTCq8Nwb/Qg7TtXJikX2b+3em/
	/MHFeqyVKrn7K4J8DOfz6VT/QZqV2+ohKpIpJF/WA8O+YUnKLeQUHK3x1zl5VoAsz6+1OO2GMIj
	+Pqxcd6EYsm5LuzR1k++W830z3u5Ac
X-Received: by 2002:a05:6000:4210:b0:3d5:9efa:fbf2 with SMTP id ffacd0b85a97d-3d59efaff51mr3979157f8f.22.1756744994954;
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (140.225.77.34.bc.googleusercontent.com. [34.77.225.140])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf274dde69sm15955362f8f.14.2025.09.01.09.43.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
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
Subject: [PATCH v2 RFC 7/7] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
Date: Mon,  1 Sep 2025 16:42:12 +0000
Message-ID: <20250901164212.460229-8-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.318.gd7df087d1a-goog
In-Reply-To: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bpBwLepQ;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
rsa_parse_priv_key to serve as real-world examples of how the framework is used.

These functions are ideal candidates for KFuzzTest as they perform complex
parsing of user-controlled data but are not directly exposed at the syscall
boundary. This makes them difficult to exercise with traditional fuzzing tools
and showcases the primary strength of the KFuzzTest framework: providing an
interface to fuzz internal functions.

The targets are defined within /lib/tests, alongside existing KUnit
tests.

Signed-off-by: Ethan Graham <ethangraham@google.com>

---
v2:
- Move KFuzzTest targets outside of the source files into dedicated
  _kfuzz.c files under /crypto/asymmetric_keys/tests/ as suggested by
  Ignat Korchagin and Eric Biggers.
---
---
 crypto/asymmetric_keys/Kconfig                | 15 ++++++++
 crypto/asymmetric_keys/Makefile               |  2 +
 crypto/asymmetric_keys/tests/Makefile         |  2 +
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    | 22 +++++++++++
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  | 38 +++++++++++++++++++
 5 files changed, 79 insertions(+)
 create mode 100644 crypto/asymmetric_keys/tests/Makefile
 create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
 create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c

diff --git a/crypto/asymmetric_keys/Kconfig b/crypto/asymmetric_keys/Kconfig
index e1345b8f39f1..7a4c5eb18624 100644
--- a/crypto/asymmetric_keys/Kconfig
+++ b/crypto/asymmetric_keys/Kconfig
@@ -104,3 +104,18 @@ config FIPS_SIGNATURE_SELFTEST_ECDSA
 	depends on CRYPTO_ECDSA=y || CRYPTO_ECDSA=FIPS_SIGNATURE_SELFTEST
 
 endif # ASYMMETRIC_KEY_TYPE
+
+config PKCS7_MESSAGE_PARSER_KFUZZ
+	bool "Build fuzz target for PKCS#7 parser"
+	depends on KFUZZTEST
+	depends on PKCS7_MESSAGE_PARSER
+	default y
+	help
+	  Builds the KFuzzTest targets for PKCS#7.
+
+config RSA_HELPER_KFUZZ
+	bool "Build fuzz targets for RSA helpers"
+	depends on KFUZZTEST
+	default y
+	help
+	  Builds the KFuzzTest targets for RSA helper functions.
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
index 000000000000..42a779c9042a
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/Makefile
@@ -0,0 +1,2 @@
+obj-$(CONFIG_PKCS7_MESSAGE_PARSER_KFUZZ) += pkcs7_kfuzz.o
+obj-$(CONFIG_RSA_HELPER_KFUZZ) += rsa_helper_kfuzz.o
diff --git a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
new file mode 100644
index 000000000000..84d0b0d8d0eb
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
+	KFUZZTEST_ANNOTATE_LEN(pkcs7_parse_message_arg, datalen, data);
+	KFUZZTEST_EXPECT_LE(pkcs7_parse_message_arg, datalen, 16 * PAGE_SIZE);
+
+	pkcs7_parse_message(arg->data, arg->datalen);
+}
diff --git a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
new file mode 100644
index 000000000000..5877e54cb75a
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
+	KFUZZTEST_ANNOTATE_LEN(rsa_parse_pub_key_arg, key_len, key);
+	KFUZZTEST_EXPECT_LE(rsa_parse_pub_key_arg, key_len, 16 * PAGE_SIZE);
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
+	KFUZZTEST_ANNOTATE_LEN(rsa_parse_priv_key_arg, key_len, key);
+	KFUZZTEST_EXPECT_LE(rsa_parse_priv_key_arg, key_len, 16 * PAGE_SIZE);
+
+	struct rsa_key out;
+	rsa_parse_priv_key(&out, arg->key, arg->key_len);
+}
-- 
2.51.0.318.gd7df087d1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901164212.460229-8-ethan.w.s.graham%40gmail.com.
