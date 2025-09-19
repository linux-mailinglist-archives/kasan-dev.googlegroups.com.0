Return-Path: <kasan-dev+bncBDP53XW3ZQCBBAG7WXDAMGQEGGGFOFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F9C5B8A1FA
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:09 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-36412b9b157sf7556951fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293889; cv=pass;
        d=google.com; s=arc-20240605;
        b=g9QsqTF2Vg4373rPJKIon3PfuxBKcZqHfFnmDYqWKoI3YPQVkFUm3kxcCo0eEHBBPT
         TQsv1TF4bUi6Bi6IF+2wL2dNXXmbXazd1vp7QGt7jv/SnwThjyhZicK8RUSCtB4zfN7m
         kF+FQBmJJm8Weux2uncKSU8mzfvXkcIrbEMquO+Cg54Ru8FPgNVHcV36m0Jxw5AB8w/y
         CyrXG9FPZfllDwJV51Ye0t1iNg9EtR28grKvV8ROEf5hl+y9rG1sHcHH3MJf8Uo0Ry3Z
         mbUdiIUDpsTHorumGmFwxraF2cLfheqQWUmgphT4kf+hDIAx29+94WIcG4YbtrpKbRmu
         sOqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=6umiYKYKEZDT0lEWLbZZHDQMVIO1UULwPEwLignwCmU=;
        fh=bjh3qaOWgXGCWIGliyGciIdQOj3ALfPcFXFhpIxUyX4=;
        b=Xo1JGK0wGCdAHaAlHktLdAl83en2IUTnCvMc66Vog8aqNF9JsZu99AH9Woi0BxWZBT
         b5/PSICkdvN7UJU72C8vqwxgtnnveq/ePOM/aExNzhmizlD+5yJk2ubuVF1TjXdXp3sg
         NlRa5oDclowcR89JgKa+9H1Sq3lRLb3aAdPhl/inXHOXVHnTTKpZIKetnWK8oEN16nEN
         6MuZPhDIxFHR/hLBiI5j0dyj0F+kGKZ5eyuOW5Vxm4ZJnK1lTrUVoONPQZzO5Npqg9OP
         alusTxkZDcaYevbsAMMVz/r4jc/ku2NUau5mMEtEj5Fc7G0LEemfcZObuuBSGKEkXTlv
         wwxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Nh1pXJpt;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293889; x=1758898689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6umiYKYKEZDT0lEWLbZZHDQMVIO1UULwPEwLignwCmU=;
        b=IPboWgsPqFdwkbodo47GbwfehKASAXPWj7Kx+RWfQVat/Mk8AVR1M2xxHMbG5lv4Ga
         PWKGwwaXqc0gr1Fvkd1vDQ0IIKbDBWk5AxVY8Rf57hbYK3PkIL2T7rfMHHzXi4ImOjqn
         XNtla5Zl8lumRKttabo456ZE+QqneyfO7xf54xkx2XQIvKAU+5xBSC3UHAQnzLYvJQuT
         8ZO4aPV2eb1r/LBmhxJ2Bpp0yRr/tqpUTXYVsXrCJyZU/19WS7dqtqzj9njMLGNw+q/M
         sWTwDLv6zQSDScEHK0+JTTBYMP+fLeLtvn/GpPLmrXYzynkllnIm5jIIR2k5qOwPdyfp
         NjWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293889; x=1758898689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=6umiYKYKEZDT0lEWLbZZHDQMVIO1UULwPEwLignwCmU=;
        b=SF17m+LjbZXU6mHyiZ5RGUFj3QMBHtyvrJrpHXM1uzdgvjy9qzFq7GcT4NrjgAlkKm
         XmJ7WyjZceIbLvfHFzQPrHlcHQHnRRuVE0Kv0bSvrEyTzGJ6Z0/x/bUrKVz9xk86vYBO
         +DwrhhlOwU1+xdGqwIqu+mn/8ctugD7y5jfvG7NJKVVmxKOOJ9L7RsP7a5QAia+jADMW
         A3h/4ZAwCbNdaIbPBiun008cRng6+L5P8uw6pFn/AGHwQpwl9LyWbaFxyUNCIaaXz2vN
         z57I1FSXq0CFq3jEerKFAOHUmoIjO+MPsY9DX4mfOqmgmm2lVpROmH9b44owQFwrDdSf
         lM7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293889; x=1758898689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6umiYKYKEZDT0lEWLbZZHDQMVIO1UULwPEwLignwCmU=;
        b=v2W4UiEirsIYpdpHetjmiRfEV0jE4t5LMgVYMGL4xxLvHqEyAPit5uKL3Ax+y9ZURs
         R8S12G+NNqNNNUrMD3Jh1uUyEfXb1g1UsMSCCtXAzYsjaG+ybuLl2H2toH2V9Z/Go0mh
         yNIjituRVYQ91sgNrTcJlGMSnHTA9njxWCSXjNNEBbxdcuq7gXNr8U1Ql4QnwAuIKuMt
         DBC1F3fBjmexXU5CYd3rL/9TgenHK8+XGFgCfJiGDkdjx1bpsN1hXa7QgcqUytav5zTM
         naE3BEubbh0AqbekKNvV17nm8h00HxLnxZVCvFKEHsxvD/Eu4CC1WsXDFP5vXFmtLE0e
         6r9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVfytq5mtqmvor/yr8BR96cI2f1KPzkptqEiHLA7nmPtFbCTnka3TPvqrbWiPGq33WeCrwWhQ==@lfdr.de
X-Gm-Message-State: AOJu0YywMkH7zqQPAPjRrPC5/Dw0oUbdEGYmZUP5j5P6IsV2enoknhDN
	9pEGaDuhiiHQgGWR+GqCc/sMtqGAm7EhcEvaTChGvyQk2hq8zMQFS9yf
X-Google-Smtp-Source: AGHT+IHR079NvVHTWbrXtyANuuqJiVEqsFr1h9izCUb9tSHQ1nqIRnYBINGja7zKZtURhcVALdR3zw==
X-Received: by 2002:a05:651c:25c3:20b0:338:166:6b87 with SMTP id 38308e7fff4ca-3641822524bmr9697871fa.35.1758293888758;
        Fri, 19 Sep 2025 07:58:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6/2HuMow85zvxnCjIetraaxcrHXTscpzXpMLhE/C+5sg==
Received: by 2002:a05:651c:255b:20b0:336:c2ac:cd28 with SMTP id
 38308e7fff4ca-361c37eaef6ls5418791fa.0.-pod-prod-05-eu; Fri, 19 Sep 2025
 07:58:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN2gWZcHszweNZuQ7pzmKRahaogJlwa4+iQNt+Pc2cd1w0czd40JtQvTxyp3s9hZaa2aQb7Y7AXys=@googlegroups.com
X-Received: by 2002:a05:651c:2221:b0:336:7747:708 with SMTP id 38308e7fff4ca-36413561e63mr10066451fa.2.1758293885698;
        Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293885; cv=none;
        d=google.com; s=arc-20240605;
        b=ikX5gyNzqQMQFtr1kzmgX0j9joZWEME11MmJohV1eBFy5giRycnp3r4f5MfuyAKRzb
         I+wtJXrXBnzc7Xcp3ifUAXGoSrSvdjbYVCgZ7TQ+sLZ/rq6kxxpv6dDXqLKW0we8UVOR
         /pCwnHKMBxmx+7CCC93qluBWz5m08Gpv66A6QbtlaS3FU1jWDVFLx/R6B5nikd4K9ybO
         tSz8nYB+Q/y2s/E0GqBQL7WPje457Ip9pIGpx7wys6Cn2BuYRsNGk/iX0ZRwL3Sb/eDq
         DWv6OqamuEKD/QvigrjybfRfOwRxmKHoyf1rHOLx9+tnvEI61bsdVt+FEIvUlR6+2KpN
         ZjxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0kKd/JXPbzTz5+ezoQ1J+mpBYdbScAPUDVkzXIQoH/8=;
        fh=ixb+TM4aD2Yud7qjXIO3NSvW1bRcmw7hE4j9qerOoe0=;
        b=JGp3qrwzZLwnujbcEw5AGuk46DjbhxBU3M9ZBMdqcbWIvgVtDH6QvdVamFQDQ/0pCC
         lZ48H3PNKDUD2ZalXAUvmC32971YZ3sPRFlMehNtxiAO92e50TiykLOEU72nIxtYld4J
         O43wB87lcYHr6A9idn6BDWdMIXcor9SadJMg8bZPDNP0vRuE6d1c7XpjefSs6YJ10ezw
         8jflv06VNQqday9e3D6XU9tS80d4YtkB1piMPvvPpzMUII0qriE/v/xsJELEocEY1NKo
         V9fQ+4xhi2RSH+tO7Qg5cyLRodYG4Ho0VtbL8YsYREcsucSOm0wy5Jk2zeSruoMmy7gQ
         ENCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Nh1pXJpt;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a62c8ff4si991651fa.3.2025.09.19.07.58.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-45f29e5e89bso25362575e9.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXGHv9e61BjTpHrmLev7VeFVJVXApiZ665F9zTO/wSjJGtTTPgo8zXQzp294uzVFSc8/P5PnycE9UI=@googlegroups.com
X-Gm-Gg: ASbGnctT336N7mMrh6AKAs9gkqb1+Up3avDMhrjpotvcI3LbOjwnfz1rJTaclBaK1rL
	ZHIw5EnpPhiRhAyg8OmISxQPy5zE2XCnA+VrWAJfvd0qG2VrChRUOBXl8IDp4FrgAYRjrIPgTzN
	xssbSnQmYti0SPINlMEqMuiO6JQ6URX6jxG/gtIS+/5/rW+n4dvnV0ulcGdt2qcS2ESY4xfHK2Z
	hX8CiOaxJ7KN0aUZah6+19N+fcP9z8sk2Nyi+JyxtJXQTLzAjRbhEoagaLDdyi1OHkVpBhOix5g
	TRO/8l7s/AHDcSA1M3lyImrvjz//ycwKTY8neJKekgukoCWZ9GxpGLHJvkrWd5s5nE3/MhC0tCy
	Knw2wBcWcmjmDej1z7IqqjsxZM4XT40MhvFIHmU/2GI9zS96TjcnmKPT3NYXZDF/U0apH/yItD1
	i+vUWtxJ03GWULDUA=
X-Received: by 2002:a05:600c:c4ab:b0:45f:2919:5e91 with SMTP id 5b1f17b1804b1-467e7f7e36dmr43014905e9.16.1758293884348;
        Fri, 19 Sep 2025 07:58:04 -0700 (PDT)
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
Subject: [PATCH v2 07/10] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
Date: Fri, 19 Sep 2025 14:57:47 +0000
Message-ID: <20250919145750.3448393-8-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Nh1pXJpt;       spf=pass
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

The targets are defined within crypto/asymmetric-keys/tests.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Reviewed-by: Ignat Korchagin <ignat@cloudflare.com>

---
PR v2:
- Make fuzz targets also depend on the KConfig options needed for the
  functions they are fuzzing, CONFIG_PKCS7_MESSAGE_PARSER and
  CONFIG_CRYPTO_RSA respectively.
- Fix build issues pointed out by the kernel test robot <lkp@intel.com>.
- Account for return value of pkcs7_parse_message, and free resources if
  the function call succeeds.
PR v1:
- Change the fuzz target build to depend on CONFIG_KFUZZTEST=y,
  eliminating the need for a separate config option for each individual
  file as suggested by Ignat Korchagin.
- Remove KFUZZTEST_EXPECT_LE on the length of the `key` field inside of
  the fuzz targets. A maximum length is now set inside of the core input
  parsing logic.
RFC v2:
- Move KFuzzTest targets outside of the source files into dedicated
  _kfuzz.c files under /crypto/asymmetric_keys/tests/ as suggested by
  Ignat Korchagin and Eric Biggers.
---
---
 crypto/asymmetric_keys/Makefile               |  2 +
 crypto/asymmetric_keys/tests/Makefile         |  4 ++
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    | 26 +++++++++++++
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  | 38 +++++++++++++++++++
 4 files changed, 70 insertions(+)
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
index 000000000000..023d6a65fb89
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/Makefile
@@ -0,0 +1,4 @@
+pkcs7-kfuzz-y := $(and $(CONFIG_KFUZZTEST),$(CONFIG_PKCS7_MESSAGE_PARSER))
+rsa-helper-kfuzz-y := $(and $(CONFIG_KFUZZTEST),$(CONFIG_CRYPTO_RSA))
+obj-$(pkcs7-kfuzz-y) += pkcs7_kfuzz.o
+obj-$(rsa-helper-kfuzz-y) += rsa_helper_kfuzz.o
diff --git a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
new file mode 100644
index 000000000000..c801f6b59de2
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
@@ -0,0 +1,26 @@
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
+	struct pkcs7_message *msg;
+
+	KFUZZTEST_EXPECT_NOT_NULL(pkcs7_parse_message_arg, data);
+	KFUZZTEST_ANNOTATE_ARRAY(pkcs7_parse_message_arg, data);
+	KFUZZTEST_ANNOTATE_LEN(pkcs7_parse_message_arg, datalen, data);
+
+	msg = pkcs7_parse_message(arg->data, arg->datalen);
+	if (msg && !IS_ERR(msg))
+		kfree(msg);
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
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-8-ethan.w.s.graham%40gmail.com.
