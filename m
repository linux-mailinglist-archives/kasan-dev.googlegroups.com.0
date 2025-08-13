Return-Path: <kasan-dev+bncBDP53XW3ZQCBBZ5K6LCAMGQEFV3QFTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A0AFB24AC2
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 15:38:48 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55b8085bdabsf3570493e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 06:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755092328; cv=pass;
        d=google.com; s=arc-20240605;
        b=H9UPL2luvwXTE9uxzmVKAR6I3kgxhKWQwKp+0L6rEhxguGqB94UgQxdZAtO1RrfEQo
         pQVGh7CJ4r9C3dhAsLqwkfG9zZusGLYIX6JQx3YAbmn+hexkdi+P/LqTQsAZUyxbhVMV
         kg1jHr2z95J4xtV2T8VWU57CB5NgF7qPGTJDi2hodVFjmOpKcHkCMIIrU95IK8ZzqtSN
         YBPAltNKE1+/+KFBUVDnjzElB1CFj+qiM39yINbiUt1x8dgOm7sZk5r1iu43H1E1X3hV
         e+yBUpLuCXOR4JX+MmK/5QBm4gMVDHrBDRaCQvQbiYe0uDggA7WwM1qePHyeEZ7x4m7u
         1dmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=AmGYgt9M8shR9U8W7ikJOEKm6Yss21TfxuKeDbtJpb4=;
        fh=5a+UPNapmz+9Egea9s272Ofvne95S/EN5T+FuNux+TE=;
        b=isOBMklhFXuEOxv4XuVE9SLxcC/q96SMbTX2hOE/LcWncDOUUAav74xFmJIo2zg8GH
         NUQvyLCUbxYfRXwykfd8Oye1s8PNaNINtrlHbtI8Zy5FDWDdfbG8o6jic61Z5ORu+mSY
         kUy6N907VktL2mtTfkJppYau+8xM/zErcrWF31dXpY+a82DvXK52Qo5zJRzvq3EvndLw
         2SiXaq+p1LA9H8yrz7XHDMu+jYnVZKZyNjU2FUuMihOphYU2573mGHTNxCRWWz3Sx5Mn
         71x+ivZ/VjaHtqoUkQqBxbxf/0zBCmkEMiI2eMZMMEriVMsuF05qsR0Uq0MwNTvKDTXN
         gfIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ftiX63k3;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755092328; x=1755697128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AmGYgt9M8shR9U8W7ikJOEKm6Yss21TfxuKeDbtJpb4=;
        b=FCw48cWktXsvb7F0mVHWbfYS9NZUxRpi3dhkBMfB278LJO1MqJ93UdtTfaFSwe/xB4
         G76vFPTjxiRpkyMTI/siNMScaIoeeM1n7X4Hkl2gShG8KB+u1iq/COEk3aYAH/wfzGce
         He4FQKVZdRipbT1Q1b00EFcq0j/c2xeFC2AsBPkHXVRGpcxHwQC3uohwDkrSJR/JcJXM
         hzNXm6mC6VoptdjiB/Gg2MG4tXpeNM8eVxxpEYYZg85geenkr7UUZinUaXtbR3o0wXQ1
         KNG3uKMCVqHtzP4xO1UHQuB2DhhszOrrdKHMt5MdBxGLKV7BR8qR2vqOaj6VoP6jLvpH
         fxEA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755092328; x=1755697128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=AmGYgt9M8shR9U8W7ikJOEKm6Yss21TfxuKeDbtJpb4=;
        b=DfNhFAjxCe/lvSmftTPje/mebfvyI9kRmA6/ZPVoDFrYGpE17vHb0SJIpS54zXGzOw
         /po8gvjLdpm1zx1MNUwMLywdbHss3cVBOdGPw9wJhOFq+LXYuq0E40n5OqQAdFNBx0JO
         YzIr3Uz8bdPBzwhurY3p/dJPOMF+ch0GtcgsZsFDM8hQQxOlnFcXU6Aj4igQ1JkP9PC/
         4jncottZ5+5M3zjGnvB2o3Bi7yqEZnMlwr6slz0ig1snHzNWzyujAL6x4giApMMMt5so
         nfiYHzrGY1pPyPnzvY8RdnNAnpO9fdQnnStl45b83FFTnEI4HIWiHs+IOl2yjd2Esb9y
         db/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755092328; x=1755697128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AmGYgt9M8shR9U8W7ikJOEKm6Yss21TfxuKeDbtJpb4=;
        b=qQa+ErV39/iHchdeCx4ppdCHrNPKRXjY3hg+lKPA0Vja6ZePRFLA+Tba2FRiaxFqiS
         G/OaIaKQs2z+dKsOFMfXt/av8/G3lBIVBnSblQpSN+EPK8tLJCPxwdl6fn1CUEx9J5Ye
         AL9ZJ8laGx3/xZxTWQ3hAP7h2abDxz6dnMDyWR/ZIM96PxClHdcNjLtqzOpc79hBWDnK
         /BsDcGxvzgJ7XVWGxnk24gnR83s2/3uJz0V4YJadcGdDV4R2xGAlDlfJft3T3X18e4I9
         DFOUQX/cEjWZIZ2NRSpktGAMslc0fkcx4c23/j3gKBtCwpvtTkmVAfL+FHfqyO9qbf++
         obow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvcqAF2lKbRRgHcKqN4+OnGnTTeI4nB8X4CevIC2tF9sKJyz+2hHc9kyVbO9t/F82Don0Qeg==@lfdr.de
X-Gm-Message-State: AOJu0Ywz9ZO1rDWZ+RTSA9Ypll2RascEoP3cfzWM+W9+gqr4BLhyljpS
	uorlUOadUOcf3/zKth2SONEs/8QcIMeC8FOIOOnTJqSzSA2kCY7djaaM
X-Google-Smtp-Source: AGHT+IHEuHKMxEmb1rKAA6Wt1XSxhPZ+sYaM8vc1V9xswP0zDOdWpYAcr+bVi8dbTZqoEpx3MFG4vA==
X-Received: by 2002:a05:6512:1195:b0:55c:c937:1106 with SMTP id 2adb3069b0e04-55ce03ac359mr967263e87.28.1755092327671;
        Wed, 13 Aug 2025 06:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcFGLIR93gMAEepCjD8p2SgS5JSwuIC4QhF8FiXqEQlZw==
Received: by 2002:ac2:4c4a:0:b0:55c:d705:e00d with SMTP id 2adb3069b0e04-55cd705e2c2ls1203380e87.1.-pod-prod-06-eu;
 Wed, 13 Aug 2025 06:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPJFXs8MuG3PCZO0ygS7g/Qq9Mu5gKDo3RlC1DaRpc0955Glz0i6K9v14W6BafjcCKc/9H5/qg1Vs=@googlegroups.com
X-Received: by 2002:a05:6512:239f:b0:554:f72c:819d with SMTP id 2adb3069b0e04-55ce03d9cb0mr1030149e87.43.1755092324458;
        Wed, 13 Aug 2025 06:38:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755092324; cv=none;
        d=google.com; s=arc-20240605;
        b=bPv1ob2LNILP6YvIVnPYsLo29YJRfYhsGto9Jm8PAeMgIME27DiJACBj2qtf65x7yb
         /HtNeP1gi2vir+hPOI2nPLTQajlFZDeSDrSwcjRwoQm3mEexcZycl+NVVJr0ZJnJayMK
         JMCSIEC9VajN8Qstw4HRWeuFBFixwEHwWX2hpgh1J0UTFJb0RCRw+utQW/hNej4egsfk
         PdBWiVCyYfvccXKLEyNUktxb1MdQWk+p4lt7hBQ98XGozmFAzb0I3F4vjYpXEucHspiK
         fmY6o/w58KF+YmuLNnpQMTxvWGnHB/SIpWKKDqBH8EwUciwa4bdq5OZRHdzMyPWcNIpI
         mFCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WCmoTAq+24iKRI4CSHEBG8UaeJTBmRNFmOmZvFaISJE=;
        fh=P66GR++itSAHfxqSoXE29IJ3QZVUMsOERrtxDe5FHyY=;
        b=J+A4styIhim09RIZITgRo70rVY96loQ4KeYRK0t2oPIBM5KkJifbEFN6SEnTm/C4hN
         PkVE+1VMFVDgsPwp8dyfG7JXR9eZor37PFY0bxeo96sPzWwASH+htY8V8uc7fPR2msWu
         v4iFENVJatSZPFXTuwNd2TIH8Gh9AbALipteItzDvWewYf7vw5Gotxyfjp7UEwCXhm3H
         3UVOUbHqn3FyPlAw74x9WARZUqz3rLaAl0us+fmCCfiGkWAvCjtU0tjfGztv/q9gcEjA
         5axvN1/fv3XrjlhlS61Mjl+M6iC0bJlLMt9xTPf4ni6PG53LccjTFQPw16STQkBIk/Db
         PpcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ftiX63k3;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b9a222e4asi711427e87.5.2025.08.13.06.38.44
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 06:38:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3b8d0f1fb49so3882802f8f.2;
        Wed, 13 Aug 2025 06:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW5PuRtEgLS5BD29FOMUbX7tSwSxO7MYki5L+jDY7mqaOD7kT9Hf6Q916wd573nFgs1e3eJx23BosM=@googlegroups.com, AJvYcCWYxIlwwmJ2eStom7cUBBTuuYDkfWhaXW/iGgCGjUgHnz28HUiVUpoY1omnckh95i5A1J+qIPS7qcA4@googlegroups.com
X-Gm-Gg: ASbGnctOUdElP7QoIB4WwCTWpKo7ptirxmOoPWoTIbzv0XKXO/8x0FbaAEhTmmjliPV
	cFBM5yHwFFdjRwvemC1xAACy2bUWmWBI2E0nFHnFUupobzq3izSgrWEZ7kCwHfEkFyYG19IE1RV
	JMQ/3B6xkzNo5bbvBZ/IXBUt2D6XC2HGlwPx2obf0iiQJ4jWUdPILij7E+Wv9uTqJZkXYRqRIoo
	mT1Rj0V8JPsM+Tx7a3a2IdFXR8w/CkFMqb9uSaLB36nxoW+zTmrBNDjNN094pGKQiL2Irqs9za+
	QLKpxYDpPaGHNVxjktNeSqJkop7sIleeaWM75S5p+LbTepMvZKcCtAsr6TzEZEoc5M3tyL0PKh9
	yiwUwB4q7/Np3G3kqWWzEBgAKvYwnyae2Cs5qjesshetpNkCIz8oIrpfsNDXuVMwBzSIojWUMI6
	Ip751mCCRt7RLC/k4tp8dacSdITw==
X-Received: by 2002:a05:6000:4308:b0:3b7:84fc:ef4c with SMTP id ffacd0b85a97d-3b917d2d303mr2420863f8f.6.1755092323832;
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (87.220.76.34.bc.googleusercontent.com. [34.76.220.87])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b8f8b1bc81sm25677444f8f.69.2025.08.13.06.38.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
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
	linux-mm@kvack.org
Subject: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
Date: Wed, 13 Aug 2025 13:38:12 +0000
Message-ID: <20250813133812.926145-7-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
In-Reply-To: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ftiX63k3;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
interface to fuzz internal, non-exported kernel functions.

The targets are defined directly within the source files of the functions they
test, demonstrating how to colocate fuzz tests with the code under test.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 crypto/asymmetric_keys/pkcs7_parser.c | 15 ++++++++++++++
 crypto/rsa_helper.c                   | 29 +++++++++++++++++++++++++++
 2 files changed, 44 insertions(+)

diff --git a/crypto/asymmetric_keys/pkcs7_parser.c b/crypto/asymmetric_keys/pkcs7_parser.c
index 423d13c47545..e8477f8b0eaf 100644
--- a/crypto/asymmetric_keys/pkcs7_parser.c
+++ b/crypto/asymmetric_keys/pkcs7_parser.c
@@ -13,6 +13,7 @@
 #include <linux/err.h>
 #include <linux/oid_registry.h>
 #include <crypto/public_key.h>
+#include <linux/kfuzztest.h>
 #include "pkcs7_parser.h"
 #include "pkcs7.asn1.h"
 
@@ -169,6 +170,20 @@ struct pkcs7_message *pkcs7_parse_message(const void *data, size_t datalen)
 }
 EXPORT_SYMBOL_GPL(pkcs7_parse_message);
 
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
+
 /**
  * pkcs7_get_content_data - Get access to the PKCS#7 content
  * @pkcs7: The preparsed PKCS#7 message to access
diff --git a/crypto/rsa_helper.c b/crypto/rsa_helper.c
index 94266f29049c..79b7ddc7c48d 100644
--- a/crypto/rsa_helper.c
+++ b/crypto/rsa_helper.c
@@ -9,6 +9,7 @@
 #include <linux/export.h>
 #include <linux/err.h>
 #include <linux/fips.h>
+#include <linux/kfuzztest.h>
 #include <crypto/internal/rsa.h>
 #include "rsapubkey.asn1.h"
 #include "rsaprivkey.asn1.h"
@@ -166,6 +167,20 @@ int rsa_parse_pub_key(struct rsa_key *rsa_key, const void *key,
 }
 EXPORT_SYMBOL_GPL(rsa_parse_pub_key);
 
+struct rsa_parse_pub_key_arg {
+	const void *key;
+	size_t key_len;
+};
+
+FUZZ_TEST(test_rsa_parse_pub_key, struct rsa_parse_pub_key_arg)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_pub_key_arg, key);
+	KFUZZTEST_EXPECT_LE(rsa_parse_pub_key_arg, key_len, 16 * PAGE_SIZE);
+
+	struct rsa_key out;
+	rsa_parse_pub_key(&out, arg->key, arg->key_len);
+}
+
 /**
  * rsa_parse_priv_key() - decodes the BER encoded buffer and stores in the
  *                        provided struct rsa_key, pointers to the raw key
@@ -184,3 +199,17 @@ int rsa_parse_priv_key(struct rsa_key *rsa_key, const void *key,
 	return asn1_ber_decoder(&rsaprivkey_decoder, rsa_key, key, key_len);
 }
 EXPORT_SYMBOL_GPL(rsa_parse_priv_key);
+
+struct rsa_parse_priv_key_arg {
+	const void *key;
+	size_t key_len;
+};
+
+FUZZ_TEST(test_rsa_parse_priv_key, struct rsa_parse_priv_key_arg)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_priv_key_arg, key);
+	KFUZZTEST_EXPECT_LE(rsa_parse_priv_key_arg, key_len, 16 * PAGE_SIZE);
+
+	struct rsa_key out;
+	rsa_parse_priv_key(&out, arg->key, arg->key_len);
+}
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813133812.926145-7-ethan.w.s.graham%40gmail.com.
