Return-Path: <kasan-dev+bncBDP53XW3ZQCBB7VNY3EQMGQEUOEITTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 185EECA3F5E
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:20 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-42e2d5e833fsf567338f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857599; cv=pass;
        d=google.com; s=arc-20240605;
        b=VqDg5DLk2g6uqTsNldheXS6IGzL5Si6ebgw4VYydwvI8WjyeJIaHbQuJTTZpf7AGPY
         U9PlibcZ4aUOaE2PCwrOHo4WHQDFw6iGl6RQt8xKAjr1S7ouFc3ySB2xLQC4oshLeFuQ
         SCf1ym5TVo9Oaj4AhFuH29kbn+7Jyzgl0kb0Jjl9abqL7fvMmGLmFD2UCp/Aa/sA0v5y
         bPbB2nq7TtNinLl9pHlrQZxaBbh7lQKygj/AFnQ83FTpnKp+iDmoacDtWteCDaGqlMX2
         n77bQif5JM/UxQgkG7axK54rCKbT1Ky+7MZmUqH4wkSVKhLWVVaB6MxejLly10NeozT3
         2ESg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=nvFEzFlPQn1yR3knaO7jysHi9Sdu6G77SmqUrgRK1zs=;
        fh=ljNJ2uSqRxCRkmsUvOW4+FFFcOeevmWYhPMD5OcE+i8=;
        b=NdTNRqy2AGpuyxlY8t5ueZW60t2U3Nn7qLhauHd5WK7Jmgvq8VU8+qbNaRBYXp91oM
         9Gru/wFqjVqo2f+Nuh1vf6zImRqZOZdnfsypxGk8r6C06tTGD6eC9c1onPOD9JrBTG+0
         yNa2sOGWCs2a1ejaG/TX+71HyICFvIV3vtVS4LGw/GbBa6bvcRJywRC3f5nVXWqmrzaS
         NpBtidQcjDPGNurUtMgJBvsUWPB32uEpTGNksV2q68HS9J3pVuZlYvWVoroFdfsjNeG1
         kIOzmHE1xUdI2Ub3s9jtmy3iatEtPfnL5coId1DOe+51tSRD/9+TOM8AaH1wTJW8jS9Q
         7lcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WF8jJDzx;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857599; x=1765462399; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nvFEzFlPQn1yR3knaO7jysHi9Sdu6G77SmqUrgRK1zs=;
        b=xMkf3OTF7mWglsPZQEFdXH20jJEt1vVzN/ia44CEqnlgCbzMzGWmRFBpyROqvSk1oG
         olkhXawSfmbBTzb6RXpu7GSn1fsWE64BS0jSK0aDBkHOZ41GMGzpnf3VmKk9Is1/3/a0
         9KYfkz0yGpLbjyoXBlvPuGRjJTWrTNZHOOQlS6J0jw99kBDFQ7YoNoWwCPxzqT0l4IbM
         JVcMDzso0RRgeQl5VRUl4Q8a33TmuKlwAWFSGrlgENCIyHgUlhQS7R8r508D53XLcHaJ
         p6AFCQc2oSmyGcaBzb/3qifte0WkFAQ/7cdsMpCs+rfMfVzSnHG2/KCGdR/gGDcmor/y
         tkqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857599; x=1765462399; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=nvFEzFlPQn1yR3knaO7jysHi9Sdu6G77SmqUrgRK1zs=;
        b=ls4B+B5QARKZjiBG+nYhuB71yZ70HmqETHK/QYBFNYJh2KvbzZuFh7BT9DGgvuRzrf
         cHO4AKgoGyX4P4NfBT9ddERAarsATFdGclddsebLdWk385Vk+F7KYHPa849AYhsSdJHU
         vCcV/itbQvWzbX/g+4XFifm/2TmpV9JrEG1QWIDEO6TS3M+zgxm4lp70K2pu8m5rJr8D
         eAnCeMZeF0uskCgUrIsabRf4e2O2AaHkQByOsJU+l2CizwkPRShzFvtzP+MlvomOvAnN
         Smbku7CMUAy52KKHUvEj9kp+G/aY4a3EzDufbnctH7gesvZDOBrDEnRgQSYkjCLCx/BA
         S/Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857599; x=1765462399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nvFEzFlPQn1yR3knaO7jysHi9Sdu6G77SmqUrgRK1zs=;
        b=v28Gafq20kCtHuCKlikrT8J4HjaHXOLgfobkFh9p7L8k6XF0idG7uxRGcglN4FTk9v
         QwVcVWnF/OMsTVnJx9oCUPfUdN/k4xnt1j12Kgud22O8zveNf7OlGfgcBjeTA0Re12+p
         xtCaOecLs8sBC1ecb56FhaBWn+5+F9+yOZFDz5hfViO0l4Sieod2JzoeNCgbVh4HivwH
         cKyliaDqSit2eTcS/Qj03J9/Hnm/OXB1h6gl90NoYepdyZs92oEDctSG55FYZ7HmXBVD
         ooFylu6tMnGuVEP0fUnNQzA/YlV9bAWuwglZhP/9YKjVT1PXJgdJcxYrLXQVFUmFZKb/
         IFfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4OhI2gl8CON6RCoxV9OO36chSGhbo3TdZ+l+dPgb/Qu5E4rfC2tIbnA6q01WqgTWmHseTig==@lfdr.de
X-Gm-Message-State: AOJu0YyfBNY5iA1DVB2jTlzmE9v8tgdm+1h26kUJF2ZtDlumXRscCo1P
	46jRAkpox5UNFSagdd9ma0IMXSpAoUZHeC3Fpu6ePnFZB346GLVqEsTK
X-Google-Smtp-Source: AGHT+IHNmC0Fo7ObFZnEHIXWrzd1OyMnsjrqYflAY4veJOchslweOYAcluLs42PzKJNRMDnS4oxd6g==
X-Received: by 2002:a5d:5e01:0:b0:42b:3246:1682 with SMTP id ffacd0b85a97d-42f731963cdmr6515094f8f.16.1764857599465;
        Thu, 04 Dec 2025 06:13:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ag8cvVfS94U4VMyCRHy/2XWv540zFzz/n0GQ2VWleg5Q=="
Received: by 2002:a05:6000:2583:b0:42b:52c4:6656 with SMTP id
 ffacd0b85a97d-42f7b2f4272ls450421f8f.2.-pod-prod-03-eu; Thu, 04 Dec 2025
 06:13:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWB1i5BrhUNUV3P30hMz68iI67UJA7Tldgl14Z1JxP1xa63W8zP59YC41VaQfM0BU2Fv9eKpoG9aWI=@googlegroups.com
X-Received: by 2002:a05:6000:430d:b0:42b:3ee9:4773 with SMTP id ffacd0b85a97d-42f7318fd33mr6875981f8f.7.1764857596617;
        Thu, 04 Dec 2025 06:13:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857596; cv=none;
        d=google.com; s=arc-20240605;
        b=WRtYv7+Uev5mEY9i/dy/nxoTVYMuU3sP2fsoEW2OmbwYCSFgF7cSL9t5J7+T1dSMfE
         V6FRuTulv3UlrF8UWyxgMOVZOH2WAYjLWGz96+xpo/C/ptmFtDgpjpXrtFUXjzTAm7OK
         3CILZsZ7SpIXtzfKrFNiG88ucESUpPIQbGy0b+E1MdVEg4hUG6DWUcrLYwwsItfhek3Z
         XcbYSnND9870OdFjgDM8E98AmhqF2pQNErB1zMV+Yaa+Ogug7/s+q4VuUYIkyabfp79j
         g4Szm7Jjh8LgEKQI40tUrCl9rufuCnkfqgMGc6FayHCThMlwxK8ok0tMGzvFUHzv2nY9
         Qv8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RabXc9ZxWPd5N856tl6EMMSdBPz7PelUrbPrIKztc18=;
        fh=mhbcKTRUZVnkoPAdY9QAA9t6ly/CDCj3rNdasJDMQ1I=;
        b=OZ+51m4K1aq5EYRI2fyK7kFaLV32P/XEZ+FfcCR+p0d8nSnRnmjk0XiAO9hdiz+QAF
         j04RWoJxEQEPIVPQc7xIZeW8NArgT+dUWO6gZn9vnf4SWLaJcyBcE63MJ1BDFVvKXCzb
         +IM3NpLB2iDzPMltdToFIBi/zvB6yYDz1L6A5nuMT2SObpdIfLmrHqnBGgMEjPxvL9mt
         eOkSincx5ydN79qQrbyuifX444iyURsmR9+wYrmBoFbic8XLCmDDF+YzMYRSHpzh1IFU
         jTW7TmhpiA6G4dVikpZmCmI7KsMHNePlTEiGCiEfw7MBv3ILBaheC3c0vob1hgKGTxbL
         FSDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WF8jJDzx;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7d21e315si32704f8f.8.2025.12.04.06.13.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:16 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-42e2d5e119fso486361f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX/JGoeTV0Y937YkbX0omuZZ6aJX+n/huPfQfeQyLxCimPJfnTQ9l5+tkFCwUmFLVCl/QMbFyUnhJA=@googlegroups.com
X-Gm-Gg: ASbGncuPzZU6+D9mUUkMViipI63uZe/swnQb3rPfrkw29v5vfDztNxNJdkegqgIMt4O
	mgGG4zAPc8mzDcYRn6I2WiFbLkyKo4DQBdrxrKU8USWEig2XYvI8588YzE5dN/4QL8/GO9wx3nx
	gcWQ5p11DzZM7nacsH6sUPeaACdpxwqFLACubcFOsBcqnmOeoRowDygVFHa7VDn3ZgqsFlkC/To
	ysVusGw2WwM+BL8vW2r7k4Vof+Wb4IVq9MtarBr+tzmmLGT0ZWfiEiHaxPjWJ8h0Apy+Rev77eC
	7FDdg7FLL0UGUvG+YPsrNUlJCuMpn2R+ALd/FIcxUOlOmlT61gPKOl+xjC5orM/aaIy58llo/4e
	PEceJjRgfR7bNGA3rWQ/3R8RoEVDaJE/6Uw94gec6zWRyC1e+4I61Fqvwd2G0MLiEjyM67rf8gf
	EsJVwrMBE18+UULVZ5E6z2d/FS/6imymjViO9rqk/LD56qef4lwb/bTzEhQKNyMedy2w==
X-Received: by 2002:a05:6000:2306:b0:42b:3963:d08e with SMTP id ffacd0b85a97d-42f731967f8mr6489489f8f.22.1764857595783;
        Thu, 04 Dec 2025 06:13:15 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:15 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
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
	tarasmadan@google.com,
	Ethan Graham <ethangraham@google.com>
Subject: [PATCH 08/10] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
Date: Thu,  4 Dec 2025 15:12:47 +0100
Message-ID: <20251204141250.21114-9-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WF8jJDzx;       spf=pass
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
Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Reviewed-by: Ignat Korchagin <ignat@cloudflare.com>

---
PR v3:
- Use the FUZZ_TEST_SIMPLE macro for all introduced fuzz targets as
  they each take `(data, datalen)` pairs. This also removes the need for
  explicit constraints and annotations which become implicit.
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
 crypto/asymmetric_keys/Makefile               |  2 ++
 crypto/asymmetric_keys/tests/Makefile         |  4 ++++
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    | 17 ++++++++++++++++
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  | 20 +++++++++++++++++++
 4 files changed, 43 insertions(+)
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
index 000000000000..345f99990653
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
@@ -0,0 +1,17 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * PKCS#7 parser KFuzzTest target
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <crypto/pkcs7.h>
+#include <linux/kfuzztest.h>
+
+FUZZ_TEST_SIMPLE(test_pkcs7_parse_message)
+{
+	struct pkcs7_message *msg;
+
+	msg = pkcs7_parse_message(data, datalen);
+	if (msg && !IS_ERR(msg))
+		kfree(msg);
+}
diff --git a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
new file mode 100644
index 000000000000..dd434f1a21ed
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
@@ -0,0 +1,20 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * RSA key extract helper KFuzzTest targets
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+#include <crypto/internal/rsa.h>
+
+FUZZ_TEST_SIMPLE(test_rsa_parse_pub_key)
+{
+	struct rsa_key out;
+	rsa_parse_pub_key(&out, data, datalen);
+}
+
+FUZZ_TEST_SIMPLE(test_rsa_parse_priv_key)
+{
+	struct rsa_key out;
+	rsa_parse_priv_key(&out, data, datalen);
+}
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-9-ethan.w.s.graham%40gmail.com.
