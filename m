Return-Path: <kasan-dev+bncBDP53XW3ZQCBB4UWSXFQMGQE6IPZX2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 68D82D15018
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:28:52 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59b7b7a46a5sf2268152e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:28:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768246131; cv=pass;
        d=google.com; s=arc-20240605;
        b=SZZEAueeQopZVpQKV0ce8Rzp/gZgoO67BY+Jpi9RZ4b1019NlYF9VOKyw6q5X5X0A8
         o5L3M9f85qG60gDgqT+sft3tNTxZopT/sWifW45T4sBKomkPclRBC95ZxyhQJLCXabUy
         wGdyU9yf9dI35TnBvTaq/yfYXBECrPrxkJGRV6giyyt6I1o/Gq9UG/oFZM7lbBxIR4lN
         AWWJVnBvL644YCjy/UawhiY+Hava0NvExu+JRnkqti3AZ3+DIOzBCYUEYCVQIiSxLqYk
         fu5ATy1m3Qq2LWzu4tLyxyp//PfRpwGD2h/4wOAJ7uqU08s8w93S/3zMdxbsgmUqz5QE
         GISQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=vOE0JWHK3leQ7gRJtwUJhyItLa7KRyRu5xvkBJwJ1fY=;
        fh=tqjF1W36skCXDzNsnSba4ZH5+0Hqu6mB+QLTVCM7c8A=;
        b=hMlpDnFzxe9aZSpggDLiY/pHHbwZ5cqmHKuWWltrEWZwInL94qijhxrRCaHaDuT9Xy
         g1L8VVHu3onsc+nNDw0YL3HNwkXtlyVTDHW+egJjkNRC5yMozTKgyUZ3HqnVZihhTg4J
         70xjjFYWAMB6Z0WS+RcgMS9zMCDLNOHVMq6UMg+eyKYV2kvFifdRksTGUWQF69qlNRD7
         FX1Xyrdjec1cASPzQDPK4yKUl+2+t1ZmioeYJatyAewAac8LKfPJQnNx5X4pVhvyA1El
         L/crX/73ppq+4WRgxgCYSf4vrx16+lOJ9IBfcOvUqR823cXX/INMyw0/h3OeRup/7qfz
         0/BQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JDpOJrJZ;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768246131; x=1768850931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vOE0JWHK3leQ7gRJtwUJhyItLa7KRyRu5xvkBJwJ1fY=;
        b=Gjn5haEBSyjwyNqjC61T0PEXhpDSb1Zd7/X8amYu8Dl+KfSxjGw+4qagQRV7Q51n5V
         dd2xxGLvqdTYCwmVOSiL4Pe6vUir6DtwpdPPgMahEOopX5EsLq8GHVaSPvwzB0mjM0tx
         VmALAmJuP+07ceRTVT2cU1p5joMh20d19y1Rqwl6OrQznvRluFva0zDCOSSMp0ffgMVj
         PqylnjGpP5qXInSw7Md3EGgnAwfUY3aXK+6DoOSIGs27nm9jQKyGLUTWHtObMOwRCX02
         DXNkIdk0/gQJzPTUtwWdPQGMYEGesUt5pCsqQwYGZnI20zOepBfyaQJObpDEU9hnC4TA
         GQew==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768246131; x=1768850931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=vOE0JWHK3leQ7gRJtwUJhyItLa7KRyRu5xvkBJwJ1fY=;
        b=CrknLuEwqP4sqlTgc3HYWd4bVhmqfuXAKa/g8QHoB1oR9BSeaBBnMYTew5eMDfxRjx
         ZB3qUKEXXDlq7uWDbHqfh0pP0LTv6MIvtB99NdqA+9/bZnwgOme9NDtKbduVDEfVQGVw
         M/Xb+HE+eJV1kxXCMuoVpuPfLuoOv3a7DQKUyekK4u7B7LcLMdHAe60vcvKjptmd8S5R
         pSDNx3WdKZ5QEIq0swWlxj3Kac9or92eg96Sb36aq+3yadvjxd9hn8iKAmh6LzsJ5uRy
         J2os9MC+3GnGG5fB4TLDigcd/gbba1OfVuNE4EXwM40hrt/W9fPgvadTDUAVJ4EKAG42
         MsHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768246131; x=1768850931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vOE0JWHK3leQ7gRJtwUJhyItLa7KRyRu5xvkBJwJ1fY=;
        b=FRo8/1CXyMQBX9mfR1xbGGSz1JhJD1x3cFTDbrJezoif2+dQvvtbJJudP+Xnq38lRN
         S+em9fbDhSoQUVouvAltNeI8JC76hN4dyhTVz7GxouD1kZxbY8KWFTwjjWMdGL/+Gmgx
         g9l4BIK0SM11luwkJKhoUk1CDgj19M3SLMcUeyWCbH99tTJkttIGYGz4d4MLu/PFnB4p
         vC+E+hWFH+y2F4izB/1EavM/gUCWJtW/IaE04D/4ab5IQNBFROqwENOQ9VzYZMhqVRZz
         JtGCGS9lItKw7Ynoe8pjxSuiE5lwI6KpUfqNRK8QcDQY0iOuNglWceUw8M5RabvUj7S+
         n+Ag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0a2hgvFiDR5Mjtdag/o6l/ySq6gWGbEZaY0AbsvXuZMSJiwuYzEn1fM0pPxewnLqRh4YDrw==@lfdr.de
X-Gm-Message-State: AOJu0YwcguUHXENf2lFXXNYLcgakWnp/+mtqkjT7WNiDVyaiBC5Hfwae
	GeS8xgR1yWYQqcFgK7piSiGs0sT57mfRR0QN380ouRzO69BwN/xCx6UR
X-Google-Smtp-Source: AGHT+IFgBWiVetLkux+bvdwmgUMD/J+XG2aj/B9IcFTiYPF/qF39V7TEr1QTye1DLP+LrZDkk09EIw==
X-Received: by 2002:a05:6512:234b:b0:59a:11ab:59c5 with SMTP id 2adb3069b0e04-59b6f03f983mr6039298e87.35.1768246131442;
        Mon, 12 Jan 2026 11:28:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E0RmWZ7jIrKYNfvyt4rq4+a91IGW52UMvr7sQzL+MYPg=="
Received: by 2002:a05:6512:138b:b0:59b:6cb8:9cf3 with SMTP id
 2adb3069b0e04-59b6cb8a21als2549549e87.1.-pod-prod-03-eu; Mon, 12 Jan 2026
 11:28:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU0Uq8Q5BPgflyeejkaHJsMlTydwZx/UhsOc5Ld5zEmJrQvc98OBx2NXrTJ0tG6q/lfJvLwkQLs3iM=@googlegroups.com
X-Received: by 2002:a05:6512:3d08:b0:595:9152:b90e with SMTP id 2adb3069b0e04-59b6f048548mr7205546e87.44.1768246128498;
        Mon, 12 Jan 2026 11:28:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768246128; cv=none;
        d=google.com; s=arc-20240605;
        b=NLIcjrl+uHtwk4GlpWCS0nL2pMS6llNp0XnQCASAhfBUsOBD8zCyJoyGiHBt4gPYnr
         rmvBtN5rDX00CyD+ahFUOdjz/HKdUnIxfpNrLJ2/yfvimoAVoHw3+ctaO7t2zKyjHJ4V
         R3p4m83HttZ1kqkyvnGYWiKwvvhqgPdLR+vAo/FV/kFj/hBWU5XNcE9niSUkM04LP6o0
         6TsHYYAN3HiQiSTdDbjRAXiPxZ8lE+kPTjIhM/XpHDhLSCURZjJgXcAPi5DjYTi4tBJx
         n/akB2+zYn2bXQ7SZLaJvHfhrIzZkv6LsvTCVTnmsiowRnAZrvmWWz241mWGt+OaUjA3
         KASA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=scWvVJzBtZkgblH2r+AxXX3I8YFcDE4LdHFKMGvKaXc=;
        fh=2sXKUtSf9bPD2isgzMgvu7rcg6EXrn12GaaLGb84E68=;
        b=Wkk7Az4BFB9dik/NwRVX/8iXwUxxzFvO2YrmeEMc5/kXJzxqlYy0X2uRtUPN5TgIiz
         u/Psv2YrJra/NFSftduTBH1W65kh0Zaf0Ao1QVrP6TUUDTb/I14Vy+WKCp3asHhTCnVc
         q0HJ1cnXD4yrq3yN+YMPa4HaZ37+BPX/voVMFZTYktk971Hw4OQZt33YNf6hB6TbQHBx
         neaiTJLVBaqgys0/CRKcYWl4ZyAfqdviEvX7gpw7RlCzdtapfzWd0iHw70eBnVcUAKmY
         RdDzEE47n1xbV1iNJLA0eH3DAwn2XrTNOTHe/u7b16ZCppLsnX6gxXJFdRR4yi3yIKBo
         tmDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JDpOJrJZ;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b6f504593si249103e87.4.2026.01.12.11.28.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:28:48 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-652fec696c9so60466a12.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:28:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU79d5Yp1tcuXNgd1Go4iETWLTWhWx1ppXsKD0Bezq98KGYCb3Z812dtgJlJXvYQY+Nx4UpcDyHQNg=@googlegroups.com
X-Gm-Gg: AY/fxX7ogid2/V9Lm7a7bK5dIMj46LB/4seF0KMb/wWNeOFD4BCkd1wkamS0ZLQEXgi
	/etemrkoiic9vkZc38Vxfo4iZVYp5/0kWOIAtozMCqgFlOC2pp7HLWThzGi/FcQcDT3ttVndEHg
	QqPlg05/zK8XWsiP5d726KZoZgeZkDKavJmkCq289y81+Ty/NwI1EBgP0Hz+dfDBvcG6u16SQoZ
	FqpOVpPqe3AGvAsgRjvT7B8O0wmq3DrvBBbiV2XfsIs7WltgHZ1CD6yjNFzsU11x55qtQFEQDtg
	/K/nYgnVoheR6fGBeckndzPruwVgBUbCr8vLYyaXCDcwD16Yg4nH9FWm9ZfAWDnVuwtLrF1nw+b
	aXHD/W3AigNObIUhKbcEbutZqN/a2zWa0Q92f8xebbFfAPCDs8DgAOH+rWWFGHTHQQFBYRoOAAP
	qkBFi8PmASjou0eAR3Sd9QhvtKWstkSksLl/wOLA6HpvoDmhc/lQ==
X-Received: by 2002:a05:6402:1e8c:b0:64d:f49:52aa with SMTP id 4fb4d7f45d1cf-65097dc6439mr18130109a12.3.1768246127869;
        Mon, 12 Jan 2026 11:28:47 -0800 (PST)
Received: from ethan-tp (xdsl-31-164-106-179.adslplus.ch. [31.164.106.179])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-6507bf667fcsm18108959a12.29.2026.01.12.11.28.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 11:28:47 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	ebiggers@kernel.org,
	elver@google.com,
	gregkh@linuxfoundation.org,
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
	mcgrof@kernel.org,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	skhan@linuxfoundation.org,
	tarasmadan@google.com,
	wentaoz5@illinois.edu
Subject: [PATCH v4 5/6] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
Date: Mon, 12 Jan 2026 20:28:26 +0100
Message-ID: <20260112192827.25989-6-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JDpOJrJZ;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>

---
PR v4:
- Use pkcs7_free_message() instead of kfree() on the success path of the
  pkcs7_parse_message fuzz target.
- Dropped Ignat Korchagin's reviewed-by due to the functional change in
  switching from kfree to pkcs7_free_message.
- Restrict introduced fuzz targets to build only when their dependencies
  (CONFIG_PKCS7_MESSAGE_PARSER and CONFIG_CRYPTO_RSA) are built-in. This
  prevents linker errors when they are configured as modules, as
  KFuzzTest symbols are not exported.
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
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    | 18 ++++++++++++++
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  | 24 +++++++++++++++++++
 4 files changed, 48 insertions(+)
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
index 000000000000..b43aa769e2ce
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/Makefile
@@ -0,0 +1,4 @@
+pkcs7-kfuzz-y := $(and $(CONFIG_KFUZZTEST),$(filter y, $(CONFIG_PKCS7_MESSAGE_PARSER)))
+rsa-helper-kfuzz-y := $(and $(CONFIG_KFUZZTEST),$(filter y, $(CONFIG_CRYPTO_RSA)))
+obj-$(pkcs7-kfuzz-y) += pkcs7_kfuzz.o
+obj-$(rsa-helper-kfuzz-y) += rsa_helper_kfuzz.o
diff --git a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
new file mode 100644
index 000000000000..2e1a59fb6035
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
@@ -0,0 +1,18 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * PKCS#7 parser KFuzzTest target.
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
+		pkcs7_free_message(msg);
+	return 0;
+}
diff --git a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
new file mode 100644
index 000000000000..e45e8fa53190
--- /dev/null
+++ b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
@@ -0,0 +1,24 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * RSA key extract helper KFuzzTest targets.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <crypto/internal/rsa.h>
+#include <linux/kfuzztest.h>
+
+FUZZ_TEST_SIMPLE(test_rsa_parse_pub_key)
+{
+	struct rsa_key out;
+
+	rsa_parse_pub_key(&out, data, datalen);
+	return 0;
+}
+
+FUZZ_TEST_SIMPLE(test_rsa_parse_priv_key)
+{
+	struct rsa_key out;
+
+	rsa_parse_priv_key(&out, data, datalen);
+	return 0;
+}
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112192827.25989-6-ethan.w.s.graham%40gmail.com.
