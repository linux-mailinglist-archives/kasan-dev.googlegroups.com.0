Return-Path: <kasan-dev+bncBDP53XW3ZQCBBZ6OUTDAMGQEOWR3IEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E46F9B5917F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:28 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3ea35489002sf1660472f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013288; cv=pass;
        d=google.com; s=arc-20240605;
        b=CDs6RxfKVSAAJ2Wmio17FLWRrlxUDArX0RGXQ+D0Qse3ptZ+FPDVcCFc1YZERKYDDQ
         g5Shx7q/fc7Z68Y1MI3CX0GCJCpv5D60zWVBSgArixFM2l2lKgHS/MPeE7Knsmh69PGD
         qcVv1R0RybWIJUXDA+jqRpZz42pkvZpcYPhxXhJ/ieQdKs1P3ZF5uNGnvCF7c7tdZhfN
         7pQQypEEuDYTyLluaUort7zqLDzNg8YBVDltN0Uj6ICMeD5Q7j0se1O06mauMo53pJCL
         tFQcocHuXytgL0XvKspt+xNVOOWF1ixLEVJGskn79lTRezSLUJwQQXDQPt+1Dq8spR+w
         D7eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=3QUlJbbjlIbk26xfw6i1RotyrLubVSUUih3Dhs7pKlo=;
        fh=deMUXYli5TfbmRqZiJUDZ7ydQEIBihlFGoK17bfMgaU=;
        b=cDqMIHSraME/1vcDTE14hRNd95bX4P8ZNCKCuICP1EjDo6Au3ZU0dfB3UqekDdgT59
         Wthx3K4NL4J/dSiiuTdA+6OHeaDtOoXMlBBS8eT4kWPM3FN+EOj6KeUbuK09O0R7kVEn
         wAl/YYDEcRBwkg0wHYVRdeVsJng3y9yrkVjg9/Qh0WAtoxIIDSvBp0dimEUxv+/ReBHE
         eIm9zPVTl7WI//Oj8RUt3zoyQUyWqjZehylK4mg6yiu9sCf/ozYGenYUYP+8iOq6pIm+
         uja0NgXwk1SRrwjwYrTa/qqb8Sn24tt0b92gXWGaQodrXONNXs5FDqr6jd+Qk6S6kB6W
         TUEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cy+xM8R/";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013288; x=1758618088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3QUlJbbjlIbk26xfw6i1RotyrLubVSUUih3Dhs7pKlo=;
        b=llLSwD9oleHd2Jg7SQngm3W0iegqoVRwt9jxsgtWZLAnpj8TZa8f+DzqBzJBOuBg2c
         5GOgtBILWSUuMLiNOeg7oBlrfpGd7s8uSxfjIEZpwk9NSGqMzlTiWMHgwxEeIm+fXCWC
         oQGPDTiuJGwOHUp6NanB5jY7PuZC5WDqHhJKBOo2d1qXm2GuXI6O8pDDPkt1kSfHr+tL
         9GXG5dribMGgnGoxyqlLe3i83LziXcnLHV7qSm7ge0dwM6qtLGZL9+sZgxlwWw5Nluwi
         z1ib2nQZovDk6EI3pbmoFiBLA4NtzbYOSeg5OqwYKk7LQo4oqfdVKbm1z2mXujfC3Tcp
         etjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013288; x=1758618088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=3QUlJbbjlIbk26xfw6i1RotyrLubVSUUih3Dhs7pKlo=;
        b=QDgqpk3cusHO+MszUOwswm95DVqZ2/PlgirlR2bLcxhu0XaeRNxlBg9lBzpjTYDjPk
         3eiwHu9fbmhgO7ZlMSHnSdumbcs0+IhwLepSDw5tSGMP1EmEp+6DaE5ETYeF8f3HrGRx
         rfjROzH3LkcZC66sDAWU+IhkjWWPEXATqt7JosFFPmTJ+0ATkTZIv+LP9ioOOhQ1ywXy
         xDc9ndCFx/2mxWVWoj7Gxv4DbCycxJCT5fQSJwMTZOD6kr+us/YMxM5slZPFGGSjm6vP
         bU3nZzzSL4GymG1PobAnVX3PiIGDViWs+6m14JKhoiadV0USjA0MBX9Ac9FMWxqDD2Rw
         a0Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013288; x=1758618088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3QUlJbbjlIbk26xfw6i1RotyrLubVSUUih3Dhs7pKlo=;
        b=O0Mszg8ryj9MLKKKnF7S/PaFsFHWcnTb6uddy+lUQS2tAtEn7ro2uAHeZM2Xf6l0Wf
         FI3rKEcFuFIfO5OxSi948mFPJ8eWfkI5DUlenpts5jtjuYme0FnuCPeOr/+uoosK0jQD
         0fiySVOUp1eY6WHgeGuGDgiYyKZCdQwN+qdA1ujX+FbXyWM1hCdbOKOuL3+qZUhfaUSv
         x251bl0TFk8OR06fq/JKb2lfR0mc33UwvJTofM4We+HwPEMbAiWk77Em5fWtRKve1dPJ
         /2sL5wAx8bjMN1jEHORPBNsF6STSz2coW264H01K0fLNfmzP+b4r45K4RjzO8EGVALO7
         K63Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmnRJBAV3VjOgiuo2omX4ojzh1RVUAlnms45n2VVOLqhslbfr1AsfpVkAt/eIo36b7SS0nZw==@lfdr.de
X-Gm-Message-State: AOJu0Yz1ZWQ797sjpTqO+PQcp+Lf6Ut+p54zSEJMs5fvfeWVHZxLUp4F
	kWzkHDoDWEmpWuPoy/EuzvXvbE0cYQAB/1m/mugQTkz+jbv94iy0WuK1
X-Google-Smtp-Source: AGHT+IHwOQf1o3ccLiA/uECLhxsUcFp7ALCU+/Xv/fjjZ/va42M27wE1OHnkg+6fPv01FSzrnvxnIQ==
X-Received: by 2002:a05:6000:22c3:b0:3e2:fcba:915b with SMTP id ffacd0b85a97d-3e765a2e03fmr11877249f8f.32.1758013287700;
        Tue, 16 Sep 2025 02:01:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeilLgBGwmK0Ns6kFxSvTTHYJUqLlAdPTyCoIfh31MD9g==
Received: by 2002:a05:600c:3d96:b0:45b:7334:a684 with SMTP id
 5b1f17b1804b1-45f290c1e61ls15078125e9.1.-pod-prod-02-eu; Tue, 16 Sep 2025
 02:01:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWQPNuHtmXAtBYXPJCUxDj+etP7pHdMm4+6EFW2i+SJHmw0bzTFi6iP0R82VWy2fVFONnh/5S2uXE=@googlegroups.com
X-Received: by 2002:a05:600c:a44:b0:45f:28bf:1d9d with SMTP id 5b1f17b1804b1-45f28bf1de7mr109197225e9.24.1758013284061;
        Tue, 16 Sep 2025 02:01:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013284; cv=none;
        d=google.com; s=arc-20240605;
        b=BslsYh1e84NeuxARx3+rzJ7PgHSPsPBT/LcE2swyCjrpvBfGUU3r53uz6882sLWgIv
         jUmlA5V4kGICVe2U3ReqkM436WKbpCPIhaSzQHhELaE+NOjMmfaz8jeChlNcyCUSDmmM
         fs9iAFphUHEW7SeT+x55TCT6HlyCLBsbrcR20Nh1RV1W1lG6VSUeeWZoHIVrU5Vcto2Y
         tORzf/VS+t5BGt5mRU8qSnRGCqNTymhGDH0FJm+EeNRBGcF2dsIbJhvu04ffIEDau1FK
         XP5D6Ad2vaEYKGiZ7BRoq5HVToNAuYw7mw8H347MY+yBSNChVeUiGXr9eZ/fE+w6G+og
         ePkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v722sbbJadlJwwsJi3TM+ZvR5FvVKggc0kwG5mj3X7w=;
        fh=j03I//bkWmukRTBVvmmcyQi9T2dWS2DTcdcrPvUo4dg=;
        b=IXvPCGpyXF7Nuy6SP428cytEPjzuXLBQUD3sptTbnPuW9LTvn0HtAFWpRXS9w5ilWc
         rr+S4qWF2+ChqgecHLZ0o8quZBwMpHvEJRVM4ZHIeyo7SiIfjb2AhhUlBqFFKjDoLrnr
         4nRIKQBEK3Xao/D6lTjAkfkr+bd8nJOigrSsIk4hDcgHGKRbydL2U9GnINpOIiJCpE6J
         kPjmJx1Ignvm4ISZqlA9k8xim9bvVKPL+vcww218uEUn9hH/EmFZlUxe75Ev1pfZCkXy
         Fo4B8lNtsmsb8/uBN2DzWR2Pj6IuE7xV64tYN2TZC87Jo95tm6wYbacXC9Z4qaAWJqZK
         POYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cy+xM8R/";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45e015297b0si1706125e9.2.2025.09.16.02.01.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-45decc9e83eso56549605e9.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVXyLUY6chqQl93Dc26EVha4M2qxHJ2qj+1CC607K4E1kIYw8fsl8yq+dQXSQy7mho/49qeP415/w=@googlegroups.com
X-Gm-Gg: ASbGnctWbwTfSCVLkb7u8CO3w9U2wsALg4veNh9ecIydwGdTj6O76/eO0HYzHiHOjDx
	H3pBDdb7TUsRfWvutLENy30+sKkoGXAnGbjv12KX8vI/hae64Oqp8xfUzi/eJK6AHKaVaexs3T/
	w6bWHD+Mg2eOSNSY8ufC8fWFf4+f8xKItzKuy3mufty2TnzE8fOiRgLQ1LyltIDZJZddUeBDDeV
	imXmsP7qoIBZKkyUohfLVyX5gK787t3Oc5Qp4dUZOLIs/njcuMyGM5ZdrIptIYlsynZmgm5vs9C
	DEbDw1F45TJeX6EJCdupLwZDPXgmqITfcxrKg1lad67rrpWQx+cuvoNRA7rCu1E6C60DctdpGGA
	/rooAtkq9DoS9mj5iVfzKnlGhbTWrivp6NRzy3nH5K/OmRex2mxyTiZ25kJ0FT961be8zIsAqD4
	lrOjPwHaa42cTF4pLIhLTrSbQ=
X-Received: by 2002:a05:600c:247:b0:45b:8ac2:9759 with SMTP id 5b1f17b1804b1-45f211fa054mr114510185e9.23.1758013282611;
        Tue, 16 Sep 2025 02:01:22 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:21 -0700 (PDT)
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
Subject: [PATCH v1 04/10] tools: add kfuzztest-bridge utility
Date: Tue, 16 Sep 2025 09:01:03 +0000
Message-ID: <20250916090109.91132-5-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="cy+xM8R/";       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Introduce the kfuzztest-bridge tool, a userspace utility for sending
structured inputs to KFuzzTest harnesses via debugfs.

The bridge takes a textual description of the expected input format, a
file containing random bytes, and the name of the target fuzz test. It
parses the description, encodes the random data into the binary format
expected by the kernel, and writes the result to the corresponding
debugfs entry.

This allows for both simple manual testing and integration with
userspace fuzzing engines. For example, it can be used for smoke testing
by providing data from /dev/urandom, or act as a bridge for blob-based
fuzzers (e.g., AFL) to target KFuzzTest harnesses.

Signed-off-by: Ethan Graham <ethangraham@google.com>

---
v3:
- Add additional context in header comment of kfuzztest-bridge/parser.c.
- Add some missing NULL checks.
- Refactor skip_whitespace() function in input_lexer.c.
- Use ctx->minalign to compute correct region alignment, which is read
  from /sys/kernel/debug/kfuzztest/_config/minalign.
---
---
 tools/Makefile                        |  15 +-
 tools/kfuzztest-bridge/.gitignore     |   2 +
 tools/kfuzztest-bridge/Build          |   6 +
 tools/kfuzztest-bridge/Makefile       |  48 ++++
 tools/kfuzztest-bridge/bridge.c       | 103 +++++++
 tools/kfuzztest-bridge/byte_buffer.c  |  87 ++++++
 tools/kfuzztest-bridge/byte_buffer.h  |  31 ++
 tools/kfuzztest-bridge/encoder.c      | 391 +++++++++++++++++++++++++
 tools/kfuzztest-bridge/encoder.h      |  16 ++
 tools/kfuzztest-bridge/input_lexer.c  | 242 ++++++++++++++++
 tools/kfuzztest-bridge/input_lexer.h  |  57 ++++
 tools/kfuzztest-bridge/input_parser.c | 395 ++++++++++++++++++++++++++
 tools/kfuzztest-bridge/input_parser.h |  81 ++++++
 tools/kfuzztest-bridge/rand_stream.c  |  77 +++++
 tools/kfuzztest-bridge/rand_stream.h  |  57 ++++
 15 files changed, 1602 insertions(+), 6 deletions(-)
 create mode 100644 tools/kfuzztest-bridge/.gitignore
 create mode 100644 tools/kfuzztest-bridge/Build
 create mode 100644 tools/kfuzztest-bridge/Makefile
 create mode 100644 tools/kfuzztest-bridge/bridge.c
 create mode 100644 tools/kfuzztest-bridge/byte_buffer.c
 create mode 100644 tools/kfuzztest-bridge/byte_buffer.h
 create mode 100644 tools/kfuzztest-bridge/encoder.c
 create mode 100644 tools/kfuzztest-bridge/encoder.h
 create mode 100644 tools/kfuzztest-bridge/input_lexer.c
 create mode 100644 tools/kfuzztest-bridge/input_lexer.h
 create mode 100644 tools/kfuzztest-bridge/input_parser.c
 create mode 100644 tools/kfuzztest-bridge/input_parser.h
 create mode 100644 tools/kfuzztest-bridge/rand_stream.c
 create mode 100644 tools/kfuzztest-bridge/rand_stream.h

diff --git a/tools/Makefile b/tools/Makefile
index c31cbbd12c45..7f1dfe022045 100644
--- a/tools/Makefile
+++ b/tools/Makefile
@@ -21,6 +21,7 @@ help:
 	@echo '  hv                     - tools used when in Hyper-V clients'
 	@echo '  iio                    - IIO tools'
 	@echo '  intel-speed-select     - Intel Speed Select tool'
+	@echo '  kfuzztest-bridge       - KFuzzTest userspace utility'
 	@echo '  kvm_stat               - top-like utility for displaying kvm statistics'
 	@echo '  leds                   - LEDs  tools'
 	@echo '  nolibc                 - nolibc headers testing and installation'
@@ -69,7 +70,7 @@ acpi: FORCE
 cpupower: FORCE
 	$(call descend,power/$@)
 
-counter firewire hv guest bootconfig spi usb virtio mm bpf iio gpio objtool leds wmi firmware debugging tracing: FORCE
+counter firewire hv guest bootconfig spi usb virtio mm bpf iio gpio objtool leds wmi firmware debugging tracing kfuzztest-bridge: FORCE
 	$(call descend,$@)
 
 bpf/%: FORCE
@@ -126,7 +127,8 @@ all: acpi counter cpupower gpio hv firewire \
 		perf selftests bootconfig spi turbostat usb \
 		virtio mm bpf x86_energy_perf_policy \
 		tmon freefall iio objtool kvm_stat wmi \
-		debugging tracing thermal thermometer thermal-engine ynl
+		debugging tracing thermal thermometer thermal-engine ynl \
+		kfuzztest-bridge
 
 acpi_install:
 	$(call descend,power/$(@:_install=),install)
@@ -134,7 +136,7 @@ acpi_install:
 cpupower_install:
 	$(call descend,power/$(@:_install=),install)
 
-counter_install firewire_install gpio_install hv_install iio_install perf_install bootconfig_install spi_install usb_install virtio_install mm_install bpf_install objtool_install wmi_install debugging_install tracing_install:
+counter_install firewire_install gpio_install hv_install iio_install perf_install bootconfig_install spi_install usb_install virtio_install mm_install bpf_install objtool_install wmi_install debugging_install tracing_install kfuzztest-bridge_install:
 	$(call descend,$(@:_install=),install)
 
 selftests_install:
@@ -170,7 +172,8 @@ install: acpi_install counter_install cpupower_install gpio_install \
 		virtio_install mm_install bpf_install x86_energy_perf_policy_install \
 		tmon_install freefall_install objtool_install kvm_stat_install \
 		wmi_install debugging_install intel-speed-select_install \
-		tracing_install thermometer_install thermal-engine_install ynl_install
+		tracing_install thermometer_install thermal-engine_install ynl_install \
+		kfuzztest-bridge_install
 
 acpi_clean:
 	$(call descend,power/acpi,clean)
@@ -178,7 +181,7 @@ acpi_clean:
 cpupower_clean:
 	$(call descend,power/cpupower,clean)
 
-counter_clean hv_clean firewire_clean bootconfig_clean spi_clean usb_clean virtio_clean mm_clean wmi_clean bpf_clean iio_clean gpio_clean objtool_clean leds_clean firmware_clean debugging_clean tracing_clean:
+counter_clean hv_clean firewire_clean bootconfig_clean spi_clean usb_clean virtio_clean mm_clean wmi_clean bpf_clean iio_clean gpio_clean objtool_clean leds_clean firmware_clean debugging_clean tracing_clean kfuzztest-bridge_clean:
 	$(call descend,$(@:_clean=),clean)
 
 libapi_clean:
@@ -230,6 +233,6 @@ clean: acpi_clean counter_clean cpupower_clean hv_clean firewire_clean \
 		freefall_clean build_clean libbpf_clean libsubcmd_clean \
 		gpio_clean objtool_clean leds_clean wmi_clean firmware_clean debugging_clean \
 		intel-speed-select_clean tracing_clean thermal_clean thermometer_clean thermal-engine_clean \
-		sched_ext_clean ynl_clean
+		sched_ext_clean ynl_clean kfuzztest-bridge_clean
 
 .PHONY: FORCE
diff --git a/tools/kfuzztest-bridge/.gitignore b/tools/kfuzztest-bridge/.gitignore
new file mode 100644
index 000000000000..4aa9fb0d44e2
--- /dev/null
+++ b/tools/kfuzztest-bridge/.gitignore
@@ -0,0 +1,2 @@
+# SPDX-License-Identifier: GPL-2.0-only
+kfuzztest-bridge
diff --git a/tools/kfuzztest-bridge/Build b/tools/kfuzztest-bridge/Build
new file mode 100644
index 000000000000..d07341a226d6
--- /dev/null
+++ b/tools/kfuzztest-bridge/Build
@@ -0,0 +1,6 @@
+kfuzztest-bridge-y += bridge.o
+kfuzztest-bridge-y += byte_buffer.o
+kfuzztest-bridge-y += encoder.o
+kfuzztest-bridge-y += input_lexer.o
+kfuzztest-bridge-y += input_parser.o
+kfuzztest-bridge-y += rand_stream.o
diff --git a/tools/kfuzztest-bridge/Makefile b/tools/kfuzztest-bridge/Makefile
new file mode 100644
index 000000000000..3a4437fb0d3f
--- /dev/null
+++ b/tools/kfuzztest-bridge/Makefile
@@ -0,0 +1,48 @@
+# SPDX-License-Identifier: GPL-2.0
+# Makefile for KFuzzTest-Bridge
+include ../scripts/Makefile.include
+
+bindir ?= /usr/bin
+
+ifeq ($(srctree),)
+srctree := $(patsubst %/,%,$(dir $(CURDIR)))
+srctree := $(patsubst %/,%,$(dir $(srctree)))
+endif
+
+MAKEFLAGS += -r
+
+override CFLAGS += -O2 -g
+override CFLAGS += -Wall -Wextra
+override CFLAGS += -D_GNU_SOURCE
+override CFLAGS += -I$(OUTPUT)include -I$(srctree)/tools/include
+
+ALL_TARGETS := kfuzztest-bridge
+ALL_PROGRAMS := $(patsubst %,$(OUTPUT)%,$(ALL_TARGETS))
+
+KFUZZTEST_BRIDGE_IN := $(OUTPUT)kfuzztest-bridge-in.o
+KFUZZTEST_BRIDGE    := $(OUTPUT)kfuzztest-bridge
+
+all: $(ALL_PROGRAMS)
+
+export srctree OUTPUT CC LD CFLAGS
+include $(srctree)/tools/build/Makefile.include
+
+$(KFUZZTEST_BRIDGE_IN): FORCE
+	$(Q)$(MAKE) $(build)=kfuzztest-bridge
+
+$(KFUZZTEST_BRIDGE): $(KFUZZTEST_BRIDGE_IN)
+	$(QUIET_LINK)$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
+
+clean:
+	rm -f $(ALL_PROGRAMS)
+	find $(or $(OUTPUT),.) -name '*.o' -delete -o -name '\.*.d' -delete -o -name '\.*.o.cmd' -delete
+
+install: $(ALL_PROGRAMS)
+	install -d -m 755 $(DESTDIR)$(bindir);		\
+	for program in $(ALL_PROGRAMS); do		\
+		install $$program $(DESTDIR)$(bindir);	\
+	done
+
+FORCE:
+
+.PHONY: all install clean FORCE prepare
diff --git a/tools/kfuzztest-bridge/bridge.c b/tools/kfuzztest-bridge/bridge.c
new file mode 100644
index 000000000000..002e1d2274d7
--- /dev/null
+++ b/tools/kfuzztest-bridge/bridge.c
@@ -0,0 +1,103 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KFuzzTest tool for sending inputs into a KFuzzTest harness
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <errno.h>
+#include <fcntl.h>
+#include <stdio.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "byte_buffer.h"
+#include "encoder.h"
+#include "input_lexer.h"
+#include "input_parser.h"
+#include "rand_stream.h"
+
+static int invoke_kfuzztest_target(const char *target_name, const char *data, ssize_t data_size)
+{
+	ssize_t bytes_written;
+	char *buf = NULL;
+	int ret;
+	int fd;
+
+	if (asprintf(&buf, "/sys/kernel/debug/kfuzztest/%s/input", target_name) < 0)
+		return -ENOMEM;
+
+	fd = openat(AT_FDCWD, buf, O_WRONLY, 0);
+	if (fd < 0) {
+		ret = -errno;
+		goto out_free;
+	}
+
+	/*
+	 * A KFuzzTest target's debugfs handler expects the entire input to be
+	 * written in a single contiguous blob. Treat partial writes as errors.
+	 */
+	bytes_written = write(fd, data, data_size);
+	if (bytes_written != data_size) {
+		ret = (bytes_written < 0) ? -errno : -EIO;
+		goto out_close;
+	}
+	ret = 0;
+
+out_close:
+	if (close(fd) != 0 && ret == 0)
+		ret = -errno;
+out_free:
+	free(buf);
+	return ret;
+}
+
+static int invoke_one(const char *input_fmt, const char *fuzz_target, const char *input_filepath)
+{
+	struct ast_node *ast_prog;
+	struct byte_buffer *bb;
+	struct rand_stream *rs;
+	struct token **tokens;
+	size_t num_tokens;
+	size_t num_bytes;
+	int err;
+
+	err = tokenize(input_fmt, &tokens, &num_tokens);
+	if (err) {
+		fprintf(stderr, "tokenization failed: %s\n", strerror(-err));
+		return err;
+	}
+
+	err = parse(tokens, num_tokens, &ast_prog);
+	if (err) {
+		fprintf(stderr, "parsing failed: %s\n", strerror(-err));
+		return err;
+	}
+
+	rs = new_rand_stream(input_filepath, 1024);
+	err = encode(ast_prog, rs, &num_bytes, &bb);
+	if (err == STREAM_EOF) {
+		fprintf(stderr, "encoding failed: reached EOF in %s\n", input_filepath);
+		return -EINVAL;
+	} else if (err) {
+		fprintf(stderr, "encoding failed: %s\n", strerror(-err));
+		return err;
+	}
+
+	err = invoke_kfuzztest_target(fuzz_target, bb->buffer, (ssize_t)num_bytes);
+	if (err)
+		fprintf(stderr, "invocation failed: %s\n", strerror(-err));
+	destroy_byte_buffer(bb);
+	destroy_rand_stream(rs);
+	return err;
+}
+
+int main(int argc, char *argv[])
+{
+	if (argc != 4) {
+		printf("Usage: %s <input-description> <fuzz-target-name> <input-file>\n", argv[0]);
+		printf("For more detailed information see /Documentation/dev-tools/kfuzztest.rst\n");
+		return 1;
+	}
+
+	return invoke_one(argv[1], argv[2], argv[3]);
+}
diff --git a/tools/kfuzztest-bridge/byte_buffer.c b/tools/kfuzztest-bridge/byte_buffer.c
new file mode 100644
index 000000000000..949278bc5257
--- /dev/null
+++ b/tools/kfuzztest-bridge/byte_buffer.c
@@ -0,0 +1,87 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * A simple byte buffer implementation for encoding binary data
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <asm-generic/errno-base.h>
+#include <stdlib.h>
+#include <string.h>
+
+#include "byte_buffer.h"
+
+struct byte_buffer *new_byte_buffer(size_t initial_size)
+{
+	struct byte_buffer *ret;
+	size_t alloc_size = initial_size >= 8 ? initial_size : 8;
+
+	ret = malloc(sizeof(*ret));
+	if (!ret)
+		return NULL;
+
+	ret->alloc_size = alloc_size;
+	ret->buffer = malloc(alloc_size);
+	if (!ret->buffer) {
+		free(ret);
+		return NULL;
+	}
+	ret->num_bytes = 0;
+	return ret;
+}
+
+void destroy_byte_buffer(struct byte_buffer *buf)
+{
+	free(buf->buffer);
+	free(buf);
+}
+
+int append_bytes(struct byte_buffer *buf, const char *bytes, size_t num_bytes)
+{
+	size_t req_size;
+	size_t new_size;
+	char *new_ptr;
+
+	req_size = buf->num_bytes + num_bytes;
+	new_size = buf->alloc_size;
+
+	while (req_size > new_size)
+		new_size *= 2;
+	if (new_size != buf->alloc_size) {
+		new_ptr = realloc(buf->buffer, new_size);
+		if (!new_ptr)
+			return -ENOMEM;
+		buf->buffer = new_ptr;
+		buf->alloc_size = new_size;
+	}
+	memcpy(buf->buffer + buf->num_bytes, bytes, num_bytes);
+	buf->num_bytes += num_bytes;
+	return 0;
+}
+
+int append_byte(struct byte_buffer *buf, char c)
+{
+	return append_bytes(buf, &c, 1);
+}
+
+int encode_le(struct byte_buffer *buf, uint64_t value, size_t byte_width)
+{
+	size_t i;
+	int ret;
+
+	for (i = 0; i < byte_width; ++i) {
+		if ((ret = append_byte(buf, (uint8_t)((value >> (i * 8)) & 0xFF)))) {
+			return ret;
+		}
+	}
+	return 0;
+}
+
+int pad(struct byte_buffer *buf, size_t num_padding)
+{
+	int ret;
+	size_t i;
+	for (i = 0; i < num_padding; i++)
+		if ((ret = append_byte(buf, 0)))
+			return ret;
+	return 0;
+}
diff --git a/tools/kfuzztest-bridge/byte_buffer.h b/tools/kfuzztest-bridge/byte_buffer.h
new file mode 100644
index 000000000000..6a31bfb5e78f
--- /dev/null
+++ b/tools/kfuzztest-bridge/byte_buffer.h
@@ -0,0 +1,31 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * A simple byte buffer implementation for encoding binary data
+ *
+ * Copyright 2025 Google LLC
+ */
+#ifndef KFUZZTEST_BRIDGE_BYTE_BUFFER_H
+#define KFUZZTEST_BRIDGE_BYTE_BUFFER_H
+
+#include <stdint.h>
+#include <stdlib.h>
+
+struct byte_buffer {
+	char *buffer;
+	size_t num_bytes;
+	size_t alloc_size;
+};
+
+struct byte_buffer *new_byte_buffer(size_t initial_size);
+
+void destroy_byte_buffer(struct byte_buffer *buf);
+
+int append_bytes(struct byte_buffer *buf, const char *bytes, size_t num_bytes);
+
+int append_byte(struct byte_buffer *buf, char c);
+
+int encode_le(struct byte_buffer *buf, uint64_t value, size_t byte_width);
+
+int pad(struct byte_buffer *buf, size_t num_padding);
+
+#endif /* KFUZZTEST_BRIDGE_BYTE_BUFFER_H */
diff --git a/tools/kfuzztest-bridge/encoder.c b/tools/kfuzztest-bridge/encoder.c
new file mode 100644
index 000000000000..dcc964ed51dc
--- /dev/null
+++ b/tools/kfuzztest-bridge/encoder.c
@@ -0,0 +1,391 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Encoder for KFuzzTest binary input format
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <errno.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+
+#include "byte_buffer.h"
+#include "input_parser.h"
+#include "rand_stream.h"
+
+#define KFUZZTEST_MAGIC 0xBFACE
+#define KFUZZTEST_PROTO_VERSION 0
+
+/* 
+ * The KFuzzTest binary input format requires at least 8 bytes of padding
+ * at the head and tail of every region.
+ */
+#define KFUZZTEST_POISON_SIZE 8
+
+#define BUFSIZE_SMALL 32
+#define BUFSIZE_LARGE 128
+
+struct region_info {
+	const char *name;
+	uint32_t offset;
+	uint32_t size;
+};
+
+struct reloc_info {
+	uint32_t src_reg;
+	uint32_t offset;
+	uint32_t dst_reg;
+};
+
+struct encoder_ctx {
+	struct byte_buffer *payload;
+	struct rand_stream *rand;
+
+	struct region_info *regions;
+	size_t num_regions;
+
+	struct reloc_info *relocations;
+	size_t num_relocations;
+
+	size_t minalign;
+	size_t reg_offset;
+	int curr_reg;
+};
+
+static void cleanup_ctx(struct encoder_ctx *ctx)
+{
+	if (ctx->regions)
+		free(ctx->regions);
+	if (ctx->relocations)
+		free(ctx->relocations);
+	if (ctx->payload)
+		destroy_byte_buffer(ctx->payload);
+}
+
+static int read_minalign(struct encoder_ctx *ctx)
+{
+	const char *minalign_file = "/sys/kernel/debug/kfuzztest/_config/minalign";
+	char buffer[64 + 1];
+	int count = 0;
+	int ret = 0;
+
+	FILE *f = fopen(minalign_file, "r");
+	if (!f)
+		return -ENOENT;
+
+	while (fread(&buffer[count++], 1, 1, f) == 1)
+		;
+	buffer[count] = '\0';
+
+	/*
+	 * atoi returns 0 on error. Since we expect a strictly positive
+	 * minalign value on all architectures, a return value of 0 represents
+	 * a failure.
+	 */
+	ret = atoi(buffer);
+	if (!ret) {
+		fclose(f);
+		return -EINVAL;
+	}
+	ctx->minalign = atoi(buffer);
+	fclose(f);
+	return 0;
+}
+
+static int pad_payload(struct encoder_ctx *ctx, size_t amount)
+{
+	int ret;
+
+	if ((ret = pad(ctx->payload, amount)))
+		return ret;
+	ctx->reg_offset += amount;
+	return 0;
+}
+
+static int align_payload(struct encoder_ctx *ctx, size_t alignment)
+{
+	size_t pad_amount = ROUND_UP_TO_MULTIPLE(ctx->payload->num_bytes, alignment) - ctx->payload->num_bytes;
+	return pad_payload(ctx, pad_amount);
+}
+
+static int lookup_reg(struct encoder_ctx *ctx, const char *name)
+{
+	size_t i;
+
+	for (i = 0; i < ctx->num_regions; i++) {
+		if (strcmp(ctx->regions[i].name, name) == 0)
+			return i;
+	}
+	return -ENOENT;
+}
+
+static int add_reloc(struct encoder_ctx *ctx, struct reloc_info reloc)
+{
+	void *new_ptr = realloc(ctx->relocations, (ctx->num_relocations + 1) * sizeof(struct reloc_info));
+	if (!new_ptr)
+		return -ENOMEM;
+
+	ctx->relocations = new_ptr;
+	ctx->relocations[ctx->num_relocations] = reloc;
+	ctx->num_relocations++;
+	return 0;
+}
+
+static int build_region_map(struct encoder_ctx *ctx, struct ast_node *top_level)
+{
+	struct ast_program *prog;
+	struct ast_node *reg;
+	size_t i;
+
+	if (top_level->type != NODE_PROGRAM)
+		return -EINVAL;
+
+	prog = &top_level->data.program;
+	ctx->regions = malloc(prog->num_members * sizeof(struct region_info));
+	if (!ctx->regions)
+		return -ENOMEM;
+
+	ctx->num_regions = prog->num_members;
+	for (i = 0; i < ctx->num_regions; i++) {
+		reg = prog->members[i];
+		/* Offset is determined after the second pass. */
+		ctx->regions[i] = (struct region_info){
+			.name = reg->data.region.name,
+			.size = node_size(reg),
+		};
+	}
+	return 0;
+}
+/**
+ * Encodes a value node as little-endian. A value node is one that has no
+ * children, and can therefore be directly written into the payload.
+ */
+static int encode_value_le(struct encoder_ctx *ctx, struct ast_node *node)
+{
+	size_t array_size;
+	char rand_char;
+	size_t length;
+	size_t i;
+	int reg;
+	int ret;
+
+	switch (node->type) {
+	case NODE_ARRAY:
+		array_size = node->data.array.num_elems * node->data.array.elem_size;
+		for (i = 0; i < array_size; i++) {
+			if ((ret = next_byte(ctx->rand, &rand_char)))
+				return ret;
+			if ((ret = append_byte(ctx->payload, rand_char)))
+				return ret;
+		}
+		ctx->reg_offset += array_size;
+		if (node->data.array.null_terminated) {
+			if ((ret = pad_payload(ctx, 1)))
+				return ret;
+			ctx->reg_offset++;
+		}
+		break;
+	case NODE_LENGTH:
+		reg = lookup_reg(ctx, node->data.length.length_of);
+		if (reg < 0)
+			return reg;
+		length = ctx->regions[reg].size;
+		if ((ret = encode_le(ctx->payload, length, node->data.length.byte_width)))
+			return ret;
+		ctx->reg_offset += node->data.length.byte_width;
+		break;
+	case NODE_PRIMITIVE:
+		for (i = 0; i < node->data.primitive.byte_width; i++) {
+			if ((ret = next_byte(ctx->rand, &rand_char)))
+				return ret;
+			if ((ret = append_byte(ctx->payload, rand_char)))
+				return ret;
+		}
+		ctx->reg_offset += node->data.primitive.byte_width;
+		break;
+	case NODE_POINTER:
+		reg = lookup_reg(ctx, node->data.pointer.points_to);
+		if (reg < 0)
+			return reg;
+		if ((ret = add_reloc(ctx, (struct reloc_info){ .src_reg = ctx->curr_reg,
+							       .offset = ctx->reg_offset,
+							       .dst_reg = reg })))
+			return ret;
+		/* Placeholder pointer value, as pointers are patched by KFuzzTest anyways. */
+		if ((ret = encode_le(ctx->payload, UINTPTR_MAX, sizeof(uintptr_t))))
+			return ret;
+		ctx->reg_offset += sizeof(uintptr_t);
+		break;
+	case NODE_PROGRAM:
+	case NODE_REGION:
+	default:
+		return -EINVAL;
+	}
+	return 0;
+}
+
+static int encode_region(struct encoder_ctx *ctx, struct ast_region *reg)
+{
+	struct ast_node *child;
+	size_t i;
+	int ret;
+
+	ctx->reg_offset = 0;
+	for (i = 0; i < reg->num_members; i++) {
+		child = reg->members[i];
+		if ((ret = align_payload(ctx, node_alignment(child))))
+			return ret;
+		if ((ret = encode_value_le(ctx, child)))
+			return ret;
+	}
+	return 0;
+}
+
+static int encode_payload(struct encoder_ctx *ctx, struct ast_node *top_level)
+{
+	struct ast_node *reg;
+	size_t i;
+	int ret;
+
+	for (i = 0; i < ctx->num_regions; i++) {
+		reg = top_level->data.program.members[i];
+		if ((ret = align_payload(ctx, MAX(ctx->minalign, node_alignment(reg)))))
+			return ret;
+
+		ctx->curr_reg = i;
+		ctx->regions[i].offset = ctx->payload->num_bytes;
+		if ((ret = encode_region(ctx, &reg->data.region)))
+			return ret;
+		if ((ret = pad_payload(ctx, KFUZZTEST_POISON_SIZE)))
+			return ret;
+	}
+	return align_payload(ctx, ctx->minalign);
+}
+
+static int encode_region_array(struct encoder_ctx *ctx, struct byte_buffer **ret)
+{
+	struct byte_buffer *reg_array;
+	struct region_info info;
+	int retcode;
+	size_t i;
+
+	reg_array = new_byte_buffer(BUFSIZE_SMALL);
+	if (!reg_array)
+		return -ENOMEM;
+
+	if ((retcode = encode_le(reg_array, ctx->num_regions, sizeof(uint32_t))))
+		goto fail;
+
+	for (i = 0; i < ctx->num_regions; i++) {
+		info = ctx->regions[i];
+		if ((retcode = encode_le(reg_array, info.offset, sizeof(uint32_t))))
+			goto fail;
+		if ((retcode = encode_le(reg_array, info.size, sizeof(uint32_t))))
+			goto fail;
+	}
+	*ret = reg_array;
+	return 0;
+
+fail:
+	destroy_byte_buffer(reg_array);
+	return retcode;
+}
+
+static int encode_reloc_table(struct encoder_ctx *ctx, size_t padding_amount, struct byte_buffer **ret)
+{
+	struct byte_buffer *reloc_table;
+	struct reloc_info info;
+	int retcode;
+	size_t i;
+
+	reloc_table = new_byte_buffer(BUFSIZE_SMALL);
+	if (!reloc_table)
+		return -ENOMEM;
+
+	if ((retcode = encode_le(reloc_table, ctx->num_relocations, sizeof(uint32_t))) ||
+	    (retcode = encode_le(reloc_table, padding_amount, sizeof(uint32_t))))
+		goto fail;
+
+	for (i = 0; i < ctx->num_relocations; i++) {
+		info = ctx->relocations[i];
+		if ((retcode = encode_le(reloc_table, info.src_reg, sizeof(uint32_t))) ||
+		    (retcode = encode_le(reloc_table, info.offset, sizeof(uint32_t))) ||
+		    (retcode = encode_le(reloc_table, info.dst_reg, sizeof(uint32_t))))
+			goto fail;
+	}
+	pad(reloc_table, padding_amount);
+	*ret = reloc_table;
+	return 0;
+
+fail:
+	destroy_byte_buffer(reloc_table);
+	return retcode;
+}
+
+static size_t reloc_table_size(struct encoder_ctx *ctx)
+{
+	return 2 * sizeof(uint32_t) + 3 * ctx->num_relocations * sizeof(uint32_t);
+}
+
+int encode(struct ast_node *top_level, struct rand_stream *r, size_t *num_bytes, struct byte_buffer **ret)
+{
+	struct byte_buffer *region_array = NULL;
+	struct byte_buffer *final_buffer = NULL;
+	struct byte_buffer *reloc_table = NULL;
+	size_t header_size;
+	int alignment;
+	int retcode;
+
+	struct encoder_ctx ctx = { 0 };
+	if ((retcode = read_minalign(&ctx)))
+		return retcode;
+
+	if ((retcode = build_region_map(&ctx, top_level)))
+		goto fail;
+
+	ctx.rand = r;
+	ctx.payload = new_byte_buffer(BUFSIZE_SMALL);
+	if (!ctx.payload) {
+		retcode = -ENOMEM;
+		goto fail;
+	}
+	if ((retcode = encode_payload(&ctx, top_level)))
+		goto fail;
+
+	if ((retcode = encode_region_array(&ctx, &region_array)))
+		goto fail;
+
+	header_size = sizeof(uint64_t) + region_array->num_bytes + reloc_table_size(&ctx);
+	alignment = node_alignment(top_level);
+	if ((retcode = encode_reloc_table(
+		     &ctx, ROUND_UP_TO_MULTIPLE(header_size + KFUZZTEST_POISON_SIZE, alignment) - header_size,
+		     &reloc_table)))
+		goto fail;
+
+	final_buffer = new_byte_buffer(BUFSIZE_LARGE);
+	if (!final_buffer) {
+		retcode = -ENOMEM;
+		goto fail;
+	}
+
+	if ((retcode = encode_le(final_buffer, KFUZZTEST_MAGIC, sizeof(uint32_t))) ||
+	    (retcode = encode_le(final_buffer, KFUZZTEST_PROTO_VERSION, sizeof(uint32_t))) ||
+	    (retcode = append_bytes(final_buffer, region_array->buffer, region_array->num_bytes)) ||
+	    (retcode = append_bytes(final_buffer, reloc_table->buffer, reloc_table->num_bytes)) ||
+	    (retcode = append_bytes(final_buffer, ctx.payload->buffer, ctx.payload->num_bytes))) {
+		destroy_byte_buffer(final_buffer);
+		goto fail;
+	}
+
+	*num_bytes = final_buffer->num_bytes;
+	*ret = final_buffer;
+
+fail:
+	if (region_array)
+		destroy_byte_buffer(region_array);
+	if (reloc_table)
+		destroy_byte_buffer(reloc_table);
+	cleanup_ctx(&ctx);
+	return retcode;
+}
diff --git a/tools/kfuzztest-bridge/encoder.h b/tools/kfuzztest-bridge/encoder.h
new file mode 100644
index 000000000000..73f8c4b7893c
--- /dev/null
+++ b/tools/kfuzztest-bridge/encoder.h
@@ -0,0 +1,16 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Encoder for KFuzzTest binary input format
+ *
+ * Copyright 2025 Google LLC
+ */
+#ifndef KFUZZTEST_BRIDGE_ENCODER_H
+#define KFUZZTEST_BRIDGE_ENCODER_H
+
+#include "input_parser.h"
+#include "rand_stream.h"
+#include "byte_buffer.h"
+
+int encode(struct ast_node *top_level, struct rand_stream *r, size_t *num_bytes, struct byte_buffer **ret);
+
+#endif /* KFUZZTEST_BRIDGE_ENCODER_H */
diff --git a/tools/kfuzztest-bridge/input_lexer.c b/tools/kfuzztest-bridge/input_lexer.c
new file mode 100644
index 000000000000..56f763e4394f
--- /dev/null
+++ b/tools/kfuzztest-bridge/input_lexer.c
@@ -0,0 +1,242 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Parser for KFuzzTest textual input format
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <errno.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+
+#include "input_lexer.h"
+
+struct keyword_map {
+	const char *keyword;
+	enum token_type type;
+};
+
+static struct keyword_map keywords[] = {
+	{ "ptr", TOKEN_KEYWORD_PTR }, { "arr", TOKEN_KEYWORD_ARR }, { "len", TOKEN_KEYWORD_LEN },
+	{ "str", TOKEN_KEYWORD_STR }, { "u8", TOKEN_KEYWORD_U8 },   { "u16", TOKEN_KEYWORD_U16 },
+	{ "u32", TOKEN_KEYWORD_U32 }, { "u64", TOKEN_KEYWORD_U64 },
+};
+
+static struct token *make_token(enum token_type type, size_t position)
+{
+	struct token *ret = calloc(1, sizeof(*ret));
+	ret->position = position;
+	ret->type = type;
+	return ret;
+}
+
+struct lexer {
+	const char *start;
+	const char *current;
+	size_t position;
+};
+
+static char advance(struct lexer *l)
+{
+	l->current++;
+	l->position++;
+	return l->current[-1];
+}
+
+static void retreat(struct lexer *l)
+{
+	l->position--;
+	l->current--;
+}
+
+static char peek(struct lexer *l)
+{
+	return *l->current;
+}
+
+static bool is_digit(char c)
+{
+	return c >= '0' && c <= '9';
+}
+
+static bool is_alpha(char c)
+{
+	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
+}
+
+static bool is_whitespace(char c)
+{
+	switch (c) {
+	case ' ':
+	case '\r':
+	case '\t':
+	case '\n':
+		return true;
+	default:
+		return false;
+	}
+}
+
+static void skip_whitespace(struct lexer *l)
+{
+	while (is_whitespace(peek(l)))
+		advance(l);
+}
+
+static struct token *number(struct lexer *l)
+{
+	struct token *tok;
+	uint64_t value;
+	while (is_digit(peek(l)))
+		advance(l);
+	value = strtoull(l->start, NULL, 10);
+	tok = make_token(TOKEN_INTEGER, l->position);
+	tok->data.integer = value;
+	return tok;
+}
+
+static enum token_type check_keyword(struct lexer *l, const char *keyword, enum token_type type)
+{
+	size_t len = strlen(keyword);
+
+	if (((size_t)(l->current - l->start) == len) && strncmp(l->start, keyword, len) == 0)
+		return type;
+	return TOKEN_IDENTIFIER;
+}
+
+static struct token *identifier(struct lexer *l)
+{
+	enum token_type type = TOKEN_IDENTIFIER;
+	struct token *tok;
+	size_t i;
+
+	while (is_digit(peek(l)) || is_alpha(peek(l)) || peek(l) == '_')
+		advance(l);
+
+	for (i = 0; i < ARRAY_SIZE(keywords); i++) {
+		if (check_keyword(l, keywords[i].keyword, keywords[i].type) != TOKEN_IDENTIFIER) {
+			type = keywords[i].type;
+			break;
+		}
+	}
+
+	tok = make_token(type, l->position);
+	if (!tok)
+		return NULL;
+	if (type == TOKEN_IDENTIFIER) {
+		tok->data.identifier.start = l->start;
+		tok->data.identifier.length = l->current - l->start;
+	}
+	return tok;
+}
+
+static struct token *scan_token(struct lexer *l)
+{
+	char c;
+	skip_whitespace(l);
+
+	l->start = l->current;
+	c = peek(l);
+
+	if (c == '\0')
+		return make_token(TOKEN_EOF, l->position);
+
+	advance(l);
+	switch (c) {
+	case '{':
+		return make_token(TOKEN_LBRACE, l->position);
+	case '}':
+		return make_token(TOKEN_RBRACE, l->position);
+	case '[':
+		return make_token(TOKEN_LBRACKET, l->position);
+	case ']':
+		return make_token(TOKEN_RBRACKET, l->position);
+	case ',':
+		return make_token(TOKEN_COMMA, l->position);
+	case ';':
+		return make_token(TOKEN_SEMICOLON, l->position);
+	default:
+		retreat(l);
+		if (is_digit(c))
+			return number(l);
+		if (is_alpha(c) || c == '_')
+			return identifier(l);
+		return make_token(TOKEN_ERROR, l->position);
+	}
+}
+
+int primitive_byte_width(enum token_type type)
+{
+	switch (type) {
+	case TOKEN_KEYWORD_U8:
+		return 1;
+	case TOKEN_KEYWORD_U16:
+		return 2;
+	case TOKEN_KEYWORD_U32:
+		return 4;
+	case TOKEN_KEYWORD_U64:
+		return 8;
+	default:
+		return 0;
+	}
+}
+
+int tokenize(const char *input, struct token ***tokens, size_t *num_tokens)
+{
+	struct lexer l = { .start = input, .current = input };
+	struct token **ret_tokens;
+	size_t token_arr_size;
+	size_t token_count;
+	struct token *tok;
+	void *tmp;
+	size_t i;
+	int err;
+
+	token_arr_size = 128;
+	ret_tokens = calloc(token_arr_size, sizeof(struct token *));
+	if (!ret_tokens)
+		return -ENOMEM;
+
+	token_count = 0;
+	do {
+		tok = scan_token(&l);
+		if (!tok) {
+			err = -ENOMEM;
+			goto failure;
+		}
+
+		if (token_count == token_arr_size) {
+			token_arr_size *= 2;
+			tmp = realloc(ret_tokens, token_arr_size);
+			if (!tmp) {
+				err = -ENOMEM;
+				goto failure;
+			}
+			ret_tokens = tmp;
+		}
+
+		ret_tokens[token_count] = tok;
+		if (tok->type == TOKEN_ERROR) {
+			err = -EINVAL;
+			goto failure;
+		}
+		token_count++;
+	} while (tok->type != TOKEN_EOF);
+
+	*tokens = ret_tokens;
+	*num_tokens = token_count;
+	return 0;
+
+failure:
+	for (i = 0; i < token_count; i++)
+		free(ret_tokens[i]);
+	free(ret_tokens);
+	return err;
+}
+
+bool is_primitive(struct token *tok)
+{
+	return tok->type >= TOKEN_KEYWORD_U8 && tok->type <= TOKEN_KEYWORD_U64;
+}
diff --git a/tools/kfuzztest-bridge/input_lexer.h b/tools/kfuzztest-bridge/input_lexer.h
new file mode 100644
index 000000000000..bdc55e08a3eb
--- /dev/null
+++ b/tools/kfuzztest-bridge/input_lexer.h
@@ -0,0 +1,57 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Lexer for KFuzzTest textual input format
+ *
+ * Copyright 2025 Google LLC
+ */
+#ifndef KFUZZTEST_BRIDGE_INPUT_LEXER_H
+#define KFUZZTEST_BRIDGE_INPUT_LEXER_H
+
+#include <stdint.h>
+#include <stdlib.h>
+#include <stdbool.h>
+
+#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
+
+enum token_type {
+	TOKEN_LBRACE,
+	TOKEN_RBRACE,
+	TOKEN_LBRACKET,
+	TOKEN_RBRACKET,
+	TOKEN_COMMA,
+	TOKEN_SEMICOLON,
+
+	TOKEN_KEYWORD_PTR,
+	TOKEN_KEYWORD_ARR,
+	TOKEN_KEYWORD_LEN,
+	TOKEN_KEYWORD_STR,
+	TOKEN_KEYWORD_U8,
+	TOKEN_KEYWORD_U16,
+	TOKEN_KEYWORD_U32,
+	TOKEN_KEYWORD_U64,
+
+	TOKEN_IDENTIFIER,
+	TOKEN_INTEGER,
+
+	TOKEN_EOF,
+	TOKEN_ERROR,
+};
+
+struct token {
+	enum token_type type;
+	union {
+		uint64_t integer;
+		struct {
+			const char *start;
+			size_t length;
+		} identifier;
+	} data;
+	int position;
+};
+
+int tokenize(const char *input, struct token ***tokens, size_t *num_tokens);
+
+bool is_primitive(struct token *tok);
+int primitive_byte_width(enum token_type type);
+
+#endif /* KFUZZTEST_BRIDGE_INPUT_LEXER_H */
diff --git a/tools/kfuzztest-bridge/input_parser.c b/tools/kfuzztest-bridge/input_parser.c
new file mode 100644
index 000000000000..61d324b9dc0e
--- /dev/null
+++ b/tools/kfuzztest-bridge/input_parser.c
@@ -0,0 +1,395 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Parser for the KFuzzTest textual input format
+ *
+ * This file implements a parser for a simple DSL used to describe C-like data
+ * structures. This format allows the kfuzztest-bridge tool to encode a random
+ * byte stream into the structured binary format expected by a KFuzzTest
+ * harness.
+ *
+ * The format consists of semicolon-separated "regions," which are analogous to
+ * C structs. For example:
+ *
+ * "my_struct { ptr[buf] len[buf, u64] }; buf { arr[u8, 42] };"
+ *
+ * This describes a `my_struct` region that contains a pointer to a `buf` region
+ * and its corresponding length encoded over 8 bytes, where `buf` itself
+ * contains a 42-byte array.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <errno.h>
+#include <stdio.h>
+#include <string.h>
+
+#include "input_lexer.h"
+#include "input_parser.h"
+
+
+static struct token *peek(struct parser *p)
+{
+	return p->tokens[p->curr_token];
+}
+
+static struct token *advance(struct parser *p)
+{
+	struct token *tok;
+	if (p->curr_token >= p->token_count)
+		return NULL;
+	tok = peek(p);
+	p->curr_token++;
+	return tok;
+}
+
+static struct token *consume(struct parser *p, enum token_type type, const char *err_msg)
+{
+	if (peek(p)->type != type) {
+		printf("parser failure at position %d: %s\n", peek(p)->position, err_msg);
+		return NULL;
+	}
+	return advance(p);
+}
+
+static bool match(struct parser *p, enum token_type t)
+{
+	struct token *tok = peek(p);
+	return tok->type == t;
+}
+
+static int parse_primitive(struct parser *p, struct ast_node **node_ret)
+{
+	struct ast_node *ret;
+	struct token *tok;
+	int byte_width;
+
+	tok = advance(p);
+	byte_width = primitive_byte_width(tok->type);
+	if (!byte_width)
+		return -EINVAL;
+
+	ret = malloc(sizeof(*ret));
+	if (!ret)
+		return -ENOMEM;
+
+	ret->type = NODE_PRIMITIVE;
+	ret->data.primitive.byte_width = byte_width;
+	*node_ret = ret;
+	return 0;
+}
+
+static int parse_ptr(struct parser *p, struct ast_node **node_ret)
+{
+	const char *points_to;
+	struct ast_node *ret;
+	struct token *tok;
+	if (!consume(p, TOKEN_KEYWORD_PTR, "expected 'ptr'"))
+		return -EINVAL;
+	if (!consume(p, TOKEN_LBRACKET, "expected '['"))
+		return -EINVAL;
+
+	tok = consume(p, TOKEN_IDENTIFIER, "expected identifier");
+	if (!tok)
+		return -EINVAL;
+
+	if (!consume(p, TOKEN_RBRACKET, "expected ']'"))
+		return -EINVAL;
+
+	ret = malloc(sizeof(*ret));
+	ret->type = NODE_POINTER;
+
+	points_to = strndup(tok->data.identifier.start, tok->data.identifier.length);
+	if (!points_to) {
+		free(ret);
+		return -EINVAL;
+	}
+
+	ret->data.pointer.points_to = points_to;
+	*node_ret = ret;
+	return 0;
+}
+
+static int parse_arr(struct parser *p, struct ast_node **node_ret)
+{
+	struct token *type, *num_elems;
+	struct ast_node *ret;
+
+	if (!consume(p, TOKEN_KEYWORD_ARR, "expected 'arr'") || !consume(p, TOKEN_LBRACKET, "expected '['"))
+		return -EINVAL;
+
+	type = advance(p);
+	if (!is_primitive(type))
+		return -EINVAL;
+
+	if (!consume(p, TOKEN_COMMA, "expected ','"))
+		return -EINVAL;
+
+	num_elems = consume(p, TOKEN_INTEGER, "expected integer");
+	if (!num_elems)
+		return -EINVAL;
+
+	if (!consume(p, TOKEN_RBRACKET, "expected ']'"))
+		return -EINVAL;
+
+	ret = malloc(sizeof(*ret));
+	if (!ret)
+		return -ENOMEM;
+
+	ret->type = NODE_ARRAY;
+	ret->data.array.num_elems = num_elems->data.integer;
+	ret->data.array.elem_size = primitive_byte_width(type->type);
+	ret->data.array.null_terminated = false;
+	*node_ret = ret;
+	return 0;
+}
+
+static int parse_str(struct parser *p, struct ast_node **node_ret)
+{
+	struct ast_node *ret;
+	struct token *len;
+
+	if (!consume(p, TOKEN_KEYWORD_STR, "expected 'str'") || !consume(p, TOKEN_LBRACKET, "expected '['"))
+		return -EINVAL;
+
+	len = consume(p, TOKEN_INTEGER, "expected integer");
+	if (!len)
+		return -EINVAL;
+
+	if (!consume(p, TOKEN_RBRACKET, "expected ']'"))
+		return -EINVAL;
+
+	ret = malloc(sizeof(*ret));
+	if (!ret)
+		return -ENOMEM;
+
+	/* A string is the susbet of byte arrays that are null-terminated. */
+	ret->type = NODE_ARRAY;
+	ret->data.array.num_elems = len->data.integer;
+	ret->data.array.elem_size = sizeof(char);
+	ret->data.array.null_terminated = true;
+	*node_ret = ret;
+	return 0;
+}
+
+static int parse_len(struct parser *p, struct ast_node **node_ret)
+{
+	struct token *type, *len;
+	struct ast_node *ret;
+
+	if (!consume(p, TOKEN_KEYWORD_LEN, "expected 'len'") || !consume(p, TOKEN_LBRACKET, "expected '['"))
+		return -EINVAL;
+
+	len = advance(p);
+	if (len->type != TOKEN_IDENTIFIER)
+		return -EINVAL;
+
+	if (!consume(p, TOKEN_COMMA, "expected ','"))
+		return -EINVAL;
+
+	type = advance(p);
+	if (!is_primitive(type))
+		return -EINVAL;
+
+	if (!consume(p, TOKEN_RBRACKET, "expected ']'"))
+		return -EINVAL;
+
+	ret = malloc(sizeof(*ret));
+	if (!ret)
+		return -ENOMEM;
+	ret->type = NODE_LENGTH;
+	ret->data.length.length_of = strndup(len->data.identifier.start, len->data.identifier.length);
+	ret->data.length.byte_width = primitive_byte_width(type->type);
+
+	*node_ret = ret;
+	return 0;
+}
+
+static int parse_type(struct parser *p, struct ast_node **node_ret)
+{
+	if (is_primitive(peek(p)))
+		return parse_primitive(p, node_ret);
+
+	if (peek(p)->type == TOKEN_KEYWORD_PTR)
+		return parse_ptr(p, node_ret);
+
+	if (peek(p)->type == TOKEN_KEYWORD_ARR)
+		return parse_arr(p, node_ret);
+
+	if (peek(p)->type == TOKEN_KEYWORD_STR)
+		return parse_str(p, node_ret);
+
+	if (peek(p)->type == TOKEN_KEYWORD_LEN)
+		return parse_len(p, node_ret);
+
+	return -EINVAL;
+}
+
+static int parse_region(struct parser *p, struct ast_node **node_ret)
+{
+	struct token *tok, *identifier;
+	struct ast_region *region;
+	struct ast_node *node;
+	struct ast_node *ret;
+	void *new_ptr;
+	size_t i;
+	int err;
+
+	identifier = consume(p, TOKEN_IDENTIFIER, "expected identifier");
+	if (!identifier)
+		return -EINVAL;
+
+	ret = malloc(sizeof(*ret));
+	if (!ret)
+		return -ENOMEM;
+
+	tok = consume(p, TOKEN_LBRACE, "expected '{'");
+	if (!tok) {
+		err = -EINVAL;
+		goto fail_early;
+	}
+
+	region = &ret->data.region;
+	region->name = strndup(identifier->data.identifier.start, identifier->data.identifier.length);
+	if (!region->name) {
+		err = -ENOMEM;
+		goto fail_early;
+	}
+
+	region->num_members = 0;
+	while (!match(p, TOKEN_RBRACE)) {
+		err = parse_type(p, &node);
+		if (err)
+			goto fail;
+		new_ptr = realloc(region->members, ++region->num_members * sizeof(struct ast_node *));
+		if (!new_ptr) {
+			err = -ENOMEM;
+			goto fail;
+		}
+		region->members = new_ptr;
+		region->members[region->num_members - 1] = node;
+	}
+
+	if (!consume(p, TOKEN_RBRACE, "expected '}'") || !consume(p, TOKEN_SEMICOLON, "expected ';'")) {
+		err = -EINVAL;
+		goto fail;
+	}
+
+	ret->type = NODE_REGION;
+	*node_ret = ret;
+	return 0;
+
+fail:
+	for (i = 0; i < region->num_members; i++)
+		free(region->members[i]);
+	free((void *)region->name);
+	free(region->members);
+fail_early:
+	free(ret);
+	return err;
+}
+
+static int parse_program(struct parser *p, struct ast_node **node_ret)
+{
+	struct ast_program *prog;
+	struct ast_node *reg;
+	struct ast_node *ret;
+	void *new_ptr;
+	size_t i;
+	int err;
+
+	ret = malloc(sizeof(*ret));
+	if (!ret)
+		return -ENOMEM;
+	ret->type = NODE_PROGRAM;
+
+	prog = &ret->data.program;
+	prog->num_members = 0;
+	prog->members = NULL;
+	while (!match(p, TOKEN_EOF)) {
+		err = parse_region(p, &reg);
+		if (err)
+			goto fail;
+
+		new_ptr = realloc(prog->members, ++prog->num_members * sizeof(struct ast_node *));
+		if (!new_ptr) {
+			err = -ENOMEM;
+			goto fail;
+		}
+		prog->members = new_ptr;
+		prog->members[prog->num_members - 1] = reg;
+	}
+
+	*node_ret = ret;
+	return 0;
+
+fail:
+	for (i = 0; i < prog->num_members; i++)
+		free(prog->members[i]);
+	free(prog->members);
+	free(ret);
+	return err;
+}
+
+size_t node_alignment(struct ast_node *node)
+{
+	size_t max_alignment = 1;
+	size_t i;
+
+	switch (node->type) {
+	case NODE_PROGRAM:
+		for (i = 0; i < node->data.program.num_members; i++)
+			max_alignment = MAX(max_alignment, node_alignment(node->data.program.members[i]));
+		return max_alignment;
+	case NODE_REGION:
+		for (i = 0; i < node->data.region.num_members; i++)
+			max_alignment = MAX(max_alignment, node_alignment(node->data.region.members[i]));
+		return max_alignment;
+	case NODE_ARRAY:
+		return node->data.array.elem_size;
+	case NODE_LENGTH:
+		return node->data.length.byte_width;
+	case NODE_PRIMITIVE:
+		/* Primitives are aligned to their size. */
+		return node->data.primitive.byte_width;
+	case NODE_POINTER:
+		return sizeof(uintptr_t);
+	}
+
+	/* Anything should be at least 1-byte-aligned. */
+	return 1;
+}
+
+size_t node_size(struct ast_node *node)
+{
+	size_t total = 0;
+	size_t i;
+
+	switch (node->type) {
+	case NODE_PROGRAM:
+		for (i = 0; i < node->data.program.num_members; i++)
+			total += node_size(node->data.program.members[i]);
+		return total;
+	case NODE_REGION:
+		for (i = 0; i < node->data.region.num_members; i++) {
+			/* Account for padding within region. */
+			total = ROUND_UP_TO_MULTIPLE(total, node_alignment(node->data.region.members[i]));
+			total += node_size(node->data.region.members[i]);
+		}
+		return total;
+	case NODE_ARRAY:
+		return node->data.array.elem_size * node->data.array.num_elems +
+		       (node->data.array.null_terminated ? 1 : 0);
+	case NODE_LENGTH:
+		return node->data.length.byte_width;
+	case NODE_PRIMITIVE:
+		return node->data.primitive.byte_width;
+	case NODE_POINTER:
+		return sizeof(uintptr_t);
+	}
+	return 0;
+}
+
+int parse(struct token **tokens, size_t token_count, struct ast_node **node_ret)
+{
+	struct parser p = { .tokens = tokens, .token_count = token_count, .curr_token = 0 };
+	return parse_program(&p, node_ret);
+}
diff --git a/tools/kfuzztest-bridge/input_parser.h b/tools/kfuzztest-bridge/input_parser.h
new file mode 100644
index 000000000000..7e965fd5def5
--- /dev/null
+++ b/tools/kfuzztest-bridge/input_parser.h
@@ -0,0 +1,81 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Parser for KFuzzTest textual input format
+ *
+ * Copyright 2025 Google LLC
+ */
+#ifndef KFUZZTEST_BRIDGE_INPUT_PARSER_H
+#define KFUZZTEST_BRIDGE_INPUT_PARSER_H
+
+#include <stdlib.h>
+
+/* Rounds x up to the nearest multiple of n. */
+#define ROUND_UP_TO_MULTIPLE(x, n) (((n) == 0) ? (0) : (((x) + (n) - 1) / (n)) * (n))
+
+#define MAX(a, b) ((a) > (b) ? (a) : (b))
+
+enum ast_node_type {
+	NODE_PROGRAM,
+	NODE_REGION,
+	NODE_ARRAY,
+	NODE_LENGTH,
+	NODE_PRIMITIVE,
+	NODE_POINTER,
+};
+
+struct ast_node; /* Forward declaration. */
+
+struct ast_program {
+	struct ast_node **members;
+	size_t num_members;
+};
+
+struct ast_region {
+	const char *name;
+	struct ast_node **members;
+	size_t num_members;
+};
+
+struct ast_array {
+	int elem_size;
+	int null_terminated; /* True iff the array should always end with 0. */
+	size_t num_elems;
+};
+
+struct ast_length {
+	size_t byte_width;
+	const char *length_of;
+};
+
+struct ast_primitive {
+	size_t byte_width;
+};
+
+struct ast_pointer {
+	const char *points_to;
+};
+
+struct ast_node {
+	enum ast_node_type type;
+	union {
+		struct ast_program program;
+		struct ast_region region;
+		struct ast_array array;
+		struct ast_length length;
+		struct ast_primitive primitive;
+		struct ast_pointer pointer;
+	} data;
+};
+
+struct parser {
+	struct token **tokens;
+	size_t token_count;
+	size_t curr_token;
+};
+
+int parse(struct token **tokens, size_t token_count, struct ast_node **node_ret);
+
+size_t node_size(struct ast_node *node);
+size_t node_alignment(struct ast_node *node);
+
+#endif /* KFUZZTEST_BRIDGE_INPUT_PARSER_H */
diff --git a/tools/kfuzztest-bridge/rand_stream.c b/tools/kfuzztest-bridge/rand_stream.c
new file mode 100644
index 000000000000..bca6b3de5aad
--- /dev/null
+++ b/tools/kfuzztest-bridge/rand_stream.c
@@ -0,0 +1,77 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Implements a cached file-reader for iterating over a byte stream of
+ * pseudo-random data
+ *
+ * Copyright 2025 Google LLC
+ */
+#include "rand_stream.h"
+
+static int refill(struct rand_stream *rs)
+{
+	rs->valid_bytes = fread(rs->buffer, sizeof(char), rs->buffer_size, rs->source);
+	rs->buffer_pos = 0;
+	if (rs->valid_bytes != rs->buffer_size && ferror(rs->source))
+		return ferror(rs->source);
+	return 0;
+}
+
+struct rand_stream *new_rand_stream(const char *path_to_file, size_t cache_size)
+{
+	struct rand_stream *rs;
+
+	rs = malloc(sizeof(*rs));
+	if (!rs)
+		return NULL;
+
+	rs->valid_bytes = 0;
+	rs->source = fopen(path_to_file, "rb");
+	if (!rs->source) {
+		free(rs);
+		return NULL;
+	}
+
+	if (fseek(rs->source, 0, SEEK_END)) {
+		fclose(rs->source);
+		free(rs);
+		return NULL;
+	}
+	rs->source_size = ftell(rs->source);
+
+	if (fseek(rs->source, 0, SEEK_SET)) {
+		fclose(rs->source);
+		free(rs);
+		return NULL;
+	}
+
+	rs->buffer = malloc(cache_size);
+	if (!rs->buffer) {
+		fclose(rs->source);
+		free(rs);
+		return NULL;
+	}
+	rs->buffer_size = cache_size;
+	return rs;
+}
+
+void destroy_rand_stream(struct rand_stream *rs)
+{
+	fclose(rs->source);
+	free(rs->buffer);
+	free(rs);
+}
+
+int next_byte(struct rand_stream *rs, char *ret)
+{
+	int res;
+
+	if (rs->buffer_pos >= rs->valid_bytes) {
+		res = refill(rs);
+		if (res)
+			return res;
+		if (rs->valid_bytes == 0)
+			return STREAM_EOF;
+	}
+	*ret = rs->buffer[rs->buffer_pos++];
+	return 0;
+}
diff --git a/tools/kfuzztest-bridge/rand_stream.h b/tools/kfuzztest-bridge/rand_stream.h
new file mode 100644
index 000000000000..acb3271d30ca
--- /dev/null
+++ b/tools/kfuzztest-bridge/rand_stream.h
@@ -0,0 +1,57 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Implements a cached file-reader for iterating over a byte stream of
+ * pseudo-random data
+ *
+ * Copyright 2025 Google LLC
+ */
+#ifndef KFUZZTEST_BRIDGE_RAND_STREAM_H
+#define KFUZZTEST_BRIDGE_RAND_STREAM_H
+
+#include <stdlib.h>
+#include <stdio.h>
+
+#define STREAM_EOF 1
+
+/**
+ * struct rand_stream - a buffered bytestream reader
+ *
+ * Reads and returns bytes from a file, using buffered pre-fetching to amortize
+ * the cost of reads.
+ */
+struct rand_stream {
+	FILE *source;
+	size_t source_size;
+	char *buffer;
+	size_t buffer_size;
+	size_t buffer_pos;
+	size_t valid_bytes;
+};
+
+/**
+ * new_rand_stream - return a new struct rand_stream
+ *
+ * @path_to_file: source of the output byte stream.
+ * @cache_size: size of the read-ahead cache in bytes.
+ */
+struct rand_stream *new_rand_stream(const char *path_to_file, size_t cache_size);
+
+/**
+ * destroy_rand_stream - clean up a rand stream's resources
+ *
+ * @rs: a struct rand_stream
+ */
+void destroy_rand_stream(struct rand_stream *rs);
+
+/**
+ * next_byte - return the next byte from a struct rand_stream
+ *
+ * @rs: an initialized struct rand_stream.
+ * @ret: return pointer.
+ *
+ * @return 0 on success or a negative value on failure.
+ *
+ */
+int next_byte(struct rand_stream *rs, char *ret);
+
+#endif /* KFUZZTEST_BRIDGE_RAND_STREAM_H */
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-5-ethan.w.s.graham%40gmail.com.
