Return-Path: <kasan-dev+bncBDP53XW3ZQCBBH4227CQMGQE3QUSDXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 06009B3EC76
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 18:43:13 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-45b920e0c25sf2880515e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 09:43:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756744992; cv=pass;
        d=google.com; s=arc-20240605;
        b=eTHnvFLrIUFs3BSJ/I9487Exrc2WZMzksX6BnYK6dUI6+h39bkKzrGdb+Izk67yqXy
         OJpHXuY1vEXq7XRYNwdDvZab8mPTRfK90H8Ce1+75COfqmWvMVykX8PY6UkqRa1IYMZW
         m6dRhT8Ok3v7wcXXjRWSevMTI7Pr3UAenbRQqx5v5r1AeU8vno7guC0SSIA95n2wVyCY
         vEHxWeIqzFlxYcAckhFU/5O7Ot/JsLysDa7cGBoe+4hMIg2ZelN4o/ozyj7UjVVDUUD1
         cs474J6o8HgaMCdi2OZiuOUzOPvR0d9AKcvpRN3uMzJGAqeat61g3h6n59tuleEsd7Gh
         oOGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=1ESSEZtBZw1/ZNLuW2aBBqBND44+yBitSgXIH6A1U1U=;
        fh=hl5JbONIquHiTLooYq66VxtnU19taahLgEKH2aYeEcs=;
        b=ZdUnJqGT6BWa2ZY2GmJXFawAPBSLaRt/RgOC7kvouwrgyQ7QANg9Aylw+jW7vso1ib
         1zSgJ3WodeFzlHWNDZiJTu/JYyeREMV/pCIhEqBVphTmDAo/BJCzL1i0/VS0WAcv9jjw
         TUIi6HU3kAeGSnkh2va9R81GX9+hfG4F6ET3ISc3CjBTwbttqpIX3HnEWWDupjyt3lDj
         HFsfb2szEKe20s3PyY1QzoV3vCjWeQGU2akAfgVRLIpKH6PXlg6yluQBJzv0Esv1pCG5
         +OXlhwJbZ5aqwRI1F57nXWCM86TVHzrKDCmCl5i82YH0da/q1aRmwySzH92bxelufYsM
         wlrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L2MVoCP7;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756744992; x=1757349792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1ESSEZtBZw1/ZNLuW2aBBqBND44+yBitSgXIH6A1U1U=;
        b=YA4LNAfuZYnprchn42NpGuJ75Kvg8FDTXQWpTT8DDpebSXMpG2h5ydG62fhdFGwTs3
         q3zLI7AiqXl9zM1Wy5P/QYM0k1ecB4YteI22TpSlF8t5YGGvQ+kihFowUXY4Wa9AekNG
         C2CaBGDksgTX3CotaxveKVtv+YXaQ9QvUBMO1veiVilwC2COh52tdgtqXXXDeg6tnS6t
         z9EwCtz7h9zt1+SJ6KtIO0f0Cvcqgco/T6bu5Jj2y2y4AzycwtAdgZP12qbMV/o6986X
         dX9wE0BxRkDTlr9PAWxpgY634t5T9RrNyNkr2zx3TuhT6e2NDLH8Fy8XAkouXyNjOd95
         aq8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756744992; x=1757349792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1ESSEZtBZw1/ZNLuW2aBBqBND44+yBitSgXIH6A1U1U=;
        b=Ha+AuS4ADIkf8atYVRPntL4a3pkdgMkIpKax4M59culoimI+5/9zGXqe1s73yrSosT
         JCEjwgdX97fs/cWQ+kbb0HgpogG8FD/MlPTXdPyIulnVc7hvGl20dsgSlME9GfiXLY3v
         OfpSr59Mp494Gf5RFdDeKxDzaE/jV8ePEeEHTxWpE9rndxAL60QEmMJjCbsmr4hzdgcY
         rdUG12oJLg/7bubt1UmFtNDeNFSLz6/zOwhUK5kzcSI9Tt8RqIFtgPAiK6T/M+kcc4/u
         Agc/sgsWlNxbBn5w8+rKjIiA3CSLJkJgiXQgMyUdEwD0L2nyp4KmrY13eW4C1VSAiU+X
         t+7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756744992; x=1757349792;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1ESSEZtBZw1/ZNLuW2aBBqBND44+yBitSgXIH6A1U1U=;
        b=CRALntm5O2WQUCvFpc7QsjU2Dc58m8GcQpb79rHFH+4bKF8kK1mjDFzKiZYUcD1Ei1
         R8dSlAL/DktsogjNgKIBiIsljzzd+lHynHoo3GhHgcp24SkC6gT044Kjzpa/QLztXoyH
         /Iy4iFk91WNR1G+Bjio8XehaEs+cjFwV58JZPAckjE5Yx/Kqx9VKMqWvpTgRFkqEo4os
         RezEqhlSXDqlt3/Sbu/hpvRF97CXIN4+G6jhhj8DqrHB3totgCIxyNhyKKm+uRENHXCE
         65W04Mb9A9MsXvdpDpthlJ07c7BamQUFQQECG7tgD6N+G0c/plYs5CQbTwmoY+9NjUGQ
         6tZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXctTAsByrKTTAmMDpAalW4YQKs9NBRcb3PCdgBI/jEruBFj5F04LnQZWL3bjFrEq8h1cuhbQ==@lfdr.de
X-Gm-Message-State: AOJu0YwH4HULGck5R5KuWBhqyp2AnFDfIxieeFhoLorV5RTDKoRVs1jm
	lV6lobKQJ2a4g/R3jYdH1nstN1DPfbY+6wtY7+xQWilvhzOmnhUcxmCA
X-Google-Smtp-Source: AGHT+IGB2TMeAjYP3/23GJeeF+B//g0Mw52tglH+eH7YfG6oF9ZprTMEo+SCXsKo/zA9C25JJoarHQ==
X-Received: by 2002:a05:600c:1384:b0:45b:7b00:c129 with SMTP id 5b1f17b1804b1-45b8558d694mr75496355e9.35.1756744992108;
        Mon, 01 Sep 2025 09:43:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdcex1ampwZ/B4sf0zVjZLzbIQY8yz3dHbchw5MpU0bcQ==
Received: by 2002:a05:600c:4d96:b0:45b:4b3a:8701 with SMTP id
 5b1f17b1804b1-45b78780a36ls17403465e9.0.-pod-prod-05-eu; Mon, 01 Sep 2025
 09:43:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXH28F2wFfUGpZothwDSaO7tLzNSe58a22Kz87G/7Ci1wcvTFpZOcUrEk1cAbNu2Ej5HFR7fZkdf4o=@googlegroups.com
X-Received: by 2002:a05:600c:4f08:b0:45b:6b0f:caf3 with SMTP id 5b1f17b1804b1-45b8843e109mr56148975e9.4.1756744989032;
        Mon, 01 Sep 2025 09:43:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756744989; cv=none;
        d=google.com; s=arc-20240605;
        b=hmKKLzR9KzfqlUrsqEsp0LKRH4RfZtGWRgvHCFjw5C506hjKaJpFI3t15fKQd4ZBP3
         Yk02ZHAxjoCTnQacx7ldyZzXeJDeZV5UuVb/Lp7lCwduehGwLDbyyAp7TGO+YaJHSGmD
         M+DfWOHpA6DSCPpmaRv3S9VbFK5SsKDRL9AM7/UXEKn2NIvvjvVrYUKPSkhLN0zaTf6o
         uMnaqdgCNJY703b7ZpBobiLlHjLAcK1PwkL9ZpBDGqNHYwop8rwwJeEvXPA11YMc31EL
         xfSaOmAStd5OEgyQsPNvnSeeYXWZw67IQTbUn06huNDtg2nJku6yWSqQ0CQEoHNSepHb
         Y1WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ElLDxS3ISbpc9W3XX626CI0E8tPaybmhnhLj5C8PR/U=;
        fh=ylZ/73ebTeYYSVcC/G36sYFxFJWp+fU8IlFPL7mDaSk=;
        b=H8KkZGidjGaI5C80gtK4RtdV3rJ6efqJwReZdufYEbd4I+wyYEBSiDNkoW9ZFumHE7
         PSartvdk6634ESOKacgNCxjevv1ZkJ2bR5m4QWyj7c7FRRLwhTTEVTVIXpXL7/qqTfO9
         oVqSDxzouGa9F2MSV7NofruTLbo4flK/GeI4hA6pNjvYoaNK1Owc57AyMCNYKy2Snm/3
         BZKIcPvrFAjfF6I0QGpiVSj4O3BOPO97HSXSUzY9AO+xlfK3xt0IW/H9O2zXJ+zfHMsy
         YGorOLJ0qjftNAPYHq6d26gSiPqDzKk6CjjFZyfrnGJz6TYX1mFAquqUu87lqWpLyRot
         ecuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L2MVoCP7;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b6f2f20e1si2261765e9.2.2025.09.01.09.43.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Sep 2025 09:43:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3d3f46e231fso1063853f8f.3;
        Mon, 01 Sep 2025 09:43:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUvM1ObAFoD9NV1312niKhg1R411TzZK/egl55KbTi5z79WWh9Uue31inXxMjCd/HdlC1N05zc4CNjR@googlegroups.com, AJvYcCW6HwVVBKN+pa149pscwWYSF4GXf5DmbSb41RKFwaYTIFhysEU1F5HVUfx9g/OOzbaz4lw6nPOX9xk=@googlegroups.com
X-Gm-Gg: ASbGncvVUhiMfcQP8sxWkdkjFmNETNKFNXmtnxmEyDv3NCn82f+KmhrETCYp/fN1Ssz
	GoQc9a5U7KhwdUeqLw9X+z4Pnl9XH7xFXC4VLr9wy043+kBCVXsKnwRDTANhyRvcH7wVkUgEukt
	zWhazwffFEcHpHwvBvF5FEkS/1Lr9ICcg9AHRtzg+ysc7JhlvHcTkfywMcHuOZAdw3e50PShDIN
	VNq5h+4yLieHj9woS/Ro/wUfPvJuDDlbFbCh6w9ILC5GVKSEHM0PM4q3a2IqO+0HBZAQvGm3sMS
	N3ccCpnL8zI99akZ0njX3ohP/APeOpZGskapCx2z4PHI4Zn2LRiNx2GvabWixkt+o3O22UseU4l
	yqNmDXkLHRkMfmVzYAnnu0x2rcBMEFUUQdLLGRYR29x38Jf64tl4qIhuljm8ylHqjR9UIvBvkj8
	olNA8kFxt2oP4pFrlmiw==
X-Received: by 2002:a5d:5f50:0:b0:3b7:8da6:1bb4 with SMTP id ffacd0b85a97d-3d1df53be89mr6492296f8f.58.1756744988266;
        Mon, 01 Sep 2025 09:43:08 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (140.225.77.34.bc.googleusercontent.com. [34.77.225.140])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf274dde69sm15955362f8f.14.2025.09.01.09.43.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 09:43:07 -0700 (PDT)
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
Subject: [PATCH v2 RFC 0/7] KFuzzTest: a new kernel fuzzing framework
Date: Mon,  1 Sep 2025 16:42:05 +0000
Message-ID: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.318.gd7df087d1a-goog
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=L2MVoCP7;       spf=pass
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

This patch series introduces KFuzzTest, a lightweight framework for
creating in-kernel fuzz targets for internal kernel functions.

The primary motivation for KFuzzTest is to simplify the fuzzing of
low-level, relatively stateless functions (e.g., data parsers, format
converters) that are difficult to exercise effectively from the syscall
boundary. It is intended for in-situ fuzzing of kernel code without
requiring that it be built as a separate userspace library or that its
dependencies be stubbed out. Using a simple macro-based API, developers
can add a new fuzz target with minimal boilerplate code.

The core design consists of three main parts:
1. A `FUZZ_TEST(name, struct_type)` macro that allows developers to
   easily define a fuzz test.
2. A binary input format that allows a userspace fuzzer to serialize
   complex, pointer-rich C structures into a single buffer.
3. Metadata for test targets, constraints, and annotations, which is
   emitted into dedicated ELF sections to allow for discovery and
   inspection by userspace tools. These are found in
   ".kfuzztest_{targets, constraints, annotations}".

To demonstrate this framework's viability, support for KFuzzTest has been
prototyped in a development fork of syzkaller, enabling coverage-guided
fuzzing. To validate its end-to-end effectiveness, we performed an
experiment by manually introducing an off-by-one buffer over-read into
pkcs7_parse_message, like so:

-ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
+ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);

A syzkaller instance fuzzing the new test_pkcs7_parse_message target
introduced in patch 7 successfully triggered the bug inside of
asn1_ber_decoder in under a 30 seconds from a cold start.

This RFC continues to seek feedback on the overall design of KFuzzTest
and the minor changes made in V2. We are particularly interested in
comments on:
- The ergonomics of the API for defining fuzz targets.
- The overall workflow and usability for a developer adding and running
  a new in-kernel fuzz target.
- The high-level architecture.

The patch series is structured as follows:
- Patch 1 adds and exposes a new KASAN function needed by KFuzzTest.
- Patch 2 introduces the core KFuzzTest API and data structures.
- Patch 3 adds the runtime implementation for the framework.
- Patch 4 adds a tool for sending structured inputs into a fuzz target.
- Patch 5 adds documentation.
- Patch 6 provides example fuzz targets.
- Patch 7 defines fuzz targets for real kernel functions.

Changes in v2:
- Per feedback from Eric Biggers and Ignat Korchagin, move the /crypto
  fuzz target samples into a new /crypto/tests directory to separate
  them from the functional source code.
- Per feedback from David Gow and Marco Elver, add the kfuzztest-bridge
  tool to generate structured inputs for fuzz targets. The tool can
  populate parts of the input structure with data from a file, enabling
  both simple randomized fuzzing (e.g, using /dev/urandom) and
  targeted testing with file-based inputs.

We would like to thank David Gow for his detailed feedback regarding the
potential integration with KUnit. The v1 discussion highlighted three
potential paths: making KFuzzTests a special case of KUnit tests, sharing
implementation details in a common library, or keeping the frameworks
separate while ensuring API familiarity.

Following a productive conversation with David, we are moving forward
with the third option for now. While tighter integration is an
attractive long-term goal, we believe the most practical first step is
to establish KFuzzTest as a valuable, standalone framework. This avoids
premature abstraction (e.g., creating a shared library with only one
user) and allows KFuzzTest's design to stabilize based on its specific
focus: fuzzing with complex, structured inputs.

Ethan Graham (7):
  mm/kasan: implement kasan_poison_range
  kfuzztest: add user-facing API and data structures
  kfuzztest: implement core module and input processing
  tools: add kfuzztest-bridge utility
  kfuzztest: add ReST documentation
  kfuzztest: add KFuzzTest sample fuzz targets
  crypto: implement KFuzzTest targets for PKCS7 and RSA parsing

 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/kfuzztest.rst         | 371 +++++++++++++
 arch/x86/kernel/vmlinux.lds.S                 |  22 +
 crypto/asymmetric_keys/Kconfig                |  15 +
 crypto/asymmetric_keys/Makefile               |   2 +
 crypto/asymmetric_keys/tests/Makefile         |   2 +
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    |  22 +
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  |  38 ++
 include/linux/kasan.h                         |  16 +
 include/linux/kfuzztest.h                     | 508 ++++++++++++++++++
 lib/Kconfig.debug                             |   1 +
 lib/Makefile                                  |   2 +
 lib/kfuzztest/Kconfig                         |  20 +
 lib/kfuzztest/Makefile                        |   4 +
 lib/kfuzztest/main.c                          | 163 ++++++
 lib/kfuzztest/parse.c                         | 208 +++++++
 mm/kasan/shadow.c                             |  31 ++
 samples/Kconfig                               |   7 +
 samples/Makefile                              |   1 +
 samples/kfuzztest/Makefile                    |   3 +
 samples/kfuzztest/overflow_on_nested_buffer.c |  52 ++
 samples/kfuzztest/underflow_on_buffer.c       |  41 ++
 tools/Makefile                                |  15 +-
 tools/kfuzztest-bridge/.gitignore             |   2 +
 tools/kfuzztest-bridge/Build                  |   6 +
 tools/kfuzztest-bridge/Makefile               |  48 ++
 tools/kfuzztest-bridge/bridge.c               |  93 ++++
 tools/kfuzztest-bridge/byte_buffer.c          |  87 +++
 tools/kfuzztest-bridge/byte_buffer.h          |  31 ++
 tools/kfuzztest-bridge/encoder.c              | 356 ++++++++++++
 tools/kfuzztest-bridge/encoder.h              |  16 +
 tools/kfuzztest-bridge/input_lexer.c          | 243 +++++++++
 tools/kfuzztest-bridge/input_lexer.h          |  57 ++
 tools/kfuzztest-bridge/input_parser.c         | 373 +++++++++++++
 tools/kfuzztest-bridge/input_parser.h         |  79 +++
 tools/kfuzztest-bridge/rand_stream.c          |  61 +++
 tools/kfuzztest-bridge/rand_stream.h          |  46 ++
 37 files changed, 3037 insertions(+), 6 deletions(-)
 create mode 100644 Documentation/dev-tools/kfuzztest.rst
 create mode 100644 crypto/asymmetric_keys/tests/Makefile
 create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
 create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
 create mode 100644 include/linux/kfuzztest.h
 create mode 100644 lib/kfuzztest/Kconfig
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 lib/kfuzztest/parse.c
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c
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

-- 
2.51.0.318.gd7df087d1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901164212.460229-1-ethan.w.s.graham%40gmail.com.
