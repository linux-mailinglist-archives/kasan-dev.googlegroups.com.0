Return-Path: <kasan-dev+bncBDP53XW3ZQCBB4NNY3EQMGQELTRXSUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id A8A3BCA3F42
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:07 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-640ed3ad89bsf1440734a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857587; cv=pass;
        d=google.com; s=arc-20240605;
        b=XSRSRgp2//UevVHFVMeYifbIQEHz489+s4Rvpwed0h3eF0FLAhH8CEbRc45kkjKVqm
         rWVAA/a+NbzqH7yCUmSbZbSuIMSTkPNp4DI38uGramExpVhIEquDUAXJegT6293mDYCC
         LFCFt0mi4PNh9ceL4Lz2HIkdq4Yk+/E0DDg2edw1DZuqKRrRtT7HLpcWBtNT2sggmWTW
         Wogt9eBZ7/SMtdyfe19dxHy3jYLCR8JmS+SStHhMULUdH9nyOjaCtu8I4LZ/K0QrorkI
         jkQ4UQ8a/hR1lfAyk9d1+JoS/PSz46vr60pkRAozduujCozjS+DW348+JQF8QvGSfHwP
         RJxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=KJiVYayfeK5UYYQAvEo3Vz2quNsEj4rKi6UcjWqBqeU=;
        fh=CRCfzobcJJ5OthEwOzqGIiLE1OuZKd86CpgOJOGutq0=;
        b=AFrDvGhSBzZVfVlIk3Gw9BHK8uvN/hYV1bhDbdZFRGB2WQT7lePyXfVlBm21BrDFHl
         GSXCVMB/T1xb+HOSw3R1b/4zaP9KBj3HkWODruvP8FcLsZ5ybClemtdTU2GBM9icXrRd
         qRMkl+rJNtM+nq3OxNozpsaqOYBBz4gPObGSko85JaOf4TZmNqydLRUz/qbft+douOol
         spenz0kAhWb6QhCjNPzwTTOG5XwhP/JpcJ9posh7EqI6N5Q0gKNF8/g8vwQiCOBPqm5V
         aC3ypCSjj1+/il1JkhrrpiCOnRMiU7FVpImBtaDXjuTrVDWqQueHNB5FFD8YdR+24ar/
         dFMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dwuhr5Tp;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857587; x=1765462387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KJiVYayfeK5UYYQAvEo3Vz2quNsEj4rKi6UcjWqBqeU=;
        b=QrhxiCzB1FYBuUlccmOV5U1RndP1Azyg6bVZleBRyNamq9g3t9q5pU/g2b8bWKBXuB
         YVTeLfGKLvGOOOiUm++rYAi2EL66XkNb7N1lg2sppSQLjrZvMRicPn8eLX6t+8c8Hp8y
         hGjvjgYBqwAFyTXNDZOrMdEog1MxKquyHUSD/LOHlZr3YzgsZSW1lxqdL/QC07HEohkn
         Bzf+1/CSD+YhR4TIV3PIFxWDnz4Db+Z54uC6Dgza4c2z/uAx9yZPSosmaIEOllDPmn1r
         dMhU8C/iTtpOML6JudSuHjSXvI0WXrkuvVix/+eAB4Zqt2oYdxm+W6dGekgDULdq2qAj
         sCdA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857587; x=1765462387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KJiVYayfeK5UYYQAvEo3Vz2quNsEj4rKi6UcjWqBqeU=;
        b=cjbzgJeMEJtsP/D75vbrUgIczum+hJxeBgiyz8gXWb0Uqd2nVDt3tnFRM6F6n6Xvu8
         A3GQcHAc3/zBtKu0BxcVnuVbv3Tsf6DvrHWYAv6TzS+fdWKJ646qAziRm88qVhQLrMIX
         VunmBZ6vwOhJ2CzvfKQ8OGx1/1zOHsKSRe5Yi5QF573d3Gh4vjr4FsI0nJU/PaI/QPgW
         MOctuGEOBN70FCr8aU+3f56jV3FSLddCMsGcwpR9IkMNIl2EO7lFRHIRfwuCA7Tc+MEz
         D0OaNtniaONdflHzJKnaNnRom3fXTg5g6e2zpa6EOzs+Md4ApW10bvJbAW7xADut6/eD
         /MYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857587; x=1765462387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KJiVYayfeK5UYYQAvEo3Vz2quNsEj4rKi6UcjWqBqeU=;
        b=F13VQ4yeUC3HQuO9KTmO5xx++sYM4qbtKiwwOii8Q2h1iDowJVSMidYUjG5Pe2EPTh
         TGLTtcy5Kdl94SDgatOlHV5nhqfdlx02zXFxQR6PRmXIjLVhR8IOkv7pmwKBPR0MkVeB
         sOAnGzAJTpxx+zdLf+iXV/gs/a+vM+0+gw0ZCCx+fbgDPkoWRJkHkqlBGlYtitxH+L8L
         qKUjunVXvaJQ3UvdsnTyyGccmoB/VXwDB7PeRnXoFppJeW3vH+P0fZUQ6TDVaVnkaFi0
         rMCBVjrUfa+hEPUAYeXk4LLh7Im4p+FlnDr81tlY51syzxF14tph3YjT6Gscc3sOWQPH
         QSQA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbQwBJT4lnlSh9sX1DN0OpxQ5y2hqXiLNU4n37LomHcqsWSlQyx1XGFiB5/uhCgDjp+T5gvg==@lfdr.de
X-Gm-Message-State: AOJu0YzA/qU+7CvtWrANfKvFuLo19NAVY5QEPdKVgu4yq8p5qSNDKr7s
	OywoZO4Uq+hjve9/EkUX68ReOYvZkYsA1GqjXpRffFrWIEFsKWsv37P0
X-Google-Smtp-Source: AGHT+IFR7eCx0ef4jUq80+4FDiZjYIvdlM731sDNfH9DIr0eS3d2yAyMY07y3vsZ5yGBpJ8xT1HGPA==
X-Received: by 2002:a05:6402:520a:b0:645:dc9d:853b with SMTP id 4fb4d7f45d1cf-6479c4769d2mr5561376a12.12.1764857586692;
        Thu, 04 Dec 2025 06:13:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aT9f005zoMtM0N5CpF16xqRR2E3iM7rQjZ2PzH5jRL8Q=="
Received: by 2002:a05:6402:1a45:b0:641:5a07:215b with SMTP id
 4fb4d7f45d1cf-647ad5c77d4ls817204a12.2.-pod-prod-06-eu; Thu, 04 Dec 2025
 06:13:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWaBbowEUFPwHZkgpRIaUMs81OOWpUaQdEmheX/BKtKZwRi9GoyWy2FYCX0qurjIZxcPPAigTCjwlI=@googlegroups.com
X-Received: by 2002:a17:907:8687:b0:b73:7f1c:b8d8 with SMTP id a640c23a62f3a-b79db5ef7b2mr653888766b.0.1764857582907;
        Thu, 04 Dec 2025 06:13:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857582; cv=none;
        d=google.com; s=arc-20240605;
        b=ZpZ/HNJo4uw2p3hmuFaiwFAqZxjuW9H99gfhMgXxjICxkctHTmKhob/3ztd4wKql71
         Q0Nu5pElhAIgMpqR6TfMMjWgvGT26im4Rq8IOXILDKld5JI+YuM7et2YZIxVnL0A8+Ea
         sg1xt4wXB1CC7L572Clc3NTANs1+x4mdt0fhcC4PrrlCAYfe6FdBEJ1gIyM1ybUq85o/
         vZnG3Jhwd4UKTdv0+/u/lEHvNiJVf8a1RLR9Y2UZ1Lyh8i+Vv3ZctLDEub4Mds36lI3X
         SDh/GUOTZJeAPLeSXsdgwm5MVDQ9X5WNjk10x/yBheuOvgOosos0BtC4avFo2OuRrmva
         Xsdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Zml3KS+UsrvHkR8m+pYaf5EprirpHcFq08V4fzn955Y=;
        fh=z8gZuOEBvDqyNuIoNBiPlfZqZB5UrVE5Gkx6w/mbtkg=;
        b=h1/gFpCcQMe2R8PRxggpfHXdeb/yHhklAYX/0aGXSSvvLrAZTfBxsErnCXgz0mAUBc
         0TFJcvVsJsYNS3zx5oSTJfck8gjoqTilJWG7lGDIwDpvqU7HKHBKtk5c4vF97MGYSiq6
         rgI0Nm/swwA2J96v/lv08yweBwO2eN8NetjVfaC29BVtdG3KuIYAfEzCFqxmnV7jPUFu
         xAsAWcSC7HHgnlHD0vHWMu+O7rRpyZt4ov7pPSE4c5eUvfqR/+AVIN7EvUuQBVK9Smzr
         Ylr+UmxuZrfQSHveUJnSk60ARoN5fGAKEcamvMKjVbUVKu/LbbRHP1VDV9TDD3ZJqCcd
         WxxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dwuhr5Tp;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b2c51979si21636a12.0.2025.12.04.06.13.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:02 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-42b3669ca3dso518471f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXPLhhc35bzgDW4DrsLsc0a9+X/ScCxZoRnbAumuLQmbbL3Pn619XMUo1sf4wlSp/+n37Raj07JqHw=@googlegroups.com
X-Gm-Gg: ASbGnctHaIxw7dY4vuL26Y9wF7vi41tVWaIEmzrWQbvW+uWVnzVpoQTStfYCB3KXzlO
	J42MynSbJazhVSpOPggHqO07repBVbaa5Gco+nC/dh9DgmEy/F3h0CPBdpuk7UC4N5S3fQqbMXR
	hBzWVbqcXAoeTgX8krAV76H8ffJldMNXr8MQbcWj/ZOyy76SM+JRRyYo5YRE3CfljTEDggolgbv
	zn+9dh4c5xJsRmOEKCVyLEiaqEo7M7mqot4P1JNfSM6h8dXPIECWpqHCU+URr8wRsCGLD4KhR4A
	S/g2BPPZ7MTVgNqmTHex27N4FPELi8I4hOdOBcuh9NYlhAyAqywjqDRa0NIo+JPJxD7tirSZy/R
	uRf+slE+qDKDHAJYZBp+X+DF7mSQ5gUPS11GAHZxNBuZ+JT7Ao0i8b3POf0sWlyRyw8cd5344Zn
	l6utJYkHDdSHlzEGCe2Or2IEaBqcCLvreCY9XiAjRTylvpx+Bf2/WePK/fWJWKn4mDBg==
X-Received: by 2002:a05:6000:2507:b0:42b:3e0a:64af with SMTP id ffacd0b85a97d-42f7317205bmr6670197f8f.11.1764857582226;
        Thu, 04 Dec 2025 06:13:02 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:01 -0800 (PST)
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
	tarasmadan@google.com
Subject: [PATCH v3 00/10] KFuzzTest: a new kernel fuzzing framework
Date: Thu,  4 Dec 2025 15:12:39 +0100
Message-ID: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dwuhr5Tp;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
1. The `FUZZ_TEST(name, struct_type)` and `FUZZ_TEST_SIMPLE(name)`
   macros that allow developers to easily define a fuzz test.
2. A binary input format that allows a userspace fuzzer to serialize
   complex, pointer-rich C structures into a single buffer.
3. Metadata for test targets, constraints, and annotations, which is
   emitted into dedicated ELF sections to allow for discovery and
   inspection by userspace tools. These are found in
   ".kfuzztest_{targets, constraints, annotations}".

As of September 2025, syzkaller supports KFuzzTest targets out of the
box, and without requiring any hand-written descriptions - the fuzz
target and its constraints + annotations are the sole source of truth.

To validate the framework's end-to-end effectiveness, we performed an
experiment by manually introducing an off-by-one buffer over-read into
pkcs7_parse_message, like so:

- ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
+ ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);

A syzkaller instance fuzzing the new test_pkcs7_parse_message target
introduced in patch 7 successfully triggered the bug inside of
asn1_ber_decoder in under 30 seconds from a cold start. Similar
experiments on the other new fuzz targets (patches 8-9) also
successfully identified injected bugs, proving that KFuzzTest is
effective when paired with a coverage-guided fuzzing engine.


The patch series is structured as follows:
- Patch 1 adds and exposes kasan_poison_range for poisoning memory
  ranges with an unaligned start address and KASAN_GRANULE_SIZE aligned
  end address.
- Patch 2 introduces the core KFuzzTest API and data structures.
- Patch 3 introduces the FUZZ_TEST_SIMPLE API for blob-based fuzzing.
- Patch 4 adds the runtime implementation for the framework.
- Patch 5 adds a tool for sending structured inputs into a fuzz target.
- Patch 6 adds documentation.
- Patch 7 provides sample fuzz targets.
- Patch 8 defines fuzz targets for several functions in /crypto.
- Patch 9 defines a fuzz target for parse_xy in /drivers/auxdisplay.
- Patch 10 adds maintainer information for KFuzzTest.

Changes since PR v2:
- Introduce the FUZZ_TEST_SIMPLE macro (patch 3) for blob-based fuzzing,
  and update the module code (now patch 4) to initialize an input_simple
  debugfs file for such targets. While not explicitly requested by
  Johannes Berg, this was developed to address his concerns of the
  serialization format representing a hard barrier for entry.
- Update the crypto/ fuzz targets to use the FUZZ_TEST_SIMPLE macro.
- Per feedback from Kees Cook, the fuzz target for binfmt_load_script
  (previously patch 9/10) has been dropped as it is trivial to fuzz from
  userspace and therefore not a good example of KFuzzTest in action.
- Per feedback from Andrey Konovalov, introduce some WARN_ONs and remove
  redundant checks from kasan_poison_range.
- Per feedback from Andrey Konovalov, move kasan_poison_range's
  implementation into mm/kasan/common.c so that it is built with HW_TAGS
  mode enabled.
- Per feedback from Andy Shevchenko and Lukas Wunner, address the build
  system concerns.

Ethan Graham (10):
  mm/kasan: implement kasan_poison_range
  kfuzztest: add user-facing API and data structures
  kfuzztest: introduce the FUZZ_TEST_SIMPLE macro
  kfuzztest: implement core module and input processing
  tools: add kfuzztest-bridge utility
  kfuzztest: add ReST documentation
  kfuzztest: add KFuzzTest sample fuzz targets
  crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
  drivers/auxdisplay: add a KFuzzTest for parse_xy()
  MAINTAINERS: add maintainer information for KFuzzTest

 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/kfuzztest.rst         | 491 +++++++++++++++
 MAINTAINERS                                   |   8 +
 crypto/asymmetric_keys/Makefile               |   2 +
 crypto/asymmetric_keys/tests/Makefile         |   4 +
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    |  17 +
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  |  20 +
 drivers/auxdisplay/Makefile                   |   3 +
 drivers/auxdisplay/tests/charlcd_kfuzz.c      |  22 +
 include/asm-generic/vmlinux.lds.h             |  26 +-
 include/linux/kasan.h                         |  11 +
 include/linux/kfuzztest.h                     | 573 ++++++++++++++++++
 lib/Kconfig.debug                             |   1 +
 lib/Makefile                                  |   2 +
 lib/kfuzztest/Kconfig                         |  20 +
 lib/kfuzztest/Makefile                        |   4 +
 lib/kfuzztest/main.c                          | 278 +++++++++
 lib/kfuzztest/parse.c                         | 236 ++++++++
 mm/kasan/common.c                             |  37 ++
 samples/Kconfig                               |   7 +
 samples/Makefile                              |   1 +
 samples/kfuzztest/Makefile                    |   3 +
 samples/kfuzztest/overflow_on_nested_buffer.c |  71 +++
 samples/kfuzztest/underflow_on_buffer.c       |  51 ++
 tools/Makefile                                |  18 +-
 tools/testing/kfuzztest-bridge/.gitignore     |   2 +
 tools/testing/kfuzztest-bridge/Build          |   6 +
 tools/testing/kfuzztest-bridge/Makefile       |  49 ++
 tools/testing/kfuzztest-bridge/bridge.c       | 115 ++++
 tools/testing/kfuzztest-bridge/byte_buffer.c  |  85 +++
 tools/testing/kfuzztest-bridge/byte_buffer.h  |  31 +
 tools/testing/kfuzztest-bridge/encoder.c      | 390 ++++++++++++
 tools/testing/kfuzztest-bridge/encoder.h      |  16 +
 tools/testing/kfuzztest-bridge/input_lexer.c  | 256 ++++++++
 tools/testing/kfuzztest-bridge/input_lexer.h  |  58 ++
 tools/testing/kfuzztest-bridge/input_parser.c | 425 +++++++++++++
 tools/testing/kfuzztest-bridge/input_parser.h |  82 +++
 .../testing/kfuzztest-bridge/kfuzztest-bridge | Bin 0 -> 911160 bytes
 tools/testing/kfuzztest-bridge/rand_stream.c  |  77 +++
 tools/testing/kfuzztest-bridge/rand_stream.h  |  57 ++
 40 files changed, 3552 insertions(+), 4 deletions(-)
 create mode 100644 Documentation/dev-tools/kfuzztest.rst
 create mode 100644 crypto/asymmetric_keys/tests/Makefile
 create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
 create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
 create mode 100644 drivers/auxdisplay/tests/charlcd_kfuzz.c
 create mode 100644 include/linux/kfuzztest.h
 create mode 100644 lib/kfuzztest/Kconfig
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 lib/kfuzztest/parse.c
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c
 create mode 100644 tools/testing/kfuzztest-bridge/.gitignore
 create mode 100644 tools/testing/kfuzztest-bridge/Build
 create mode 100644 tools/testing/kfuzztest-bridge/Makefile
 create mode 100644 tools/testing/kfuzztest-bridge/bridge.c
 create mode 100644 tools/testing/kfuzztest-bridge/byte_buffer.c
 create mode 100644 tools/testing/kfuzztest-bridge/byte_buffer.h
 create mode 100644 tools/testing/kfuzztest-bridge/encoder.c
 create mode 100644 tools/testing/kfuzztest-bridge/encoder.h
 create mode 100644 tools/testing/kfuzztest-bridge/input_lexer.c
 create mode 100644 tools/testing/kfuzztest-bridge/input_lexer.h
 create mode 100644 tools/testing/kfuzztest-bridge/input_parser.c
 create mode 100644 tools/testing/kfuzztest-bridge/input_parser.h
 create mode 100755 tools/testing/kfuzztest-bridge/kfuzztest-bridge
 create mode 100644 tools/testing/kfuzztest-bridge/rand_stream.c
 create mode 100644 tools/testing/kfuzztest-bridge/rand_stream.h

-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-1-ethan.w.s.graham%40gmail.com.
