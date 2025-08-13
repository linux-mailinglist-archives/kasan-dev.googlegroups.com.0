Return-Path: <kasan-dev+bncBDP53XW3ZQCBBYVK6LCAMGQEZRIBBWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BECD6B24ABB
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 15:38:43 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3b7886bfc16sf4239840f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755092323; cv=pass;
        d=google.com; s=arc-20240605;
        b=GTB6NIKnwg5MTfNp/HddAFX554s6hgSQ525kFe3ZWyYqtePES1m43Rps6h7+7GrG1h
         OnyxGwZpl1XOBZbDX/8lUrYPVigtD/Rl88V74AwDf25Twm5unbxLjBwbl56q9XWA2bSA
         HkIjIISnaOvMgh42+oS0jXwOs2MXBXT868AWtkt2zGCZ17epdC/ZmuAF0mxDLWKGGLm+
         xOL4hHRKDP5axRgRJbDq4YRjV3RndUfRMU4+fX3VQG2nSfpddCPGxKYBmDA/pYrVUwAT
         0rBIP90h2a1A5nY8vSQnHTC+202d3DnpplxywpSMU+bRz0U38cWUS19j6Z+7F/oLxc8x
         ttFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=8altNzJwVIG+F+c84BgBkb4kF0YZmrD9Cu+hk54UbwE=;
        fh=FNy/ruT6078rDk6SbgZHefkvhSBBLpZA73IjherIqdc=;
        b=RZMeJUoS++VshUnv2k6rssmDZoXL0RuaMPFSYSK+xTs1AZxOhHFJ0bPSZtln0E95DA
         OcxOFd427QRx63GWyWAeW+WXBnB+Yso5Q/7F2MFcv7lW6e8R0MaaBscM3J/tBHiaaZwn
         kAEOenu5Hq+Bn7YyRGVKRHiAYTTupvmSWeFZ5hbBQQriPVs3Y5lh/mzSnf2W0KPlnG8G
         2393pT5WY7P3cKBZZcvcg5/LUf8p7inwHH+dZbY4bCefinU63bLnQdbYsOFCWO8nZ0F1
         RSZLH8mfPsQqv+W7ZHCc2ZFzzbZZvpJYrHtfJqklT+pgUUTLdlO+mWExwm/7sONRw7yP
         OHPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iaTRSRqF;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755092323; x=1755697123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8altNzJwVIG+F+c84BgBkb4kF0YZmrD9Cu+hk54UbwE=;
        b=nOO3hfoFTmmJhsIlSDpSTJaA0LKdNStuCfI+cZ4Rv2ZH8m5XLV8z0zCaiobCWK2U2s
         R+3vbPwBNDjllQ/9MIl2xupb1vcQhFtoWGNsPftPodPOAL0XD9yt+biqyGOoE8312pAB
         niqYaE7u+t2xprOC/duMYzl27xxOnMLddh6AR5KRYfqgas+YUUj9W6BsMqkZ9Yr/K20a
         hnxg+So0zPp1VeoOsKdVmcwZfevBi9bBcwv6YqTIPbz4JzCJTxp++VKKACue0jhglLVj
         Zty7p6n/EQ23RQy6tjXiDxs3LlRF4aKZNU4MkP0+dmN1Q1z2LmETVKzbwHdm3rfnXGkl
         E/og==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755092323; x=1755697123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8altNzJwVIG+F+c84BgBkb4kF0YZmrD9Cu+hk54UbwE=;
        b=Px0CYjiAHYH+AQx+KWkS/8JVl2qS4qhzz1mqDOunON6LCChf+xku91SiM5L2Qmjoiv
         NONpKhPV7L3BuVApZZbG8WGFhipQu7cBI3AJMWJRwr0XiQiWB1kSCpYmqG8iS/grBkML
         huOPpLbo+/TTmHZ9nvhLapoh0aVwNzv3UqgOn5A7EBQIgO0gY8JG2B8vhbbZTs71/feK
         DD7ngM9ZTXi4g6ZSuEY1+VI+XpBNlnxeXOeMGjplO+IE+Is1kdf3YBVMXQB2ngLBaKx5
         Y1t230HqLDXh26hHulymTVb0VH8eQhAas+am9R62Vcx/HB/mDfsQmfi+jYvbsMrFaOFu
         j6Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755092323; x=1755697123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8altNzJwVIG+F+c84BgBkb4kF0YZmrD9Cu+hk54UbwE=;
        b=t2LPwMAbx2ZzV5EiTWVqMK99TB1JOiL3n/dyqrXrVqtwkSrGuXgrRZ4JjV2+rjdhrO
         NveYMp8AsOL3hA1K/YxWM83TclpUeErFFSws87SKMoGeBzCcRXNrD9gTP7Z9VT2fwTbk
         q7IRl+QBg/IVyLTYHhAdVu/OChpU/iXfuMIplhuWziVkjW8KsFwerQw4rMxShhkTmIWY
         DoJ4YP37iPincFpodEd+jYsR2vN1FhKY/Syur6/Fu67zipXEyaLCntqQtkO2F4uC8oF3
         qoDaSQ8rboiDyjo4X6vfMuj/w4k9cIf8gZX9hUSobK4vsncdJCDssOeIR5ITmjNlF0nB
         Op8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcAK1soBfhZzgrZ5q83Y/09j8dO0z7DrKca58VOjCpW6q8bB5GRg2ooviOkPy9dXQJjB1ecQ==@lfdr.de
X-Gm-Message-State: AOJu0YxS+iFZAf4qxeFNnv+gQUuFoPU15RYq9nIV/WtO/wWttdK0cnaj
	OkLJm3TP2wmpOtjW8m2ijMLGYUsYKwmK3ZdIJK2kBY4a1qUetV7m2UKy
X-Google-Smtp-Source: AGHT+IGOo+C5pa+w1/Uaaaxuntnq8o6PsqowYCFdK1H2/yWQKH+ynS4XIr5pU1cSxSlZsAiQT8Y2Zw==
X-Received: by 2002:a05:6000:240c:b0:3b7:8af8:b91d with SMTP id ffacd0b85a97d-3b917eae69emr2878683f8f.35.1755092322834;
        Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdeBQVkKHuIvkJ+DFGT2xNJa5sNGLgcMZMHQyMlKTFl6g==
Received: by 2002:a05:6000:1785:b0:3b7:89fd:a279 with SMTP id
 ffacd0b85a97d-3b8f9239ad2ls3371336f8f.0.-pod-prod-05-eu; Wed, 13 Aug 2025
 06:38:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbFzF7S4YBnQZDBAgPvQA/Fjo5dnlAKkG5GMKhRRI/f9EvOSS2JjJLYHfIPYJC0FhvDRJpRgbdHwU=@googlegroups.com
X-Received: by 2002:a05:6000:420e:b0:3b9:16ac:6af4 with SMTP id ffacd0b85a97d-3b917edd9bcmr2668346f8f.56.1755092319495;
        Wed, 13 Aug 2025 06:38:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755092319; cv=none;
        d=google.com; s=arc-20240605;
        b=fy55QNjwH7iyLjbpw5AhD16YYdNP8txyzj5mcZKWHGvIj8Pqwo7Qa3TpeiKKxzj8qL
         jk20FNkW/hKfWyAUj8rzEb+4/BEf85/LEbRzq09VTOProGTox8RsmTIjILCyP3rCl/JA
         kHontvmjAV+WQjFRsIwXwc3Zngz6BWNBKECMeAbu5RZMHFoSSszTO2vKu4q9dtz7SYis
         lWJQskbQvqXkbxnOwk27m8fuN+J2VkbvDIt2cRtc63c8lkKLprpVboFSh2mZfvN/odCF
         QKXJymZiipVHKTilPa+svck119cOioE6Jv4IS7AcVm+Cf1bLV/GaSTJSdsGO5Z361xLg
         TNlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=0Nw3bTX6xGGMKWExTDEEfa2WPWmKzMn7BL7inlmF4mY=;
        fh=AiprbMv3QE7MiFiJOuN29vv14aXrao4uAruqY7BENGM=;
        b=X6NBLC+Vxe4UDOiRes6k/VBmRRImtO6iW2UfiC9grq0R4uYrLJgwpDtDeNT1xTPvf5
         BnR5UseCpPqun8b6FamqouKdOwOHfftMp3RtQpkNkmbOwfk+B1xeOdyqrzj2tllqiczT
         3T+zgPzkaLoJPZnOG3KmCgzH22/f/2tMf+UzRK1dQoTUAYS+T5VsfDiehGJA0ztwB2Lt
         KUxvyH9Qn+M9m6Lkbv0KZ518HXyHbfTTd0zln9wDeqmUopznXh+5+FkCUEoM1Efg7IMg
         TG4CWCTe/F9j3oVSKiHoh/UM+JpIw+8qtchwqMKKN1PrTlPWrEkQUcAbHycpFNi6c6Fu
         2xFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iaTRSRqF;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b91b0c5b14si29161f8f.7.2025.08.13.06.38.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 06:38:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3b78315ff04so5594076f8f.0;
        Wed, 13 Aug 2025 06:38:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVIJjo4/xhrEYYbv7JnJqLoSmwvKl2VdehR+saqSYSCCRu/EYTFZgoCf8SeDEYlh0zx7EeAQvi75MM=@googlegroups.com, AJvYcCVMlZfqWzoZnZUbSSVFnz+VDMZOXEvlWsENe4eo7kPTCCazOjP873g2EI1nqXZuCpE6gpMKPsw+EFX7@googlegroups.com
X-Gm-Gg: ASbGnctxEFXk2+oviAOc6C/ifzGrV/hXSVbq7AdYdJ+wcrJxW/9dzfUpsMTcurvyeIL
	t1YZlVY0pe95vPqCez52eZ47OnZJJElQ+Fh7ruGO+aaf7rZyGvAaOW+0vmcls1zXZoGsSeLWADy
	20uFYfq/FvcF0jZ0O3P1RPvQwJmlz6+8tNSyxvWRI/i+pG7iP9bqlpsM67OOiPj0YduEhtkikwv
	YH7YIw5WQKhUARG+14AkHOF22CuEp/AgnQCS8cU0rrzZ0MoHqrpHfs9ix7xC2rXrRv4XimYIcA0
	axios6xXmg7zW2SYRj2WHTkmUkZoTti19q4cMogos3MRVLulyeqyBRiPTG7UD/SxmeJvcZD/++Q
	yjk1Te9FQOcC6ZFJt7g1hoJHAgZy/PD5Q3rEu/iov58NhjUsYM4jcd78jItXaU8AblFUfY066Ic
	3lJCFt8q/d93kXAQ36m81rlm3Pgg==
X-Received: by 2002:a05:6000:188e:b0:3a3:6e85:a529 with SMTP id ffacd0b85a97d-3b917edcf84mr2417374f8f.51.1755092318802;
        Wed, 13 Aug 2025 06:38:38 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (87.220.76.34.bc.googleusercontent.com. [34.76.220.87])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b8f8b1bc81sm25677444f8f.69.2025.08.13.06.38.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 06:38:38 -0700 (PDT)
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
Subject: [PATCH v1 RFC 0/6] kfuzztest: a new kernel fuzzing framework
Date: Wed, 13 Aug 2025 13:38:06 +0000
Message-ID: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iaTRSRqF;       spf=pass
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
introduced in patch 6 successfully triggered the bug inside of
asn1_ber_decoder in under a 30 seconds from a cold start.

This series is an RFC to gather early feedback on the overall design and
approach. We are particularly interested in feedback on:
- The general utility of such a framework.
- The design of the binary serialization format.
- The use of ELF sections for metadata and discovery.

The patch series is structured as follows:
- Patch 1 adds and exposes a new KASAN function needed by KFuzzTest.
- Patch 2 introduces the core KFuzzTest API and data structures.
- Patch 3 adds the runtime implementation for the framework.
- Patch 4 adds documentation.
- Patch 5 provides example fuzz targets.
- Patch 6 defines fuzz targets for real kernel functions.

Ethan Graham (6):
  mm/kasan: implement kasan_poison_range
  kfuzztest: add user-facing API and data structures
  kfuzztest: implement core module and input processing
  kfuzztest: add ReST documentation
  kfuzztest: add KFuzzTest sample fuzz targets
  crypto: implement KFuzzTest targets for PKCS7 and RSA parsing

 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/kfuzztest.rst         | 279 ++++++++++
 arch/x86/kernel/vmlinux.lds.S                 |  22 +
 crypto/asymmetric_keys/pkcs7_parser.c         |  15 +
 crypto/rsa_helper.c                           |  29 +
 include/linux/kasan.h                         |  16 +
 include/linux/kfuzztest.h                     | 508 ++++++++++++++++++
 lib/Kconfig.debug                             |   1 +
 lib/Makefile                                  |   2 +
 lib/kfuzztest/Kconfig                         |  20 +
 lib/kfuzztest/Makefile                        |   4 +
 lib/kfuzztest/main.c                          | 161 ++++++
 lib/kfuzztest/parse.c                         | 208 +++++++
 mm/kasan/shadow.c                             |  31 ++
 samples/Kconfig                               |   7 +
 samples/Makefile                              |   1 +
 samples/kfuzztest/Makefile                    |   3 +
 samples/kfuzztest/overflow_on_nested_buffer.c |  52 ++
 samples/kfuzztest/underflow_on_buffer.c       |  41 ++
 19 files changed, 1401 insertions(+)
 create mode 100644 Documentation/dev-tools/kfuzztest.rst
 create mode 100644 include/linux/kfuzztest.h
 create mode 100644 lib/kfuzztest/Kconfig
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 lib/kfuzztest/parse.c
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813133812.926145-1-ethan.w.s.graham%40gmail.com.
