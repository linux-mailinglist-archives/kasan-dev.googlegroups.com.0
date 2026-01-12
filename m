Return-Path: <kasan-dev+bncBDP53XW3ZQCBB24WSXFQMGQEMCNDQNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DBFAAD15006
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:28:44 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-59b730b2b0asf3282328e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:28:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768246124; cv=pass;
        d=google.com; s=arc-20240605;
        b=H5jnEGez3mIRzvlaG6jBgKEICPQ6TKN6aWxxDhxJPb49Pu3jI0DAcp0W3oUh5zglAh
         eB81b7rbfKSkbEI22fDkBs8gzWQc7j5WHqvvXGuPQLxQ56+m5h2NkWcTEK6cN2iF3tk0
         Mb6oJCWDJRiiWfY9F9eNXiyxDeCV+v+12LnnCbLNWwCr2v6tKg8v//ZuTCHRI6hVwg+c
         rtnj69+n7Rz3nalTnQXQ4hz74Hk/xQVMx3Fv014LcZmPl+jtX96rKoq9SnmCZ4tWGJR2
         Lgsz4HTooqx1OYRhaw4a5TvAcQbxAOjbD9JbM68jkPX3p1+qjfZL6aaSlCtNhpbBD+S0
         Q7UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=hDqCFMNPrioMto5Ifqgt0SxUtuWheARBuazjeTFcmPk=;
        fh=Pl6b8cAKZr/HhF9Blu2ZKbG+P9U1ZWjC5uViuIaE16g=;
        b=GoTC/VHUorwIHuvFLPyMcJ/eMMcDQPtH2el5F+Cbe/rgfs6sfARRIN8OyDwk2ZEUq/
         vhk9M540AofOIThk9yGilYh51hfb8CVffXxxSFsLrCkT5QYMCI+twXSVX4c8nGr84ZLl
         XLjFKnqYQ3+OJW3zu2zorQz+jptNJDDyiDb9kaerQ3PkKWVUaxNJQNB5LRVswAPMN3mp
         nV5SIJaxbG0juK+fLbkDHHklNKu/XFBTesNkWc6+E+PYLJUEf3tBnGZC2W77GehydPl+
         aUO44/EIFUGuV0GBi84jMjFnutq9WyQcRrbENQvc/UMabRNB4eclJK2w0Nt4IPXpBq5N
         WSNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pm9QoZLC;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768246124; x=1768850924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hDqCFMNPrioMto5Ifqgt0SxUtuWheARBuazjeTFcmPk=;
        b=MSDk0TxAFRiAQbZiIkAfUNofFdTiBmExCHcyESX8cBaGGquq3cIlQ+W7zRYe0pAFTd
         gqIqYKltJqnn+DEuW4BzQh4PxIeJnz9wZRd95z8uJftgnVQbA8cwbg2Gnv3vtKSUsweh
         ycQ8pYThzytvMVI5BOtyHW1h21LtLlgexLWv7UtEQCg5dKAyIz49ZI926y4C1UaxK2NA
         aSEwrZhnT/wwTaNuew56trlUdlUSE4/PMSLilOVWrP7rHaXLAr/rwEQqyUJNU3Ze/l4q
         O2tVhGSpEmUzhHbex1hBmo0JQCklLgf+LI9GH0mJ7bTQB2jUU0D75YlfxCeEFBjeCOFx
         UdXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768246124; x=1768850924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hDqCFMNPrioMto5Ifqgt0SxUtuWheARBuazjeTFcmPk=;
        b=I5/8JrRyw6wyIuPODWqub7P0q5tD0//xEj1oTZkxZYnxlPS6q9YuQcWLuWHnknqy3B
         ZdqnX3J79PQFzk5u/dZ3ljKiY96J5kVRW93nuEzw26eFHpBcFJFYx6EDJYD+VvktqivL
         W4Id73efdJ2bbCymjMGlHb8iNWnW3HHd/usFYLKOI0sO/dEGSBm0lU2/0x5RQdAmTU1M
         xFU7XMvTR9ru0H3H0ESi+X3UiOsfmhQiELF4Dbfs/Dn/aToqYiFUAoD/eIUgtqDFjCzm
         qYqhkYjzW9HTWo2oS4dMBi45+vwt2F+W3DsX62Qz9eMge6PTWENkvZ2j5NcRQ83ADbLO
         9sBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768246124; x=1768850924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hDqCFMNPrioMto5Ifqgt0SxUtuWheARBuazjeTFcmPk=;
        b=PzPm8nhT7ZNeJBMbqpKmq7fbkO5gwcMVdFDixE1VeTNDlkINN2TpmJtXPAtOlZiydL
         QVrcZGJbPYuY3MqUwobj7RJTA3Q86gwJWOPyzPBdU1QmePq4qaIirD5UMiUNWL0yU27B
         2J9Ry9TJDFSDAknH0Cb+jy9WCDePcnqLihPSDjXsFaobXMd79KkySnGfscHizur51fOM
         20Ic1xOzaDbCYJBela7qPsef4aXtMK68Y5Q72JRWixQQHBQs+4wjQK31S5+sFLrCMhna
         ovWTmZ5ATsMjc6aGOM2wYy5Hp8nhXj9k6MNeWNf1DxVoYq99JRMQapgpMT6DIi++hdqN
         S7QQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDx+u61nRh3fd2jPMXx5DLPooSvZUOlHr6nkw3HYm7zWd3UxEjlMY9VWJXiUT0nrw2LGgS9w==@lfdr.de
X-Gm-Message-State: AOJu0Yw8oI/XMmDzCU1z9vq3XJOpz4HKSqTs+fa3GG7X1IW+1hgwDuLu
	oUPAlpl8meJjQRtEY/16puCwzP/xkFRmaFOxPwfny7GsBmXmnJWgojcq
X-Received: by 2002:a05:6512:3ca3:b0:59b:7baa:2e77 with SMTP id 2adb3069b0e04-59b9941926cmr124579e87.13.1768246123742;
        Mon, 12 Jan 2026 11:28:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FeWfS2HBtyBy9lPuaU7+xm3SIw50Vq5TRm5rqZiHxFQQ=="
Received: by 2002:a05:6512:8008:10b0:59b:575e:9764 with SMTP id
 2adb3069b0e04-59b6ef18bf2ls604616e87.1.-pod-prod-00-eu-canary; Mon, 12 Jan
 2026 11:28:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVoXc/IaRTrbLNXHlepKV+bxZHVjELpnKoOaQ+BxZAuDeBThkyjhGQj8uwMJke84n9kBJEhA0exPS8=@googlegroups.com
X-Received: by 2002:a2e:ab19:0:b0:37b:9361:711d with SMTP id 38308e7fff4ca-38350a55384mr1508081fa.8.1768246120701;
        Mon, 12 Jan 2026 11:28:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768246120; cv=none;
        d=google.com; s=arc-20240605;
        b=FuVZFZmeby+uW9h9MgIoGT5il++84YOrW7aDOxBxqJc6fNO9JjOf+WBf47MTIVkICb
         5xxbM47JEDB575x7ou5QzV3N1FVplmKDC50/oP6O0euCRDRFqx9JKvSsx6oMB487vvWR
         hsnA5M7remLH0XXhQdDSpt5luRJQIAM6mdRyJl4LdmYthflrrzpJBCwoCSUCkspRhvli
         wVb242+g0tGPMbwnbmKa+Rk+AcIlmQlMuXuomDKxYrfVGLo/qVdlv0JXb8DX+4NBLEeb
         UB2wmGq3O/GH3hdadBENsdv322ymTGPa+CMWZlGMh+XvFHST+vKqODopvrV/rfAkai8f
         5pjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=a8RC3/jOXChgUFu7fWCHeysuCImlO6A97UJW0JalKx0=;
        fh=nOOZwXefZ0QZa3ZYFpggX1v699ka4YLT3Dc1jRb2/hE=;
        b=H6lPm51Dh3pVcaSFmk9cjlynYMdKNxYBAATfowZyZ+E4gV/y4J39RWeIsYPBJJdG6a
         OzmNQuUG+MB9dx6aUKua05rfhaXHsJU0bKFV5f8PrXrdelSuYpJMFCIPyfyxsDP+GtRs
         9BfwSDmApnZzc9dpDAPvOb8pFkTm46iXUxeaA9TyhMr3IOLgldp5wabztO3mFWP/9dME
         Rj5I/9j0U8KASeFNADklEHQdDST90SwseIrEX3TDFEZGUazrC7Yl909rZbInT8BonGaq
         RtHW+5ScN4qgQMy6btkPYzAvhLuOTWctIwJEZx4amM2EEQ7r9xCDETNQrBIMzINETwDX
         XKJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pm9QoZLC;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52b.google.com (mail-ed1-x52b.google.com. [2a00:1450:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38310a87156si2632971fa.0.2026.01.12.11.28.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:28:40 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) client-ip=2a00:1450:4864:20::52b;
Received: by mail-ed1-x52b.google.com with SMTP id 4fb4d7f45d1cf-64b9dfc146fso1716093a12.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:28:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVwlGCqOi7mxHZBYCuwl0nqGWya3QIpg5/lHFzVFg28X0zw4s0DS7bMceBBMJ412MayYQ++EawwicU=@googlegroups.com
X-Gm-Gg: AY/fxX67O1bsOB45J81fPXQZzFL2hAQwH0ZBbcQn8XdFAu2aSbJdJMAAzi4UfDwD1s+
	1/SyXQGWsKQjhsskRwZwLHSIM9tcgOhURGepvl9VCStNvPmnNS/oMY39ng5d6TDjzc0ExHtIgXT
	p1wlNPlMiqgb+eV5JDZD2n+KYxPmkIB2TjievRX2w4cmBe1gqVobPAqW9Q8lVTnXI+sJTS60Xzd
	xbYK3sw2Pl2+SZR6H0rO7tOxj03p9K1t3d0Muuh52OYSjMNdHno4flFlE19o6qIP7Oy5nxPbxut
	5xlLnezYTfoUc7fn9i3N3jPALaGqYHif40qQ7s0qnDV24vaIrqHbfkIPi5mjr35/k91y/sOhHf6
	wV/hCELFfl/DkCEi4KOHKp12jjNYdTNjVq2I+fKN/k9YbJzoSKYcHzWdkPKVhHq5jojofXiVz6J
	/sGqVowfavlFcMaBhGkdnqlRM9uUQfe7pfZf0PHbNikUtcnreUhw==
X-Received: by 2002:a05:6402:326:b0:641:88ff:10ad with SMTP id 4fb4d7f45d1cf-652e58769e9mr330944a12.14.1768246119781;
        Mon, 12 Jan 2026 11:28:39 -0800 (PST)
Received: from ethan-tp (xdsl-31-164-106-179.adslplus.ch. [31.164.106.179])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-6507bf667fcsm18108959a12.29.2026.01.12.11.28.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 11:28:38 -0800 (PST)
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
Subject: [PATCH v4 0/6] KFuzzTest: a new kernel fuzzing framework
Date: Mon, 12 Jan 2026 20:28:21 +0100
Message-ID: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Pm9QoZLC;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
dependencies be stubbed out.

Following feedback from the Linux Plumbers Conference and mailing list
discussions, this version of the framework has been significantly
simplified. It now focuses exclusively on handling raw binary inputs,
removing the complexity of the custom serialization format and DWARF
parsing found in previous iterations.

The core design consists of two main parts:
1. The `FUZZ_TEST_SIMPLE(name)` macro, which allows developers to define
   a fuzz test that accepts a buffer and its length.
2. A simplified debugfs interface that allows userspace fuzzers (or
   simple command-line tools) to pass raw binary blobs directly to the
   target function.

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

This patch series is structured as follows:
- Patch 1 introduces the core KFuzzTest API, including the main
  FUZZ_TEST_SIMPLE macro.
- Patch 2 adds the runtime implementation for the framework
- Patch 3 adds documentation.
- Patch 4 provides sample fuzz targets.
- Patch 5 defines fuzz targets for several functions in crypto/.
- Patch 6 adds maintainer information for KFuzzTest.

Changes since PR v3:
- Major simplification of the architecture, removing the complex
  `FUZZ_TEST` macro, the custom serialization format, domain
  constraints, annotations, and associated DWARF metadata regions.
- The framework now only supports `FUZZ_TEST_SIMPLE` targets, which
  accept raw binary data.
- Removed the userspace bridge tool as it is no longer required for
  serializing inputs.
- Updated documentation and samples to reflect the "simple-only"
  approach.

Ethan Graham (6):
  kfuzztest: add user-facing API and data structures
  kfuzztest: implement core module and input processing
  kfuzztest: add ReST documentation
  kfuzztest: add KFuzzTest sample fuzz targets
  crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
  MAINTAINERS: add maintainer information for KFuzzTest

 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/kfuzztest.rst         | 152 ++++++++++++++++++
 MAINTAINERS                                   |   7 +
 crypto/asymmetric_keys/Makefile               |   2 +
 crypto/asymmetric_keys/tests/Makefile         |   4 +
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    |  18 +++
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  |  24 +++
 include/asm-generic/vmlinux.lds.h             |  14 +-
 include/linux/kfuzztest.h                     |  90 +++++++++++
 lib/Kconfig.debug                             |   1 +
 lib/Makefile                                  |   2 +
 lib/kfuzztest/Kconfig                         |  16 ++
 lib/kfuzztest/Makefile                        |   4 +
 lib/kfuzztest/input.c                         |  47 ++++++
 lib/kfuzztest/main.c                          | 142 ++++++++++++++++
 samples/Kconfig                               |   7 +
 samples/Makefile                              |   1 +
 samples/kfuzztest/Makefile                    |   3 +
 samples/kfuzztest/underflow_on_buffer.c       |  52 ++++++
 19 files changed, 586 insertions(+), 1 deletion(-)
 create mode 100644 Documentation/dev-tools/kfuzztest.rst
 create mode 100644 crypto/asymmetric_keys/tests/Makefile
 create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
 create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
 create mode 100644 include/linux/kfuzztest.h
 create mode 100644 lib/kfuzztest/Kconfig
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/input.c
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112192827.25989-1-ethan.w.s.graham%40gmail.com.
