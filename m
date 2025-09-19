Return-Path: <kasan-dev+bncBDP53XW3ZQCBB666WXDAMGQEBZK3ZNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C4C1B8A1E3
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:05 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-55f742d8515sf1240984e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293884; cv=pass;
        d=google.com; s=arc-20240605;
        b=KZM0/iq1vpXyP/XvKKcRLhOOr9TRR+YAlBIe6CaEoKL6q7eb6GyL7X9DtlXEjoNQX5
         flgC5CpEFIFhKSkATIZL6aDV087CP9N2GoqCCdkzweZDyEVaqoJCwCmHVNF/zfIigbx6
         1duBpVtagAsSpqqgEMloMQbhUEIa9vrmd8CbBo04+BB5lNKULBOLCdjGVzZH5tS2lc5g
         vM1F3rSjoejgmgAzeufMlGGgDZkqxLBd/4hYtsVkA5yq2oOhejaURi9ThOfmHeZAe00V
         bTxXK9xy4PIa35AZMYmGJnJrTaNyB8gt6o2ax0RDximyakTg0Mq5fwiDYhuLHHhPSyJb
         QYyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=EX2nFsmx0r0Ey8YR42ZiSuQQuonH4i7C++viH0/pwj4=;
        fh=Xr5HcCxctwvVIP3+dZOt2ufs7qVNMdI4PKq+H/s6F38=;
        b=O2QYB2iWkKo8XS+m/6MwM5d8Z6RheZrnQ0Ifdl3zwXEcFpmpoNYmClsK2gWg0wEE1j
         4ZOZ+Y8eHtnJ9okuXYU7K/coiiwAdaNTKvlno+MoMPFKkOPNHp3gDgnyoOrkqcF5Y9iG
         vObj+1K6hRr+N091bCBlp9RiRZhMi0fqeJMNIekW3OqunHawLKpm+LM+fZlvViDJSRpN
         Nn8lPT5YVh6A93kw2PSS1m/CZk8vxIh+wte3AfJUGCsIZ7wVT98vq63p6GevuLtZAoUB
         6tq+01RxD5yUWNsXj/gfzS7tuBKBGbJQQLrIfFgnE7ynZOQQ9KCy81Xc5YLHlnV3T1sS
         T4eQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QVXMJxlL;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293884; x=1758898684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EX2nFsmx0r0Ey8YR42ZiSuQQuonH4i7C++viH0/pwj4=;
        b=Vjf8oc0jQ7J8/8KVdRGfZbW2WEk2JEb7yaBmQRt1P1yH+OUkyyn/zuLcFeBkj1Uf7Z
         vY8CXzTiFm/nKM4W6oOMTWvzu2mTGsgz5SwNCaiIp+usK6L8EZhEynQiEVuVLyspfVEe
         isSzdvuP3Eqi0FIeYUhLvfttjWASlAFug3ItzkrzMHJZQ3Qfbpd/WHhq97POKdTDyZuu
         NHQexJNBaOVm/gHz6/wCQTon/yYglsACgRTVUse4fqSAdkAD/cbgPslLqkU4MCH2n3uZ
         vmM4yiurieVpor0d3pgutvy3S2I5jGv89wzW8FqvaPWhTLQCKGgGWDvLkeD0gWEJ8Vyr
         xxEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293884; x=1758898684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EX2nFsmx0r0Ey8YR42ZiSuQQuonH4i7C++viH0/pwj4=;
        b=f4JyAqgJsSQZ5MZilxxuBcXSsLokRivnv3xu2unidvgcWMov3dY0cueDL36fyD8m1B
         Ujiizt4ur5cWltcDBvkp2xeox6aI1TfgZLa8r2pJ60ZYSuTNQPP93cpIt3FQMSV8xzbD
         av7WeZYSNUrcaXPgMvthMBOkveAYcGoH58v766qmklnoKwY5u+RF2W24+IGNdP23/9/h
         HA5s/ijWIhkzNiEOB6hp2PkRj3NlrZ1j8Pd2puTCv2Ozy86qUOhz5ZwZ7IWYh2fWdXRO
         C0bDw7svM+6N/m2FJeUU+Sqfh8CCmNxaWcHCe8EqgA2iPGLZ6756YPaPsvNHE6HrKnMc
         5EgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293884; x=1758898684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EX2nFsmx0r0Ey8YR42ZiSuQQuonH4i7C++viH0/pwj4=;
        b=GPaaj2ftcsw+SH37znwz46ZD9X2GnONB1jVaDCWj6l4bOKZe9IhbpD3bB+uQY2ptyV
         4KRX59f7S+oNDOVrzd4edPo+fwEMzMgn+KR0fkL8VCxu3+601hFkvDOHmuQ57x6+lfng
         UrKMLL43lK4gPwUdbaXPi/OYh0Cz4DyU/vM7T2Qp+ZgacV3I+2VDlH1oKfe2VMEpCMtG
         fSxc+90Pciap7DAu1Zi2mDzgjz4ziFnWdDZlSNsK9UREaQVv+goHwBKlNTbN9SFEXBSQ
         Whujq5UF9FSoytxXqaAJ25S6g2b3n6FFiLmsma46+s4cC/1PFxFNkPgFwxKlJZl1HAE/
         G4DA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6lvW7V+tMLAolzkHJDoSYFbbKgHfo6o6gwCcqrgg0oL6ZvmlmDVrwbAOytmIsdF4lv0+JtA==@lfdr.de
X-Gm-Message-State: AOJu0Yzuq8lpdtOvt75oDww/p8BPSmDueNl8JhVBsB+SBLiuhhbbsjdZ
	gJ2kKwFK1AA8GB+VH885kKoxmpLF9pKKr9wYGpjN332BxQb52HXkrP6G
X-Google-Smtp-Source: AGHT+IExuxRigFRgnjxNDUVmjT+vjddw+D7Zmfc9LYTIhgPrIeO6RjM+zGjRIIUI+qf2YnGYUI9RQA==
X-Received: by 2002:a05:6512:20da:b0:55f:6c08:a15a with SMTP id 2adb3069b0e04-579e213146cmr1159759e87.32.1758293883773;
        Fri, 19 Sep 2025 07:58:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Lk061lTVOUh/4rVO7vdsI5Xk3yDeaPZk34kv+wShO2Q==
Received: by 2002:a05:6512:6090:b0:570:9608:9f38 with SMTP id
 2adb3069b0e04-578c72f3b2bls525336e87.0.-pod-prod-09-eu; Fri, 19 Sep 2025
 07:58:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPO0Vg6jRrxIGSOEC3bEg1iuz6qFMDgcrB3xNqrIg+HjvKIs89Yoq4a9c7TG7SY1P/ZbWnpKZn1yc=@googlegroups.com
X-Received: by 2002:a05:6512:20da:b0:563:3ac3:1ec1 with SMTP id 2adb3069b0e04-579e3380adamr1165848e87.54.1758293879999;
        Fri, 19 Sep 2025 07:57:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293879; cv=none;
        d=google.com; s=arc-20240605;
        b=aeqzdIeG6ykGi2k2I5tzQhKd1vPm3tAraPaCMDAqZsHXM8r/yQDd1xExftqKpsyNUg
         k9H7V8QWjG9I/NnO3Dgwl+moP6DCgH0B2VdeHD0WEmbs9OrSkc460+ziqRKVVgf56Os2
         k1diciMbcGjTadj3b9Gvvi8oP8B0JEsQ+5ZrGhItxciBPrg7Fpp0SpgDwiyY1IphOFMg
         MFojZYeV0pN9RHKkKAtzF6/wvXnM5RJnxTOJlMshRN4njBJrW7K3a2thdT+4x80oyacp
         UD/fh04sN/W7f886NyzGhbyzd7Fz86vK6ojadgflqib/bqHLyUVB3lnKa8Uo6hb0SiDn
         RlwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gkRYzWYSGqW8b5cMZYzB+a2FlxSRz9tBtPdwTZuG88Q=;
        fh=bRLdbkQ+dEwacbhO/PXihgzXjDLG1Ei1MHz/OrqwirM=;
        b=a/qXWxiIt0ZheFmlfjMmJ5WP7aeUr7kyhmm2K96AKSQP1HZtQOS+wYuj0LbMGWKNR2
         LihJdpTRz0Prg3x9bblaodW7DUhzGnfC0Sf3uhBNQjI+LwenPvQCo7ZW2f9/YeyynQu9
         dG38adzTZxKtltzmQAFXXzDtdXM4wvTzTgep2mrhUG/E/Cn/OhcLjKxUVXbtB6n/bdJ2
         HoHF8iEjS0BKv1+tB5w6eDhjRA3SWA5cfacmM6xd3OY6Xrl9wevmWbN4oILHARsr84wc
         EUFeDoZgpLCu8S6O7gtHjadYbBB1KE8vJBap8AD3+hhBe0tAMzhB01UUMcLIQaDUuFrU
         Uryg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QVXMJxlL;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-57aa85bd5d3si33208e87.4.2025.09.19.07.57.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:57:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3ee64bc6b85so946422f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:57:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPpZjORYtsiKezdJ513X9s1W8+gTpq/8N8OyXpbILxskmlhZZ96pKXOJdmGb7X6GJlIJao7KOGedU=@googlegroups.com
X-Gm-Gg: ASbGncsA4ZNuVF+2vTii7D1O7fYIG5k569qTamJo+5Bt82/GZ1L2EDGJzVF3zxMjH+4
	EnoSsZ5g8ZsiaXRl07H3TB/Jk2iJX2WW2z23OtK/Y9Ez7UDFgRk1j+CjGSYdYcchSiFbwG+AQOV
	yIM9LF+uJVwLcDoFhUFgclC1CvW5884WvO2hs7a0eAte+T5x23uySBR+WqNcAUkSeWhVEFypX7L
	H4rE38t6VwtUjd8jDsoMRWBrewBAHwCCDpTW/MALM0xSzPkr/1NQnF58abtTAOrA+76z0ikDFjA
	AazAl9ddusXGq7idsPEVhF9xIZFmmyarifA4+uGEXfHe2VIaYwNaKwncoA2id9yABcZB57e1FfP
	oWts63T81ikjzhK242pHgv9OUJwth8T4aqpdM+Xu4T6jOWY03+82DtReu1rMirpL21yxwu/NPdW
	qNDn4QdEhIEycgoQ0=
X-Received: by 2002:a05:6000:605:b0:3ec:db87:e908 with SMTP id ffacd0b85a97d-3ee7da56fbdmr3112750f8f.7.1758293878859;
        Fri, 19 Sep 2025 07:57:58 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.57.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:57:58 -0700 (PDT)
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
Subject: [PATCH v2 0/10] KFuzzTest: a new kernel fuzzing framework
Date: Fri, 19 Sep 2025 14:57:40 +0000
Message-ID: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QVXMJxlL;       spf=pass
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

- ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
+ ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);

A syzkaller instance fuzzing the new test_pkcs7_parse_message target
introduced in patch 7 successfully triggered the bug inside of
asn1_ber_decoder in under 30 seconds from a cold start. Similar
experiements on the other new fuzz targets (patches 8-9) also
successfully identified injected bugs, proving that KFuzzTest is
effective when paired with a coverage-guided fuzzing engine.

A note on build system integration: several new fuzz targets (patches
7-9) are included by conditionally importing a .c file when
CONFIG_KFUZZTEST=y. While this may seem unusual, it follows a pattern
used by some KUnit tests (e.g., in /fs/binfmt_elf.c). We considered
defining macros like VISIBLE_IF_KFUZZTEST, but believe the final
integration approach is best decided by subsystem maintainers. This
avoids creating a one-size-fits-all abstraction prematurely.

The patch series is structured as follows:
- Patch 1 adds and exposes kasan_poison_range for poisoning memory
  ranges with an unaligned start address and KASAN_GRANULE_SIZE aligned
  end address.
- Patch 2 introduces the core KFuzzTest API and data structures.
- Patch 3 adds the runtime implementation for the framework.
- Patch 4 adds a tool for sending structured inputs into a fuzz target.
- Patch 5 adds documentation.
- Patch 6 provides sample fuzz targets.
- Patch 7 defines fuzz targets for several functions in /crypto.
- Patch 8 defines a fuzz target for parse_xy in /drivers/auxdisplay.
- Patch 9 defines a fuzz target for load_script in /fs.
- Patch 10 adds maintainer information for KFuzzTest.

Changes since PR v1:
- Per feedback from SeongJae Park, move kfuzztest-bridge into the
  testing/tools directory, and update the Makefile accordingly.
- Per review from Alexander Potapenko, address some cleanup issues and
  nits.
- Fix build issues identified by the kernel test robot <lkp@intel.com>.

Ethan Graham (10):
  mm/kasan: implement kasan_poison_range
  kfuzztest: add user-facing API and data structures
  kfuzztest: implement core module and input processing
  tools: add kfuzztest-bridge utility
  kfuzztest: add ReST documentation
  kfuzztest: add KFuzzTest sample fuzz targets
  crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
  drivers/auxdisplay: add a KFuzzTest for parse_xy()
  fs/binfmt_script: add KFuzzTest target for load_script
  MAINTAINERS: add maintainer information for KFuzzTest

 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/kfuzztest.rst         | 385 ++++++++++++++
 MAINTAINERS                                   |   8 +
 crypto/asymmetric_keys/Makefile               |   2 +
 crypto/asymmetric_keys/tests/Makefile         |   4 +
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    |  26 +
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  |  38 ++
 drivers/auxdisplay/charlcd.c                  |   8 +
 drivers/auxdisplay/tests/charlcd_kfuzz.c      |  20 +
 fs/binfmt_script.c                            |   8 +
 fs/tests/binfmt_script_kfuzz.c                |  58 ++
 include/asm-generic/vmlinux.lds.h             |  22 +-
 include/linux/kasan.h                         |  11 +
 include/linux/kfuzztest.h                     | 497 ++++++++++++++++++
 lib/Kconfig.debug                             |   1 +
 lib/Makefile                                  |   2 +
 lib/kfuzztest/Kconfig                         |  20 +
 lib/kfuzztest/Makefile                        |   4 +
 lib/kfuzztest/main.c                          | 242 +++++++++
 lib/kfuzztest/parse.c                         | 204 +++++++
 mm/kasan/shadow.c                             |  34 ++
 samples/Kconfig                               |   7 +
 samples/Makefile                              |   1 +
 samples/kfuzztest/Makefile                    |   3 +
 samples/kfuzztest/overflow_on_nested_buffer.c |  71 +++
 samples/kfuzztest/underflow_on_buffer.c       |  59 +++
 tools/Makefile                                |  18 +-
 tools/testing/kfuzztest-bridge/.gitignore     |   2 +
 tools/testing/kfuzztest-bridge/Build          |   6 +
 tools/testing/kfuzztest-bridge/Makefile       |  49 ++
 tools/testing/kfuzztest-bridge/bridge.c       | 115 ++++
 tools/testing/kfuzztest-bridge/byte_buffer.c  |  85 +++
 tools/testing/kfuzztest-bridge/byte_buffer.h  |  31 ++
 tools/testing/kfuzztest-bridge/encoder.c      | 390 ++++++++++++++
 tools/testing/kfuzztest-bridge/encoder.h      |  16 +
 tools/testing/kfuzztest-bridge/input_lexer.c  | 256 +++++++++
 tools/testing/kfuzztest-bridge/input_lexer.h  |  58 ++
 tools/testing/kfuzztest-bridge/input_parser.c | 425 +++++++++++++++
 tools/testing/kfuzztest-bridge/input_parser.h |  82 +++
 tools/testing/kfuzztest-bridge/rand_stream.c  |  77 +++
 tools/testing/kfuzztest-bridge/rand_stream.h  |  57 ++
 41 files changed, 3399 insertions(+), 4 deletions(-)
 create mode 100644 Documentation/dev-tools/kfuzztest.rst
 create mode 100644 crypto/asymmetric_keys/tests/Makefile
 create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
 create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
 create mode 100644 drivers/auxdisplay/tests/charlcd_kfuzz.c
 create mode 100644 fs/tests/binfmt_script_kfuzz.c
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
 create mode 100644 tools/testing/kfuzztest-bridge/rand_stream.c
 create mode 100644 tools/testing/kfuzztest-bridge/rand_stream.h

-- 
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-1-ethan.w.s.graham%40gmail.com.
