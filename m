Return-Path: <kasan-dev+bncBDP53XW3ZQCBBYWOUTDAMGQECLWCZZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 64264B5917A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:24 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-45b920a0c89sf28103835e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013284; cv=pass;
        d=google.com; s=arc-20240605;
        b=bn6pymWZLp9MfCYjNmNKtp8LCO0BkR+oYlyWgqMPvDDX9KJyNJDPvMa6FPqZ5cFkgt
         h7kvswsAK8BCIqX95tGKrq00JX4AWH015p0HiDceavy3MeBroFDTJuMq2yDcgIi6yA91
         oAg2iY9R6zDBlHgBCSOTjy9Yhyg1WSDpYcYQpNswRKXiasFo+sBgxu5MTcTofhF7vKmH
         Ar6Tqe7AML4jxMHMxCyVfA5bFhIWyqnWLMiMYxsDgDAJfzCpVVIgXOeBzcimFvIwi57D
         ViV7b51MRodRN9AvqYq3NImhMKpY4D86N3CR1o3iDZ7zeEG4pkX6O/JXLEMlAuBdC7WR
         Wgfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=pY5yXZuaTTb3T/u8gZ9keczutsDYCSeVwY+BHNHVXdA=;
        fh=IWxUTbzBMtwA4qcEymESeVE2KaPziUlurU8cPYVTV00=;
        b=ZyFEu+mvAPJ9smGjLUGFHWCgm9iohyT+GPvrl8T11j0I5GaH2XpRblM9oGEIh/Mkfd
         CLtLhLTy0lrzqmUqHDlIhL1X7ENx4NVDrvCNckcPwcv4XgzrvXQ+/PlYxy3LEDIURxzl
         JTaiUwoIUM+KnxzXQPzy1RDnlCvnq5gEaxdgc1NyAJL975+vy/0RMtMsa5arOr80WJBM
         TspxINSKt2TdITE7eTcR47PnnUlm6DVap6yqj7oS/4QLEzK6jIEl9ha3V9Kf0VtSym0i
         +F2Lt4YlDxHSmeMoMuPzFC//1gh1MKtLM0h5oDUA2cXxRCgIXMc49kWgCFWj2xDQ/6Y3
         GPHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ghjwZGnk;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013284; x=1758618084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pY5yXZuaTTb3T/u8gZ9keczutsDYCSeVwY+BHNHVXdA=;
        b=dIcqeQuXM+cLQw8yPAVCSZ/nq5QYN+dJdmTSCvIDHeOq6td7y3A6s7YqF/Yr1xl3Kt
         oUQG/2HHpuXfmWyhdKsjggBR8snryP3RD3x6CM0V/y5xyyZyGAeF9kehySy8Stikcyan
         Jh0aw7Fznc28KaERImpt5WZY0XQKZardlO4woDFN0SYbOsMzdJuDNSCwLfC80lLspbQM
         a5Co88op7mktwqOMkwMuBlJ40SnEMpAhftK7+n4BU+tnrbrj9tteTGd011PTNRx0z8LP
         fYw/TkEGDy0+iD4w39smTka+MCQvaQx9g48smZi+HQX4G4db5GCpBc5w+tQa9J3UrNeJ
         spfw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013284; x=1758618084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pY5yXZuaTTb3T/u8gZ9keczutsDYCSeVwY+BHNHVXdA=;
        b=iAhpuqjV1vkoqUmraOiIwZqpPuXiS5nfoUAGODV3xlbcbtR2LLQw9qNbabs72Y1jU3
         2Ns/TfmVchgvluIJ5SC8yZWuiFI4haIyLAHfaJNF+gk5i0RYWY8uP8HxBA+oa1kIQGF0
         ctRP4sti/ZzdL4PTKhUwXa7zywvEjFnqUAG/WaNNZdmyR7WWMHgbbsPn+BQ6MUjC9hGC
         z7GW1E7h5l7ByMeffH6/gSnhyxW/LDV0WjTd2mWMeZUyfPhaSP9rsKvJt8Md+N+Or+C4
         EbRgUtAb05+RrO8G7LNwJb40nIsXZcGBuUTmHZEmwft3RWzgF97LwDwdMIQP1pdaqIZh
         GvQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013284; x=1758618084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pY5yXZuaTTb3T/u8gZ9keczutsDYCSeVwY+BHNHVXdA=;
        b=j85XLNFpoAImWDjhcjIwaUXssyNuulHH7iL3TfEHUk8sUddwt2k6S8wsroVz1sEYmA
         eNF3izjyjT9zTURKz5AZQ/4KxgaZHToe7YBa9+29YGViI/ZUN2so5fcLg6GS25zqJDA9
         Td2Q1VH3zFJaLTBQ5kGP63+HMid3UER3CNKKCwAsuhZNhabqh+pJE/LiM1y78Wamlzfc
         04cywcdMKJi/uIHr1Rb8n0gO/9QiiJoD2QbJ/Je9IaR/roFqntPpku2Vkt59+aBq4GHp
         LweXHFxJgVZH8d1LKq3z3z4kjDIDqZUH1ABQe1uEjpw/h0AVc4xRMTOuK5zX3dgB9eci
         S/Dw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVI43AA6OFnmdjrw7O1nRV1MxpvlXt4WFPyoMPf0ixtdPrTz35XH6zpDHSLGuNbrYjZEvjusQ==@lfdr.de
X-Gm-Message-State: AOJu0YwOoiiFxz19UYKVTjL1dScM4gJjLob4t5zhWmEH9v++V4/LJhVI
	VmGrQqVpkliwmDUFyGaJgPbuR2zl72mgYiVGEsnLbAyRtc9SthbbXb0k
X-Google-Smtp-Source: AGHT+IGqZ6cG2iUhxrLklcpv+MeL48yiiHhVIsqdQC888OxEszxUU6jzqVhy/wmX0FdvESnE9jpBvg==
X-Received: by 2002:a05:600c:8a17:20b0:45b:8504:3002 with SMTP id 5b1f17b1804b1-45f211d50a9mr134184215e9.10.1758013283165;
        Tue, 16 Sep 2025 02:01:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7/+k7gNrG46ILmdHHFkjCO7Nge1T7Moes+xDelht1ctA==
Received: by 2002:a05:600c:1f06:b0:45d:d5d8:c718 with SMTP id
 5b1f17b1804b1-45dffc127ddls29804905e9.1.-pod-prod-06-eu; Tue, 16 Sep 2025
 02:01:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuSr6ObNhokmG6R0bJGl6ehg2xZgz6bsFEvQB/oRXSuiBBX06QK8uF5aIMMpaVQ79pQpOoENjKQX4=@googlegroups.com
X-Received: by 2002:a05:600c:4453:b0:45b:9c37:6c92 with SMTP id 5b1f17b1804b1-45f211ffa8bmr149949605e9.31.1758013279491;
        Tue, 16 Sep 2025 02:01:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013279; cv=none;
        d=google.com; s=arc-20240605;
        b=Lbj+4t/2IJ/W58FU83m2PuPgofUg/2ntISXLSq2pLa/VVPNxiE4skATjrj6E99lyaC
         0n74bNkW00vHhr7kgHy9sdiVTlXl6iNin/I0YivZcp4vLVx8h7hPUsB91cK3aoQJAVBS
         erH3Nhgt5W831L/TszGE71opDKoEEKb3gvBJOc7EC43jkXhQhnbEh92udiDrEZeaRoKz
         e+oH8RES3q575wDAxhsapk4GkjByTdtDAiWgFvjq3nRvROwQXrn2PPEg2pWWozYFQoLA
         35bRSDIn4YgQxADdOd6A/pBi2inTIc69/mDelJegwh1fXZUxj/iPLzzPaSu6satdUWIh
         j7wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=upMhvQF//L2bSGTsud4VXsSZCTKFm60OzLUP07Pokt0=;
        fh=3OFoRNn0arG1m+mC9gi/RweDuOfxv8oP/l7QX5irYVM=;
        b=N80B+rbTs3pjHTDHMgjxmTRcY+I+IIvjJYqg0+Bn6mVn1YnTqsyQDwb40S1ruEiIWl
         uescabCf62KNljELsK6GVWOpC5WhFBzyAaoeE/8UI8gepOS4o/ITW4QNMjbeuHMPyEeM
         GjMjOftZ/9YJLTRXFAAUFYboJBgRis0Jl1stugbHkE7Dq84k4U0mDAmieYBTqVOFp6p3
         +HObxE68au0C5Bcer/l4vZpRN84f3EM/ashB7RTZkURuikXYl1ve8gdBSPd/an3UVKFh
         hHE/YH6u7nFdBvN7TW0/dcI+JamAuHV6bB6vZWti4nBAbtYfyNJnn5uqOHYV7l2k1KAv
         GLow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ghjwZGnk;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f2d5af66dsi881725e9.1.2025.09.16.02.01.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-45f2c5ef00fso19209935e9.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9rPKW2VALgO7qXLr5MuLJtKFLD4uokGl2cmH5Ul8CdgRokSOO/gOTwQbKRVmDLs8tvxBlM10Mm7k=@googlegroups.com
X-Gm-Gg: ASbGncuxmPVw9oak4L7a51EGBFZ50nbehnQRr6ygQOjUUDUyazUtNFo0fvHaZ9Z7Qk/
	yMfb6sb4fE+wOTlvFfl9KzgYgGX262FEvVN/+PheF66rqbhJY2qNdcofWbAQEZID/+wyDDalZfX
	LzflIc1IAFXluZQhShGsFIef46BBWbvpCtQUp0FlqyTD9JHYOtoAenzQk71Bod9McKvS5bTVFg9
	E3iHK9/kEe//vrcTgsUJogdDcX5uhLSEp/N/TWca8FprqnQjp1B/QzIY1+b3tOfklt4tYcrNtny
	Vz9woFjOopDU/xhzXsjFLjDOBrRVeG10kAPByyW6RD6RfpOo/GZqKFkoeANWBhl8HFnLho8Vqpt
	B3Spv7TrDfShlzvTJcpQB7vw54QCYIJj5KAxix5OtfuftSjk///B8Yk17R1tC85RPePm5GL+dXf
	Sf6ofF6Iegch5RO+RDsT1BHnQ=
X-Received: by 2002:a05:600c:a0b:b0:45b:74fc:d6ec with SMTP id 5b1f17b1804b1-45f211ca9dbmr161780395e9.8.1758013278551;
        Tue, 16 Sep 2025 02:01:18 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:17 -0700 (PDT)
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
Subject: [PATCH v1 0/10] KFuzzTest: a new kernel fuzzing framework
Date: Tue, 16 Sep 2025 09:00:59 +0000
Message-ID: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ghjwZGnk;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Changes since RFC v2:
- Per feedback from Ignat Korchagin a fuzz target has been defined for
  the load_script function in binfmt_script.c, and all fuzz targets are
  built with CONFIG_KFUZZTEST=y rather than a specialized configuration
  option per module.
- Per feedback from David Gow and Alexander Potapenko, KFuzzTest linkage
  definitions have been moved into the generic linkage header so that
  the framework isn't bound to x86_64.

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
 crypto/asymmetric_keys/tests/Makefile         |   2 +
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    |  22 +
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  |  38 ++
 drivers/auxdisplay/charlcd.c                  |   8 +
 drivers/auxdisplay/tests/charlcd_kfuzz.c      |  20 +
 fs/binfmt_script.c                            |   8 +
 fs/tests/binfmt_script_kfuzz.c                |  51 ++
 include/asm-generic/vmlinux.lds.h             |  22 +-
 include/linux/kasan.h                         |  11 +
 include/linux/kfuzztest.h                     | 498 ++++++++++++++++++
 lib/Kconfig.debug                             |   1 +
 lib/Makefile                                  |   2 +
 lib/kfuzztest/Kconfig                         |  20 +
 lib/kfuzztest/Makefile                        |   4 +
 lib/kfuzztest/main.c                          | 240 +++++++++
 lib/kfuzztest/parse.c                         | 204 +++++++
 mm/kasan/shadow.c                             |  34 ++
 samples/Kconfig                               |   7 +
 samples/Makefile                              |   1 +
 samples/kfuzztest/Makefile                    |   3 +
 samples/kfuzztest/overflow_on_nested_buffer.c |  71 +++
 samples/kfuzztest/underflow_on_buffer.c       |  59 +++
 tools/Makefile                                |  15 +-
 tools/kfuzztest-bridge/.gitignore             |   2 +
 tools/kfuzztest-bridge/Build                  |   6 +
 tools/kfuzztest-bridge/Makefile               |  48 ++
 tools/kfuzztest-bridge/bridge.c               | 103 ++++
 tools/kfuzztest-bridge/byte_buffer.c          |  87 +++
 tools/kfuzztest-bridge/byte_buffer.h          |  31 ++
 tools/kfuzztest-bridge/encoder.c              | 391 ++++++++++++++
 tools/kfuzztest-bridge/encoder.h              |  16 +
 tools/kfuzztest-bridge/input_lexer.c          | 242 +++++++++
 tools/kfuzztest-bridge/input_lexer.h          |  57 ++
 tools/kfuzztest-bridge/input_parser.c         | 397 ++++++++++++++
 tools/kfuzztest-bridge/input_parser.h         |  81 +++
 tools/kfuzztest-bridge/rand_stream.c          |  77 +++
 tools/kfuzztest-bridge/rand_stream.h          |  57 ++
 41 files changed, 3325 insertions(+), 7 deletions(-)
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-1-ethan.w.s.graham%40gmail.com.
