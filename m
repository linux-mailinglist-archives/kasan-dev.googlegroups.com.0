Return-Path: <kasan-dev+bncBDP53XW3ZQCBBA4YT3FQMGQEKKU6GYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8E66D1EBE2
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 13:28:53 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2a377e15716sf189562995ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 04:28:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768393732; cv=pass;
        d=google.com; s=arc-20240605;
        b=bk+2gI4xkrR9e5dodq032Ylx0Qbn+KVYCG21sDqK88fEoMRwdge9Ldz3sNlyADwVEm
         KMIWJ3yJHttjTDopRi9oOFrQZJI7LOSnbd9cs05gFW0/S/P6dg8jdLzEkG3ruIRd8hQN
         wPIaaW+/AM7yW0OcmmnNFZ6LYHNjJxQgfxkNjkhP4yK7B/y8cxfMkqfKbxXByo58EHIE
         Sg/vsHSLLCGnQWe9noEVV/LwAYXExtgHojYPfW8pMPLfwh2CfJjP+THp2PedTKJRV57B
         MOEkiZOHpBczCFtgUXoHQqIE3gauaB6HxwDcbT3Es1KL/ihcl7aqqWyXknS6f4w3PlzV
         QxrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=HyHUUba3uX4lgNJcgKx3npwtKDgOoc0I7OBmOYWCQkI=;
        fh=5iChJK7edyX7coKZbZmMqMEkf2Ls6SlSkE+L98be6kc=;
        b=MF+6AEp6VCwgjaEt5CLS+jvnbyRX9iu9Vv96fqfrLB6Q0EQbnbFOpSXsUxNPZyU+aE
         E3VXXwT15kz8g7oceujkJUFX8gNPXpF65W1ZO7zXNSZkvz51jC7ejLDmjK7y0gfqqU47
         3LtetB1lfaqjOEV4YEhKN0z/5Wu/m4ddIPoeGITP9LsRAB5ulodYX1f8J6N7X/ieDP+5
         LIZb5Wvd8ERkDbM/JvB8BAb/EMwp38b0PHbUjNkL+y6wz+fIZHevwMfECcQiXfwPmVee
         Yd7MqZ/wUNJ33j6TjEwGHVl/fdUXatO6JmxWW1fBFrziTAMBg7SkL1W//YoJuwOLYY3/
         cRzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N5oCndTK;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768393732; x=1768998532; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HyHUUba3uX4lgNJcgKx3npwtKDgOoc0I7OBmOYWCQkI=;
        b=itetMC9fTGySMM7tHx5n9eXy/ms0KwZAL+/GMrUD8KE8kWAPaKfKvaMJKDpIYqx22K
         3XMUXiJXWHVT7nhpfHIiO6LG8ZMHyuKOW+0BdxKnOnmFAjmfSwfsh0fFA+l3PeKiE6Zq
         95U/w8i3p4JAtObn4ntpiaGv7ztLfg6tzv7ZRQ3Bq1bUknafuUjl/YcptzwI1UBskE8B
         peAIEEI6tXzxTg7GbnsIrDtGRLbQ/7hhBmOYzOqspGf6cAb6TJOIgNVlNl82KTXRGutS
         gaFgqnPlFGS1uB/+uu+10TqFUT86Ss7l64653uEzM47JrhMUXmhS814bcAGruKR3aBrb
         +r8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768393732; x=1768998532; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HyHUUba3uX4lgNJcgKx3npwtKDgOoc0I7OBmOYWCQkI=;
        b=GwVkppgk0VAru2HpauuKLrvSI1sKGh0CQaqcgEjaatSTVkVtcqmchJ9+91DicaPg55
         Md7qV6vNy8aNRCn89OEszueh46WkaVj7gIHaGy/zDKNTrI4Bjhq/l7EOOvcYIfzFpofE
         XtiST8aGEq4W28uzDZ46g0Dqe0FTEQrBgfpnZTc9/cD80OOqex85YYXTFWFdK3DftL1X
         +J0RIDY5GlZZvB1ULBKq/BYdhwdHnNZ854Wq/jEu2EHLCBjIPdWZLTP70HpH/a8zQulW
         ro3q4a0cT2RhFEG7AGBn3zQ73AVONY+VSN/fUJhhFdaFzCK4Upm0zkO3OEBEmVvWijhO
         LYqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768393732; x=1768998532;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HyHUUba3uX4lgNJcgKx3npwtKDgOoc0I7OBmOYWCQkI=;
        b=UvK7UpC1MQq3KHto6oNqmWjehrpibjAQyB/X5iKCXpJHNLVyIQiOGIL2dHoBDOMHiV
         wpQunW6cte87fD0n2esuasBtAVlnqLFe9dj0XDcspG/64EEjtzFvy8Lwhhv9GHS6CnCS
         +/s2FVBj96yXydy+wZUcIt8EREaqb7EF9l5t4anmz19Ew92cySVDeBQgx6p8iUFhI5P+
         y+bM9+iEgqbQzjyeqiyU4N/MP59BB/hV1CP1AufJWVdiNuubFv0hkPCmCH1hEbR/68PU
         aNOEEnjK2aJ8mpao46lE4yFSzSDW3ex+AQLMXMecYP+m8u1cFfYqeqdzIdfvsO8KxLmX
         L3lA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6aeSvqpP9u+t7sS+zRtzRju5lckRzpZe2uFk1iFlWg74h0DhCNUEwCUML8t61gHZPPE/8IA==@lfdr.de
X-Gm-Message-State: AOJu0Yzro4Bb0vfYjWCr2kyYgR94hOm8cXP01Z+GkWAO1GhmUmJzw0/o
	X8ETIUVUd8riDkw1/hKqr9t8vTGcY9C0fbahwo6VtdC96p4JvZ7Am0rl
X-Received: by 2002:a17:903:3c2c:b0:258:f033:3ff9 with SMTP id d9443c01a7336-2a599e3dbbamr23601335ad.48.1768393732145;
        Wed, 14 Jan 2026 04:28:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G/IQSwoxm6d+cssMPwfnpyAa3mGw0zbtVe6AbXpfsalw=="
Received: by 2002:a17:902:6b09:b0:297:d9d1:1fb3 with SMTP id
 d9443c01a7336-2a3e2b1869cls67352705ad.2.-pod-prod-06-us; Wed, 14 Jan 2026
 04:28:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWLBLW9CRtPLj+biN2hXOW5RUoBm4M2YxHz1zios3ZInz7Z1fv23qVvs2MuIypNhJejcNXU2acD+GI=@googlegroups.com
X-Received: by 2002:a17:902:cf4a:b0:29f:1bf:642a with SMTP id d9443c01a7336-2a599d85e59mr23928265ad.12.1768393730542;
        Wed, 14 Jan 2026 04:28:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768393730; cv=none;
        d=google.com; s=arc-20240605;
        b=jKfy+76lt/GeJZTzWKlRiI7IJjrqRhynTrUL7ujLe+0a0St+cb/xeQA9/KN5LUykVx
         9XFTMAdjfRaLQnGcMf6jH6lUWZPG2SBbTqPXhK2ve63CeAFIO+bAhIM3XvXa4jVjJCDl
         Pq+i5ILFvwT2FvEn3G/K+9/uYhq7ovcxNvcbt0mWnpqubz0ys/EvVOJgXbLHGaHB/Nav
         5pIQqL0CThBwYkAnV34+UFJA2xKgYpRNbUhQPvYlQ91m66XAdJqbv1xELER7075kYd4Q
         RiGQPTlsPSewVhH8ad2CDFjqxjnQ0kS8K0j1FPDpxFlA9WfxA5W36k8RmrveMauLwj4s
         4WlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LRMIFkzXb5IBhiTKdWbjWhp1Z2C8Xy7d3z7GyFAcX9o=;
        fh=qie3GeYuRojmpbTzitSg9LCSjPyrjM1UvbYcCqZ2DfQ=;
        b=ZceJsRdV1nPlZBWQ83JU8uWkIO9JTsLj1iL6zMRJU6otDMAV6+LbXW4lE2BLG0+p1Q
         HNBumxlU5qj98LuEe4yUm/SUV4Gxvu9k+E6Oq6zjJ6aoq48ao3ArEvp4YAWrXS8CtSvY
         KqFCEyfNfYPUHeBn+9P0TMcumt5smi8GnD8o/nsuXpsEcZhS1a5r8oncPNIIwK1hr0a5
         NibdkeiBLbnn7zk2lvlyquq4ykSS1VhJY2JN866Jy5FaV7Owc3FR42av6xPb/69JS5DD
         zFiMPjn/FOO/M66hF66+SsfFNo8W/2VNoK6PsCDx2hicoXQJ7Hqk+yqxBqa6IcIt/0rv
         B39w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N5oCndTK;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1234.google.com (mail-dl1-x1234.google.com. [2607:f8b0:4864:20::1234])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a3e474be76si8700535ad.8.2026.01.14.04.28.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jan 2026 04:28:50 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1234 as permitted sender) client-ip=2607:f8b0:4864:20::1234;
Received: by mail-dl1-x1234.google.com with SMTP id a92af1059eb24-11f3a10dcbbso7991725c88.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Jan 2026 04:28:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX5uFFFdCa9N3AMI7E10v7edBfEaGMeYuQxRPBkuJhDnHfhWCFd4ZWTQiLnW8mh+JyW7i2/e3h8ALU=@googlegroups.com
X-Gm-Gg: AY/fxX6ztEMx6PkvtqmGnO6emzlsaxYKSSVYSLhPjkocafUxE7hoE/N8B9BmXBRgebm
	LlAk2XItK2L4mP12+ShMV5j5CxVTHO4QzQ8RD4rReo1+1N/yQsSfncsylB9Me+Tac/i+7DCBx5d
	5tkQ6Yas2KdjbXHgguwXt5KTTEX9qsR5u/HfQ/G/z+WVfYBXFbwENptOL8qmkQbV6GDfW0cd02Z
	A37+vKTvLuNd8bbx5ZKseVKeVsPMVu1zg6MHuR2+bAOm5OB8wxGYLIZ4dxt+KOQMNrMlHj8CeWs
	aarER9j9LCI8PcUBI/GJEyJE
X-Received: by 2002:a05:701b:231a:b0:11d:f440:b757 with SMTP id
 a92af1059eb24-12336a8ac7cmr2122254c88.26.1768393729717; Wed, 14 Jan 2026
 04:28:49 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Wed, 14 Jan 2026 13:28:38 +0100
X-Gm-Features: AZwV_QgmF4HyCsXk2jh6zEFc90ih1bVBX_Jk6twBkZMZEi05K-WZZcMS9j7S7Fc
Message-ID: <CANgxf6yGDGAD9VCqZyqJ8__dqHOk-ywfSdhXL5qATfxnT-QGFA@mail.gmail.com>
Subject: Re: [PATCH v4 0/6] KFuzzTest: a new kernel fuzzing framework
To: ethan.w.s.graham@gmail.com, glider@google.com
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, shuah@kernel.org, 
	sj@kernel.org, skhan@linuxfoundation.org, tarasmadan@google.com, 
	wentaoz5@illinois.edu, raemoar63@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=N5oCndTK;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Johannes,

I wanted to check if this v4 aligns with your previous feedback regarding
the tight coupling with userspace tools.

The custom serialization has been removed entirely along with the bridge
tool. This series now focuses exclusively on passing raw binary inputs
via debugfs with the FUZZ_TEST_SIMPLE macro.

The decoupling eliminates any dependency on syzkaller and should help
remove some of the blockers that you previously encountered when
considering integration with other fuzzing engines.

Does this simplified design look closer to what you need?

Thanks,
Ethan

On Mon, Jan 12, 2026 at 8:28=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.
>
> The primary motivation for KFuzzTest is to simplify the fuzzing of
> low-level, relatively stateless functions (e.g., data parsers, format
> converters) that are difficult to exercise effectively from the syscall
> boundary. It is intended for in-situ fuzzing of kernel code without
> requiring that it be built as a separate userspace library or that its
> dependencies be stubbed out.
>
> Following feedback from the Linux Plumbers Conference and mailing list
> discussions, this version of the framework has been significantly
> simplified. It now focuses exclusively on handling raw binary inputs,
> removing the complexity of the custom serialization format and DWARF
> parsing found in previous iterations.
>
> The core design consists of two main parts:
> 1. The `FUZZ_TEST_SIMPLE(name)` macro, which allows developers to define
>    a fuzz test that accepts a buffer and its length.
> 2. A simplified debugfs interface that allows userspace fuzzers (or
>    simple command-line tools) to pass raw binary blobs directly to the
>    target function.
>
> To validate the framework's end-to-end effectiveness, we performed an
> experiment by manually introducing an off-by-one buffer over-read into
> pkcs7_parse_message, like so:
>
> - ret =3D asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
> + ret =3D asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);
>
> A syzkaller instance fuzzing the new test_pkcs7_parse_message target
> introduced in patch 7 successfully triggered the bug inside of
> asn1_ber_decoder in under 30 seconds from a cold start. Similar
> experiments on the other new fuzz targets (patches 8-9) also
> successfully identified injected bugs, proving that KFuzzTest is
> effective when paired with a coverage-guided fuzzing engine.
>
> This patch series is structured as follows:
> - Patch 1 introduces the core KFuzzTest API, including the main
>   FUZZ_TEST_SIMPLE macro.
> - Patch 2 adds the runtime implementation for the framework
> - Patch 3 adds documentation.
> - Patch 4 provides sample fuzz targets.
> - Patch 5 defines fuzz targets for several functions in crypto/.
> - Patch 6 adds maintainer information for KFuzzTest.
>
> Changes since PR v3:
> - Major simplification of the architecture, removing the complex
>   `FUZZ_TEST` macro, the custom serialization format, domain
>   constraints, annotations, and associated DWARF metadata regions.
> - The framework now only supports `FUZZ_TEST_SIMPLE` targets, which
>   accept raw binary data.
> - Removed the userspace bridge tool as it is no longer required for
>   serializing inputs.
> - Updated documentation and samples to reflect the "simple-only"
>   approach.
>
> Ethan Graham (6):
>   kfuzztest: add user-facing API and data structures
>   kfuzztest: implement core module and input processing
>   kfuzztest: add ReST documentation
>   kfuzztest: add KFuzzTest sample fuzz targets
>   crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
>   MAINTAINERS: add maintainer information for KFuzzTest
>
>  Documentation/dev-tools/index.rst             |   1 +
>  Documentation/dev-tools/kfuzztest.rst         | 152 ++++++++++++++++++
>  MAINTAINERS                                   |   7 +
>  crypto/asymmetric_keys/Makefile               |   2 +
>  crypto/asymmetric_keys/tests/Makefile         |   4 +
>  crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    |  18 +++
>  .../asymmetric_keys/tests/rsa_helper_kfuzz.c  |  24 +++
>  include/asm-generic/vmlinux.lds.h             |  14 +-
>  include/linux/kfuzztest.h                     |  90 +++++++++++
>  lib/Kconfig.debug                             |   1 +
>  lib/Makefile                                  |   2 +
>  lib/kfuzztest/Kconfig                         |  16 ++
>  lib/kfuzztest/Makefile                        |   4 +
>  lib/kfuzztest/input.c                         |  47 ++++++
>  lib/kfuzztest/main.c                          | 142 ++++++++++++++++
>  samples/Kconfig                               |   7 +
>  samples/Makefile                              |   1 +
>  samples/kfuzztest/Makefile                    |   3 +
>  samples/kfuzztest/underflow_on_buffer.c       |  52 ++++++
>  19 files changed, 586 insertions(+), 1 deletion(-)
>  create mode 100644 Documentation/dev-tools/kfuzztest.rst
>  create mode 100644 crypto/asymmetric_keys/tests/Makefile
>  create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
>  create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
>  create mode 100644 include/linux/kfuzztest.h
>  create mode 100644 lib/kfuzztest/Kconfig
>  create mode 100644 lib/kfuzztest/Makefile
>  create mode 100644 lib/kfuzztest/input.c
>  create mode 100644 lib/kfuzztest/main.c
>  create mode 100644 samples/kfuzztest/Makefile
>  create mode 100644 samples/kfuzztest/underflow_on_buffer.c
>
> --
> 2.51.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6yGDGAD9VCqZyqJ8__dqHOk-ywfSdhXL5qATfxnT-QGFA%40mail.gmail.com.
