Return-Path: <kasan-dev+bncBCMIZB7QWENRB7O4ULCAMGQE3YAW4LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 61E39B14CEB
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:20:31 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32b3ba8088fsf25951271fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:20:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753788030; cv=pass;
        d=google.com; s=arc-20240605;
        b=OAByhB2MhIbVmJNoU9MYPk5TSXLTTNNpoYzICX/3l6ySOLzEs+LiU3o7GQO3Y2DVgd
         gH6apc1I4745/Q8gKIu7QxrD4aYFCAxY8+mAKNiGcSCs/X1if/c3gbIqw0rKcQJ2J2W7
         VkftDBn1nx1TJcbWMj7g+Be49x6NReu+G44f3QLPaZnobIQH8oSDOLGP70KxaKFfYald
         pksmUHEo3ur+zmKsD1y6JObOyoeQxRmvb4mEsLjN3Dg24mHQnV+A6je1E11+5CFQnVlK
         lzXPIsBMhHxmOI9TWanHWRJ/UMwZmvcCY+BuWOvHOMfuXC2iJ2JFMbNBijDOBMk4YJLy
         4YKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+KzbTcZpwMo5LtWihtAV+gTr2IGvaQK3P2kp1th+WQI=;
        fh=+B9BkuKCnNt7YGpqnUzgaQfSqbK1AEUyHQ4xstXFbZI=;
        b=DjydAf+dy66PqTtKygwjSci6jECkIU9O4ZXsHmT9fxuR8vdbF5MuDsITkMk4mkgpia
         dSASGzZUH2Rw8mKuNLNy9ut4BCo/999q8tLYhuKYHqYNOyVZ9jE4u1jGGP/Y2bsjHztn
         ueKeUO0o78SS8X/v70cfVn/EHuvwT9v0wlUvscTUD855sw0Ag9PmcX5Y3Vl+r7YzEnTk
         GC2ThpmJZk1+kAjzIcE2vb3PIx42RiXutMMptb/kzy+OucI+8pGMa3DST1fgYbgFJZ0t
         u1pBRJzx5yZU1/Q99UFLAxK0lE27F7cZdN2zFT5wOUS6wqGBFhiwGvFIE0/ksKARt0b3
         3exA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WvZd4JOA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753788030; x=1754392830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+KzbTcZpwMo5LtWihtAV+gTr2IGvaQK3P2kp1th+WQI=;
        b=xvcXNF5q/V5Pj7H3v/78FvuygDFWvNPfHybb2RinRZmXRK86MmrczGgrkmgPXo5TPa
         x/RVXbLA5wyaJUbDJsmmtuNUGCyGjHFtGm/NkMafL9LUwbYPthGfN5XM0kKNBk1VGOPl
         ZDcBXwbECL/0Nv8xgiZm1jDrQMuuqUyqd2hquFhiI3gdAJgEufkdnTZn3eHpxbgATKEf
         MJubkSjNH5ZtqlweDs56AUdbm8rhpsYE3f3HyRlawTLMHXbRrzud9tvVEhz7j4MQmKpf
         NQKtAQ8e1asFNtJKOXhW8GQJt+ey5PDN/1Q50yeNBopVBWp4+oqyl9ImZHkjZ5Crf4ZG
         S1ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753788030; x=1754392830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+KzbTcZpwMo5LtWihtAV+gTr2IGvaQK3P2kp1th+WQI=;
        b=EIN7jGyupgOusC54NpGFoPmgZf8y82xC4RzO8bb3w9viSLNxUIdVMGtV6JzsruVji4
         T/JQrOvHqSGPBMz6b4zFCR7IiIPhJuuZN6pqQga9rXI7PhDpqQu/3XlbHHWHaf2AiG/9
         OZTBnWjVbVMgHY9TcwQwNJpoML9LtXWUH6mK+KQw365AfNEVrtMHVBtumxUXPb+4jWoV
         QmbDiZxIuRclcozyvDm7n+8MBfZ/WMKWd/aHCRLVMvAxdVVzeaVcGoYUnVfkQxyAedrA
         bma90kUUKYFm379vtdlOqfC72f33f36h/ZgbnSJHmIoqr9PNsSStsR+ENC9XJ8L/WI3G
         Ftug==
X-Forwarded-Encrypted: i=2; AJvYcCVxcRG8tlR613Yc3+mXyf4Ywzb9+9y7FM4h4JOarf/VboZXc2E4ot0UJJBS5AzPpya7QrO/vA==@lfdr.de
X-Gm-Message-State: AOJu0YwjDlP4+UbQv/Y0Q1sZLC57S8oGxJEBTCI5h0Q7K8jKmuId7sii
	C6l82Ta0AN1NQfNuWUoekUUafgCK8/8Kly5tdHzDBtN+H0N/bPXTBWP9
X-Google-Smtp-Source: AGHT+IGXScQKtJLBBW52PSfF2j3BJzq739Jyd5wOeXRY3Q9om4vaIM+9+iIdKQm+5cuLPYqhI/JYMw==
X-Received: by 2002:a05:651c:12c3:b0:32b:541c:eae1 with SMTP id 38308e7fff4ca-331ee7d5070mr42264771fa.25.1753788030308;
        Tue, 29 Jul 2025 04:20:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfU6958Cgz50p/BzAUyHOzlQfZgUwlWjjnj7/spn4Ooig==
Received: by 2002:a2e:ae0e:0:b0:32e:7ea6:5ee9 with SMTP id 38308e7fff4ca-331dd854bd7ls7562851fa.0.-pod-prod-01-eu;
 Tue, 29 Jul 2025 04:20:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVdUMopRZXAol4bkN1IMWgDKMRoU8blOBB7AJmw2JIjB64vxq4tbGpKmeKMmccXC0A4/RzhXRCqHU=@googlegroups.com
X-Received: by 2002:a2e:a016:0:20b0:32c:bc69:e918 with SMTP id 38308e7fff4ca-331ee6e8258mr24998091fa.1.1753788027371;
        Tue, 29 Jul 2025 04:20:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753788027; cv=none;
        d=google.com; s=arc-20240605;
        b=RK3R3Ksucpl9x19y+S49DgiHhPbsKnZbi6VOrBCPy3yIX1ykUI/2xt3rFfbuLcsLIm
         DqOYZPsqzWjV50DmKtkYI/zPNKG9SvRpRetWbEGrk17+u3y9JbGWOk4SUV9cokLOUPuB
         Mc+TJewWYVibPOl2W38dkimeQXGbEha1VIhLSBjRx+F3Re6HLynSmB1TEat5L8RzhXP0
         8d07XCCNqPVF8nMfjgdTAgXLG3iksSCpAO1X6RTUVxCWmkawxqEeem/lwzY6xcjnfPZr
         CdRl4GrvxE84XHdRKJlwCcBrb1U4oM5z57mnS8+d+f6OsOy0JWw15xO2wI+yrVCW0aKW
         +vQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U7a5Qfq8u0F7Zd+NXZdg2+TWeHkUTlUkzN/PPKJBQOE=;
        fh=BAYlfYM9mmgipIINAB0ebXsqm3RIPkl2miT/ifKXHIM=;
        b=UI75lPenMoCoC5rwoFY5ykUWqf8l6W2cnQ6+bNjJtXeugkRpLxv+X+/F9128Q127g7
         k5zW1Bv/aO0/KenPG9wZDZRX6M2LlHoRAIt5NFhf00ZaYFz0Kf+Rg38QDX8A7Qgvcms7
         sS57hCBRlhvbs6piMpaQHrvi+S/twOViUWS6OYyOzotv0fTE2/R71gyU5DV9OVgxqOLu
         Yi+sSOsQWX7DmspCj7BELx2lTDnX6c8uyf3pGJCB9oXE8eBBs7O0u/6XEGBcRvc2Mfhf
         tpJ2vR4n9wmkMFjzJ+kkO5zLkWy40AhvqPMyNddboUM5kqe1XnMY71H9DZIJXcOjx/5/
         rDtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WvZd4JOA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331f3f71112si2375261fa.0.2025.07.29.04.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 04:20:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-32b5931037eso44452031fa.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 04:20:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX8LmQxA3W5pEvCcfX0zbibYizCk+F/sNyblWhD4NTZocUkizUqp1nRDtGZDQ/v+vunrXs1jzalUXE=@googlegroups.com
X-Gm-Gg: ASbGncvvDLGA4n9If7+JZ4sv8YI4u+4Ro9l8XnfU6+XZs76HbTra5+Ce+rJ/ccji+sT
	1QRGHle2xv1o/RAnTMJTUzON2HsXBERO3Y1noMoOaCcwqM9qe+kwjc7yxi1OzoTeUQkzedDliZq
	C+5bVb7txsLVJYPZgo7U6Q6iWYx8cwRquBffVRgxR5Auj67ePS7XSQd/NE5etOKo6qDkRmfUS0r
	rQk5dn1+iHTDlxaMdjMuhdWZ+Iq2TrB0IZqhA==
X-Received: by 2002:a2e:be11:0:b0:32b:3437:7e8d with SMTP id
 38308e7fff4ca-331ee71f2b2mr38797181fa.15.1753788026564; Tue, 29 Jul 2025
 04:20:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-10-glider@google.com>
In-Reply-To: <20250728152548.3969143-10-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 13:20:14 +0200
X-Gm-Features: Ac12FXxoKFsyI2LAq_zjKXTGWQpiTX5B6u3J6kcXFdWKj58bU12TFaRGu0CROPY
Message-ID: <CACT4Y+Y6gkd23+cVEkTs_MDfvOskd=Z4=dVh-LL-F_Jbgf8xnA@mail.gmail.com>
Subject: Re: [PATCH v3 09/10] kcov: selftests: add kcov_test
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WvZd4JOA;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wrote:
>
> Implement test fixtures for testing different combinations of coverage
> collection modes:
>  - unique and non-unique coverage;
>  - collecting PCs and comparison arguments;
>  - mapping the buffer as RO and RW.
>
> To build:
>  $ make -C tools/testing/selftests/kcov kcov_test
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v3:
>  - Address comments by Dmitry Vyukov:
>    - add tools/testing/selftests/kcov/config
>    - add ifdefs to KCOV_UNIQUE_ENABLE and KCOV_RESET_TRACE
>  - Properly handle/reset the coverage buffer when collecting unique
>    coverage
>
> Change-Id: I0793f1b91685873c77bcb222a03f64321244df8f
> ---
>  MAINTAINERS                              |   1 +
>  tools/testing/selftests/kcov/Makefile    |   6 +
>  tools/testing/selftests/kcov/config      |   1 +
>  tools/testing/selftests/kcov/kcov_test.c | 401 +++++++++++++++++++++++
>  4 files changed, 409 insertions(+)
>  create mode 100644 tools/testing/selftests/kcov/Makefile
>  create mode 100644 tools/testing/selftests/kcov/config
>  create mode 100644 tools/testing/selftests/kcov/kcov_test.c
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 6906eb9d88dae..c1d64cef693b9 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13018,6 +13018,7 @@ F:      include/linux/kcov_types.h
>  F:     include/uapi/linux/kcov.h
>  F:     kernel/kcov.c
>  F:     scripts/Makefile.kcov
> +F:     tools/testing/selftests/kcov/
>
>  KCSAN
>  M:     Marco Elver <elver@google.com>
> diff --git a/tools/testing/selftests/kcov/Makefile b/tools/testing/selftests/kcov/Makefile
> new file mode 100644
> index 0000000000000..08abf8b60bcf9
> --- /dev/null
> +++ b/tools/testing/selftests/kcov/Makefile
> @@ -0,0 +1,6 @@
> +# SPDX-License-Identifier: GPL-2.0-only
> +LDFLAGS += -static
> +
> +TEST_GEN_PROGS := kcov_test
> +
> +include ../lib.mk
> diff --git a/tools/testing/selftests/kcov/config b/tools/testing/selftests/kcov/config
> new file mode 100644
> index 0000000000000..75726b2aa9979
> --- /dev/null
> +++ b/tools/testing/selftests/kcov/config
> @@ -0,0 +1 @@
> +CONFIG_KCOV=y

Doesn't it also need CONFIG_KCOV_UNIQUE=y since it tests the unique
mode as well?


> diff --git a/tools/testing/selftests/kcov/kcov_test.c b/tools/testing/selftests/kcov/kcov_test.c
> new file mode 100644
> index 0000000000000..daf12aeb374b5
> --- /dev/null
> +++ b/tools/testing/selftests/kcov/kcov_test.c
> @@ -0,0 +1,401 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * Test the kernel coverage (/sys/kernel/debug/kcov).
> + *
> + * Copyright 2025 Google LLC.
> + */
> +#include <fcntl.h>
> +#include <linux/kcov.h>
> +#include <stdint.h>
> +#include <stddef.h>
> +#include <stdio.h>
> +#include <stdlib.h>
> +#include <sys/ioctl.h>
> +#include <sys/mman.h>
> +#include <sys/types.h>
> +#include <unistd.h>
> +
> +#include "../kselftest_harness.h"
> +
> +/* Normally these defines should be provided by linux/kcov.h, but they aren't there yet. */
> +#ifndef KCOV_UNIQUE_ENABLE
> +#define KCOV_UNIQUE_ENABLE _IOW('c', 103, unsigned long)
> +#endif
> +#ifndef KCOV_RESET_TRACE
> +#define KCOV_RESET_TRACE _IO('c', 104)
> +#endif
> +
> +#define COVER_SIZE (64 << 10)
> +#define BITMAP_SIZE (4 << 10)
> +
> +#define DEBUG_COVER_PCS 0
> +
> +FIXTURE(kcov)
> +{
> +       int fd;
> +       unsigned long *mapping;
> +       size_t mapping_size;
> +};
> +
> +FIXTURE_VARIANT(kcov)
> +{
> +       int mode;
> +       bool fast_reset;
> +       bool map_readonly;
> +};
> +
> +/* clang-format off */
> +FIXTURE_VARIANT_ADD(kcov, mode_trace_pc)
> +{
> +       /* clang-format on */
> +       .mode = KCOV_TRACE_PC,
> +       .fast_reset = true,
> +       .map_readonly = false,
> +};
> +
> +/* clang-format off */
> +FIXTURE_VARIANT_ADD(kcov, mode_trace_cmp)
> +{
> +       /* clang-format on */
> +       .mode = KCOV_TRACE_CMP,
> +       .fast_reset = true,
> +       .map_readonly = false,
> +};
> +
> +/* clang-format off */
> +FIXTURE_VARIANT_ADD(kcov, reset_ioctl_rw)
> +{
> +       /* clang-format on */
> +       .mode = KCOV_TRACE_PC,
> +       .fast_reset = false,
> +       .map_readonly = false,
> +};
> +
> +FIXTURE_VARIANT_ADD(kcov, reset_ioctl_ro)
> +/* clang-format off */
> +{
> +       /* clang-format on */
> +       .mode = KCOV_TRACE_PC,
> +       .fast_reset = false,
> +       .map_readonly = true,
> +};
> +
> +int kcov_open_init(struct __test_metadata *_metadata, unsigned long size,
> +                  int prot, unsigned long **out_mapping)
> +{
> +       unsigned long *mapping;
> +
> +       /* A single fd descriptor allows coverage collection on a single thread. */
> +       int fd = open("/sys/kernel/debug/kcov", O_RDWR);
> +
> +       ASSERT_NE(fd, -1)
> +       {
> +               perror("open");
> +       }
> +
> +       EXPECT_EQ(ioctl(fd, KCOV_INIT_TRACE, size), 0)
> +       {
> +               perror("ioctl KCOV_INIT_TRACE");
> +               close(fd);
> +       }
> +
> +       /* Mmap buffer shared between kernel- and user-space. */
> +       mapping = (unsigned long *)mmap(NULL, size * sizeof(unsigned long),
> +                                       prot, MAP_SHARED, fd, 0);
> +       ASSERT_NE((void *)mapping, MAP_FAILED)
> +       {
> +               perror("mmap");
> +               close(fd);
> +       }
> +       *out_mapping = mapping;
> +
> +       return fd;
> +}
> +
> +FIXTURE_SETUP(kcov)
> +{
> +       int prot = variant->map_readonly ? PROT_READ : (PROT_READ | PROT_WRITE);
> +
> +       /* Read-only mapping is incompatible with fast reset. */
> +       ASSERT_FALSE(variant->map_readonly && variant->fast_reset);
> +
> +       self->mapping_size = COVER_SIZE;
> +       self->fd = kcov_open_init(_metadata, self->mapping_size, prot,
> +                                 &(self->mapping));
> +
> +       /* Enable coverage collection on the current thread. */
> +       EXPECT_EQ(ioctl(self->fd, KCOV_ENABLE, variant->mode), 0)
> +       {
> +               perror("ioctl KCOV_ENABLE");
> +               /* Cleanup will be handled by FIXTURE_TEARDOWN. */
> +               return;
> +       }
> +}
> +
> +void kcov_uninit_close(struct __test_metadata *_metadata, int fd,
> +                      unsigned long *mapping, size_t size)
> +{
> +       /* Disable coverage collection for the current thread. */
> +       EXPECT_EQ(ioctl(fd, KCOV_DISABLE, 0), 0)
> +       {
> +               perror("ioctl KCOV_DISABLE");
> +       }
> +
> +       /* Free resources. */
> +       EXPECT_EQ(munmap(mapping, size * sizeof(unsigned long)), 0)
> +       {
> +               perror("munmap");
> +       }
> +
> +       EXPECT_EQ(close(fd), 0)
> +       {
> +               perror("close");
> +       }
> +}
> +
> +FIXTURE_TEARDOWN(kcov)
> +{
> +       kcov_uninit_close(_metadata, self->fd, self->mapping,
> +                         self->mapping_size);
> +}
> +
> +void dump_collected_pcs(struct __test_metadata *_metadata, unsigned long *cover,
> +                       size_t start, size_t end)
> +{
> +       int i = 0;
> +
> +       TH_LOG("Collected %lu PCs", end - start);
> +#if DEBUG_COVER_PCS
> +       for (i = start; i < end; i++)
> +               TH_LOG("0x%lx", cover[i + 1]);
> +#endif
> +}
> +
> +/* Coverage collection helper without assertions. */
> +unsigned long collect_coverage_unchecked(struct __test_metadata *_metadata,
> +                                        unsigned long *cover, bool dump)
> +{
> +       unsigned long before, after;
> +
> +       before = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> +       /*
> +        * Call the target syscall call. Here we use read(-1, NULL, 0) as an example.
> +        * This will likely return an error (-EFAULT or -EBADF), but the goal is to
> +        * collect coverage for the syscall's entry/exit paths.
> +        */
> +       read(-1, NULL, 0);
> +
> +       after = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> +
> +       if (dump)
> +               dump_collected_pcs(_metadata, cover, before, after);
> +       return after - before;
> +}
> +
> +unsigned long collect_coverage_once(struct __test_metadata *_metadata,
> +                                   unsigned long *cover)
> +{
> +       unsigned long collected =
> +               collect_coverage_unchecked(_metadata, cover, /*dump*/ true);
> +
> +       /* Coverage must be non-zero. */
> +       EXPECT_GT(collected, 0);
> +       return collected;
> +}
> +
> +void reset_coverage(struct __test_metadata *_metadata, bool fast, int fd,
> +                   unsigned long *mapping)
> +{
> +       unsigned long count;
> +
> +       if (fast) {
> +               __atomic_store_n(&mapping[0], 0, __ATOMIC_RELAXED);
> +       } else {
> +               EXPECT_EQ(ioctl(fd, KCOV_RESET_TRACE, 0), 0)
> +               {
> +                       perror("ioctl KCOV_RESET_TRACE");
> +               }
> +               count = __atomic_load_n(&mapping[0], __ATOMIC_RELAXED);
> +               EXPECT_NE(count, 0);
> +       }
> +}
> +
> +TEST_F(kcov, kcov_basic_syscall_coverage)
> +{
> +       unsigned long first, second, before, after, i;
> +
> +       /* Reset coverage that may be left over from the fixture setup. */
> +       reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
> +
> +       /* Collect the coverage for a single syscall two times in a row. */
> +       first = collect_coverage_once(_metadata, self->mapping);
> +       second = collect_coverage_once(_metadata, self->mapping);
> +       /* Collected coverage should not differ too much. */
> +       EXPECT_GT(first * 10, second);
> +       EXPECT_GT(second * 10, first);
> +
> +       /* Now reset the buffer and collect the coverage again. */
> +       reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
> +       collect_coverage_once(_metadata, self->mapping);
> +
> +       /* Now try many times to fill up the buffer. */
> +       reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
> +       while (collect_coverage_unchecked(_metadata, self->mapping,
> +                                         /*dump*/ false)) {
> +               /* Do nothing. */
> +       }
> +       before = __atomic_load_n(&(self->mapping[0]), __ATOMIC_RELAXED);
> +       /*
> +        * Resetting with ioctl may still generate some coverage, but much less
> +        * than there was before.
> +        */
> +       reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
> +       after = __atomic_load_n(&(self->mapping[0]), __ATOMIC_RELAXED);
> +       EXPECT_GT(before, after);
> +       /* Collecting coverage after reset will now succeed. */
> +       collect_coverage_once(_metadata, self->mapping);
> +}
> +
> +FIXTURE(kcov_uniq)
> +{
> +       int fd;
> +       unsigned long *mapping;
> +       size_t mapping_size;
> +       unsigned long *bitmap;
> +       size_t bitmap_size;
> +       unsigned long *cover;
> +       size_t cover_size;
> +};
> +
> +FIXTURE_VARIANT(kcov_uniq)
> +{
> +       bool fast_reset;
> +       bool map_readonly;
> +};
> +
> +/* clang-format off */
> +FIXTURE_VARIANT_ADD(kcov_uniq, fast_rw)
> +{
> +       /* clang-format on */
> +       .fast_reset = true,
> +       .map_readonly = false,
> +};
> +
> +/* clang-format off */
> +FIXTURE_VARIANT_ADD(kcov_uniq, slow_rw)
> +{
> +       /* clang-format on */
> +       .fast_reset = false,
> +       .map_readonly = false,
> +};
> +
> +/* clang-format off */
> +FIXTURE_VARIANT_ADD(kcov_uniq, slow_ro)
> +{
> +       /* clang-format on */
> +       .fast_reset = false,
> +       .map_readonly = true,
> +};
> +
> +FIXTURE_SETUP(kcov_uniq)
> +{
> +       int prot = variant->map_readonly ? PROT_READ : (PROT_READ | PROT_WRITE);
> +
> +       /* Read-only mapping is incompatible with fast reset. */
> +       ASSERT_FALSE(variant->map_readonly && variant->fast_reset);
> +
> +       self->mapping_size = COVER_SIZE;
> +       self->fd = kcov_open_init(_metadata, self->mapping_size, prot,
> +                                 &(self->mapping));
> +
> +       self->bitmap = self->mapping;
> +       self->bitmap_size = BITMAP_SIZE;
> +       /*
> +        * Enable unique coverage collection on the current thread. Carve out
> +        * self->bitmap_size unsigned long's for the bitmap.
> +        */
> +       EXPECT_EQ(ioctl(self->fd, KCOV_UNIQUE_ENABLE, self->bitmap_size), 0)
> +       {
> +               perror("ioctl KCOV_ENABLE");
> +               /* Cleanup will be handled by FIXTURE_TEARDOWN. */
> +               return;
> +       }
> +       self->cover = self->mapping + BITMAP_SIZE;
> +       self->cover_size = self->mapping_size - BITMAP_SIZE;
> +}
> +
> +FIXTURE_TEARDOWN(kcov_uniq)
> +{
> +       kcov_uninit_close(_metadata, self->fd, self->mapping,
> +                         self->mapping_size);
> +}
> +
> +void reset_uniq_coverage(struct __test_metadata *_metadata, bool fast, int fd,
> +                        unsigned long *bitmap, unsigned long *cover)
> +{
> +       unsigned long count;
> +
> +       if (fast) {
> +               /*
> +                * Resetting the buffer for unique coverage collection requires
> +                * zeroing out the bitmap and cover[0]. We are assuming that
> +                * the coverage buffer immediately follows the bitmap, as they
> +                * belong to the same memory mapping.
> +                */
> +               if (cover > bitmap)
> +                       memset(bitmap, 0, sizeof(unsigned long) * (cover - bitmap));
> +               __atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
> +       } else {
> +               EXPECT_EQ(ioctl(fd, KCOV_RESET_TRACE, 0), 0)
> +               {
> +                       perror("ioctl KCOV_RESET_TRACE");
> +               }
> +               count = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> +               EXPECT_NE(count, 0);
> +       }
> +}
> +
> +TEST_F(kcov_uniq, kcov_uniq_coverage)
> +{
> +       unsigned long first, second, before, after, i;
> +
> +       /* Reset coverage that may be left over from the fixture setup. */
> +       reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
> +
> +       /*
> +        * Collect the coverage for a single syscall two times in a row.
> +        * Use collect_coverage_unchecked(), because it may return zero coverage.
> +        */
> +       first = collect_coverage_unchecked(_metadata, self->cover,
> +                                          /*dump*/ true);
> +       second = collect_coverage_unchecked(_metadata, self->cover,
> +                                           /*dump*/ true);
> +
> +       /* Now reset the buffer and collect the coverage again. */
> +       reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
> +       collect_coverage_once(_metadata, self->cover);
> +
> +       /* Now try many times to saturate the unique coverage bitmap. */
> +       reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
> +       for (i = 0; i < 1000; i++)
> +               collect_coverage_unchecked(_metadata, self->cover,
> +                                          /*dump*/ false);
> +
> +       /* Another invocation of collect_coverage_unchecked() should not produce new coverage. */
> +       EXPECT_EQ(collect_coverage_unchecked(_metadata, self->cover,
> +                                            /*dump*/ false),
> +                 0);
> +
> +       before = __atomic_load_n(&(self->cover[0]), __ATOMIC_RELAXED);
> +       /*
> +        * Resetting with ioctl may still generate some coverage, but much less
> +        * than there was before.
> +        */
> +       reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
> +       after = __atomic_load_n(&(self->cover[0]), __ATOMIC_RELAXED);
> +       EXPECT_GT(before, after);
> +       /* Collecting coverage after reset will now succeed. */
> +       collect_coverage_once(_metadata, self->cover);
> +}
> +
> +TEST_HARNESS_MAIN
> --
> 2.50.1.470.g6ba607880d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY6gkd23%2BcVEkTs_MDfvOskd%3DZ4%3DdVh-LL-F_Jbgf8xnA%40mail.gmail.com.
