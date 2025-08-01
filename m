Return-Path: <kasan-dev+bncBCMIZB7QWENRBMX4WDCAMGQE3J7RL7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DC9C0B17BAF
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 06:10:27 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3b783265641sf874871f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 21:10:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754021427; cv=pass;
        d=google.com; s=arc-20240605;
        b=KkF6bk6tD/YVDupqk9Ssgqn0ZtEtqBQUew+R8zdQFg+aOJuMjwtBzjj/F2DRodb2aa
         t0OvQM6Q4fg7UR6Ck4BSZj6eG1qxgpH86hHDzf6DXE5kcXshHIJ8puQ6kNK0ewGvV5pm
         5ULjTxhz+Z57Fj8hjJawSuoAynGlfz78OVK2fQ6OXEFU6Zn048Ehru1/6FJN/AO6NYmc
         mYjk4vaO2bWy6oY6ly/3an4DgY3xQBesxngTC54ZYuD1ubQzRyJk6fzcCsOoI2D2/i2i
         Ne3nkYMJmpfcsgDzTjK482ilcKje6aHTAUlxiDHP/wWq0EiRU3jbp5GEC9xxY0B2xIDW
         7HQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PxdI2yGhv6qgWW32R/SslMBJBt0CrYomCUiDdmkq+OQ=;
        fh=PPu3TqiKxB0yPIGN+zO3GMv13sQhepZn42KGZKJq4r0=;
        b=V42qvbF0P5OG34ytjYLpdk7rBqNiH6A/ThDxXa6PWAWSrz06+HxLfzuhFKmNT2WE/1
         DL94Ncg476KhorwTujGbbzW+4J0Re1zGX8vMLpJJdNBNTLLTATM73itPugYvb7mf6ofX
         hAybH5IvCXcDPPMEWZIB00+Sa/FACqnUjpWrGosI8ik/8Ui36o6YMv4mwq/dWljSpybG
         XfMMF0G/ZYBelucG86oRA9w1Jjr2VICPDoVPg9+j5ZxIkZxmWH60A4ZjBg4n0wI2BUnL
         cW4eobffgglyiO8CbCENc2ihz5eJpJCW6nukYys2mlnXrn6wI+G+uJUOGqEJ9ZxvsUe7
         ZJsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kOXJXXFT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754021427; x=1754626227; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PxdI2yGhv6qgWW32R/SslMBJBt0CrYomCUiDdmkq+OQ=;
        b=fOYSp8TKAsZZ5YerQZQQGZqqWJtFUKnamXpjt/TRptN8LhptL8uHNHFpIqywcxd/M9
         u2+lBphEa2NM2whQvu9tx/o3B6pBTVsmZ7HD/30VlahCiFMWCpSoEld1XzAQPQOkMMHE
         w/+B7loO70vbvB9bhqpKdTPXznAJuDliXEh/H5fSUHF86nd93MXeas1iA7tx6FPP6iZH
         0SGCBxarKtZa1dSKXckcJvWe+z9Rw1e237DB4eLWUvCA1aQKyTGZVH0L2eIe4bRaxdH9
         vgZ9xbzZx0PIrOZZtgfI7BAN6IrVIulLjn553+oeXIKcTnXQU213hRYqLpmYklR6zKiL
         uxnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754021427; x=1754626227;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PxdI2yGhv6qgWW32R/SslMBJBt0CrYomCUiDdmkq+OQ=;
        b=P/eBRbS6l3aOFr9+LI0hCImX1Wm0KZ7NNABtKTyLzYIc1cZi4wNgqDJxR4m6+B8wII
         vOcksZ3MNDj7pJLNOWicukNCYxg46QLqK12C9/3+gu6fW4bhd++C86EX6fXtxAj32of+
         z04v7QPD7K2dI9ayomxz/pQSgSC0Kp6BraiRpfOy8Si91ggeGAsCQ3jk1/s7vQTGDfyz
         Dtn3y6pxIFJ9ytC3G79obJaANzg+9qNSo3i7Lp0tEUr2hkBoUGU7trkYvs89Oz3hmxe9
         tnBDLL1rgv6TmN2imM+EmodR7nhJYcGZAkgVYm83MVvc7EVeamhC090/jUF1375X6+FC
         qjZQ==
X-Forwarded-Encrypted: i=2; AJvYcCX4GtrMxJp5i7FucQlZ3f4oF5BwArfV5QGtjibvKITucqTjTHFVkIbfiRwAUIDNzjbddjMGuw==@lfdr.de
X-Gm-Message-State: AOJu0YwXC86mg2B7uvenp6YvoV46LQM4cyRd35BSvkQNHdaKprqxQIjQ
	AYRiEBvuF3+T91Cr+a/UwMTLVCEQ2zALv0a8x4cahzP6Lr2KLrMLUO6C
X-Google-Smtp-Source: AGHT+IH30Ylu1XiGIU3fTx/aynRY3OVLEUXDEwQlEIIDFk59k6Ppw7EnKib37BQ/96KhwV3j1vJDhw==
X-Received: by 2002:a05:6000:2501:b0:3b7:974d:533f with SMTP id ffacd0b85a97d-3b7974d58a4mr5711723f8f.34.1754021427010;
        Thu, 31 Jul 2025 21:10:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfp1C0OMUg28S/IHKOgucMyDdI/qEPJ0jAaCYzD8jQ52A==
Received: by 2002:a05:6000:2892:b0:3b7:9bb1:790b with SMTP id
 ffacd0b85a97d-3b79c34dc78ls572784f8f.0.-pod-prod-04-eu; Thu, 31 Jul 2025
 21:10:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8ZoTuJaPm3+90oNpfeT1LLm25NtnYLBCmRbf1VkkUL+AY2nLtrBW6IIHS1f8hoQb6+dL/vhznbjM=@googlegroups.com
X-Received: by 2002:a05:6000:40ce:b0:3b7:78c8:937f with SMTP id ffacd0b85a97d-3b794fc30e4mr7197319f8f.20.1754021424327;
        Thu, 31 Jul 2025 21:10:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754021424; cv=none;
        d=google.com; s=arc-20240605;
        b=c9cyFldeCorKwLek+HBdNXQLq9EnqHPsK75A25t4VJZBB7rpUUXaDj3rDN69g3Hu06
         HvzUXapvNTF49l2e954vzgsVLKXaXyJ/BX1Gfihbpe1ZM+7x9L/6ynDONSnzGmWZvNHl
         Ik1Gzbcb5uA+DsuScwz+pMTh5pEPZ8BgeSaet9jXz/3441aAa6XM0pvce4vlblo93jEq
         SrI39t1GHj6OjoJBI//6HJ/6VyS57EMQ+mQOq2ss/+7C+doWhO0ROe9KacJjFRAQmSIH
         b62gO2jNXsmBBBKS5hZUoMaS6ghw+CO3YbCt32NvUxoMMaxBsBWSZjplEgRGzoYig7V/
         vptg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DAW4jsjGko+3B//T/ExjPGSsgZPk1ToCs8jJS1FOe/8=;
        fh=xp3yhMsV5SV+3N2M2mxuxKs8kzvaHJFV4Ne+nhpIW6A=;
        b=OO2sqySvQ0ziWQhD7xk4PGNj1tQZPy1wy3ofIf6kt4BjFtJMqNjCUlZrPfcawDpEdW
         TRygK2GkLYn+ZGoMvkhgg03xI/VzNtlW6XRuYaGhnBEaZ0S5cmuKQfu5BDhlpUQOHDCr
         kBCnT5xyqX5fVP4uD77zi/SuIf0sa8Iiwg/Fh87s3jVGT8CBuarbgcNQ9k4lGUOtXs16
         njBlx5ec9LqIho9rp4ZPekB+ET2ps0pVjlFlG4u+oMH/uQquV/8p3JXnDFPGtPGWXFCd
         eZhoyV2VRg4rQSED6Fx6/6MrK8tU0u0HXbYR1p+OOBOChIxOkZB5TQctr8+S4pWemwod
         b0gA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kOXJXXFT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c48d27dsi79771f8f.8.2025.07.31.21.10.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 21:10:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-33211f7f06eso9935551fa.2
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 21:10:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmJxl0PCIhAqyIiGaHuTVk4i2zNRw7HgymVQGJ5JHWqma7Da61ACsT6RoxHADGmQSsJuNiURBYl8E=@googlegroups.com
X-Gm-Gg: ASbGnctlHliPCPWhya7zpUfYwJzsYK34atdIRdSqB9DWnp2JcsT2A4uINMOeEMzf40I
	VFEX49N7/GnyObm119aSp6PPueIyUMogAzg5keNs8Tf+NjMwn4z5o+LNG0O8esVjVl2ptHzfMlD
	2ykSniXOEVZN7CVXWjBAftb7Il22Bu2jkA9js4ulzbAa+Funk8uHSTXpAKox9I9E3TLecAudWQk
	a7dehSS2wWJKSomqlL9DLBD+IsMAluFkOA3heg=
X-Received: by 2002:a2e:9215:0:b0:32c:bc69:e921 with SMTP id
 38308e7fff4ca-33224a7b2b4mr24191841fa.9.1754021423238; Thu, 31 Jul 2025
 21:10:23 -0700 (PDT)
MIME-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com> <20250731115139.3035888-10-glider@google.com>
In-Reply-To: <20250731115139.3035888-10-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Aug 2025 06:10:11 +0200
X-Gm-Features: Ac12FXzVDZLMsbHd-ebP8MIlpJEBPq1Ul2ifjai1v48RZ5V6KaIP2GFJOPpyIHU
Message-ID: <CACT4Y+bLQvbfW0_wmJ9f+ESrOd4JuR6jk5ngzq936XkZNSRZ9Q@mail.gmail.com>
Subject: Re: [PATCH v4 09/10] kcov: selftests: add kcov_test
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
 header.i=@google.com header.s=20230601 header.b=kOXJXXFT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236
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

On Thu, 31 Jul 2025 at 13:52, Alexander Potapenko <glider@google.com> wrote:
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v4:
>  - Per Dmitry Vyukov's request, add CONFIG_KCOV_UNIQUE=y to the
>    list of required configs
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
>  tools/testing/selftests/kcov/config      |   2 +
>  tools/testing/selftests/kcov/kcov_test.c | 401 +++++++++++++++++++++++
>  4 files changed, 410 insertions(+)
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
> index 0000000000000..ba0c1a0bc8bf2
> --- /dev/null
> +++ b/tools/testing/selftests/kcov/config
> @@ -0,0 +1,2 @@
> +CONFIG_KCOV=y
> +CONFIG_KCOV_UNIQUE=y
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
> 2.50.1.552.g942d659e1b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbLQvbfW0_wmJ9f%2BESrOd4JuR6jk5ngzq936XkZNSRZ9Q%40mail.gmail.com.
