Return-Path: <kasan-dev+bncBCMIZB7QWENRBKUPXLBQMGQEOEFKNLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A751CAFED61
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jul 2025 17:15:55 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-453817323afsf33782905e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 08:15:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752074155; cv=pass;
        d=google.com; s=arc-20240605;
        b=CqA0LSrdEkQbB1H8efp1AG47+3+P3h6LrbiVUbPCcxPBfhRcXItfGyLqjVvTB3qZRO
         SIqu1Ak8cwLX77/EnRqP83If87YcNL4huWh1FpGCZGKme3nvH+7Qex8HPjqw9b7MoT/b
         CmqBlQaPayJCeaf6SligiE9R6b1vGPCIGacp6Ko/BdVwcbjIqoMXOp252oQm7TxMa5my
         /pW6uUxGKHSALWBo9kpIWYV41ixiNHjDh12LrdU2q5EHJTUgClCCXKtRch79FIJHkuEk
         FL26Am+r6fZLV8Z9eRWKncmZdFUOcTdynnyXSsZndaX9SDSSgx4BCCqaX2IrGoJS9bk5
         9gzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0iEEAaNoj0mA2X7jhk95WDjj6G6xgsD6P/mDcHhEpUw=;
        fh=iaFkM+CwdjBBpHYqpqvBFr99SKRB5Zuw97rB8YpQNXM=;
        b=biNKckGTMyLvIKDsc7iRpmhyrVgM47cm+GLpzK9o/IfDwbgOGaqiVbC70wvk79EjGr
         eSgmDXUaN4Q1OnsYX/y/7Wi448LZGx9eyHLp1npFciUgCSz0ZWchnxMSrVjEOMW2jWGM
         59svoZFO2NQcsUblsA4WL1b9N1TerzQY+ZAZO9MBDqoWlIltA/lblr1wl86p3ekDmoH4
         cWe/CQGpjKokwmr0RyvwVmc2Y4zHyM+65LZEDeQNi/WiCVV2zdYyD6FqAoWI9Ve2qaGe
         qsY54ELvNB7RzNOnVMrebR4fZJ2AeOPMGqLPM6QUzj1aiCPcR8fICieHEtUUYMGHu9LX
         V3LQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vnEsuWUI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752074155; x=1752678955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0iEEAaNoj0mA2X7jhk95WDjj6G6xgsD6P/mDcHhEpUw=;
        b=taE1zB5AI7/e3P1ZWwJIiCmsIsATVaqfATy053o7YiEpVNX4xJJuhqTf/Cc7RxsjqS
         cLq5B9jKgOz/IT4BIDWD9kqF3b9Iqj9RCR+y5r2uH8qqCgrv4aBeBy2oCVtLZ5LC7RDW
         mOyrTwh+7+C+J601Dpl1fG4Mfgq53D2BpS5dBEuVK5+ULbDN+nRRXWeqUb428cpLBJbI
         8N6V0HEjEXuwa4KCp1753d4rf6Hvzxao+fwHvdSo2bCPzfOQ0P2KW5yPa/OI4tq2/8QT
         4eVogzEIbOce4BgCzwgcrVcfrAXBpCAbdZuM/W0cQ+Ds3Ci3eBOZnVl5wW1xX2jlwH2U
         Na8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752074155; x=1752678955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0iEEAaNoj0mA2X7jhk95WDjj6G6xgsD6P/mDcHhEpUw=;
        b=BmLRldj3U6WYvc+Q9PLdLmcDN880b+x6NAVZrAEhlnK2NggmlXenAkd599tOf6mHnN
         fvPKQoAY1zqhXbEtKXSr2tgMNEoTAmoJ6ImSu1LATkZ+bz9wBEMMocM+QyxbEG3oB5X9
         VT9tTzEvAHhXcxjbxy40Ep9cDwWFLRt9xctVfY6G7FL3CgoaOqX0R28GEyMiw/MhbEI5
         doo69+tHaTQ7LXTpkPzk4hFUBFga9nzp0j79G11c0x9UKZeEjJKC4rFvifKnD2YT2v1R
         Xx5dRiL2JGBBwuoDwqAMdlfDHeVoytVyxD/HASDyBPB9JC902QpflCy2MOu0y4FN7QDJ
         0DmQ==
X-Forwarded-Encrypted: i=2; AJvYcCUItIofaH91TK4X57lD92iS8Z0liSltw0w9I5sNjz8RqjERW3l6RcDMX7w6gpi4q9jsbJ4haw==@lfdr.de
X-Gm-Message-State: AOJu0Yzt04uSDNDG9RZeZezrospC1ijlTheGoi+/4WpQZ4LGlbWmwCSo
	elElMyIl4yHoHxi61nlE4F7iM1TJmaAq9HYL0vR089cPicASiT6pLUKp
X-Google-Smtp-Source: AGHT+IFTsO64D20vKo2Q6IWF/fLpiuIFITyWH+8hXJfPwa4EBo5fscYhopg+b0oBJRXKWaEEL7K6NQ==
X-Received: by 2002:a05:600c:198c:b0:442:dc6f:7a21 with SMTP id 5b1f17b1804b1-454d52f3b13mr31710735e9.3.1752074154633;
        Wed, 09 Jul 2025 08:15:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfw+Y3IZ/Q6aM0lklXwuN1K9nBePOk23BbPl6XSwbkzMg==
Received: by 2002:a05:600c:4f07:b0:454:ae22:a989 with SMTP id
 5b1f17b1804b1-454db524ddels125065e9.2.-pod-prod-04-eu; Wed, 09 Jul 2025
 08:15:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9yHqdi0B+MOhnl06ViJcjmZnipkH8R3l5xied5VUMTTtwxvXJC5enhA3BTpsQtdIHQNz+yFOxWL0=@googlegroups.com
X-Received: by 2002:a05:600c:4f11:b0:43d:9d5:474d with SMTP id 5b1f17b1804b1-454d522d0d0mr32338255e9.0.1752074151729;
        Wed, 09 Jul 2025 08:15:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752074151; cv=none;
        d=google.com; s=arc-20240605;
        b=fvYDwFUtBjWUt12Xwj3YxzBUgQHITBGPztZ8mG47CQ89ZrGjqnS5BW/XIQ9VbgRvMp
         IILPsLSMdRmOyWk507qSSQwsyUoWSO6QBOgXhOUE55k2RJ8KC2J6PYSRW3IFUresN/xx
         h920GwPR+mH/3PRVVt7UodefV5QUwNE/7DFd9Zbb9vG7OnbOCP4l+GwXGqXPSMlORy4Y
         zKbLcNYSA+uIB6MZJp/bJVBpaUMLiCQtXCOa3Xe2Pqn7e3z2OnXhSWC2yukaBMAuAkwq
         kDe8aFAdctPPBeROK/lccWDom3iBmjX/KJxygMgJnixc11nw0sIqJPsq/RPlMxYnaNR6
         uGGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A27z97/vgIlW4uCKp2EUHjwiwnAcyEU21rAHulzMCfI=;
        fh=SmWGiGKaxOZ/J9Dz2TGAZSIE3Yrf3hfdxrHw1hUNJOM=;
        b=jHV9Ak88418eZ8E2Zhxlw2LdAFg6X1zBXBHNfrO8ANZHihqGAxKeE2wuW1baP16bqZ
         CDX2AmwoiB/HrqlrG6doKWpHlQMQ5f8qql0aHCkwzN8TklgqopnfYz6gVNzJlhHmecE1
         6sD9/pyOMhI/AVtvs426Ia7waAf7BFzJ6JOOgqCIgxcllQcuQeJKSKMgtY1lgKxjopPK
         g2+UZEypy9sPe2LKbQU1ZOvcOY6qcbnwNGRoWrfZZMtQ43p9j67cULSO3B1XGHDSb5Vl
         S+/MKdWFKs55XA7bwPB1/x4JARkEeQc+HJXjS3tZB1j8vIfW8NhKL52C7FhZTrRi6dHS
         HuHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vnEsuWUI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-454d4fc2865si447365e9.0.2025.07.09.08.15.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jul 2025 08:15:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-32b43846e8cso45754491fa.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Jul 2025 08:15:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrqtrpnN7NS7201jTZgvCb3KqgoVRJsEwiMAyBvPCmxSQYq7D69FYDE0DU5NX9AgSU+GaAD02qB5k=@googlegroups.com
X-Gm-Gg: ASbGncug7xzU0Obgt1u3QhsvVjqZVGYRRZlFoLkrsi4z3PJ5cto+Xpr3h7fHhfr30Zn
	2O24x8dZL9fx+K9NeMlOOgbYslRrISbCMojhyoPTux88UUYuYVibdvyP5w6A15cwGUqyOV8zfVB
	ML1aNIFvWDsZOhJMv5XeBELrVP3GdN5YtkzOnf037izYOL+OAmwm2TCSLzmgT6mC39zSfSnvXQw
	b2z
X-Received: by 2002:a2e:a98a:0:b0:32a:7d76:262e with SMTP id
 38308e7fff4ca-32f5005d663mr477901fa.3.1752074150568; Wed, 09 Jul 2025
 08:15:50 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-11-glider@google.com>
In-Reply-To: <20250626134158.3385080-11-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Jul 2025 17:15:39 +0200
X-Gm-Features: Ac12FXxtraw61CeongbninQQSqNyIx-qmohyONha6T45O1gbt8Lp-PbNMBz2M-A
Message-ID: <CACT4Y+YSfOE6Y9y-8mUwUOyyE-L3PUHUr6PuNX=iu-zyMyv3=A@mail.gmail.com>
Subject: Re: [PATCH v2 10/11] kcov: selftests: add kcov_test
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
 header.i=@google.com header.s=20230601 header.b=vnEsuWUI;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231
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

On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wrote:
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
>  MAINTAINERS                              |   1 +
>  tools/testing/selftests/kcov/Makefile    |   6 +
>  tools/testing/selftests/kcov/kcov_test.c | 364 +++++++++++++++++++++++

Let's also add 'config' fragment (see e.g. ./dma/config)
Otherwise it's impossible to run these tests in automated fashion.

>  3 files changed, 371 insertions(+)
>  create mode 100644 tools/testing/selftests/kcov/Makefile
>  create mode 100644 tools/testing/selftests/kcov/kcov_test.c
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 5bbc78b0fa6ed..0ec909e085077 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -12833,6 +12833,7 @@ F:      include/linux/kcov_types.h
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
> diff --git a/tools/testing/selftests/kcov/kcov_test.c b/tools/testing/selftests/kcov/kcov_test.c
> new file mode 100644
> index 0000000000000..4d3ca41f28af4
> --- /dev/null
> +++ b/tools/testing/selftests/kcov/kcov_test.c
> @@ -0,0 +1,364 @@
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

Then I think we need to do:
#ifndef KCOV_UNIQUE_ENABLE



> +#define KCOV_UNIQUE_ENABLE _IOW('c', 103, unsigned long)
> +#define KCOV_RESET_TRACE _IO('c', 104)
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
> +       EXPECT_EQ(ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE), 0)
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
> +               munmap(self->mapping, COVER_SIZE * sizeof(unsigned long));
> +               close(self->fd);
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
> +       /* Enable coverage collection on the current thread. */
> +       EXPECT_EQ(ioctl(self->fd, KCOV_UNIQUE_ENABLE, BITMAP_SIZE), 0)
> +       {
> +               perror("ioctl KCOV_ENABLE");
> +               munmap(self->mapping, COVER_SIZE * sizeof(unsigned long));
> +               close(self->fd);
> +       }
> +}
> +
> +FIXTURE_TEARDOWN(kcov_uniq)
> +{
> +       kcov_uninit_close(_metadata, self->fd, self->mapping,
> +                         self->mapping_size);
> +}
> +
> +TEST_F(kcov_uniq, kcov_uniq_coverage)
> +{
> +       unsigned long first, second, before, after, i;
> +
> +       /* Reset coverage that may be left over from the fixture setup. */
> +       reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
> +
> +       /*
> +        * Collect the coverage for a single syscall two times in a row.
> +        * Use collect_coverage_unchecked(), because it may return zero coverage.
> +        */
> +       first = collect_coverage_unchecked(_metadata, self->mapping,
> +                                          /*dump*/ true);
> +       second = collect_coverage_unchecked(_metadata, self->mapping,
> +                                           /*dump*/ true);
> +
> +       /* Now reset the buffer and collect the coverage again. */
> +       reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
> +       collect_coverage_once(_metadata, self->mapping);
> +
> +       /* Now try many times to saturate the unique coverage bitmap. */
> +       reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
> +       for (i = 0; i < 1000; i++)
> +               collect_coverage_unchecked(_metadata, self->mapping,
> +                                          /*dump*/ false);
> +       /* Another invocation of collect_coverage_unchecked() should not produce new coverage. */
> +       EXPECT_EQ(collect_coverage_unchecked(_metadata, self->mapping,
> +                                            /*dump*/ false),
> +                 0);
> +
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
> +TEST_HARNESS_MAIN
> --
> 2.50.0.727.gbf7dc18ff4-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYSfOE6Y9y-8mUwUOyyE-L3PUHUr6PuNX%3Diu-zyMyv3%3DA%40mail.gmail.com.
