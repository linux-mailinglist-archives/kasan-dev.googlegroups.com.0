Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKUS3PCQMGQEBBATFGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id ED44FB3FCC0
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 12:38:35 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-7457492926asf2976062a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 03:38:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756809514; cv=pass;
        d=google.com; s=arc-20240605;
        b=XevZ+da8fHyfLLCxKkLErGzBrJjC1kGpszn0zdECbIQvWUVUgyOp9+y4OjDh/LJE1d
         +oOX3kRSe97+GMPzU1Sj51cQ9hQEWkblvSkRt/lstJqU5IHb5k0rdBKotCLkbEyN/kUO
         pxyYkeULFxvJqcHYXKPoNLo7qf34SkO2mRQACdoUfL7XMG0j2dXrkVoHMteePOvcDMUI
         7tmmQN1ah/pyvgDJhT6iAgSx6BRauw/ePp9rPYt9Iwyy5Xobgt4E4Yj3Ymgbb+gE0cGb
         L0NXaVMOtqXu1VWBU7LUFAexEojetO/ljKc97mNSyl8g7GNGIjhUaUwQnKC2NIwztKpC
         eseQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yZBubkZhD8Sce+FWJZzG+IcW/vJOrd4VcrPxmIhgZXY=;
        fh=M4YEkfVFOdENcjuUnm2u+wUV81bchm8sSa+80Fga1hM=;
        b=hzKexvwwKf2hIH/oGHd1yuyT+k8S+ElIOnvsunezV3BDApsFQ0+C3AfW3wFyZlmIm+
         oXonm9pdGSSY2W+NZ33IiabtyEFXQzLZBvIdtuAyV4mIGM4hUyFrauYfpIxTqA1gakOL
         3KIDCqbjQ91I8d3Jy8/+GN8RH6nN9MMejfd5zjvKZ/0soPaHdB4iaV7vo3mowyBSg8NX
         qHtxTpBlmWNYTF0aToBqUaWJjZv7bjs4PRFgPtiPbHiY3JPj2b6QQXSXhmIiMWL4qQsS
         Slv1mttv7nFA9ZODHZBobcwErLqAsYZ1Q2I7bFHLcuMkTmjvFvbTJy4+DV7WDjA9QOeh
         sACQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O7IAybKs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756809514; x=1757414314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yZBubkZhD8Sce+FWJZzG+IcW/vJOrd4VcrPxmIhgZXY=;
        b=H64iRfcqgoXz4P5EG2tDCrOdTjsWaIxZXUi4/ZBLfAn7rgU3vFPfXX55/1SItX+Ye7
         SolvtTOvyNMuVJb+QiVE6dfr4LspCt79+87fjxO0ScVyusfNVjTgZfxrTTeSARRqoBCk
         ZUw+4F9r3VEtuW35KupaKItv225n5/wdFweMbzU196bJlbg5n6NHrroBKyMBAUOLW0X6
         5YXZ2obsqKcnDKqtlm2wdorm1T/YKsvO4i3eu8OINO9e70D6S6R5m+HgUxfkDI7ihf5J
         BQxdQIsu7UAM7IHWjUDGk+8Weksls8j84O1gY3fOviTL2+sobGjnsUsrbieT+3zAnl++
         OC9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756809514; x=1757414314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yZBubkZhD8Sce+FWJZzG+IcW/vJOrd4VcrPxmIhgZXY=;
        b=tklglMEeXVMd1uerGbGy0bZ0590oCwFz4EEJTGevap3yKUYJfeCScjHYPRh78fdCCq
         maomcjy6xEVK0QNWeQRgz+Wh1MSQ62fmSkGV1H4RCJW1P9vMnoA+tjuGm7W2Q0nqmmBt
         9MRbf6hbwX3wxWf10/S0huYUBjbke02oYbxReKvbIH8O0I1lRndJG6IpES1HtPI2nKxs
         bZFGBqwgu3RydVMwNhjVWhDlJfX2eHvkqSauW5LP5nUrrE4eklFd9kjz2BfoU2gKYvxs
         sJiJFdcby6OlyHs3cWgOvK+MDbiyke8wK0164URMxKP6TcTRCT8wjdMTB+ZYqplzuq/l
         BmqQ==
X-Forwarded-Encrypted: i=2; AJvYcCUV2Zyva1T3ENKrhsQ6qQMismkkzJYo/Oxy0yBRNoCcQMTS0cPdsOL1FjM8VeDwowDAfzpMAg==@lfdr.de
X-Gm-Message-State: AOJu0YwDgPa2o8ltXwI3Ut6cczXUTbVsl3RG+PgMXphOV8qvOsYehU+H
	dNMHQ6tvNefrbWrl+4fSCMtGiWZbHjcyJjNlVMMEnGW95XP3k0suX14W
X-Google-Smtp-Source: AGHT+IHVBUAtWdjzIGTJ1+hCrMuZqHyik/AC+JrfX+MjcW2N4IW0r7XnJLHx8C3maSA8NeQiOolP6w==
X-Received: by 2002:a05:6830:6ab0:b0:745:529e:1d60 with SMTP id 46e09a7af769-74569f272aamr5829674a34.34.1756809514526;
        Tue, 02 Sep 2025 03:38:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfASl7W94PVvyFI7qYK5pzi4YK1QttvCh95r5r3pldokA==
Received: by 2002:a05:6820:4614:b0:61d:f8d4:b32a with SMTP id
 006d021491bc7-61e1271c1c3ls1532126eaf.1.-pod-prod-09-us; Tue, 02 Sep 2025
 03:38:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwfDdCj7WLLIn36f/G7q8r1mL20xPgTju5PIvR+/EEZYg8vOhqhBrbi7ku2oRVW1PK+VYTlNyWB54=@googlegroups.com
X-Received: by 2002:a05:6820:1c9f:b0:61e:2be3:97af with SMTP id 006d021491bc7-61e336fdbd7mr6183610eaf.3.1756809513615;
        Tue, 02 Sep 2025 03:38:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756809513; cv=none;
        d=google.com; s=arc-20240605;
        b=PQlCZjAnCj+lpyUUTW6PvyKQNYfLvDly6BdvAXiZZzC6YLMak2pnili0nK4A5uvQPi
         nHk85tP9yVpq95SzdDzm6a0Z5WCsa2rfwKfEvnfXmydOi+ZwtLHEz+Gj8O/TqNLkqvMu
         pu6xKYARFrwqkUh5Gfi1FKgDsd1Amhq+hthKYf0DdfE0loDw9WmNYfrGh3McA0oHFapV
         7076xd1HbAE+R4CATBae+nVSeEfgxUMMpGnaWgEQ980ojVTl/pNRigosjvgpsTM4NrI5
         1vdaOhc4IMagaEahGEl48pLn3KVjT5MGGvJKyyfP4KXqn+w2PuVSz0hU4MfqZ7b3nKAK
         ikBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ICDHDQOE/MqfzqVw1JP76OGka1MOGXAS8IvpvXWx/yc=;
        fh=KIH4YiRrk4NIlc5vEYmfuJOuIjkegDfXKunxSRhjINY=;
        b=TrLEap5iUe43g6VHdGijizS0Xe9bqH5/41g3FBhDXLYTaM/xZ86QVQXYny/XexMi41
         lF+bb5GGSYe88fLq732g4RLEz16HugaYPekMIzovYwSMuony+W0yg1OgEmN7n4CS1UeU
         bRmHMggmCkRzyon7FuRaPOgDvoISva7IKg4yY+JfhyfoWmNIsdJoctFYz6lUx0BZnccl
         Gk8ioR9ZAzuNvS5J8mXGqCwBXFObHtppCkIB4lhWs99XAsnCcWDFZGNkv6mvxedRNb3L
         sikALcG1Rpm7BBKtqM4iExRAo94swMF4JWRIjMCkXalcCk4/3OMtsEHbMIoROpKeEbTD
         Nn9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O7IAybKs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61e31dbf0fbsi297814eaf.1.2025.09.02.03.38.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 03:38:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-77251d7cca6so1722517b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 02 Sep 2025 03:38:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV7594GuWxRivzKxam5qsjczdi0Z93bSqpWeACosBfkhaX9OGi0DvkYzWgiE1cfK96ge/FZhiqEFe4=@googlegroups.com
X-Gm-Gg: ASbGncv1256Dx0a1no4F3i6V12Sxf821pM1rTgQtGv2f2hRWa9JGoZS/JSF4yLRtQVl
	nq9UbtXRiwcqmRD2FybGL4dz3unxIzuR+MbfeE9IoF8X7d+XmnaV9pmTOCDlcVYwQMceA6qC6th
	eXkQP6iFXJEG+VsLgPDO2C/tMfE5u66JUZhY810d9yalRYiQ4B/TP8zTiPpUkq5aqqYhEiJHb1V
	lRwJaxreETGxiLmWpSzHXpAI1y7ebAVoRL88B7Kv658PI88eQQjCRin7tw=
X-Received: by 2002:a17:903:2283:b0:246:c826:bd16 with SMTP id
 d9443c01a7336-249449045afmr157494805ad.23.1756809512599; Tue, 02 Sep 2025
 03:38:32 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Sep 2025 12:37:56 +0200
X-Gm-Features: Ac12FXz7J8bg8X83a1ag38KTiTzEMRGomHBE6seyfLTm8GmDhRz2HtgUe7tcQkA
Message-ID: <CANpmjNPmCtSayPBLN18BcX=thdeW5q3UdZzPo6Lz7K2B5HRuWg@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 2/7] kfuzztest: add user-facing API and data structures
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, davidgow@google.com, dvyukov@google.com, 
	jannh@google.com, rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=O7IAybKs;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 1 Sept 2025 at 18:43, Ethan Graham <ethan.w.s.graham@gmail.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add the foundational user-facing components for the KFuzzTest framework.
> This includes the main API header <linux/kfuzztest.h>, the Kconfig
> option to enable the feature, and the required linker script changes
> which introduce three new ELF sections in vmlinux.
>
> Note that KFuzzTest is intended strictly for debug builds only, and
> should never be enabled in a production build. The fact that it exposes
> internal kernel functions and state directly to userspace may constitute
> a serious security vulnerability if used for any reason other than
> testing.
>
> The header defines:
> - The FUZZ_TEST() macro for creating test targets.
> - The data structures required for the binary serialization format,
>   which allows passing complex inputs from userspace.
> - The metadata structures for test targets, constraints and annotations,
>   which are placed in dedicated ELF sections (.kfuzztest_*) for discovery.
>
> This patch only adds the public interface and build integration; no
> runtime logic is included.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
> ---
>  arch/x86/kernel/vmlinux.lds.S |  22 ++
>  include/linux/kfuzztest.h     | 508 ++++++++++++++++++++++++++++++++++
>  lib/Kconfig.debug             |   1 +
>  lib/kfuzztest/Kconfig         |  20 ++
>  4 files changed, 551 insertions(+)
>  create mode 100644 include/linux/kfuzztest.h
>  create mode 100644 lib/kfuzztest/Kconfig
>
> diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
> index 4fa0be732af1..484e3e1ffb9f 100644
> --- a/arch/x86/kernel/vmlinux.lds.S
> +++ b/arch/x86/kernel/vmlinux.lds.S
> @@ -112,6 +112,26 @@ ASSERT(__relocate_kernel_end - __relocate_kernel_start <= KEXEC_CONTROL_CODE_MAX
>  #else
>  #define KEXEC_RELOCATE_KERNEL
>  #endif
> +
> +#ifdef CONFIG_KFUZZTEST
> +#define KFUZZTEST_TABLE                                                        \
> +       . = ALIGN(PAGE_SIZE);                                           \
> +       __kfuzztest_targets_start = .;                                  \
> +       KEEP(*(.kfuzztest_target));                                     \
> +       __kfuzztest_targets_end = .;                                    \
> +       . = ALIGN(PAGE_SIZE);                                           \
> +       __kfuzztest_constraints_start = .;                              \
> +       KEEP(*(.kfuzztest_constraint));                                 \
> +       __kfuzztest_constraints_end = .;                                \
> +       . = ALIGN(PAGE_SIZE);                                           \
> +       __kfuzztest_annotations_start = .;                              \
> +       KEEP(*(.kfuzztest_annotation));                                 \
> +       __kfuzztest_annotations_end = .;
> +
> +#else /* CONFIG_KFUZZTEST */
> +#define KFUZZTEST_TABLE
> +#endif /* CONFIG_KFUZZTEST */
> +
>  PHDRS {
>         text PT_LOAD FLAGS(5);          /* R_E */
>         data PT_LOAD FLAGS(6);          /* RW_ */
> @@ -199,6 +219,8 @@ SECTIONS
>                 CONSTRUCTORS
>                 KEXEC_RELOCATE_KERNEL
>
> +               KFUZZTEST_TABLE
> +
>                 /* rarely changed data like cpu maps */
>                 READ_MOSTLY_DATA(INTERNODE_CACHE_BYTES)
>
> diff --git a/include/linux/kfuzztest.h b/include/linux/kfuzztest.h
> new file mode 100644
> index 000000000000..11a647c1d925
> --- /dev/null
> +++ b/include/linux/kfuzztest.h
> @@ -0,0 +1,508 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * The Kernel Fuzz Testing Framework (KFuzzTest) API for defining fuzz targets
> + * for internal kernel functions.
> + *
> + * For more information please see Documentation/dev-tools/kfuzztest.rst.
> + *
> + * Copyright 2025 Google LLC
> + */
> +#ifndef KFUZZTEST_H
> +#define KFUZZTEST_H
> +
> +#include <linux/fs.h>
> +#include <linux/printk.h>
> +#include <linux/types.h>
> +
> +#define KFUZZTEST_HEADER_MAGIC (0xBFACE)
> +#define KFUZZTEST_V0 (0)
> +
> +/**
> + * @brief The KFuzzTest Input Serialization Format
> + *
> + * KFuzzTest receives its input from userspace as a single binary blob. This
> + * format allows for the serialization of complex, pointer-rich C structures
> + * into a flat buffer that can be safely passed into the kernel. This format
> + * requires only a single copy from userspace into a kenrel buffer, and no
> + * further kernel allocations. Pointers are patched internally using a "region"
> + * system where each region corresponds to some pointed-to data.
> + *
> + * Regions should be padded to respect alignment constraints of their underlying
> + * types, and should be followed by at least 8 bytes of padding. These padded
> + * regions are poisoned by KFuzzTest to ensure that KASAN catches OOB accesses.
> + *
> + * The format consists of a prefix and three main components:
> + * 1. An 8-byte header: Contains KFUZZTEST_MAGIC in the first 4 bytes, and the
> + *     version number in the subsequent 4 bytes. This ensures backwards
> + *     compatibility in the event of future format changes.
> + * 2. A reloc_region_array: Defines the memory layout of the target structure
> + *     by partitioning the payload into logical regions. Each logical region
> + *     should contain the byte representation of the type that it represents,
> + *     including any necessary padding. The region descriptors should be
> + *     ordered by offset ascending.
> + * 3. A reloc_table: Provides "linking" instructions that tell the kernel how
> + *     to patch pointer fields to point to the correct regions. By design,
> + *     the first region (index 0) is passed as input into a FUZZ_TEST.
> + * 4. A Payload: The raw binary data for the structure and its associated
> + *     buffers. This should be aligned to the maximum alignment of all
> + *     regions to satisfy alignment requirements of the input types, but this
> + *     isn't checked by the parser.
> + *
> + * For a detailed specification of the binary layout see the full documentation
> + * at: Documentation/dev-tools/kfuzztest.rst
> + */
> +
> +/**
> + * struct reloc_region - single contiguous memory region in the payload
> + *
> + * @offset: The byte offset of this region from the start of the payload, which
> + *     should be aligned to the alignment requirements of the region's
> + *     underlying type.
> + * @size: The size of this region in bytes.
> + */
> +struct reloc_region {
> +       uint32_t offset;
> +       uint32_t size;
> +};
> +
> +/**
> + * struct reloc_region_array - array of regions in an input
> + * @num_regions: The total number of regions defined.
> + * @regions: A flexible array of `num_regions` region descriptors.
> + */
> +struct reloc_region_array {
> +       uint32_t num_regions;
> +       struct reloc_region regions[];
> +};
> +
> +/**
> + * struct reloc_entry - a single pointer to be patched in an input
> + *
> + * @region_id: The index of the region in the `reloc_region_array` that
> + *     contains the pointer.
> + * @region_offset: The start offset of the pointer inside of the region.
> + * @value: contains the index of the pointee region, or KFUZZTEST_REGIONID_NULL
> + *     if the pointer is NULL.
> + */
> +struct reloc_entry {
> +       uint32_t region_id;
> +       uint32_t region_offset;
> +       uint32_t value;
> +};
> +
> +/**
> + * struct reloc_entry - array of relocations required by an input
> + *
> + * @num_entries: the number of pointer relocations.
> + * @padding_size: the number of padded bytes between the last relocation in
> + *     entries, and the start of the payload data. This should be at least
> + *     8 bytes, as it is used for poisoning.
> + * @entries: array of relocations.
> + */
> +struct reloc_table {
> +       uint32_t num_entries;
> +       uint32_t padding_size;
> +       struct reloc_entry entries[];
> +};
> +
> +/**
> + * kfuzztest_parse_and_relocate - validate and relocate a KFuzzTest input
> + *
> + * @input: A buffer containing the serialized input for a fuzz target.
> + * @input_size: the size in bytes of the @input buffer.
> + * @arg_ret: return pointer for the test case's input structure.
> + */
> +int kfuzztest_parse_and_relocate(void *input, size_t input_size, void **arg_ret);
> +
> +/*
> + * Dump some information on the parsed headers and payload. Can be useful for
> + * debugging inputs when writing an encoder for the KFuzzTest input format.
> + */
> +__attribute__((unused)) static inline void kfuzztest_debug_header(struct reloc_region_array *regions,
> +                                                                 struct reloc_table *rt, void *payload_start,
> +                                                                 void *payload_end)
> +{
> +       uint32_t i;
> +
> +       pr_info("regions: { num_regions = %u } @ %px", regions->num_regions, regions);
> +       for (i = 0; i < regions->num_regions; i++) {
> +               pr_info("  region_%u: { start: 0x%x, size: 0x%x }", i, regions->regions[i].offset,
> +                       regions->regions[i].size);
> +       }
> +
> +       pr_info("reloc_table: { num_entries = %u, padding = %u } @ offset 0x%lx", rt->num_entries, rt->padding_size,
> +               (char *)rt - (char *)regions);
> +       for (i = 0; i < rt->num_entries; i++) {
> +               pr_info("  reloc_%u: { src: %u, offset: 0x%x, dst: %u }", i, rt->entries[i].region_id,
> +                       rt->entries[i].region_offset, rt->entries[i].value);
> +       }
> +
> +       pr_info("payload: [0x%lx, 0x%lx)", (char *)payload_start - (char *)regions,
> +               (char *)payload_end - (char *)regions);
> +}
> +
> +struct kfuzztest_target {
> +       const char *name;
> +       const char *arg_type_name;
> +       ssize_t (*write_input_cb)(struct file *filp, const char __user *buf, size_t len, loff_t *off);
> +} __aligned(32);
> +
> +/**
> + * FUZZ_TEST - defines a KFuzzTest target
> + *
> + * @test_name: The unique identifier for the fuzz test, which is used to name
> + *     the debugfs entry, e.g., /sys/kernel/debug/kfuzztest/@test_name.
> + * @test_arg_type: The struct type that defines the inputs for the test. This
> + *     must be the full struct type (e.g., "struct my_inputs"), not a typedef.
> + *
> + * Context:
> + * This macro is the primary entry point for the KFuzzTest framework. It
> + * generates all the necessary boilerplate for a fuzz test, including:
> + *   - A static `struct kfuzztest_target` instance that is placed in a
> + *     dedicated ELF section for discovery by userspace tools.
> + *   - A `debugfs` write callback that handles receiving serialized data from
> + *     a fuzzer, parsing it, and "hydrating" it into a valid C struct.
> + *   - A function stub where the developer places the test logic.
> + *
> + * User-Provided Logic:
> + * The developer must provide the body of the fuzz test logic within the curly
> + * braces following the macro invocation. Within this scope, the framework
> + * provides the following variables:
> + *
> + * - `arg`: A pointer of type `@test_arg_type *` to the fully hydrated input
> + * structure. All pointer fields within this struct have been relocated
> + * and are valid kernel pointers. This is the primary variable to use
> + * for accessing fuzzing inputs.
> + *
> + * - `regions`: A pointer of type `struct reloc_region_array *`. This is an
> + * advanced feature that allows access to the raw region metadata, which
> + * can be useful for checking the actual allocated size of a buffer via
> + * `KFUZZTEST_REGION_SIZE(n)`.

I don't see `regions` being passed. I only see:

+       static void kfuzztest_logic_##test_name(test_arg_type *arg)

Am I looking at the wrong one?

> + * Example Usage:
> + *
> + * // 1. The kernel function we want to fuzz.
> + * int process_data(const char *data, size_t len);
> + *
> + * // 2. Define a struct to hold all inputs for the function.
> + * struct process_data_inputs {
> + *     const char *data;
> + *     size_t len;
> + * };
> + *
> + * // 3. Define the fuzz test using the FUZZ_TEST macro.
> + * FUZZ_TEST(process_data_fuzzer, struct process_data_inputs)
> + * {
> + *     int ret;
> + *     // Use KFUZZTEST_EXPECT_* to enforce preconditions.
> + *     // The test will exit early if data is NULL.
> + *     KFUZZTEST_EXPECT_NOT_NULL(process_data_inputs, data);
> + *
> + *     // Use KFUZZTEST_ANNOTATE_* to provide hints to the fuzzer.
> + *     // This links the 'len' field to the 'data' buffer.
> + *     KFUZZTEST_ANNOTATE_LEN(process_data_inputs, len, data);
> + *
> + *     // Call the function under test using the 'arg' variable. OOB memory
> + *     // accesses will be caught by KASAN, but the user can also choose to
> + *     // validate the return value and log any failures.
> + *     ret = process_data(arg->data, arg->len);
> + * }
> + */
> +#define FUZZ_TEST(test_name, test_arg_type)                                                                  \
> +       static ssize_t kfuzztest_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len, \
> +                                                     loff_t *off);                                          \
> +       static void kfuzztest_logic_##test_name(test_arg_type *arg);                                         \
> +       const struct kfuzztest_target __fuzz_test__##test_name __section(".kfuzztest_target") __used = {     \
> +               .name = #test_name,                                                                          \
> +               .arg_type_name = #test_arg_type,                                                             \
> +               .write_input_cb = kfuzztest_write_cb_##test_name,                                            \
> +       };                                                                                                   \
> +       static ssize_t kfuzztest_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len, \
> +                                                     loff_t *off)                                           \
> +       {                                                                                                    \
> +               test_arg_type *arg;                                                                          \
> +               void *buffer;                                                                                \
> +               int ret;                                                                                     \
> +                                                                                                             \
> +               buffer = kmalloc(len, GFP_KERNEL);                                                           \

Should there be some kind of cap on the max allocation size, because
the user space tool controls this. If something went wrong on the user
space side, it can DoS the kernel and make for a poor debugging
experience.
Perhaps print a message like pr_warn(#test_name ": oversized input of
size %sz") and return -EINVAL.

> +               if (!buffer)                                                                                 \
> +                       return -ENOMEM;                                                                      \
> +               ret = simple_write_to_buffer(buffer, len, off, buf, len);                                    \
> +               if (ret < 0)                                                                                 \
> +                       goto out;                                                                            \
> +               ret = kfuzztest_parse_and_relocate(buffer, len, (void **)&arg);                              \
> +               if (ret < 0)                                                                                 \
> +                       goto out;                                                                            \
> +               kfuzztest_logic_##test_name(arg);                                                            \
> +               ret = len;                                                                                   \
> +out:                                                                                                         \
> +               kfree(buffer);                                                                               \
> +               return ret;                                                                                  \
> +       }                                                                                                    \
> +       static void kfuzztest_logic_##test_name(test_arg_type *arg)
> +
> +enum kfuzztest_constraint_type {
> +       EXPECT_EQ,
> +       EXPECT_NE,
> +       EXPECT_LT,
> +       EXPECT_LE,
> +       EXPECT_GT,
> +       EXPECT_GE,
> +       EXPECT_IN_RANGE,
> +};
> +
> +/**
> + * struct kfuzztest_constraint - a metadata record for a domain constraint
> + *
> + * Domain constraints are rules about the input data that must be satisfied for
> + * a fuzz test to proceed. While they are enforced in the kernel with a runtime
> + * check, they are primarily intended as a discoverable contract for userspace
> + * fuzzers.
> + *
> + * Instances of this struct are generated by the KFUZZTEST_EXPECT_* macros
> + * and placed into the read-only ".kfuzztest_constraint" ELF section of the
> + * vmlinux binary. A fuzzer can parse this section to learn about the
> + * constraints and generate valid inputs more intelligently.
> + *
> + * For an example of how these constraints are used within a fuzz test, see the
> + * documentation for the FUZZ_TEST() macro.
> + *
> + * @input_type: The name of the input struct type, without the leading
> + *     "struct ".
> + * @field_name: The name of the field within the struct that this constraint
> + *     applies to.
> + * @value1: The primary value used in the comparison (e.g., the upper
> + *     bound for EXPECT_LE).
> + * @value2: The secondary value, used only for multi-value comparisons
> + *     (e.g., the upper bound for EXPECT_IN_RANGE).
> + * @type: The type of the constraint.
> + */
> +struct kfuzztest_constraint {
> +       const char *input_type;
> +       const char *field_name;
> +       uintptr_t value1;
> +       uintptr_t value2;
> +       enum kfuzztest_constraint_type type;
> +} __aligned(64);
> +
> +#define __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val1, val2, tpe)                                         \
> +       static struct kfuzztest_constraint __constraint_##arg_type##_##field __section(".kfuzztest_constraint") \
> +               __used = {                                                                                      \
> +                       .input_type = "struct " #arg_type,                                                      \
> +                       .field_name = #field,                                                                   \
> +                       .value1 = (uintptr_t)val1,                                                              \
> +                       .value2 = (uintptr_t)val2,                                                              \
> +                       .type = tpe,                                                                            \
> +               }
> +
> +/**
> + * KFUZZTEST_EXPECT_EQ - constrain a field to be equal to a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable
> + * @val: a value of the same type as @arg_type.@field
> + */
> +#define KFUZZTEST_EXPECT_EQ(arg_type, field, val)                                    \
> +       do {                                                                         \
> +               if (arg->field != val)                                               \
> +                       return;                                                      \
> +               __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_EQ); \
> +       } while (0)
> +
> +/**
> + * KFUZZTEST_EXPECT_NE - constrain a field to be not equal to a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_NE(arg_type, field, val)                                    \
> +       do {                                                                         \
> +               if (arg->field == val)                                               \
> +                       return;                                                      \
> +               __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_NE); \
> +       } while (0)
> +
> +/**
> + * KFUZZTEST_EXPECT_LT - constrain a field to be less than a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_LT(arg_type, field, val)                                    \
> +       do {                                                                         \
> +               if (arg->field >= val)                                               \
> +                       return;                                                      \
> +               __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LT); \
> +       } while (0)
> +
> +/**
> + * KFUZZTEST_EXPECT_LE - constrain a field to be less than or equal to a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_LE(arg_type, field, val)                                    \
> +       do {                                                                         \
> +               if (arg->field > val)                                                \
> +                       return;                                                      \
> +               __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LE); \
> +       } while (0)
> +
> +/**
> + * KFUZZTEST_EXPECT_GT - constrain a field to be greater than a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_GT(arg_type, field, val)                                   \
> +       do {                                                                        \
> +               if (arg->field <= val)                                              \
> +                       return;                                                     \
> +               __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GT) \
> +       } while (0)
> +
> +/**
> + * KFUZZTEST_EXPECT_GE - constrain a field to be greater than or equal to a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_GE(arg_type, field, val)                                   \
> +       do {                                                                        \
> +               if (arg->field < val)                                               \
> +                       return;                                                     \
> +               __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GE)` \

Stray `

> +       } while (0)
> +
> +/**
> + * KFUZZTEST_EXPECT_GE - constrain a pointer field to be non-NULL
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_NOT_NULL(arg_type, field) KFUZZTEST_EXPECT_NE(arg_type, field, NULL)
> +
> +/**
> + * KFUZZTEST_EXPECT_IN_RANGE - constrain a field to be within a range
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @lower_bound: a lower bound of the same type as @arg_type.@field.
> + * @upper_bound: an upper bound of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_IN_RANGE(arg_type, field, lower_bound, upper_bound)                              \
> +       do {                                                                                              \
> +               if (arg->field < lower_bound || arg->field > upper_bound)                                 \
> +                       return;                                                                           \
> +               __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, lower_bound, upper_bound, EXPECT_IN_RANGE) \
> +       } while (0)
> +
> +/**
> + * Annotations express attributes about structure fields that can't be easily
> + * or safely verified at runtime. They are intended as hints to the fuzzing
> + * engine to help it generate more semantically correct and effective inputs.
> + * Unlike constraints, annotations do not add any runtime checks and do not
> + * cause a test to exit early.
> + *
> + * For example, a `char *` field could be a raw byte buffer or a C-style
> + * null-terminated string. A fuzzer that is aware of this distinction can avoid
> + * creating inputs that would cause trivial, uninteresting crashes from reading
> + * past the end of a non-null-terminated buffer.
> + */
> +enum kfuzztest_annotation_attribute : uint8_t {
> +       ATTRIBUTE_LEN,
> +       ATTRIBUTE_STRING,
> +       ATTRIBUTE_ARRAY,
> +};
> +
> +/**
> + * struct kfuzztest_annotation - a metadata record for a fuzzer hint
> + *
> + * This struct captures a single hint about a field in the input structure.
> + * Instances are generated by the KFUZZTEST_ANNOTATE_* macros and are placed
> + * into the read-only ".kfuzztest_annotation" ELF section of the vmlinux binary.
> + *
> + * A userspace fuzzer can parse this section to understand the semantic
> + * relationships between fields (e.g., which field is a length for which
> + * buffer) and the expected format of the data (e.g., a null-terminated
> + * string). This allows the fuzzer to be much more intelligent during input
> + * generation and mutation.
> + *
> + * For an example of how annotations are used within a fuzz test, see the
> + * documentation for the FUZZ_TEST() macro.
> + *
> + * @input_type: The name of the input struct type.
> + * @field_name: The name of the field being annotated (e.g., the data
> + *     buffer field).
> + * @linked_field_name: For annotations that link two fields (like
> + *     ATTRIBUTE_LEN), this is the name of the related field (e.g., the
> + *     length field). For others, this may be unused.
> + * @attrib: The type of the annotation hint.
> + */
> +struct kfuzztest_annotation {
> +       const char *input_type;
> +       const char *field_name;
> +       const char *linked_field_name;
> +       enum kfuzztest_annotation_attribute attrib;
> +} __aligned(32);
> +
> +#define __KFUZZTEST_ANNOTATE(arg_type, field, linked_field, attribute)                                          \
> +       static struct kfuzztest_annotation __annotation_##arg_type##_##field __section(".kfuzztest_annotation") \
> +               __used = {                                                                                      \
> +                       .input_type = "struct " #arg_type,                                                      \
> +                       .field_name = #field,                                                                   \
> +                       .linked_field_name = #linked_field,                                                     \
> +                       .attrib = attribute,                                                                    \
> +               }
> +
> +/**
> + * KFUZZTEST_ANNOTATE_STRING - annotate a char* field as a C string
> + *
> + * We define a C string as a sequence of non-zero characters followed by exactly
> + * one null terminator.
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: the name of the field to annotate.
> + */
> +#define KFUZZTEST_ANNOTATE_STRING(arg_type, field) __KFUZZTEST_ANNOTATE(arg_type, field, NULL, ATTRIBUTE_STRING)
> +
> +/**
> + * KFUZZTEST_ANNOTATE_ARRAY - annotate a pointer as an array
> + *
> + * We define an array as a contiguous memory region containing zero or more
> + * elements of the same type.
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: the name of the field to annotate.
> + */
> +#define KFUZZTEST_ANNOTATE_ARRAY(arg_type, field) __KFUZZTEST_ANNOTATE(arg_type, field, NULL, ATTRIBUTE_ARRAY)
> +
> +/**
> + * KFUZZTEST_ANNOTATE_LEN - annotate a field as the length of another
> + *
> + * This expresses the relationship `arg_type.field == len(linked_field)`, where
> + * `linked_field` is an array.
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: the name of the field to annotate.
> + * @linked_field: the name of an array field with length @field.
> + */
> +#define KFUZZTEST_ANNOTATE_LEN(arg_type, field, linked_field) \
> +       __KFUZZTEST_ANNOTATE(arg_type, field, linked_field, ATTRIBUTE_LEN)
> +
> +#define KFUZZTEST_REGIONID_NULL U32_MAX
> +
> +/**
> + * The end of the input should be padded by at least this number of bytes as
> + * it is poisoned to detect out of bounds accesses at the end of the last
> + * region.
> + */
> +#define KFUZZTEST_POISON_SIZE 0x8
> +
> +#endif /* KFUZZTEST_H */
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index ebe33181b6e6..3542e94204c8 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -1947,6 +1947,7 @@ endmenu
>  menu "Kernel Testing and Coverage"
>
>  source "lib/kunit/Kconfig"
> +source "lib/kfuzztest/Kconfig"
>
>  config NOTIFIER_ERROR_INJECTION
>         tristate "Notifier error injection"
> diff --git a/lib/kfuzztest/Kconfig b/lib/kfuzztest/Kconfig
> new file mode 100644
> index 000000000000..f9fb5abf8d27
> --- /dev/null
> +++ b/lib/kfuzztest/Kconfig
> @@ -0,0 +1,20 @@
> +# SPDX-License-Identifier: GPL-2.0-only
> +
> +config KFUZZTEST
> +       bool "KFuzzTest - enable support for internal fuzz targets"
> +       depends on DEBUG_FS && DEBUG_KERNEL
> +       help
> +         Enables support for the kernel fuzz testing framework (KFuzzTest), an
> +         interface for exposing internal kernel functions to a userspace fuzzing
> +         engine. KFuzzTest targets are exposed via a debugfs interface that
> +         accepts serialized userspace inputs, and is designed to make it easier
> +         to fuzz deeply nested kernel code that is hard to reach from the system
> +         call boundary. Using a simple macro-based API, developers can add a new
> +         fuzz target with minimal boilerplate code.
> +
> +         It is strongly recommended to also enable CONFIG_KASAN for byte-accurate
> +         out-of-bounds detection, as KFuzzTest was designed with this in mind. It
> +         is also recommended to enable CONFIG_KCOV for coverage guided fuzzing.
> +
> +         WARNING: This exposes internal kernel functions directly to userspace
> +         and must NEVER be enabled in production builds.
> --
> 2.51.0.318.gd7df087d1a-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPmCtSayPBLN18BcX%3DthdeW5q3UdZzPo6Lz7K2B5HRuWg%40mail.gmail.com.
