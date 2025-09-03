Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPX637CQMGQEAF22TUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7422BB418DE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 10:41:44 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7724bca103dsf3180040b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 01:41:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756888894; cv=pass;
        d=google.com; s=arc-20240605;
        b=AXIy8Po7bX98IvDJDYKbFs1J9VjCYJgxgeJ9OzVyhRN00WorxNPv4p6LQSfm71gkUw
         hhxFpQNE79J6mQtn6IZxHoXH/BApJLWsRtaBKxD4TgNfkR3i67O/VcLyNFclDILoILrd
         DaV3yPoh/MU4/rH+aNtQv2nBS+YU3plyoKVJpRzJRMY6G6IBQZYRU+amlgG+E6jMErJz
         BK0+zvEf1/QJ5umJrdFL6W1TE85gE1CgTIGks8DlOoJHygePV7XuZOmxjfrQGt46wPrO
         iFDhpG8Y8J2IQO3RodprSGKTSDshLW92SSV5JbDWIKR3oaasqjPzub80lSZvl9MHzrs3
         WhUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sCVcTealz5JU3nUMpgf449vsH/YI9onHKZOXpZ4gJmU=;
        fh=dl97ZIskc/olfnaaJImypbPEQzGfhoJcv3XMI10dFCA=;
        b=ZeM8fQaWxU4zQtCpyHgWmer/Txk0o2/kjkkQIVMsT6VNiGBDlY21p0fPVjJ/pp6DA0
         ukb5eSrax6MSt5qyiv5rx5FjBQKXaL5lqNsy2aguUC8f6Tl/EECfdHehLqmwzPysOV3G
         5ehxS0yN0te+Sia6lla4AyQ4MnBVMllnVEziJhJa9LijVEvejR+j0whSyUbOziGHGytm
         ACqrnk8KA8syS/lQemOCfOmxstYxzJxfwCash1jD69hr8guKjwQZg+HyOADGlJsvpMoR
         1+7e5DD3QcxQ4ydT9V7yf4EVxNhCO/xTfFM1UzaWPQmLERXt0A4qhVoGascCB1gOR6Lx
         qQcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Hc/+2O99";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756888894; x=1757493694; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sCVcTealz5JU3nUMpgf449vsH/YI9onHKZOXpZ4gJmU=;
        b=i3qm/6xBui37fQpAwlHEZjvgBAZVx6hay5uMIy/jINtDpjjWd7sCZoh7cEaSZbVGsq
         8XUVD9zrUILVZY3JTxxEBAh6+dYvTIEf51uutK6Hm4M42LKBU/aLbQmkmXyRDsx7Gx+g
         H6X0v7pk8W9QnwEA8xQkJ3kvR3P2vtTokF4+4dfvpBeWnb46z/3FjO5TBpTFDMPkx+5M
         e+Bhbmk1twuWHWWxcrMC+WfFxMdDr4ACd1C/HET0LmFmeq0ZN07RH1HxXrghkqMmrUCj
         1noTWL6/snXDSjoJB4Oa0pB17sQnYOJf337m+SsmldI6qdzKhbvd6m4X5y0Dc5GLWd6w
         uT8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756888894; x=1757493694;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sCVcTealz5JU3nUMpgf449vsH/YI9onHKZOXpZ4gJmU=;
        b=vapkZZFuAKb4QAKTmsa+F0y8pIGFf3pdeDImvNE3p/Ko7tYoARerXu/LZHDUEIqryy
         RefHZwxLu0kWPVKG1pBNV9Lnaqbb5yGa9ciRQxgbsGZXj1rJY9VTcqLHGPpFw9G72o0q
         wt+t+J8O1LalEmU0iNYeyVGLiqJuu9l3KkHtH2CUfgo+SI11/OKA/DtaukYoZmCSuldz
         97CCZLOum/hizXgDzzTHwv2gL/5OYmxTqKqy2J4xk/qg/J+B9CLhNl01DFhQ7tFhLFIn
         khJwl+nCwy5SFQ6rAod/EZh7XDQ5fNd8GrYK23VtiIFZe+EO1yzZGyF5pg5bBXQRHFVi
         JCDg==
X-Forwarded-Encrypted: i=2; AJvYcCV/xD6g4Fnns5wpSGz9Nl4YIqfTilLYuS/HxvywodBYBR1v4uv7TfycrZIAR8PmOTpkQA619Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxe6LcM6f8eMHryWhsI9oouECMvSturaXxstXt+snra4WjmGj/s
	R7gCC1ElGYmpEdoNfHWwOAaMC9KH3BCRhrdEWp/u09ppRXGdAWglEyuo
X-Google-Smtp-Source: AGHT+IG03RyOQoWPIIa4nafVEblNvzaynFSuMxTQ59XiqQsAihs7hUKtCCP3+QWS8IYpQDQxHAaxyQ==
X-Received: by 2002:aa7:88c2:0:b0:772:867d:6bd7 with SMTP id d2e1a72fcca58-772867d6cfamr345713b3a.0.1756888894470;
        Wed, 03 Sep 2025 01:41:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdJXV6zlk2Ue1ycC/e8WL4Xhj7sZu72O6eESjH6sHYv7g==
Received: by 2002:a05:6a00:92a1:b0:772:628c:ad19 with SMTP id
 d2e1a72fcca58-772628cae12ls3540401b3a.1.-pod-prod-05-us; Wed, 03 Sep 2025
 01:41:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcpTRVwQj9oDXvtA8n2bLLGwoiuVUQwinaJZzeXAszS593JiHku8JAb4cmghoy3r7rkuzkRV6fPgY=@googlegroups.com
X-Received: by 2002:a05:6a20:258f:b0:243:ca56:a719 with SMTP id adf61e73a8af0-243d6f3798bmr19030381637.41.1756888893051;
        Wed, 03 Sep 2025 01:41:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756888893; cv=none;
        d=google.com; s=arc-20240605;
        b=afmQtD+W8GEXfcONe9ZB3Um0YhYTSpELMgNRcKjdaIyxff0UiDk51nAoXvq602OqBf
         oHeBGqoz9CZRmEt4p5iwW7bGI5dGlJ1LbM8pQDHwnrfpJKBdfOENBcyBlv23ldVXBinr
         4vuEKxSNd5QrePSnwW6opVVh4qRUCs7ptdT8m6UyzuyaGdJjwZAVyeTK8ccyLxrNyHeV
         or4Wa3KmNs64DdUIgg7zeBKDT51vvfLHXz9lvBkktH54e80tTTc8KSUakkGbQBpR5nMa
         NGbB0tG4kfby8ETPGpy2zwjlSDECmkTURD6Oh/nFB6oaYh/5xYDbVBJ//xQaPflgMNix
         rJ/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q/+sjUPKzzeyDNJhhYPMVRz16X6YZ4H6NdmqB+0gdRo=;
        fh=8cGnYZpJtCvEXet13wrHhhfdLIzssGl9OvCbrt6wzlw=;
        b=Rchb4NATSNXFZxgOxktQ2ptMkdPzvuzKNuN8RVSmEEoaG5Z5KDOIWEZHFMgdWmPIds
         LprtHZFmnOV81rgHtihXEYA4ukMmf7GHotaEBYvWLmUTYmmlawPQ0aFwczOHW3vYADLD
         J2qN5LDixIf1/O3kgHYn15ZjddjlkG3WcCGHXCJQ+viQfdIJFnbnv+Ri3VdXF75YYcLx
         3CeMXPWJc6o0qDIuSBm5Hassai2BUCwiaq+EWVYiXQYv4YnTkxwBBlfmJx0Nh52TFAEM
         fDRqyIG6kAtB+H8MZ+p47idII53gq4zfXCSlkx68rvgfhCq6RcC6bgTmJk34vAzPDaIl
         vuWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Hc/+2O99";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4ccf7a0dfasi549988a12.1.2025.09.03.01.41.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 01:41:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id 6a1803df08f44-70ddd2e61d9so67786776d6.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 01:41:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW1N87NPlEnVWtJix0LiuAmfcjA/tFDhsvD3sJ3wHSwBTKCiapk/SFzvHfSgN0EyPnYdPy/aFf4sd0=@googlegroups.com
X-Gm-Gg: ASbGncsTBHfXdE4xeEuo3RZIrqF60Tc8rqI6vG0d+hT/sswf4PF9yj7h42MyjZzim2v
	O7m0t2KE63n3XNeJ1AupWJkVgQDWNV8809gyFdWbzvgt3FZV4VBHsajqWhNN7gTf8/K4/tLktuN
	lvlKvkGgvFShHpy2bkaTPLXcIAXpzhnhZ6tPly1Y9hkQTzIhja5yUc/zmer3/+HSG67CT0Fl4z4
	tBduQoS+1qGwkFWH+qzJ5fLPXHKVFm4b/fvuEFerEE=
X-Received: by 2002:a05:6214:400c:b0:70d:fd01:992d with SMTP id
 6a1803df08f44-70fac73d452mr164331216d6.16.1756888891694; Wed, 03 Sep 2025
 01:41:31 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Sep 2025 10:40:55 +0200
X-Gm-Features: Ac12FXwvjV2R_1nfj-fpPxtTM3Ef-lrf13TD6fJR0T0JxJ4IOXBIbC7rd81mwII
Message-ID: <CAG_fn=XWr1_Qvzqq3_dUm-3DjpCFxBz7SbYaW8OMZ1BohjVYDA@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 2/7] kfuzztest: add user-facing API and data structures
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Hc/+2O99";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

I think the definition of KFUZZTEST_TABLE should better be in
include/asm-generic/vmlinux.lds.h, so that it can be used by other
architectures.

> + * KFuzzTest receives its input from userspace as a single binary blob. This
> + * format allows for the serialization of complex, pointer-rich C structures
> + * into a flat buffer that can be safely passed into the kernel. This format
> + * requires only a single copy from userspace into a kenrel buffer, and no

Nit: kernel

> + * further kernel allocations. Pointers are patched internally using a "region"
> + * system where each region corresponds to some pointed-to data.
> + *
> + * Regions should be padded to respect alignment constraints of their underlying
> + * types, and should be followed by at least 8 bytes of padding. These padded
> + * regions are poisoned by KFuzzTest to ensure that KASAN catches OOB accesses.
> + *
> + * The format consists of a prefix and three main components:

Nit: s/prefix/header?

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

Maybe also call it "target structure" here?

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

Nit: newline here for consistency.


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

Doesn't the compiler complain about defining __used in the middle of the block?
Maybe move it before the if statement?

> + * KFUZZTEST_EXPECT_NE - constrain a field to be not equal to a value

Nit: you could probably save some space and extract the boilerplate
from KFUZZTEST_EXPECT_XX into a helper macro.

> +config KFUZZTEST
> +       bool "KFuzzTest - enable support for internal fuzz targets"
> +       depends on DEBUG_FS && DEBUG_KERNEL

Given that you only have the sections defined for x86, you should
probably put something like "depends on X86_64" here.
If you go for it, please mention somewhere that the framework is only
available for x86_64, and add "x86:" to the patch title.

An alternative would be to add KFUZZTEST_TABLE to vmlinux.lds.S for
every architecture.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXWr1_Qvzqq3_dUm-3DjpCFxBz7SbYaW8OMZ1BohjVYDA%40mail.gmail.com.
