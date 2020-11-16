Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFV6ZL6QKGQEJSVXWKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B366E2B49C4
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:47:34 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id a134sf8832961wmd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:47:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605541654; cv=pass;
        d=google.com; s=arc-20160816;
        b=tF1wyazL0VpmyE5DlNZoiva5EOQBYgkRKet6y9X/1wvF3ju6WHjIKF7Lc9wwtDjPs7
         fZ5aYqHBjs7BWafWLswM98WP1FHlA6VWupW0QW8qTvRIDaEApRNQrLgmhmkirGOYDlvb
         r5gsaFkjpDlFsJFDOr3wsZ/iSive+DUH3lB10QCO8VwwI1I/a47mpNGBjs0u0hbI2t5f
         dc/RsOLGzvOumcaGyUwa4WIzX9BVVoG1mId1TDVpVMawf7a83XlrjnoOnTl1wFoGVfOd
         g9u5QLQ0iEaLjimr0DzAW51VDbTvppOhwnv0S4bS2qRZM0YR7/5yyEepsi83sk5EoGgj
         i/sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SIShdh6ez3exOjbM6w0rUtzCOFEP6YNB/KmONTB6DBc=;
        b=wRFUIoG256NsnMnNJNFZsFDMU3HDSQKhtxQQAxULicg63JYJWwU4XmrWg7iGATbAn7
         dnGbWXUSwlRueKHwioKDi1pi29elOAAOnjzgfNYN/RCfvoc65AwQhMCnuSQInKRtMqGB
         3ydqEUyJ88DdEJJoaotJ0bZrKJuJTI+dZvZvgqknwCup3lTv6n7ecqlB66vZC91DbI7x
         oE2h827J98xIQ3a9e1lbhnRQyyYQn80/KZn+5RcjdnoS9YoCPrFc9RXQOTNIA65I408L
         4eixO2CjOCIq0gevvRtcItkK+VLjf1aRMlcAZYbxwHFABa5ypMX2XSX/HHJF6IkhMkvL
         qaPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ShfON6UV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SIShdh6ez3exOjbM6w0rUtzCOFEP6YNB/KmONTB6DBc=;
        b=GvtUiqqBkB/HeeNV8vRlPliuFRL+LOUtDN3FnCquyrzHZyBsKZysRoPSm63BVKd2W7
         WabuK4yLvcY0xOGBdRlw8hyzYblMQYo1EuEwJfGqt3C9EVpmYy6Z5aBlKcX4ACxsclU4
         WTcNUzhBG5IMdoIHuH9tLC5mwtnsEH6TwuISMGxdBPg+gNE9tcEnVw614wGH26XBevB7
         Ei46sGMcC9O0dQEIFy2AsgGsdprVmLMT4PJEMqPTMwrdDfdfbtfccXMOGjitvb6pQNt0
         vg1WgfXwT8CBJhKmNaLUfL8bbkykcgfDsd82Q/dNoAGnTcIiTkgafCaDbayMO00Yfuae
         r3hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SIShdh6ez3exOjbM6w0rUtzCOFEP6YNB/KmONTB6DBc=;
        b=FKkMjkvY/OCTd6g9EhrvARUKbeS+qAQvzmKvu8ft93R9Z5t5HqinYV6QJsvjL6JYbX
         geSIUopicm80JfGS9/12Al+ujZBu7onQXHAhDAeVQzvh/hgoGYSYvMUYcQhtLTcWUPGB
         cBramVa7PqS7racEf78vdwGOovZn/RDGuDeo7DwghrgX1gh58FqKbOxx3JF2Zv1wO9RR
         Wym9NAovq+tawAhI08L0iVdKutr9r6dHnHtMYz1/ezu2rw7syFDF8dLjvU83sl6rBr4l
         DOyJItwh2zDZOtHxI5agCBIzjHMu+g+E9S1gqG5ArVkZnXh8xFHrSrhmg2rXmBhwIg1k
         PKyA==
X-Gm-Message-State: AOAM532G4wFIdci8WccrJlh7UA+Z3DNRwqq9QdDnIhaocYJaR6JPUo7d
	CW8dP458Unies9bq9HepNHM=
X-Google-Smtp-Source: ABdhPJxl2z4BxxJo4PCckR5YTy4s9g9AIlMpEReFtwBOdWLOuj1sxOLUU5mYSUm6p/jz03/PgRzRqg==
X-Received: by 2002:a5d:4104:: with SMTP id l4mr21523462wrp.276.1605541654402;
        Mon, 16 Nov 2020 07:47:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c689:: with SMTP id j9ls15982920wrg.0.gmail; Mon, 16 Nov
 2020 07:47:33 -0800 (PST)
X-Received: by 2002:adf:c147:: with SMTP id w7mr21735251wre.60.1605541653418;
        Mon, 16 Nov 2020 07:47:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605541653; cv=none;
        d=google.com; s=arc-20160816;
        b=J0cCRcgXS/XY07oKoyqcTJK+HQszqAfPxjB9gNPsoedgRZB0Nw+/XrMCk2tE+EtUqV
         UXOTwcnO+dsBb000oNbhfXWrUIRjO3LOhNQcNl35KWi0bLWMRHVQcNMxapG8hrJPxJbR
         xh4+emSptusnBNe9IrPJijtLqxn2dIBi21O7A72OhVHqy9WF5vXNFaOjWQFBCxpkgiVP
         lR2vk38pkCXI/75XPw6bd65vaPAMzlO5bkFt7ehcTh3R7w6+pNQ8sAkyYL8cvXMRl2QZ
         +VKdeNUfjx8rrTo2B9gskakHhXxJWFl8gDYEwcThn3YPdPQfhKjc3bcFToBFthUQqNFm
         qE4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/B72MSgPAcGFOtHsFbzRv4hXre435lWI6Ni4s+kykJk=;
        b=nop9Hp+XzWnUdoOROb2op/pdjxIE5JGGLTruFE1RrLk1xF2a/Q6zfO3cxo2JSBlUqE
         jLihgziDMY9gJO2kAsPKV+Ym2D3LJQLcStc58bNSLHZVIuWKdLKkNa89YZPpMN32XOg6
         s6k3cAU/XZljG8kAwUgWMTOLF5oLUPCi9ie2pxjjqC/CoYmQTPmmHl9V0HEK9uf51nDM
         k6qxbouURe/Vhvpss22Ww1bMACYHHbCkpnWwixyQ3NWXSf0nWIhmmsUGhDBK4BgvkxA3
         3/9ycGZ/a+y4dkh5FrkrQ1uM2uhXGNtVvCLTSIi+bhBFy1AwNTDtV24yeB/eRbLNVMYL
         /b8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ShfON6UV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id y14si620692wrq.0.2020.11.16.07.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:47:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id m6so2012399wrg.7
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:47:33 -0800 (PST)
X-Received: by 2002:a05:6000:10c9:: with SMTP id b9mr21240865wrx.251.1605541652752;
        Mon, 16 Nov 2020 07:47:32 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id t15sm19609192wmn.19.2020.11.16.07.47.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Nov 2020 07:47:31 -0800 (PST)
Date: Mon, 16 Nov 2020 16:47:26 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v3 19/19] kasan: update documentation
Message-ID: <20201116154726.GI1357314@elver.google.com>
References: <cover.1605305978.git.andreyknvl@google.com>
 <1668fc1d020f9c1f2b8bf57467f0433bfd74d0a3.1605305978.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1668fc1d020f9c1f2b8bf57467f0433bfd74d0a3.1605305978.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ShfON6UV;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Nov 13, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> This change updates KASAN documentation to reflect the addition of boot
> parameters and also reworks and clarifies some of the existing sections,
> in particular: defines what a memory granule is, mentions quarantine,
> makes Kunit section more readable.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ib1f83e91be273264b25f42b04448ac96b858849f

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 186 +++++++++++++++++++-----------
>  1 file changed, 116 insertions(+), 70 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index ffbae8ce5748..0d5d77919b1a 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -4,8 +4,9 @@ The Kernel Address Sanitizer (KASAN)
>  Overview
>  --------
>  
> -KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
> -find out-of-bound and use-after-free bugs. KASAN has three modes:
> +KernelAddressSANitizer (KASAN) is a dynamic memory safety error detector
> +designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
> +
>  1. generic KASAN (similar to userspace ASan),
>  2. software tag-based KASAN (similar to userspace HWASan),
>  3. hardware tag-based KASAN (based on hardware memory tagging).
> @@ -39,23 +40,13 @@ CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
>  The former produces smaller binary while the latter is 1.1 - 2 times faster.
>  
>  Both software KASAN modes work with both SLUB and SLAB memory allocators,
> -hardware tag-based KASAN currently only support SLUB.
> -For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
> +while the hardware tag-based KASAN currently only support SLUB.
> +
> +For better error reports that include stack traces, enable CONFIG_STACKTRACE.
>  
>  To augment reports with last allocation and freeing stack of the physical page,
>  it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
>  
> -To disable instrumentation for specific files or directories, add a line
> -similar to the following to the respective kernel Makefile:
> -
> -- For a single file (e.g. main.o)::
> -
> -    KASAN_SANITIZE_main.o := n
> -
> -- For all files in one directory::
> -
> -    KASAN_SANITIZE := n
> -
>  Error reports
>  ~~~~~~~~~~~~~
>  
> @@ -140,22 +131,75 @@ freed (in case of a use-after-free bug report). Next comes a description of
>  the accessed slab object and information about the accessed memory page.
>  
>  In the last section the report shows memory state around the accessed address.
> -Reading this part requires some understanding of how KASAN works.
> -
> -The state of each 8 aligned bytes of memory is encoded in one shadow byte.
> -Those 8 bytes can be accessible, partially accessible, freed or be a redzone.
> -We use the following encoding for each shadow byte: 0 means that all 8 bytes
> -of the corresponding memory region are accessible; number N (1 <= N <= 7) means
> -that the first N bytes are accessible, and other (8 - N) bytes are not;
> -any negative value indicates that the entire 8-byte word is inaccessible.
> -We use different negative values to distinguish between different kinds of
> -inaccessible memory like redzones or freed memory (see mm/kasan/kasan.h).
> +Internally KASAN tracks memory state separately for each memory granule, which
> +is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
> +memory state section of the report shows the state of one of the memory
> +granules that surround the accessed address.
> +
> +For generic KASAN the size of each memory granule is 8. The state of each
> +granule is encoded in one shadow byte. Those 8 bytes can be accessible,
> +partially accessible, freed or be a part of a redzone. KASAN uses the following
> +encoding for each shadow byte: 0 means that all 8 bytes of the corresponding
> +memory region are accessible; number N (1 <= N <= 7) means that the first N
> +bytes are accessible, and other (8 - N) bytes are not; any negative value
> +indicates that the entire 8-byte word is inaccessible. KASAN uses different
> +negative values to distinguish between different kinds of inaccessible memory
> +like redzones or freed memory (see mm/kasan/kasan.h).
>  
>  In the report above the arrows point to the shadow byte 03, which means that
>  the accessed address is partially accessible.
>  
>  For tag-based KASAN this last report section shows the memory tags around the
> -accessed address (see Implementation details section).
> +accessed address (see `Implementation details`_ section).
> +
> +Boot parameters
> +~~~~~~~~~~~~~~~
> +
> +Hardware tag-based KASAN mode (see the section about different mode below) is
> +intended for use in production as a security mitigation. Therefore it supports
> +boot parameters that allow to disable KASAN competely or otherwise control
> +particular KASAN features.
> +
> +The things that can be controlled are:
> +
> +1. Whether KASAN is enabled at all.
> +2. Whether KASAN collects and saves alloc/free stacks.
> +3. Whether KASAN panics on a detected bug or not.
> +
> +The ``kasan.mode`` boot parameter allows to choose one of three main modes:
> +
> +- ``kasan.mode=off`` - KASAN is disabled, no tag checks are performed
> +- ``kasan.mode=prod`` - only essential production features are enabled
> +- ``kasan.mode=full`` - all KASAN features are enabled
> +
> +The chosen mode provides default control values for the features mentioned
> +above. However it's also possible to override the default values by providing:
> +
> +- ``kasan.stacktrace=off`` or ``=on`` - enable alloc/free stack collection
> +					(default: ``on`` for ``mode=full``,
> +					 otherwise ``off``)
> +- ``kasan.fault=report`` or ``=panic`` - only print KASAN report or also panic
> +					 (default: ``report``)
> +
> +If ``kasan.mode`` parameter is not provided, it defaults to ``full`` when
> +``CONFIG_DEBUG_KERNEL`` is enabled, and to ``prod`` otherwise.
> +
> +For developers
> +~~~~~~~~~~~~~~
> +
> +Software KASAN modes use compiler instrumentation to insert validity checks.
> +Such instrumentation might be incompatible with some part of the kernel, and
> +therefore needs to be disabled. To disable instrumentation for specific files
> +or directories, add a line similar to the following to the respective kernel
> +Makefile:
> +
> +- For a single file (e.g. main.o)::
> +
> +    KASAN_SANITIZE_main.o := n
> +
> +- For all files in one directory::
> +
> +    KASAN_SANITIZE := n
>  
>  
>  Implementation details
> @@ -164,10 +208,10 @@ Implementation details
>  Generic KASAN
>  ~~~~~~~~~~~~~
>  
> -From a high level, our approach to memory error detection is similar to that
> -of kmemcheck: use shadow memory to record whether each byte of memory is safe
> -to access, and use compile-time instrumentation to insert checks of shadow
> -memory on each memory access.
> +From a high level perspective, KASAN's approach to memory error detection is
> +similar to that of kmemcheck: use shadow memory to record whether each byte of
> +memory is safe to access, and use compile-time instrumentation to insert checks
> +of shadow memory on each memory access.
>  
>  Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (e.g. 16TB
>  to cover 128TB on x86_64) and uses direct mapping with a scale and offset to
> @@ -194,7 +238,10 @@ function calls GCC directly inserts the code to check the shadow memory.
>  This option significantly enlarges kernel but it gives x1.1-x2 performance
>  boost over outline instrumented kernel.
>  
> -Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
> +Generic KASAN is the only mode that delays the reuse of freed object via
> +quarantine (see mm/kasan/quarantine.c for implementation).
> +
> +Generic KASAN prints up to two call_rcu() call stacks in reports, the last one
>  and the second to last.
>  
>  Software tag-based KASAN
> @@ -304,15 +351,15 @@ therefore be wasteful. Furthermore, to ensure that different mappings
>  use different shadow pages, mappings would have to be aligned to
>  ``KASAN_GRANULE_SIZE * PAGE_SIZE``.
>  
> -Instead, we share backing space across multiple mappings. We allocate
> +Instead, KASAN shares backing space across multiple mappings. It allocates
>  a backing page when a mapping in vmalloc space uses a particular page
>  of the shadow region. This page can be shared by other vmalloc
>  mappings later on.
>  
> -We hook in to the vmap infrastructure to lazily clean up unused shadow
> +KASAN hooks into the vmap infrastructure to lazily clean up unused shadow
>  memory.
>  
> -To avoid the difficulties around swapping mappings around, we expect
> +To avoid the difficulties around swapping mappings around, KASAN expects
>  that the part of the shadow region that covers the vmalloc space will
>  not be covered by the early shadow page, but will be left
>  unmapped. This will require changes in arch-specific code.
> @@ -323,24 +370,31 @@ architectures that do not have a fixed module region.
>  CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
>  --------------------------------------------------
>  
> -``CONFIG_KASAN_KUNIT_TEST`` utilizes the KUnit Test Framework for testing.
> -This means each test focuses on a small unit of functionality and
> -there are a few ways these tests can be run.
> +KASAN tests consist on two parts:
> +
> +1. Tests that are integrated with the KUnit Test Framework. Enabled with
> +``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verified
> +automatically in a few different ways, see the instructions below.
>  
> -Each test will print the KASAN report if an error is detected and then
> -print the number of the test and the status of the test:
> +2. Tests that are currently incompatible with KUnit. Enabled with
> +``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
> +only be verified manually, by loading the kernel module and inspecting the
> +kernel log for KASAN reports.
>  
> -pass::
> +Each KUnit-compatible KASAN test prints a KASAN report if an error is detected.
> +Then the test prints its number and status.
> +
> +When a test passes::
>  
>          ok 28 - kmalloc_double_kzfree
>  
> -or, if kmalloc failed::
> +When a test fails due to a failed ``kmalloc``::
>  
>          # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
>          Expected ptr is not null, but is
>          not ok 4 - kmalloc_large_oob_right
>  
> -or, if a KASAN report was expected, but not found::
> +When a test fails due to a missing KASAN report::
>  
>          # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
>          Expected kasan_data->report_expected == kasan_data->report_found, but
> @@ -348,46 +402,38 @@ or, if a KASAN report was expected, but not found::
>          kasan_data->report_found == 0
>          not ok 28 - kmalloc_double_kzfree
>  
> -All test statuses are tracked as they run and an overall status will
> -be printed at the end::
> +At the end the cumulative status of all KASAN tests is printed. On success::
>  
>          ok 1 - kasan
>  
> -or::
> +Or, if one of the tests failed::
>  
>          not ok 1 - kasan
>  
> -(1) Loadable Module
> -~~~~~~~~~~~~~~~~~~~~
> +
> +There are a few ways to run KUnit-compatible KASAN tests.
> +
> +1. Loadable module
> +~~~~~~~~~~~~~~~~~~
>  
>  With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
> -a loadable module and run on any architecture that supports KASAN
> -using something like insmod or modprobe. The module is called ``test_kasan``.
> +a loadable module and run on any architecture that supports KASAN by loading
> +the module with insmod or modprobe. The module is called ``test_kasan``.
>  
> -(2) Built-In
> -~~~~~~~~~~~~~
> +2. Built-In
> +~~~~~~~~~~~
>  
>  With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
> -on any architecure that supports KASAN. These and any other KUnit
> -tests enabled will run and print the results at boot as a late-init
> -call.
> +on any architecure that supports KASAN. These and any other KUnit tests enabled
> +will run and print the results at boot as a late-init call.
>  
> -(3) Using kunit_tool
> -~~~~~~~~~~~~~~~~~~~~~
> +3. Using kunit_tool
> +~~~~~~~~~~~~~~~~~~~
>  
> -With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, we can also
> -use kunit_tool to see the results of these along with other KUnit
> -tests in a more readable way. This will not print the KASAN reports
> -of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
> -information on kunit_tool.
> +With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it's also
> +possible use ``kunit_tool`` to see the results of these and other KUnit tests
> +in a more readable way. This will not print the KASAN reports of the tests that
> +passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
> +for more up-to-date information on ``kunit_tool``.
>  
>  .. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
> -
> -``CONFIG_TEST_KASAN_MODULE`` is a set of KASAN tests that could not be
> -converted to KUnit. These tests can be run only as a module with
> -``CONFIG_TEST_KASAN_MODULE`` built as a loadable module and
> -``CONFIG_KASAN`` built-in. The type of error expected and the
> -function being run is printed before the expression expected to give
> -an error. Then the error is printed, if found, and that test
> -should be interpretted to pass only if the error was the one expected
> -by the test.
> -- 
> 2.29.2.299.gdc1121823c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201116154726.GI1357314%40elver.google.com.
