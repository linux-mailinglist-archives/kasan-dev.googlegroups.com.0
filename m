Return-Path: <kasan-dev+bncBDB3VRFH7QKRBKFDTTCQMGQEDVBJABQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DAA4B2F80C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:31:38 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7e864817cb8sf555891685a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 05:31:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755779497; cv=pass;
        d=google.com; s=arc-20240605;
        b=RFnLe5gPvEgwnYfpbAjjD58fUA6TtFdPn6s+XdxAbUjCoPXYvr3oTWfyGGgYVzJeCR
         94MnuZ25L14Z8fAcE8xIyJQrtOgBfxo6l8qXpXwUsVvezyySy+pPuwhgrfn3inDqELVu
         spUTdCIbSao4Xo/yVt/17iQpWT/P6nKlcKC8fv2e4Ow3wLyYDc1xCWWkLC+iUFSH5+3G
         wTlcpHMx1ke6kx6BwK/KRkPo45dniBuT0atvaLzrjArWmgrhlcp/u5N1PYXUqdmAE4wT
         wvr1lOnwcjulp5HMXRYlac4eNxhMhPG24w646pXisMSOhtHJGpwXPkXIKqCFoon2H5sQ
         Pe8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=RfVfbvfWMQG3IA4nzA9Ogy04pg6jTz2zMYuMIsUYJZE=;
        fh=mk70xZkhDrp/YOlmqADglc9ZMRlncCJqMFvAPjOBKvM=;
        b=bJISMs8ONr0zXNxWltZrCwNJa0Gk4U0VnwYLnv3Oap885E+6ESetSF97skZPBI5Vup
         qj8DDWZCvMwioKtp8Pu6fcvs3KE8KD58p6fyT/QVa3m7Hl1zfdryM36jDLn8CrRBboWq
         R/ugE1nZGHM2q0HaoabQyUhvUAt1v4vtyFFF500qoP/Niw5DBzo47GlhsjMAX1izSxNd
         uhyHCydqaUjyC1tmUdpfOTmZ9i/k5jUenCFMvgf/IGk+lvpSBvjHUOlXfqBd3az5w+3a
         TimS0or70FvhW0GhOm9fT661nwihdLCU6fYN/FxzroZWk/rhRc6XrhsUiKj3zXc0v6DG
         DNwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755779497; x=1756384297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RfVfbvfWMQG3IA4nzA9Ogy04pg6jTz2zMYuMIsUYJZE=;
        b=O/7g1eJG6qYvnqVZ/o4u+mqr2X4ETqx1mkIkrH+Q5X0OlyBW4Mt0Pb8tuLOoKBFmdU
         aLphBSIX2nEWXZd3kl0QHocpbeUIqngkdXsMlVbt3YD6fbRk2xfXahVQo2NNM9L8sUrD
         Buw5bGZdKPM/PYBfzzClII86NRG9cl+rgi+FaysSBicwT5ZgTvcQcQzgr8Up0aESEoJW
         8UVyBAYmlnZrZ1P6D/zXcQ44OVKkggmQq5iFZwlSPZmHlWPyfNH0HqxklD19ZK4VYKEB
         Gp1SIOcXOBZb8pUVZIbXIa9xm6pae7s5jjSDsVbk5rYeg44CoH/6YFH2IFSqIr1jNELG
         X0qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755779497; x=1756384297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RfVfbvfWMQG3IA4nzA9Ogy04pg6jTz2zMYuMIsUYJZE=;
        b=dPTM0B01j4DCj78O4OlZK+WjuDVYy8Eww+3JHBFk2j8ZdHfdc/XM4SPao2WBGmTs29
         cZIVqOkitg7FRNCRkdJVXmB/9wEE18tO+ct+Kgiaj70TR4632OioxYdsgYHak3vFF8Sh
         vsYtosPNHO9+bggG1l1IhyEkUjwVlZ43BCpktN584Uy3aN9ScVzwIf2q4gXJvvX9D7Oy
         9K+3CVGckLHRb0TWSXDYhCpyxCHOFBCOFFr9tg80lfBSRPSXPWB1e8CS4BzAhQFMeRs1
         2jzbNNQMFzzfcyariySvaX41DVf8pHQ+X5hRKdEmlzVx9PgEAiZmQgCO6eUykP2/D73m
         bkHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzdse2BDkHhNnFGFgaxiGMVk4G4pIhMwxebOvtmqag7eb873E1E9beZdMDClC7zhwS7MpSlQ==@lfdr.de
X-Gm-Message-State: AOJu0YxTEEPHYstQeB+UnyeK8Zo89G8nW19gzM+qXNugI1hzlo0/jkvu
	/BhEXYJDEix0FCH1WYVJYV2awRYO+p0hYcasWgCtNj4Mf4/Oqg5Ya0XC
X-Google-Smtp-Source: AGHT+IEwGCsZciV5yBIel1KvlmeWWPuOjnqAQFf1a2fyOW/V4mh6q32LxOjt1lGUsfiHkoOUngv7XQ==
X-Received: by 2002:a05:620a:6cc3:b0:7ea:5a9:d8a4 with SMTP id af79cd13be357-7ea0970a9c5mr223053985a.30.1755779496950;
        Thu, 21 Aug 2025 05:31:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfwivykZh80zp92gGr8QZ8bgD9m77AosuL6OyL1ORleDA==
Received: by 2002:ac8:7dcd:0:b0:4b0:7448:c7e8 with SMTP id d75a77b69052e-4b29d90b2a4ls8592481cf.2.-pod-prod-00-us;
 Thu, 21 Aug 2025 05:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHUHwVxyZ7LJhMim5ZSBikTSBRveI4aIMmugHFjDJY+sRNE9dCieY/kOSeYQiAqCH3jKaLDJqcDzE=@googlegroups.com
X-Received: by 2002:ac8:7fc8:0:b0:4b0:ca36:90 with SMTP id d75a77b69052e-4b2a039160cmr21200581cf.8.1755779496165;
        Thu, 21 Aug 2025 05:31:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755779496; cv=none;
        d=google.com; s=arc-20240605;
        b=TeZujxGzv1Zjt1guPU7fJmPLGdGEO8/7Z7VUI51Ca8OICFtCQWY5sW1CKMngcwzpKn
         ygoXcLNnt7wQOi9gJPbsomjd7NwTjqkBHk9kHPJD8Jk3XJvN2fO+KbFm4zaEKtmxOVcl
         9jG6EEi1SDFOl9XA/O1xcotm4ynM4YWP6NhEgcAU956xQSiJNSvsJSwgRbs+uTkNsN2g
         MChHphQIzETcdbvaVaLJ7nAoirJFOu7u66A4NrXaie+FEoq2EW8vCleDYYv50QJvXehw
         N2VwvPqsxbgL9Zen1nKHxwBXLDkGpgEj7BqaWXbcQYbyUUp/9L7mam08QFEgCM2SzyOR
         NDgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id;
        bh=msLKTrFNCSuC37B5mp2zis7jYbT/mkgbxzbGwZfsaV0=;
        fh=oaeHw1qMwC0mU/ri8FxDkoEgtWwNrwPpkGfOYJsYqwM=;
        b=dPA32vsPX3MHW5RpTIf3L8emfqnBWV7CrLIy+a2PU17uJJS47FySK0PoX3jN4bp/ec
         QhgM7K65rvEl44Guvmegzs3ciGIPzGjjnTYIk5YETcQPRte7gBKIGs0hrgjt9NsGFBpp
         WPZ7bW58/L4SqW0NOy+OCo3RNWLEsXTk12VMvqu2gHu4fhkKePJ/tY4ncxmorGxbUH4l
         pac878xZdg/v7SYFTxRpg5AUeKKXYRhJiPk/8dpVWIQOUfkVL+CiVmEGZ869HNkJcwzr
         2aFXu4l8AzTFz/Yyp28Hs0ulg6IRJJfC5uvTGAN+0D4RQanGGp1M8LN181qQyBIgMSYA
         dURQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d75a77b69052e-4b29e076500si900661cf.0.2025.08.21.05.31.36
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Aug 2025 05:31:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2BF6E152B;
	Thu, 21 Aug 2025 05:31:27 -0700 (PDT)
Received: from [10.57.1.220] (unknown [10.57.1.220])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8ED163F63F;
	Thu, 21 Aug 2025 05:31:18 -0700 (PDT)
Message-ID: <9eb211ee-94bf-431b-981c-e305c8ea5e0b@arm.com>
Date: Thu, 21 Aug 2025 13:30:28 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 00/18] kasan: x86: arm64: KASAN tag-based mode for x86
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
 Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
 kaleshsingh@google.com, rppt@kernel.org, leitao@debian.org, coxu@redhat.com,
 surenb@google.com, akpm@linux-foundation.org, luto@kernel.org,
 jpoimboe@kernel.org, changyuanl@google.com, hpa@zytor.com,
 dvyukov@google.com, kas@kernel.org, corbet@lwn.net,
 vincenzo.frascino@arm.com, smostafa@google.com,
 nick.desaulniers+lkml@gmail.com, morbo@google.com, andreyknvl@gmail.com,
 alexander.shishkin@linux.intel.com, thiago.bauermann@linaro.org,
 catalin.marinas@arm.com, ryabinin.a.a@gmail.com, jan.kiszka@siemens.com,
 jbohac@suse.cz, dan.j.williams@intel.com, joel.granados@kernel.org,
 baohua@kernel.org, kevin.brodsky@arm.com, nicolas.schier@linux.dev,
 pcc@google.com, andriy.shevchenko@linux.intel.com, wei.liu@kernel.org,
 bp@alien8.de, xin@zytor.com, pankaj.gupta@amd.com, vbabka@suse.cz,
 glider@google.com, jgross@suse.com, kees@kernel.org, jhubbard@nvidia.com,
 joey.gouly@arm.com, ardb@kernel.org, thuth@redhat.com,
 pasha.tatashin@soleen.com, kristina.martsenko@arm.com,
 bigeasy@linutronix.de, lorenzo.stoakes@oracle.com, jason.andryuk@amd.com,
 david@redhat.com, graf@amazon.com, wangkefeng.wang@huawei.com,
 ziy@nvidia.com, mark.rutland@arm.com, dave.hansen@linux.intel.com,
 samuel.holland@sifive.com, kbingham@kernel.org, trintaeoitogc@gmail.com,
 scott@os.amperecomputing.com, justinstitt@google.com,
 kuan-ying.lee@canonical.com, maz@kernel.org, tglx@linutronix.de,
 samitolvanen@google.com, mhocko@suse.com, nunodasneves@linux.microsoft.com,
 brgerst@gmail.com, willy@infradead.org, ubizjak@gmail.com,
 peterz@infradead.org, mingo@redhat.com, sohil.mehta@intel.com,
 linux-mm@kvack.org, linux-kbuild@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, x86@kernel.org, llvm@lists.linux.dev,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, Ada Couprie Diaz <ada.coupriediaz@arm.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
Content-Language: en-US
Organization: Arm Ltd.
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi,

On 12/08/2025 14:23, Maciej Wieczor-Retman wrote:
> [...]
> ======= Testing
> Checked all the kunits for both software tags and generic KASAN after
> making changes.
>
> In generic mode the results were:
>
> kasan: pass:59 fail:0 skip:13 total:72
> Totals: pass:59 fail:0 skip:13 total:72
> ok 1 kasan
>
> and for software tags:
>
> kasan: pass:63 fail:0 skip:9 total:72
> Totals: pass:63 fail:0 skip:9 total:72
> ok 1 kasan
I tested the series on arm64 and after fixing the build issues mentioned
I was able to boot without issues and did not observe any regressions
in the KASAN KUnit tests with either generic or software tags.

So this is Tested-by: Ada Couprie Diaz <ada.coupriediaz@arm.com> (For arm64)

I will note that the tests `kmalloc_memmove_negative_size` and
`kmalloc_memmove_invalid_size` seem to be able to corrupt memory
and lead to kernel crashes if `memmove()` is not properly instrumented,
which I discovered while investigating [0].
> [...]
> ======= Compilation
> Clang was used to compile the series (make LLVM=1) since gcc doesn't
> seem to have support for KASAN tag-based compiler instrumentation on
> x86.

Interestingly, while investigating [0], this comment slipped by me and
I managed to compile your series for x86 with software tags using GCC,
though it is a bit hacky.
You need to update the CC_HAS_KASAN_SW_TAGS to pass `-mlam=u48`
or `-mlam=u57`, as it is disabled by default, and pass `-march=arrowlake`
for compilation (the support for software tags depends on the arch).
You could then test with GCC (though the issue in [0] also applies to x86).

Best,
Ada

[0]: https://groups.google.com/g/kasan-dev/c/v1PYeoitg88

> ======= Dependencies
> The base branch for the series is the mainline kernel, tag 6.17-rc1.
>
> ======= Enabling LAM for testing
> Since LASS is needed for LAM and it can't be compiled without it I
> applied the LASS series [1] first, then applied my patches.
>
> [1] https://lore.kernel.org/all/20250707080317.3791624-1-kirill.shutemov@linux.intel.com/
>
> Changes v4:
> - Revert x86 kasan_mem_to_shadow() scheme to the same on used in generic
>    KASAN. Keep the arithmetic shift idea for the KASAN in general since
>    it makes more sense for arm64 and in risc-v.
> - Fix inline mode but leave it unavailable until a complementary
>    compiler patch can be merged.
> - Apply Dave Hansen's comments on series formatting, patch style and
>    code simplifications.
>
> Changes v3:
> - Remove the runtime_const patch and setup a unified offset for both 5
>    and 4 paging levels.
> - Add a fix for inline mode on x86 tag-based KASAN. Add a handler for
>    int3 that is generated on inline tag mismatches.
> - Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
>    reflected there.
> - Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
>    account.
> - Made changes to the kasan_non_canonical_hook() according to upstream
>    discussion.
> - Remove patches 2 and 3 since they related to risc-v and this series
>    adds only x86 related things.
> - Reorder __tag_*() functions so they're before arch_kasan_*(). Remove
>    CONFIG_KASAN condition from __tag_set().
>
> Changes v2:
> - Split the series into one adding KASAN tag-based mode (this one) and
>    another one that adds the dense mode to KASAN (will post later).
> - Removed exporting kasan_poison() and used a wrapper instead in
>    kasan_init_64.c
> - Prepended series with 4 patches from the risc-v series and applied
>    review comments to the first patch as the rest already are reviewed.
>
> Maciej Wieczor-Retman (16):
>    kasan: Fix inline mode for x86 tag-based mode
>    x86: Add arch specific kasan functions
>    kasan: arm64: x86: Make special tags arch specific
>    x86: Reset tag for virtual to physical address conversions
>    mm: x86: Untag addresses in EXECMEM_ROX related pointer arithmetic
>    x86: Physical address comparisons in fill_p*d/pte
>    x86: KASAN raw shadow memory PTE init
>    x86: LAM compatible non-canonical definition
>    x86: LAM initialization
>    x86: Minimal SLAB alignment
>    kasan: arm64: x86: Handle int3 for inline KASAN reports
>    kasan: x86: Apply multishot to the inline report handler
>    kasan: x86: Logical bit shift for kasan_mem_to_shadow
>    mm: Unpoison pcpu chunks with base address tag
>    mm: Unpoison vms[area] addresses with a common tag
>    x86: Make software tag-based kasan available
>
> Samuel Holland (2):
>    kasan: sw_tags: Use arithmetic shift for shadow computation
>    kasan: sw_tags: Support tag widths less than 8 bits
>
>   Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
>   Documentation/arch/x86/x86_64/mm.rst      |  6 +-
>   MAINTAINERS                               |  4 +-
>   arch/arm64/Kconfig                        | 10 ++--
>   arch/arm64/include/asm/kasan-tags.h       |  9 +++
>   arch/arm64/include/asm/kasan.h            |  6 +-
>   arch/arm64/include/asm/memory.h           | 14 ++++-
>   arch/arm64/include/asm/uaccess.h          |  1 +
>   arch/arm64/kernel/traps.c                 | 17 +-----
>   arch/arm64/mm/kasan_init.c                |  7 ++-
>   arch/x86/Kconfig                          |  4 +-
>   arch/x86/boot/compressed/misc.h           |  1 +
>   arch/x86/include/asm/cache.h              |  4 ++
>   arch/x86/include/asm/kasan-tags.h         |  9 +++
>   arch/x86/include/asm/kasan.h              | 71 ++++++++++++++++++++++-
>   arch/x86/include/asm/page.h               | 24 +++++++-
>   arch/x86/include/asm/page_64.h            |  2 +-
>   arch/x86/kernel/alternative.c             |  4 +-
>   arch/x86/kernel/head_64.S                 |  3 +
>   arch/x86/kernel/setup.c                   |  2 +
>   arch/x86/kernel/traps.c                   |  4 ++
>   arch/x86/mm/Makefile                      |  2 +
>   arch/x86/mm/init.c                        |  3 +
>   arch/x86/mm/init_64.c                     | 11 ++--
>   arch/x86/mm/kasan_init_64.c               | 19 +++++-
>   arch/x86/mm/kasan_inline.c                | 26 +++++++++
>   arch/x86/mm/pat/set_memory.c              |  1 +
>   arch/x86/mm/physaddr.c                    |  1 +
>   include/linux/kasan-tags.h                | 21 +++++--
>   include/linux/kasan.h                     | 51 +++++++++++++++-
>   include/linux/mm.h                        |  6 +-
>   include/linux/mmzone.h                    |  1 -
>   include/linux/page-flags-layout.h         |  9 +--
>   lib/Kconfig.kasan                         |  3 +-
>   mm/execmem.c                              |  4 +-
>   mm/kasan/hw_tags.c                        | 11 ++++
>   mm/kasan/report.c                         | 45 ++++++++++++--
>   mm/kasan/shadow.c                         | 18 ++++++
>   mm/vmalloc.c                              |  8 +--
>   scripts/Makefile.kasan                    |  3 +
>   scripts/gdb/linux/kasan.py                |  5 +-
>   scripts/gdb/linux/mm.py                   |  5 +-
>   42 files changed, 381 insertions(+), 82 deletions(-)
>   mode change 100644 => 100755 Documentation/arch/arm64/kasan-offsets.sh
>   create mode 100644 arch/arm64/include/asm/kasan-tags.h
>   create mode 100644 arch/x86/include/asm/kasan-tags.h
>   create mode 100644 arch/x86/mm/kasan_inline.c
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9eb211ee-94bf-431b-981c-e305c8ea5e0b%40arm.com.
