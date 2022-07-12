Return-Path: <kasan-dev+bncBDW2JDUY5AORBCN2W6LAMGQEVSRVUHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 64DC657278E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 22:43:55 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id mm6-20020a17090b358600b001ef7bd409b0sf4240640pjb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 13:43:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657658633; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZUQl4nuysK/uBLmwRX6B9mWyUuauVUX6P1boCwIeVk3zNMhqY6DthKQ/bUh6TlVAq0
         io/qfvuqbyJzLWY/WuAehswCRl/e04CkDBCrrBp3UhqOMA2tP9CZwm31tzktxgrSw95j
         IcWrFkCO3kEjeBwG+6rBlDlK+UMi1iVR9xjIt6aMiWSy5u+tvvKW7FKsokePKTiwEB/P
         OLVYR5wWdI0yM2qvGQ/VLWg/g7I/CAYrBYgMgANSmM2OWF5W2oycqCd66ytwufirZ7SE
         i7uEfLHXkf3Zb1aasqv10P1HmbDGIQZG+9nAzuKtBJimIUZrwjzb7pIySsJ8WVzhmYCn
         V4iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4s4kfzpuRr6YZQFnb+QMufqsuWvJHscK0WEFFWSe8WQ=;
        b=iaQtV+4viZs95rIt5ILlUaVDHqoPxSj/G1OVbmQd6eZ8aYYso/L0iIqHeNbPBdZvMh
         T5bsE1iajvKQdcDOYNRZ9j/7MVo+VWn+vWum1y/DHz/nnZSPo946bJoxPNYe2oPNfVbw
         5xkItYrwo47vfzfxcvJY3Jo74PQXJqb1977vwrdB0mfbZaq6dIBbgpdj7GdPurz0la8z
         5rfkpvc7i3uueoNgmCY+cLUBUpUGxUvfxvIkydVNiPZaazS7ZKK9Lia91ksswYaU+iSC
         nmoX48Z4cRVg4B8qtbZEPAnMlt5EWLHcTjCWFyM2gvHMiR+58bmqKxzwPfejiHbhLDOP
         rwqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P0GjUZi6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4s4kfzpuRr6YZQFnb+QMufqsuWvJHscK0WEFFWSe8WQ=;
        b=WP+eNGO0X+ScORFnkqMw72We3gZ7uOxKojFLhitesnzDrg73EaMw1vKOtbiz5xoHoH
         hPpxnmEWtxy2uIINi+mIEAQSUd5ctkdjv//l7gfq+oWpSpf6ooIjhSDj0yAYTouVJesE
         cujzv3BuNIsMD6diAX8ypZZQ27Efh151rq8NvuaBinG0NakWNve7yJbHcqKJJmagBAlm
         RYkaTXYZoiLdEQvuY4dUne97L80BDnzpsZOBv/9B6NW9qrOWVD3LkwK11QJqpXppBvEi
         8sw/xeImfYCT+QEQuQbzy3Qldr6AdzOnlNAIGhixltushYfmAgmptFVKRx41t3/5KdzX
         dF3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4s4kfzpuRr6YZQFnb+QMufqsuWvJHscK0WEFFWSe8WQ=;
        b=jeZc0Bc/H7quBmszU+zRrCMTu/wrTPMFuS647vG6HiALQ/7Z5whQ2zcqtmfGBK8aj3
         ZsHgkOMGjoIGRYe6PxNMzBKmJMMuDyusj9Uad+cTZjxFlZIw0zxOkRucm1WP3Za8rTzY
         krpiwLVJr4iBq6YqeBkhJhdru7kwMJ6x6UQ8Mg7oolmCnDwn/nIBbpxkOqVwyMId8m8Y
         JztTZ3vmQ2+2muSQPAVTkyGg5P0C0TKlgDqkzuZO1HEVbv9AzJW4D0TMp2QPq43Nigzu
         3/+kUAKdyXjhKoR7JnkQ2GaUxY76i9tVM4GrMwjEw21vtkSbCTaTwMFlHx6rDUkMiK88
         VBAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4s4kfzpuRr6YZQFnb+QMufqsuWvJHscK0WEFFWSe8WQ=;
        b=SApnrI3OMiDGihTKHZJLKGM7TeHPbGe+IiqmrSrsxMVlo9uYQqOZE62BtFx2/F1fMK
         TfrR9m0wOhKzsls2T8NEYR96Sp1Rbe8poQc6UVZDPrH/1qbvVCqn9dPt/m+QW4hYvIWd
         e4HCHnDIstO6rBf+Gu6w2mQaf4H3exvwsNi7IQOjfnO4HtGMzGMaSLnXejp9hzPDEWNR
         rIjEWnIMkIh1JBgUXd4FNiqfBTKZGbvXarquAc8dZbHo6/2Pn4kpObyDelPmhXw5zfCT
         tz/IKTTglh5RRmtQ5QqOw8brakQz6r3sscbmO4VI4SG6AhNkCXu2kCIX0CipvCuO+OUu
         xUCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora81beEG0jrAyAkgcJeK5mcjLqiPp/TA0wDqaCySiwf45P4PXcp/
	lHE/ag7zdHRnEpbw/YsjclA=
X-Google-Smtp-Source: AGRyM1uMtTcMvDMkPcjNdOfkWNPZTWskk8X44+qkUJ1iX80ZkpVfVsR8CkKoHp5AydWLji7pvj/YKQ==
X-Received: by 2002:a63:f854:0:b0:419:83a9:4c00 with SMTP id v20-20020a63f854000000b0041983a94c00mr67459pgj.115.1657658633499;
        Tue, 12 Jul 2022 13:43:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2b81:0:b0:40d:b5db:7e75 with SMTP id r123-20020a632b81000000b0040db5db7e75ls1303622pgr.11.gmail;
 Tue, 12 Jul 2022 13:43:52 -0700 (PDT)
X-Received: by 2002:a63:8ac4:0:b0:414:df9b:45c6 with SMTP id y187-20020a638ac4000000b00414df9b45c6mr71485pgd.560.1657658632823;
        Tue, 12 Jul 2022 13:43:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657658632; cv=none;
        d=google.com; s=arc-20160816;
        b=JpXK+/M4LJWEFfx5SK0q5A8j5IDwM2/xgLuj2ggRTejxnRFJ9TYgBdFlPs3K7Cghs1
         iITRWxQvJVqStiZv5ny2beD7Vj2usWqDK51PH7FBoXhkLVYPZVCacI+huE2IkqLaDR4c
         e2HV7Uoh4LUREGHzpnc/OYd6r6QcgPXgfViEoWG7E9eJ4NVbl0eaGmfqHrWh9/ogJeta
         SSRDzW6IEIMeQGkPcOB+J41bu280BQ3B8JeS3n3NkJDnzgLUi7iwchXde4MYO0SJWXfV
         B374URk2H/CM1Wd/W7Dc+PtF/EivxFdn95zEqGzFscQ9CemGVey8hmo2OD3G3NGzdTVB
         aOuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r642Vyyz6e/+S5tpfBaXlyA6JS5RlQbrmCv6QVyB8K8=;
        b=KgrurWpII3erXP0vWjg310Yyq/jovYET3XlKxpWuH2r6VCox1n2yYmSAlUiO56rJq7
         zmGhl0W5ER8sgBDxsml6ubLUZbbMAU4+L/DVW6puDawJKBGF07pBqXkkGn9CrBlE4vJm
         P2f9ZyW1zMMFgCcrlKGu9nvqwHaUzWkLYQOGha7L6ogoX7O4vsQpy9Zo1cO8CpVjLXNo
         lPxcJk0vXkOJ2xC6VuzeUY776PTcRcIPifNwuTgoe/bmZCuO8UVlwjm/Uv5frliieMw/
         CCPW8ouQClu6CtmhxknOmZ/WzEvUAet1Mva4dXuA6GgrcGbUBPoP9MU8zBgOwbnqgb+q
         BJxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P0GjUZi6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id q3-20020a17090a2e0300b001efafd808b5si107282pjd.3.2022.07.12.13.43.52
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 13:43:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id u20so9038407iob.8;
        Tue, 12 Jul 2022 13:43:52 -0700 (PDT)
X-Received: by 2002:a6b:5f06:0:b0:67b:853f:565d with SMTP id
 t6-20020a6b5f06000000b0067b853f565dmr20947iob.118.1657658632140; Tue, 12 Jul
 2022 13:43:52 -0700 (PDT)
MIME-Version: 1.0
References: <20220701091621.3022368-1-davidgow@google.com> <20220701091621.3022368-2-davidgow@google.com>
In-Reply-To: <20220701091621.3022368-2-davidgow@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Jul 2022 22:43:41 +0200
Message-ID: <CA+fCnZdRUDO5wB1UKCZxT=XkLR49rjntXGi9-3S5h6_LTyBc8g@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] UML: add support for KASAN under x86_64
To: David Gow <davidgow@google.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=P0GjUZi6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Jul 1, 2022 at 11:16 AM David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Make KASAN run on User Mode Linux on x86_64.
>
> The UML-specific KASAN initializer uses mmap to map the ~16TB of shadow
> memory to the location defined by KASAN_SHADOW_OFFSET.  kasan_init()
> utilizes constructors to initialize KASAN before main().
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the KASAN_SHADOW_OFFSET
> option. The default location of this offset is 0x100000000000, which
> keeps it out-of-the-way even on UML setups with more "physical" memory.
>
> For low-memory setups, 0x7fff8000 can be used instead, which fits in an
> immediate and is therefore faster, as suggested by Dmitry Vyukov. There
> is usually enough free space at this location; however, it is a config
> option so that it can be easily changed if needed.
>
> Note that, unlike KASAN on other architectures, vmalloc allocations
> still use the shadow memory allocated upfront, rather than allocating
> and free-ing it per-vmalloc allocation.
>
> If another architecture chooses to go down the same path, we should
> replace the checks for CONFIG_UML with something more generic, such
> as:
> - A CONFIG_KASAN_NO_SHADOW_ALLOC option, which architectures could set
> - or, a way of having architecture-specific versions of these vmalloc
>   and module shadow memory allocation options.
>
> Also note that, while UML supports both KASAN in inline mode
> (CONFIG_KASAN_INLINE) and static linking (CONFIG_STATIC_LINK), it does
> not support both at the same time.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Johannes Berg <johannes@sipsolutions.net>
> ---
> This is v5 of the KASAN/UML port. It should be ready to go (this time,
> for sure! :-))
>
> Note that this will fail to build if UML is linked statically due to:
> https://lore.kernel.org/all/20220526185402.955870-1-davidgow@google.com/
>
> Changes since v4:
> https://lore.kernel.org/lkml/20220630080834.2742777-2-davidgow@google.com/
> - Instrument all of the stacktrace code (except for the actual reading
>   of the stack frames).
>   - This means that stacktrace.c and sysrq.c are now instrumented.
>   - Stack frames are read with READ_ONCE_NOCHECK()
>   - Thanks Andrey for pointing this out.
>
> Changes since v3:
> https://lore.kernel.org/lkml/20220630074757.2739000-2-davidgow@google.com/
> - Fix some tabs which got converted to spaces by a rogue vim plugin.
>
> Changes since v2:
> https://lore.kernel.org/lkml/20220527185600.1236769-2-davidgow@google.com/
> - Don't define CONFIG_KASAN in USER_CFLAGS, given we dont' use it.
>   (Thanks Johannes)
> - Update patch descriptions and comments given we allocate shadow memory based
>   on the size of the virtual address space, not the "physical" memory
>   used by UML.
>   - This was changed between the original RFC and v1, with
>     KASAN_SHADOW_SIZE's definition being updated.
>   - References to UML using 18TB of space and the shadow memory taking
>     2.25TB were updated. (Thanks Johannes)
>   - A mention of physical memory in a comment was updated. (Thanks
>     Andrey)
> - Move some discussion of how the vmalloc() handling could be made more
>   generic from a comment to the commit description. (Thanks Andrey)
>
> Changes since RFC v3:
> https://lore.kernel.org/all/20220526010111.755166-1-davidgow@google.com/
> - No longer print "KernelAddressSanitizer initialized" (Johannes)
> - Document the reason for the CONFIG_UML checks in shadow.c (Dmitry)
> - Support static builds via kasan_arch_is_ready() (Dmitry)
> - Get rid of a redundant call to kasam_mem_to_shadow() (Dmitry)
> - Use PAGE_ALIGN and the new PAGE_ALIGN_DOWN macros (Dmitry)
> - Reinstate missing arch/um/include/asm/kasan.h file (Johannes)
>
> Changes since v1:
> https://lore.kernel.org/all/20200226004608.8128-1-trishalfonso@google.com/
> - Include several fixes from Vincent Whitchurch:
> https://lore.kernel.org/all/20220525111756.GA15955@axis.com/
> - Support for KASAN_VMALLOC, by changing the way
>   kasan_{populate,release}_vmalloc work to update existing shadow
>   memory, rather than allocating anything new.
> - A similar fix for modules' shadow memory.
> - Support for KASAN_STACK
>   - This requires the bugfix here:
> https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
>   - Plus a couple of files excluded from KASAN.
> - Revert the default shadow offset to 0x100000000000
>   - This was breaking when mem=1G for me, at least.
> - A few minor fixes to linker sections and scripts.
>   - I've added one to dyn.lds.S on top of the ones Vincent added.
>
> ---
>  arch/um/Kconfig                  | 15 +++++++++++++
>  arch/um/include/asm/common.lds.S |  2 ++
>  arch/um/include/asm/kasan.h      | 37 ++++++++++++++++++++++++++++++++
>  arch/um/kernel/dyn.lds.S         |  6 +++++-
>  arch/um/kernel/mem.c             | 19 ++++++++++++++++
>  arch/um/kernel/stacktrace.c      |  2 +-
>  arch/um/os-Linux/mem.c           | 22 +++++++++++++++++++
>  arch/um/os-Linux/user_syms.c     |  4 ++--
>  arch/x86/um/Makefile             |  3 ++-
>  arch/x86/um/vdso/Makefile        |  3 +++
>  mm/kasan/shadow.c                | 29 +++++++++++++++++++++++--
>  11 files changed, 135 insertions(+), 7 deletions(-)
>  create mode 100644 arch/um/include/asm/kasan.h
>
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 8062a0c08952..289c9dc226d6 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -12,6 +12,8 @@ config UML
>         select ARCH_HAS_STRNLEN_USER
>         select ARCH_NO_PREEMPT
>         select HAVE_ARCH_AUDITSYSCALL
> +       select HAVE_ARCH_KASAN if X86_64
> +       select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ASM_MODVERSIONS
>         select HAVE_UID16
> @@ -220,6 +222,19 @@ config UML_TIME_TRAVEL_SUPPORT
>
>           It is safe to say Y, but you probably don't need this.
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x100000000000
> +       help
> +         This is the offset at which the ~16TB of shadow memory is
> +         mapped and used by KASAN for memory debugging. This can be any
> +         address that has at least KASAN_SHADOW_SIZE (total address space divided
> +         by 8) amount of space so that the KASAN shadow memory does not conflict
> +         with anything. The default is 0x100000000000, which works even if mem is
> +         set to a large value. On low-memory systems, try 0x7fff8000, as it fits
> +         into the immediate of most instructions, improving performance.
> +
>  endmenu
>
>  source "arch/um/drivers/Kconfig"
> diff --git a/arch/um/include/asm/common.lds.S b/arch/um/include/asm/common.lds.S
> index eca6c452a41b..fd481ac371de 100644
> --- a/arch/um/include/asm/common.lds.S
> +++ b/arch/um/include/asm/common.lds.S
> @@ -83,6 +83,8 @@
>    }
>    .init_array : {
>         __init_array_start = .;
> +       *(.kasan_init)
> +       *(.init_array.*)
>         *(.init_array)
>         __init_array_end = .;
>    }
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> new file mode 100644
> index 000000000000..0d6547f4ec85
> --- /dev/null
> +++ b/arch/um/include/asm/kasan.h
> @@ -0,0 +1,37 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_UM_KASAN_H
> +#define __ASM_UM_KASAN_H
> +
> +#include <linux/init.h>
> +#include <linux/const.h>
> +
> +#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +
> +/* used in kasan_mem_to_shadow to divide by 8 */
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +
> +#ifdef CONFIG_X86_64
> +#define KASAN_HOST_USER_SPACE_END_ADDR 0x00007fffffffffffUL
> +/* KASAN_SHADOW_SIZE is the size of total address space divided by 8 */
> +#define KASAN_SHADOW_SIZE ((KASAN_HOST_USER_SPACE_END_ADDR + 1) >> \
> +                       KASAN_SHADOW_SCALE_SHIFT)
> +#else
> +#error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
> +#endif /* CONFIG_X86_64 */
> +
> +#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
> +#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> +
> +#ifdef CONFIG_KASAN
> +void kasan_init(void);
> +void kasan_map_memory(void *start, unsigned long len);
> +extern int kasan_um_is_ready;
> +
> +#ifdef CONFIG_STATIC_LINK
> +#define kasan_arch_is_ready() (kasan_um_is_ready)
> +#endif
> +#else
> +static inline void kasan_init(void) { }
> +#endif /* CONFIG_KASAN */
> +
> +#endif /* __ASM_UM_KASAN_H */
> diff --git a/arch/um/kernel/dyn.lds.S b/arch/um/kernel/dyn.lds.S
> index 2f2a8ce92f1e..2b7fc5b54164 100644
> --- a/arch/um/kernel/dyn.lds.S
> +++ b/arch/um/kernel/dyn.lds.S
> @@ -109,7 +109,11 @@ SECTIONS
>       be empty, which isn't pretty.  */
>    . = ALIGN(32 / 8);
>    .preinit_array     : { *(.preinit_array) }
> -  .init_array     : { *(.init_array) }
> +  .init_array     : {
> +    *(.kasan_init)
> +    *(.init_array.*)
> +    *(.init_array)
> +  }
>    .fini_array     : { *(.fini_array) }
>    .data           : {
>      INIT_TASK_DATA(KERNEL_STACK_SIZE)
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 15295c3237a0..276a1f0b91f1 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -18,6 +18,25 @@
>  #include <kern_util.h>
>  #include <mem_user.h>
>  #include <os.h>
> +#include <linux/sched/task.h>
> +
> +#ifdef CONFIG_KASAN
> +int kasan_um_is_ready;
> +void kasan_init(void)
> +{
> +       /*
> +        * kasan_map_memory will map all of the required address space and
> +        * the host machine will allocate physical memory as necessary.
> +        */
> +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +       init_task.kasan_depth = 0;
> +       kasan_um_is_ready = true;
> +}
> +
> +static void (*kasan_init_ptr)(void)
> +__section(".kasan_init") __used
> += kasan_init;
> +#endif
>
>  /* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
>  unsigned long *empty_zero_page = NULL;
> diff --git a/arch/um/kernel/stacktrace.c b/arch/um/kernel/stacktrace.c
> index 86df52168bd9..fd3b61b3d4d2 100644
> --- a/arch/um/kernel/stacktrace.c
> +++ b/arch/um/kernel/stacktrace.c
> @@ -27,7 +27,7 @@ void dump_trace(struct task_struct *tsk,
>
>         frame = (struct stack_frame *)bp;
>         while (((long) sp & (THREAD_SIZE-1)) != 0) {
> -               addr = *sp;
> +               addr = READ_ONCE_NOCHECK(*sp);
>                 if (__kernel_text_address(addr)) {
>                         reliable = 0;
>                         if ((unsigned long) sp == bp + sizeof(long)) {
> diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
> index 3c1b77474d2d..8530b2e08604 100644
> --- a/arch/um/os-Linux/mem.c
> +++ b/arch/um/os-Linux/mem.c
> @@ -17,6 +17,28 @@
>  #include <init.h>
>  #include <os.h>
>
> +/*
> + * kasan_map_memory - maps memory from @start with a size of @len.
> + * The allocated memory is filled with zeroes upon success.
> + * @start: the start address of the memory to be mapped
> + * @len: the length of the memory to be mapped
> + *
> + * This function is used to map shadow memory for KASAN in uml
> + */
> +void kasan_map_memory(void *start, size_t len)
> +{
> +       if (mmap(start,
> +                len,
> +                PROT_READ|PROT_WRITE,
> +                MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
> +                -1,
> +                0) == MAP_FAILED) {
> +               os_info("Couldn't allocate shadow memory: %s\n.",
> +                       strerror(errno));
> +               exit(1);
> +       }
> +}
> +
>  /* Set by make_tempfile() during early boot. */
>  static char *tempdir = NULL;
>
> diff --git a/arch/um/os-Linux/user_syms.c b/arch/um/os-Linux/user_syms.c
> index 715594fe5719..cb667c9225ab 100644
> --- a/arch/um/os-Linux/user_syms.c
> +++ b/arch/um/os-Linux/user_syms.c
> @@ -27,10 +27,10 @@ EXPORT_SYMBOL(strstr);
>  #ifndef __x86_64__
>  extern void *memcpy(void *, const void *, size_t);
>  EXPORT_SYMBOL(memcpy);
> -#endif
> -
>  EXPORT_SYMBOL(memmove);
>  EXPORT_SYMBOL(memset);
> +#endif
> +
>  EXPORT_SYMBOL(printf);
>
>  /* Here, instead, I can provide a fake prototype. Yes, someone cares: genksyms.
> diff --git a/arch/x86/um/Makefile b/arch/x86/um/Makefile
> index ba5789c35809..f778e37494ba 100644
> --- a/arch/x86/um/Makefile
> +++ b/arch/x86/um/Makefile
> @@ -28,7 +28,8 @@ else
>
>  obj-y += syscalls_64.o vdso/
>
> -subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o
> +subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o \
> +       ../lib/memmove_64.o ../lib/memset_64.o
>
>  endif
>
> diff --git a/arch/x86/um/vdso/Makefile b/arch/x86/um/vdso/Makefile
> index 5943387e3f35..8c0396fd0e6f 100644
> --- a/arch/x86/um/vdso/Makefile
> +++ b/arch/x86/um/vdso/Makefile
> @@ -3,6 +3,9 @@
>  # Building vDSO images for x86.
>  #
>
> +# do not instrument on vdso because KASAN is not compatible with user mode
> +KASAN_SANITIZE                 := n
> +
>  # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
>  KCOV_INSTRUMENT                := n
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index a4f07de21771..0e3648b603a6 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -295,9 +295,22 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>                 return 0;
>
>         shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> -       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>         shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> -       shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +
> +       /*
> +        * User Mode Linux maps enough shadow memory for all of virtual memory
> +        * at boot, so doesn't need to allocate more on vmalloc, just clear it.
> +        *
> +        * The remaining CONFIG_UML checks in this file exist for the same
> +        * reason.
> +        */
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset((void *)shadow_start, KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
> +               return 0;
> +       }
> +
> +       shadow_start = PAGE_ALIGN_DOWN(shadow_start);
> +       shadow_end = PAGE_ALIGN(shadow_end);
>
>         ret = apply_to_page_range(&init_mm, shadow_start,
>                                   shadow_end - shadow_start,
> @@ -466,6 +479,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>
>         if (shadow_end > shadow_start) {
>                 size = shadow_end - shadow_start;
> +               if (IS_ENABLED(CONFIG_UML)) {
> +                       __memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
> +                       return;
> +               }
>                 apply_to_existing_page_range(&init_mm,
>                                              (unsigned long)shadow_start,
>                                              size, kasan_depopulate_vmalloc_pte,
> @@ -531,6 +548,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>         if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
>                 return -EINVAL;
>
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset((void *)shadow_start, KASAN_SHADOW_INIT, shadow_size);
> +               return 0;
> +       }
> +
>         ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
>                         shadow_start + shadow_size,
>                         GFP_KERNEL,
> @@ -554,6 +576,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>
>  void kasan_free_module_shadow(const struct vm_struct *vm)
>  {
> +       if (IS_ENABLED(CONFIG_UML))
> +               return;
> +
>         if (vm->flags & VM_KASAN)
>                 vfree(kasan_mem_to_shadow(vm->addr));
>  }
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdRUDO5wB1UKCZxT%3DXkLR49rjntXGi9-3S5h6_LTyBc8g%40mail.gmail.com.
