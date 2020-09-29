Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLGSZX5QKGQELYHCFYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 726BF27D419
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 19:04:45 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 63sf2439892edy.9
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 10:04:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601399085; cv=pass;
        d=google.com; s=arc-20160816;
        b=mobyho6KUOY1r9WJW3BPE0EVg4ouE+079oHv3gA/zjY7DCR1/CEPwYeSAEBmHoxnlD
         ueAoG5kNzJ0bgUiiJO1YwgxANI+mU8Z1Trf4VKGQPtXt5lUPW1w36AE7UVwFo0oa38Ys
         Nj3ugwjj6e6sLPhg+ePTUh/HLwkrshlHE6syVywnCcZ97uFW4EIkPSJtCCa9d3/waZGv
         +JHflOAiAIV8JtuyAi9prbjrq2NuoL5SOijkkWj1JZEz1DHXRtIQaabcnW857ZyPaE1F
         H9DNxdsiAIpnZCdNWVMdBYicqUiglupjMcN3nsTDAY3hOYrJEbVfRk0RNZYbIRxMHdP3
         bidQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pA2nGq5CvkVyzjJroJoyXvbfILpaauu4/U3v4l0POGo=;
        b=X+uubXEPPFn+NLQGqznQcjxya4etjYuvkeh90M0rvk1NMLqMQ1hCRxLtUiC32yu9Da
         ntAFs7CJbERFlVLYuCco4KL+SlYJTuDAuWfNqr5/jHPYw5C60xFImM0TSx1RA7uuBP+u
         dyeA25ymnnS4iqsXNm4b/BghfGZogBc9ELFfDBU5QMhvpYu8eyeEsR8LXE1PjnD4UviZ
         6lkpjcPj1wpGJah5j7p4kA/cQNcK7g1EpfA4IGAyb9Qg1gCNvaBw2idtXf8DnAY4xwuI
         oTrkcQPzPrSHfFTeyqM/LiKu4GLKzeeAs2JdUrfAIgwdvgHxfuR/s49UW/yF13xe7lVL
         oINg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kj6x+I9c;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pA2nGq5CvkVyzjJroJoyXvbfILpaauu4/U3v4l0POGo=;
        b=DxJ/T2GofvK9DILFvefY4+FyiU2+5NNNVfnce7/oRqw3CdaAN0Mi1KlLyiDx1MlocV
         blXuRgZ1v/Q2e3XMbsvbD4jBDucsRZb//cYqwY31Xlm9m3SUTdxOCT+jaQx+9jiVRqC9
         tdlzWIiRHCMzBgL2Iz0V4969gMehvWlOHJ2bp9UghizKHf5X6Ie5tN2Bk+zwflK2C7Il
         yWoNi/Ts0Hi0qW/UAs9kgXJB3PAoC2hHL9swkptkDeeop6y/3TJtbchVihbFbcvz78df
         20a88m/R+dssDNzcDLl32nrlSKr6OGAi8A65KkNzjsmqSyMT9noYD5tqfzBIH9iwRmHq
         qfyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pA2nGq5CvkVyzjJroJoyXvbfILpaauu4/U3v4l0POGo=;
        b=BVA/s4NsCdH3HgYymZtC+gkbEe+FVQ5U/6EgL2WfDcHuRMk2dLIh6hP8F0lBRlWMbH
         mJM7/giYsilnmYtMfcEX6GHOMDnmDfgn6GAsRPIxEyAZwycQjbqeJQHLflD1caV9UD7J
         6Q0EGAHgCidxoFuSWw3SeETz//PCfiCZZpebPX/YrOkp8dPBiXiC0n4EytPhxsbi/LL1
         bnx7/X9CVQBLpLQh3jxmNOspnuRNPrRw0hP6yk+qnlySOoBhrnymDC2f+HoUy12PuCuQ
         tJ7y0STJ1Wbln7mA7C6j/wYI9l9qT2TASBLmd+josqSMGWZtM21QPnLYB/Ms9NQyg59M
         pd9Q==
X-Gm-Message-State: AOAM530TrqvwKyEcTAnwEz+GPqK0txorT0wOdaJSC4V9HMjOhx01dR4O
	uYUsVJFTyXUTo7KxO1xR4og=
X-Google-Smtp-Source: ABdhPJzmIkhhLxN/XGQrGNLQzQiY5agxUrhzy4+KSciwv+r27X5tau/XSMC/aYt8xvB/SjlqYS1NVw==
X-Received: by 2002:a05:6402:202a:: with SMTP id ay10mr4469911edb.36.1601399085139;
        Tue, 29 Sep 2020 10:04:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:924e:: with SMTP id c14ls1626709ejx.0.gmail; Tue, 29
 Sep 2020 10:04:44 -0700 (PDT)
X-Received: by 2002:a17:906:1118:: with SMTP id h24mr2159357eja.515.1601399084236;
        Tue, 29 Sep 2020 10:04:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601399084; cv=none;
        d=google.com; s=arc-20160816;
        b=Q5cYKjBjZsTjfkX5a4RDaeeFrxRT/8axBu9oNPnN5ymV+X8vEIliRg093UYC0W34xl
         Vb0GM+RD2RQJcSUG5/epKxs/PG85oD9LnrmVaiNVYXV3SmGJFi87FGlTtypS7eRWvPoP
         ifYFxaxszuU1nv5FemV6XzVdM+aNP5S/4l6eOZCEg/dbPh8PTVrVtqPkx45VLtvXlb+a
         +7Cjd6eGajnGUIzyB7L0YcloKCJLSIdOr0g+kqbae0360sw8NQME0HT7FBnxVbo+Be4W
         Xnz+ePT77rvr/UcgpdhmHg3bAEMWYS4r2fgjQ76oT42uc28XuwvBcZLRB78r4N5RDV2s
         G9cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Q2qSwq54NZdSyl2veBn7BJhqFUUK7iFcl9H/GTVRA5E=;
        b=QRL1PNnEUSvoXNt7pjyqSCaYW7aO1YWEqTerdgUGmJFF0Ku1zMmqdxRiNhSnjVVFZ1
         xqe0CxsURKIFru1FcYTrew43wTtJe2F8OPfntq8WSfVtO5Dlz9fscLBZZ8awF4GKdJJ2
         0oPWWfV9PUEOpvb25S04W+SOYl/2sNIF+oLOSBtDLiBo08sLGJ2kWfhVEYow0iIwsHmJ
         6BHxmbsi2MkniBHIXMEXqMUNlc3a3LK18dzPrcJzZHaTxFmPpmdRFU48tfouA5YOKr2m
         Xyi/5wUOJUVz27i3uAoBcahNlV6rp4OHlS0Ja6Ft7a08H5hbsLEvojVV97/QSGt+1JmF
         /j/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kj6x+I9c;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id dk15si184356edb.2.2020.09.29.10.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 10:04:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id x23so5362526wmi.3
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 10:04:44 -0700 (PDT)
X-Received: by 2002:a7b:c749:: with SMTP id w9mr5250095wmk.29.1601399083707;
 Tue, 29 Sep 2020 10:04:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200929142752.GD53442@C02TD0UTHF1T.local>
In-Reply-To: <20200929142752.GD53442@C02TD0UTHF1T.local>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 19:04:32 +0200
Message-ID: <CAG_fn=X5ZwMLC9OJaMzcV2WpRgxHyfSeb+0A+1rPYcRYu27V=g@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kj6x+I9c;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Sep 29, 2020 at 4:28 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Mon, Sep 21, 2020 at 03:26:04PM +0200, Marco Elver wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the arm64 architecture. In particular, this implements the
> > required interface in <asm/kfence.h>. Currently, the arm64 version does
> > not yet use a statically allocated memory pool, at the cost of a pointe=
r
> > load for each is_kfence_address().
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > For ARM64, we would like to solicit feedback on what the best option is
> > to obtain a constant address for __kfence_pool. One option is to declar=
e
> > a memory range in the memory layout to be dedicated to KFENCE (like is
> > done for KASAN), however, it is unclear if this is the best available
> > option. We would like to avoid touching the memory layout.
> > ---
> >  arch/arm64/Kconfig              |  1 +
> >  arch/arm64/include/asm/kfence.h | 39 +++++++++++++++++++++++++++++++++
> >  arch/arm64/mm/fault.c           |  4 ++++
> >  3 files changed, 44 insertions(+)
> >  create mode 100644 arch/arm64/include/asm/kfence.h
> >
> > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > index 6d232837cbee..1acc6b2877c3 100644
> > --- a/arch/arm64/Kconfig
> > +++ b/arch/arm64/Kconfig
> > @@ -132,6 +132,7 @@ config ARM64
> >       select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >       select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> >       select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> > +     select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
> >       select HAVE_ARCH_KGDB
> >       select HAVE_ARCH_MMAP_RND_BITS
> >       select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
> > diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/k=
fence.h
> > new file mode 100644
> > index 000000000000..608dde80e5ca
> > --- /dev/null
> > +++ b/arch/arm64/include/asm/kfence.h
> > @@ -0,0 +1,39 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +#ifndef __ASM_KFENCE_H
> > +#define __ASM_KFENCE_H
> > +
> > +#include <linux/kfence.h>
> > +#include <linux/log2.h>
> > +#include <linux/mm.h>
> > +
> > +#include <asm/cacheflush.h>
> > +
> > +#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
> > +
> > +/*
> > + * FIXME: Support HAVE_ARCH_KFENCE_STATIC_POOL: Use the statically all=
ocated
> > + * __kfence_pool, to avoid the extra pointer load for is_kfence_addres=
s(). By
> > + * default, however, we do not have struct pages for static allocation=
s.
> > + */
> > +
> > +static inline bool arch_kfence_initialize_pool(void)
> > +{
> > +     const unsigned int num_pages =3D ilog2(roundup_pow_of_two(KFENCE_=
POOL_SIZE / PAGE_SIZE));
> > +     struct page *pages =3D alloc_pages(GFP_KERNEL, num_pages);
> > +
> > +     if (!pages)
> > +             return false;
> > +
> > +     __kfence_pool =3D page_address(pages);
> > +     return true;
> > +}
> > +
> > +static inline bool kfence_protect_page(unsigned long addr, bool protec=
t)
> > +{
> > +     set_memory_valid(addr, 1, !protect);
> > +
> > +     return true;
> > +}
>
> This is only safe if the linear map is force ot page granularity. That's
> the default with rodata=3Dfull, but this is not always the case, so this
> will need some interaction with the MMU setup in arch/arm64/mm/mmu.c.

On x86 we ensure this by reallocating the necessary page tables.

But looks like your suggestion is what we need for arm64 as long as we
also want virt_to_page() to work for our pool.
It's still unclear to me whether a carveout you suggest can be placed
at a fixed (known at link time) address, as the main point of this
dance is to remove memory accesses from is_kfence_addr().

> Thanks,
> Mark.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX5ZwMLC9OJaMzcV2WpRgxHyfSeb%2B0A%2B1rPYcRYu27V%3Dg%40mai=
l.gmail.com.
