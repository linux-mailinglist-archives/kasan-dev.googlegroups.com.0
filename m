Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZF3T6LQMGQEF24WA4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 72DD6586C8C
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Aug 2022 16:06:29 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id i5-20020aca2b05000000b0033a509b7255sf2990139oik.21
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Aug 2022 07:06:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659362788; cv=pass;
        d=google.com; s=arc-20160816;
        b=IxXPyE/WRWxtvgadGYJGukMVTck7Ozid4eEeaXsMW6vlqWaSBlGucVEVdtpKG0t0Ht
         zChmK8+BmBHMCYql23yTpqf7e4FBHbBatk/ptd/S+LChA3gEy8RZZUp2JWlM8CQ8O2y0
         Fp7evQ7dmhVOxdCOuQYmDPM/fdcMebyIK5QMW8JW1H3t/H/SOL0dV06TgbfVOrcGFTmR
         bJ4vBq4sMAHo2+CS0TfSz/KBfuFBWcBwqVkx7uEBRorci5Bi1p6yIXWpigYA4YxRTPGD
         l2uK5/MIIAqGbn3idi56ymrezMyYjApOrp5zJCLAhHvj3BFSaBbUV3bclyqySsn4U13r
         2D9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wSSEap1SLIuTmYoJRZAL8JWxS5gbEbhfghMh139fIG8=;
        b=DTC7BIhfW4iv+dDuq1ebNiEJQ/ymEJR62GgWicwdg8rmVah2pjdGar8Izg1jGrdyiV
         PymFYd4TWZs79YorriJg1lQjD31H21PmG0Ya2iS5UUeyOU62pe5dshxiE1TvOmtumSXl
         I6b57ax0S+r1Q+fQkcg+hCcSOGUkvdrnEW19LjS8F57NzaBwUIlryqFSSL1QDjnkMw27
         +qFdyBItRc7qvnhzUOT/CA/494Z92LwkfqRmadhlJea1Dcntj4FdgmBEyTOLMlQ1O72C
         lg+FGHoMQ2w9W63M8GolG2bQIqxD++tCoE/pj+VCQsMwoSPRWZbpI2tVBuxSv6wvh4gt
         Twvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rAPWjvDI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wSSEap1SLIuTmYoJRZAL8JWxS5gbEbhfghMh139fIG8=;
        b=ZWsxC39SRz1Uatx6wOD1f986sz4Fq0s9Mr54yr2jTJLUqaIfZsn0gtuOFuSbZezayr
         5EJtymVOIpo/HqQRMp6XPjtiiM4PI0wmw8hC/3dPINcDGXohG5TXsjPHJZu/fLbehSRf
         gITH5QmbYD7/484gAcOk+h1E+VZaeP/+mst2aD+lOUZRfT/owvdAh8gvVde5+QIsxhsB
         vYp+iuQj37bG5l0W9SCmeYYAvlhugL02apiefvhrarP12GZDveyjBZZBfTeBqJEfko1i
         zGaFupmpGVxWsbCisrCAJ9liw3Z0AsKtqLN7GdJO69kYBJQaboYGppU/erilxpGiWFKB
         72cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wSSEap1SLIuTmYoJRZAL8JWxS5gbEbhfghMh139fIG8=;
        b=T6ocL8j8D1yWoTbrZy1+rMB7++o3pUIjcnJave+J5lvFwFo2RYG8vIPAJqQCUN4jsP
         +lqRQeTQWzKzBMS6/waSIgz2cTC3HfKDDNkXEULzsXpTyUV+ad3cnoYPVVpq7WF65UvO
         9Q4HehHP2+8REmD9rYtCxPmmXVfhCKbvDVW4fvP65e7WYdBWacqt3AAuSkYRs6kwEaV/
         4jA2PIXqcvEaX8l7idhDLkMtbo6yVJEUljy66kw5fVOX5AAzcN7i+r9aeo434fSx8Htc
         uQWUny+mVUql0PDdBR4PJidynZxi3JxHcusJWatUJqITIJEBv0CmAazx0+YscUiSzmbl
         krIg==
X-Gm-Message-State: AJIora/V+mEyx1KfZMswZaAhJxDykt3NHVSptNH+lhlvVWg6SwidVcuu
	w7thwqU5ml7ukjIJYKFOvZ4=
X-Google-Smtp-Source: AGRyM1vG7r/ISS96Sf/MnDdZkn924B9sRHSyCQ4MVU4LE7hXTjW0v3DMbUx3YxbhFnWs3bn+qh1isA==
X-Received: by 2002:a05:6871:93:b0:fe:23b6:6efb with SMTP id u19-20020a056871009300b000fe23b66efbmr7142086oaa.201.1659362788137;
        Mon, 01 Aug 2022 07:06:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6e0f:0:b0:61c:a0ad:d8a with SMTP id e15-20020a9d6e0f000000b0061ca0ad0d8als2113030otr.5.-pod-prod-gmail;
 Mon, 01 Aug 2022 07:06:27 -0700 (PDT)
X-Received: by 2002:a05:6830:2b2a:b0:61c:aa78:7e0c with SMTP id l42-20020a0568302b2a00b0061caa787e0cmr6035029otv.51.1659362787609;
        Mon, 01 Aug 2022 07:06:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659362787; cv=none;
        d=google.com; s=arc-20160816;
        b=tyCjH4Q9qRJi/DqZ6Xj/5+WtXqYcY+jYYfFneW+SxN4mgUSwMhYLIcsahjw/ptk93L
         4tNcz28R1RDnzaxe6t1grj/yHfldoJoEAQpNzOAq11nqR9cfrVsrPUvNhWnme2ITIXXj
         fDZVECR4C3qoQNdqa1FxpittGHKzQLm6108RKAT2b32PF2KNSX7rgRJ2qEhIL1ZdRu7z
         COhQfxoBtiZyFhSLIASoW+AyZGq00lQdijR2wGfszbtWdTem8DD49YHASGzTdyWjFomu
         DZDY9csy6NuHLqXXmoo1gZCTP7GCpxn0+NRONnzyL/hSwG4Y2rM7ZklvGfBzPO65fd7p
         dkXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G5UhvGzRrQcBGCWtOdqFEgZwHRGSXUKRpcxRX6CD/7s=;
        b=JHj8N2Uh77Pe30zaqadtw60vHZNwbbr7Q9TQsabYX3RshFu3WDkaa92EqbtXLyN6Jm
         iSI6/B9B2OJB9wdklir8Kx7HwHT4iC11qTOhQv47WZFRwzUjV0u9Gi4q7P6qg7S9pHPe
         hI45vaZCSDIKa0KZK6RLMt0eoKjhxfV0B5PlvvEMu9qsId74a8NMuynlIkdGvaae6GYO
         inT7QiZuhRnLROKx1WHtgl/SMxRKEwfW0PWgFOWpP4CBwS5ihlEVIRDxOdGY/9IjyN3O
         D98/6QP2UEmyChgLVLMrT96k+L9/BwX+fCHFYyjBvyFTKNDkWW/HWjsfvp2WSrF13FSL
         sg4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rAPWjvDI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id z3-20020a056870d68300b0010c5005e1c8si1023952oap.3.2022.08.01.07.06.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Aug 2022 07:06:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-32269d60830so110181897b3.2
        for <kasan-dev@googlegroups.com>; Mon, 01 Aug 2022 07:06:27 -0700 (PDT)
X-Received: by 2002:a0d:f045:0:b0:324:55ec:6595 with SMTP id
 z66-20020a0df045000000b0032455ec6595mr11570098ywe.255.1659362787035; Mon, 01
 Aug 2022 07:06:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220628113714.7792-1-yee.lee@mediatek.com> <20220628113714.7792-2-yee.lee@mediatek.com>
 <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
 <20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org>
 <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
 <CANpmjNPhhPUZFSZaLbwyJfACWMOqFchvm-Sx+iwGSM3sxkky8Q@mail.gmail.com>
 <20220719161356.df8d7f6fc5414cc9cc7f8302@linux-foundation.org> <dc7800c0-43f3-6453-ef5f-1ceb659062de@intel.com>
In-Reply-To: <dc7800c0-43f3-6453-ef5f-1ceb659062de@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Aug 2022 16:05:50 +0200
Message-ID: <CANpmjNNpvbBR6z0T7m1gCp1XoVOHN7CpHoauMKLvtFd5NYJK2Q@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
To: Dave Hansen <dave.hansen@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	yee.lee@mediatek.com, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rAPWjvDI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as
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

[+x86 maintainers ...]

On Wed, 20 Jul 2022 at 01:22, Dave Hansen <dave.hansen@intel.com> wrote:
> On 7/19/22 16:13, Andrew Morton wrote:
> > On Mon, 18 Jul 2022 16:26:25 +0200 Marco Elver <elver@google.com> wrote:
> >
> >> On Sat, 16 Jul 2022 at 20:43, Geert Uytterhoeven <geert@linux-m68k.org> wrote:
> >> [...]
> >>>> - This patch has been accused of crashing the kernel:
> >>>>
> >>>>         https://lkml.kernel.org/r/YsFeUHkrFTQ7T51Q@xsang-OptiPlex-9020
> >>>>
> >>>>   Do we think that report is bogus?
> >>> I think all of this is highly architecture-specific...
> >> The report can be reproduced on i386 with CONFIG_X86_PAE=y. But e.g.
> >> mm/memblock.c:memblock_free() is also guilty of using __pa() on
> >> previously memblock_alloc()'d addresses. Looking at the phys addr
> >> before memblock_alloc() does virt_to_phys(), the result of __pa()
> >> looks correct even on PAE, at least for the purpose of passing it on
> >> to kmemleak(). So I don't know what that BUG_ON(slow_virt_to_phys() !=
> >> phys_addr) is supposed to tell us here.
> >>
> > It's only been nine years, so I'm sure Dave can remember why he added
> > it ;)
> >
> >               BUG_ON(slow_virt_to_phys((void *)x) != phys_addr);
> >
> > in arch/x86/mm/physaddr.c:__phys_addr().
>
> I think I intended it to double check that the linear map is *actually*
> a linear map for 'x'.  Sure, we can use the "x - PAGE_OFFSET" shortcut,
> but did it turn out to be actually accurate for the address it was handed?
>
> I'd be curious what the page tables actually say for the address that's
> causing problems.

test robot just reminded us again:
https://lore.kernel.org/all/YufXncrWhJZH0ifB@xsang-OptiPlex-9020/T/#u

Few things I noticed:

* mm/memblock.c's memblock_free() also uses __pa() to convert back to
physical address. Presumably that's also wrong. What should be used
instead?

* kmemleak happily converts phys_addr_t to unsigned long everywhere,
but with i386 PAE, this will narrow a 64-bit address to a 32-bit
address. Is that correct? Does kmemleak need a "depends on 64BIT ||
!PHYS_ADDR_T_64BIT"?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNpvbBR6z0T7m1gCp1XoVOHN7CpHoauMKLvtFd5NYJK2Q%40mail.gmail.com.
