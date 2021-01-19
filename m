Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYHITSAAMGQEXTL5ZUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id F14092FC013
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 20:34:57 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id b81sf4432010pfb.21
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:34:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611084896; cv=pass;
        d=google.com; s=arc-20160816;
        b=pKXUd04pSSTGUj1j6mVvxmeTmIe4GD7sNRhoqolw+ArQIqeGmyU6daOtzelr/lCHcb
         fj3aWPeDz5qIAIJjbw5KC76VrcLpJGW1ZmgqZ1oiSNZyTzZrqnO0c7yQzZ2FbypMEXBB
         Zt0dmCrR+5umvscxjNwgnJxKYLM1kYc74r8Pkew9VosTHytCRfEnQWCR4U5qj+lpPzev
         U5dQAfnyldZtvMQWJcZyrirN0uK99LXH2pGqA71MXXWuZ+lS8+BHLkX0pAZYVnx+Q0hV
         cD7KhhV2LY77hh5Y1icBXfeUtn6kNcpn8apNqENoPVipQKnNHt3Vj2AaVN0B7uqJrlYd
         kNzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Dak747tIjYEj8yE47ly2kYy6E+EfLbaNCsgbHz9IFCI=;
        b=1CMj3H5T0HD8/OWuFG8btFZyJ1tqV/fUs68hVUoq8xSVEBtmCyniQfMWn4WbibOlQv
         FJS4Z11ICO1r3LCKP9paJ7wqUKEJcey/AKZb6XbGrm8hgaCJD2OhK0PJNRoQC5bEAvOj
         /vjMfiHdh0of0ouaMzpm/w7GXpdVDMSKQplYaaxjaXXRCTUNfut6EIfFA2nkSay/Sxra
         ssSrw+JkDo8HFSgLnKbzkMEFmo7CcB+iiNqA7WfY4rBZd9l+jvI174C2KPHUXWWoOlqJ
         rBIebBAUidvc0zikwEcjdQCTS7yv/3ZA1jxOX1VSLa2wdXuUp6AEBOX5i7+8S5rY4vVB
         Un7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=btK4sahz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dak747tIjYEj8yE47ly2kYy6E+EfLbaNCsgbHz9IFCI=;
        b=OdcQJqM8H5cHME0wUdY+dX8o9dCmy4QnvHVDmvaSGrwZWldcz9H7AJfIRJ7LU69KLk
         M9X8+sjCrbYZZ7NGeeE31jMEJi7FMKYQbVH+9/t3D/dDyOz3loRP+v+VBDa+I5QXKL6x
         0YoA6xfkvUrvadYjaiHZ9z/RlDs2lJdc31T48YrG6ro9gU3c6sOD49ipiNR8CHEOTgCn
         dqtQ6JCuinMziVxi276uJd/BsHeTPMyxC14swRLh3dxVGVNUgiuQln/IDNWx+3EguBDY
         B8zFYOoJ3g7isRdzk6w7rzknUPrFe0P4URiy/S334uu/t+W9zYzWAE8JuEC4GTP4wnkz
         VzFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dak747tIjYEj8yE47ly2kYy6E+EfLbaNCsgbHz9IFCI=;
        b=bn8oLGOl4zMpVI+ISgYtYSIGkQ8tGs3urvnEohmBn6q8T0sQegxE4qqjH4u6Q1AU5K
         tcIVrtCPc2iLaoX9uowM2J+e69kSCeoc+3gZcQmzELVCDuDpDx9Dgkb8Q05rTeGAMM85
         V939H3HXiA496xAJSZfldYmsFoteoHMfq0Bp1z5ETdwnVU2x7tdB8w0iPThzGJhkaajU
         ONx6xfWQhO2jlfJP3idj5gMx98JuhxLVdTlzfONmxt6WEY5c2BLqrmx5CDIIuG4Hvtg+
         ozOkNeyovKR+YI2+EB9lLgqwj1Xqh+QYc6WuDgUn98dILtNepRNKOLUEekJWWJubV1PY
         VsbA==
X-Gm-Message-State: AOAM530i6TCGtgIYzPtW8S6oBQTGXDOj/Y5pRC45wB+vdu4PPFx8OF8R
	a+LNCAJq1QZUI6m2qYqFoN4=
X-Google-Smtp-Source: ABdhPJzYPnjK+1PtV1MFcgf5eucqPhc+9jvKTN/X7AC0whJK8slluY0FeLskKk18tgACOW23G6QITQ==
X-Received: by 2002:a63:2c9:: with SMTP id 192mr5819399pgc.325.1611084896737;
        Tue, 19 Jan 2021 11:34:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls403270pjz.1.canary-gmail;
 Tue, 19 Jan 2021 11:34:46 -0800 (PST)
X-Received: by 2002:a17:90a:4582:: with SMTP id v2mr1399152pjg.15.1611084886708;
        Tue, 19 Jan 2021 11:34:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611084886; cv=none;
        d=google.com; s=arc-20160816;
        b=jfoIrk6TYjM16bNSUzVCc9xKWoBu95H4/OpVNL1iDfrPSOZi+z1MBJqxkueJQ/NlZq
         9dDSb9zotARgu3dYGmchDoIfrarOW8dzfQUFd/lu8i1pL15ZB+2scj0qT22flJcl7eWD
         XPHFp+4VRM/rWdYxah7LxaYnd6dLHO9SzhG4uspS/MXXv+ygACHYZ68PwIYnO6QaLY23
         6DIyA9zJ/coKyvU0QOSP5kjaZ+eCbhG1Evtznl6pdRyortGK63F7GxF4jtdYq/cj57a+
         6zN3HqPfzRj0OC0JwRy9MTgA5MKJ8RrKBQ1/Qnmx9h5QeyO5q1i0o3pjUwH3MSxbfyYA
         fjeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UzjGhv/xtQmLzd1fmO3nz3CB6VSkFAgOhOGhk3ruAHo=;
        b=UXrdSDONBSp8WNtQI+mySDCTh81fsfrxgodDwcGHzC3uI3kdvl6urux2O/3omJchQc
         2O4WeqnaZplvlr6HLscvrCUAGoP0OU+ZB3z+0g1KsTdGYppW5vwQ4iCl68oNdH8p7Tuz
         MYNsMWYIBkjmIdu8kur9qCkwPWImbjy9NBCaYzwiREdgffN6doQ9hYeGAkdBQOYDVJ6S
         Rp4k3RLZnB+3YfCRddf39NF3EYYoBBwnCzjNpWkZF/mH2QH+MF204rZy+dyaOQyNeaRz
         rxjPyL/bB28N3Znf3Mgh7Zs6F5o+yWXR74OPEqqF41/fQqauO1VYR2YtAl+tPZvr0OBm
         JvSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=btK4sahz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id nl3si381387pjb.0.2021.01.19.11.34.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 11:34:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id j12so5750486pfj.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 11:34:46 -0800 (PST)
X-Received: by 2002:a65:430b:: with SMTP id j11mr5646612pgq.130.1611084886235;
 Tue, 19 Jan 2021 11:34:46 -0800 (PST)
MIME-Version: 1.0
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-6-vincenzo.frascino@arm.com> <20210119144459.GE17369@gaia>
 <1bb4355f-4341-21a7-0a53-a4a27840adee@arm.com> <CAAeHK+y9sw0SENeDXLLBxD8XqD396rXbg1GeBRDEm7PnMzMmHQ@mail.gmail.com>
 <20210119190037.GB26948@gaia>
In-Reply-To: <20210119190037.GB26948@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 20:34:34 +0100
Message-ID: <CAAeHK+w3+StvU60KNPknQyEnGH_8BfwFdJbTifPb3gGQhXLDyw@mail.gmail.com>
Subject: Re: [PATCH v4 5/5] arm64: mte: Inline mte_assign_mem_tag_range()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=btK4sahz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 19, 2021 at 8:00 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Jan 19, 2021 at 07:12:40PM +0100, Andrey Konovalov wrote:
> > On Tue, Jan 19, 2021 at 4:45 PM Vincenzo Frascino
> > <vincenzo.frascino@arm.com> wrote:
> > > On 1/19/21 2:45 PM, Catalin Marinas wrote:
> > > > On Mon, Jan 18, 2021 at 06:30:33PM +0000, Vincenzo Frascino wrote:
> > > >> mte_assign_mem_tag_range() is called on production KASAN HW hot
> > > >> paths. It makes sense to inline it in an attempt to reduce the
> > > >> overhead.
> > > >>
> > > >> Inline mte_assign_mem_tag_range() based on the indications provided at
> > > >> [1].
> > > >>
> > > >> [1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/
> > > >>
> > > >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> > > >> Cc: Will Deacon <will@kernel.org>
> > > >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > > >> ---
> > > >>  arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
> > > >>  arch/arm64/lib/mte.S         | 15 ---------------
> > > >>  2 files changed, 25 insertions(+), 16 deletions(-)
> > > >>
> > > >> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > > >> index 237bb2f7309d..1a6fd53f82c3 100644
> > > >> --- a/arch/arm64/include/asm/mte.h
> > > >> +++ b/arch/arm64/include/asm/mte.h
> > > >> @@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
> > > >>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
> > > >>                       unsigned long addr, unsigned long data);
> > > >>
> > > >> -void mte_assign_mem_tag_range(void *addr, size_t size);
> > > >> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> > > >> +{
> > > >> +    u64 _addr = (u64)addr;
> > > >> +    u64 _end = _addr + size;
> > > >> +
> > > >> +    /*
> > > >> +     * This function must be invoked from an MTE enabled context.
> > > >> +     *
> > > >> +     * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> > > >> +     * size must be non-zero and MTE_GRANULE_SIZE aligned.
> > > >> +     */
> > > >> +    do {
> > > >> +            /*
> > > >> +             * 'asm volatile' is required to prevent the compiler to move
> > > >> +             * the statement outside of the loop.
> > > >> +             */
> > > >> +            asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> > > >> +                         :
> > > >> +                         : "r" (_addr)
> > > >> +                         : "memory");
> > > >> +
> > > >> +            _addr += MTE_GRANULE_SIZE;
> > > >> +    } while (_addr != _end);
> > > >> +}
> > > >
> > > > While I'm ok with moving this function to C, I don't think it solves the
> > > > inlining in the kasan code. The only interface we have to kasan is via
> > > > mte_{set,get}_mem_tag_range(), so the above function doesn't need to
> > > > live in a header.
> > > >
> > > > If you do want inlining all the way to the kasan code, we should
> > > > probably move the mte_{set,get}_mem_tag_range() functions to the header
> > > > as well (and ideally backed by some numbers to show that it matters).
> > > >
> > > > Moving it to mte.c also gives us more control on how it's called (we
> > > > have the WARN_ONs in place in the callers).
> > > >
> > >
> > > Based on the thread [1] this patch contains only an intermediate step to allow
> > > KASAN to call directly mte_assign_mem_tag_range() in future. At that point I
> > > think that mte_set_mem_tag_range() can be removed.
> > >
> > > If you agree, I would live the things like this to give to Andrey a chance to
> > > execute on the original plan with a separate series.
> >
> > I think we should drop this patch from this series as it's unrelated.
> >
> > I will pick it up into my future optimization series. Then it will be
> > easier to discuss it in the context. The important part that I needed
> > is an inlinable C implementation of mte_assign_mem_tag_range(), which
> > I now have with this patch.
>
> That's fine by me but we may want to add some forced-alignment on the
> addr and size as the loop here depends on them being aligned, otherwise
> it gets stuck. The mte_set_mem_tag_range() at least had a WARN_ON in
> place. Here we could do:
>
>         addr &= MTE_GRANULE_MASK;
>         size = ALIGN(size, MTE_GRANULE_SIZE);
>
> (or maybe trim "size" with MTE_GRANULE_MASK)
>
> That's unless the call places are well known and guarantee this
> alignment (only had a very brief look).

No problem. I'll either add the ALIGN or change the call site to
ensure alignment.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw3%2BStvU60KNPknQyEnGH_8BfwFdJbTifPb3gGQhXLDyw%40mail.gmail.com.
