Return-Path: <kasan-dev+bncBDDL3KWR4EBRBW6YTSAAMGQE3NXHIJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 36CA72FBFA0
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 20:00:45 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id t15sf390090ioi.14
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:00:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611082844; cv=pass;
        d=google.com; s=arc-20160816;
        b=IT4T76/Gr12Vtm44xRqVL7wby8L7qL9AIJvKW9DAXrPaZhUTSmfYqSY3r2DvzlUVgI
         Jb3LhM0um1ozhVlbIy+VduUqa/BiR/g7rbsMGCkx60yqDLa/DU/F1Mg5jOqyi9jF6whb
         hPgxdHzEmM0XztY4cby+GTwC8FBUedMfVcTg6d2Y6PxxxEdMT7Hs3QuVk/+Jv/cU6a+o
         Ez64Fugut5fIF0l64HuJh4758LWaYj3l8+P6bf2hawS0xds1GsCkGjxiEHoGle+r24Oz
         FHkn6ylNLBZMCqoTnUIBBARsqZjLwDNx20ZP02U7BRfIBuCzvWv6jM62DVUpPNO+no9/
         NhJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=KGvpraH0iyO5nO+eMb8C1sYE4VUhwT5VkcUlNQBAMDo=;
        b=vfzdo0iTTKE1Cw8vIHydZS2PEA2kS0khzEIB2oct9jKrPm97qpAStEqcrtRnOzf28D
         S7b6fa/ymtVaktk3UTR8QgG8bzR/CGIUxOzXgnHtPBwFJMW0yTtKgu7PYxWbrROjUvlu
         kPgQRTb48Wwbnc7DlJeswADGcaUSWZoLh0Ikmi2M/DVlQ0WLH8ciNI6MS3qKhMNk3BNW
         nHH5P0XaD4cjji9LdYuRYvhVWCGZW1EEx8dzXdzH8H/XmwXVgLssmwsTBKFr3Xv5hqRA
         0UUMbdVFKA4UazoOK/0ica2nXa9hvBnhMHIe1cyfd2d8Q6QJgksRCBs4dpl+s6dGyxSd
         RRZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KGvpraH0iyO5nO+eMb8C1sYE4VUhwT5VkcUlNQBAMDo=;
        b=nSRyo2qLdooQWWyQwnOL3e+sPQYZuV+8eY6hQnVtYGyXWY+zogUDvPYSbpM6jTiJBH
         DOSTWGm1L21kaEeJ0L+qq8VKOvCSVOb9ncrCnmjAvwP/QsYMronx5SiIhKNHE4C6wwqf
         QJ4dcw0zvhzgxUCS423z0+xdgIt6AnRy8wj+Dh5P/Y1VzeW35bkBgX9fTJzdO5PuY+n/
         rBVee47kE9mVTd2u0VcAHEUcV+eu8YYYi2ChkVtFPhtCirBJMer07HDpj9t2Jgdzryzs
         pdwhuFyml/t5ywK4afKxdFq1sEefaEWe3Jf90nRSpGBAEpQ7qTGLqoty4vzEFXr65Qkw
         XoiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KGvpraH0iyO5nO+eMb8C1sYE4VUhwT5VkcUlNQBAMDo=;
        b=MNOV05cOnC2IVgbjNXipyhszsY+1IqNKytxz/3H99S1WwcoIuVO5pMbk525GeNaTcY
         qWyOOSn2hnerCMwA0XCrnm1FVWoP2U0s2rqy0NaTHxBHzwA1D3kgDxOUrUje6m0SIXnj
         pVsC01uHbjP3ezcyKxk39OmQYwAB/Q/rFxUz2bt58tDttwe9m1h5ydsbI5b82WDX+nzE
         /aN4hzupIVQxmyB1OScTSDkUg3VRv2Ly/FcXxGvfjIIvBVJZhdTKXhFuJnEVhp2hxe/L
         yVVXOoRJ3j6PduIJe9tByiTYjXpmLvDV5Um8OmjMZhuG3GHFUGQrgbgXhb48gXYUV68a
         6Fvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MCLDtTZr3nVUbwf68Ay3sJBezQ4oxLoNDsnJRk9GZ+VSGsANI
	C5QO2mOJcbFC/IHpah+iKlU=
X-Google-Smtp-Source: ABdhPJwqnX3w45JOeFwwdfIIVcTtPsOmSyewz8rB6zG8Q+Lt+Nt1pBZtxcIO+W8ZUiXfKJvjuVu9eA==
X-Received: by 2002:a92:444e:: with SMTP id a14mr4769112ilm.129.1611082844269;
        Tue, 19 Jan 2021 11:00:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8356:: with SMTP id q22ls3151219ior.3.gmail; Tue, 19 Jan
 2021 11:00:43 -0800 (PST)
X-Received: by 2002:a6b:2c42:: with SMTP id s63mr4071216ios.48.1611082843517;
        Tue, 19 Jan 2021 11:00:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611082843; cv=none;
        d=google.com; s=arc-20160816;
        b=g2seVcQsLjBv+Pb0q8FuzEc2nko0EoWWnQRl7rwpZS3VR+27HV9z1HQ/Zy6DoT79Vg
         zxqi1/lyTD5QqekHZnuvJx4xeeS2B09XIGMfvFTfovAHAVB5G8WDrDRWT0+qBtuJ3jdi
         Rn/JTXbDoeNUveo2mMqaXstL48Rf20tIGV2smT1RiHvLhczKA58fOe29BqFyYEE2bove
         yGsDNHJyb9bbGVRznG6fAq15hU67Mbrt9uxp0i/qbOCymV8dhw3ZWYt6aLsGnXIUZ18y
         T84fg09SY5a33sgA16y61QvLRw7s0oF5uHk3Z5hwgPwJFjXt0dqI3BRRhdQpnORtuko5
         NuOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=IbhoZ1WTsCulT0GCiFoEg7UVw+MheLwn3/ekBnC5ghA=;
        b=YAs6zuaoFuA97YHTvqKfBgO7YmgyeDJSkgVe9uJAple4AqtH3y5hf9ssoYvefLmdPM
         3Pa291qcq0v15Rc0WNy3f99i/mwx3/xh96UZxvtwXodf5cGZUXMdihE3Nd/JuoCHZBgy
         iLBCGKOyKJga8U2F5GtJDLZHZD2kO+4eOf/2SML5/QSBSGVnv3E+ys/Gwc5vQKOzVool
         VZ6WlDG9PHkAya+oePAYTnFcIzvSSEsyVn3ZN3Dy+IuLApBMyugYgRWfvzjT4kE8UbKO
         RZXcGmh8a5w2NmW9C1MoomlXcxHuo9IMalpG3Jdrj1yzs5vO3eHYdMn3w1BWnciSMGGI
         Tc0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j21si277755ilg.5.2021.01.19.11.00.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 11:00:43 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8BAF020776;
	Tue, 19 Jan 2021 19:00:40 +0000 (UTC)
Date: Tue, 19 Jan 2021 19:00:38 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>
Subject: Re: [PATCH v4 5/5] arm64: mte: Inline mte_assign_mem_tag_range()
Message-ID: <20210119190037.GB26948@gaia>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-6-vincenzo.frascino@arm.com>
 <20210119144459.GE17369@gaia>
 <1bb4355f-4341-21a7-0a53-a4a27840adee@arm.com>
 <CAAeHK+y9sw0SENeDXLLBxD8XqD396rXbg1GeBRDEm7PnMzMmHQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+y9sw0SENeDXLLBxD8XqD396rXbg1GeBRDEm7PnMzMmHQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jan 19, 2021 at 07:12:40PM +0100, Andrey Konovalov wrote:
> On Tue, Jan 19, 2021 at 4:45 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
> > On 1/19/21 2:45 PM, Catalin Marinas wrote:
> > > On Mon, Jan 18, 2021 at 06:30:33PM +0000, Vincenzo Frascino wrote:
> > >> mte_assign_mem_tag_range() is called on production KASAN HW hot
> > >> paths. It makes sense to inline it in an attempt to reduce the
> > >> overhead.
> > >>
> > >> Inline mte_assign_mem_tag_range() based on the indications provided at
> > >> [1].
> > >>
> > >> [1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/
> > >>
> > >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> > >> Cc: Will Deacon <will@kernel.org>
> > >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > >> ---
> > >>  arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
> > >>  arch/arm64/lib/mte.S         | 15 ---------------
> > >>  2 files changed, 25 insertions(+), 16 deletions(-)
> > >>
> > >> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > >> index 237bb2f7309d..1a6fd53f82c3 100644
> > >> --- a/arch/arm64/include/asm/mte.h
> > >> +++ b/arch/arm64/include/asm/mte.h
> > >> @@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
> > >>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
> > >>                       unsigned long addr, unsigned long data);
> > >>
> > >> -void mte_assign_mem_tag_range(void *addr, size_t size);
> > >> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> > >> +{
> > >> +    u64 _addr = (u64)addr;
> > >> +    u64 _end = _addr + size;
> > >> +
> > >> +    /*
> > >> +     * This function must be invoked from an MTE enabled context.
> > >> +     *
> > >> +     * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> > >> +     * size must be non-zero and MTE_GRANULE_SIZE aligned.
> > >> +     */
> > >> +    do {
> > >> +            /*
> > >> +             * 'asm volatile' is required to prevent the compiler to move
> > >> +             * the statement outside of the loop.
> > >> +             */
> > >> +            asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> > >> +                         :
> > >> +                         : "r" (_addr)
> > >> +                         : "memory");
> > >> +
> > >> +            _addr += MTE_GRANULE_SIZE;
> > >> +    } while (_addr != _end);
> > >> +}
> > >
> > > While I'm ok with moving this function to C, I don't think it solves the
> > > inlining in the kasan code. The only interface we have to kasan is via
> > > mte_{set,get}_mem_tag_range(), so the above function doesn't need to
> > > live in a header.
> > >
> > > If you do want inlining all the way to the kasan code, we should
> > > probably move the mte_{set,get}_mem_tag_range() functions to the header
> > > as well (and ideally backed by some numbers to show that it matters).
> > >
> > > Moving it to mte.c also gives us more control on how it's called (we
> > > have the WARN_ONs in place in the callers).
> > >
> >
> > Based on the thread [1] this patch contains only an intermediate step to allow
> > KASAN to call directly mte_assign_mem_tag_range() in future. At that point I
> > think that mte_set_mem_tag_range() can be removed.
> >
> > If you agree, I would live the things like this to give to Andrey a chance to
> > execute on the original plan with a separate series.
> 
> I think we should drop this patch from this series as it's unrelated.
> 
> I will pick it up into my future optimization series. Then it will be
> easier to discuss it in the context. The important part that I needed
> is an inlinable C implementation of mte_assign_mem_tag_range(), which
> I now have with this patch.

That's fine by me but we may want to add some forced-alignment on the
addr and size as the loop here depends on them being aligned, otherwise
it gets stuck. The mte_set_mem_tag_range() at least had a WARN_ON in
place. Here we could do:

	addr &= MTE_GRANULE_MASK;
	size = ALIGN(size, MTE_GRANULE_SIZE);

(or maybe trim "size" with MTE_GRANULE_MASK)

That's unless the call places are well known and guarantee this
alignment (only had a very brief look).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119190037.GB26948%40gaia.
