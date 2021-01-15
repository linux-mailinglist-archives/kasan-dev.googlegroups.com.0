Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJUSQ6AAMGQEVBWIPRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id AAF552F8149
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 17:56:07 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id n8sf6331066pfa.8
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 08:56:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610729766; cv=pass;
        d=google.com; s=arc-20160816;
        b=ORMbeuar979o6B4dUCM/hzIges3M6jZZh5sB8HZZTUhBA0/VKDp3aq6Hy3b97YK7/+
         0S5fcrMgC8o8ruHaQUA6m+vFUlkXxwYKLb5+wolczO2xdUhr9TjWLAuekWjqeZdlpCrD
         lh3g2x8qflZTYasfEE/O+/+zG0seW1Nw3Db4bXY1jqlEOONvxvOPwohHsOcnPozJrD+2
         MxOEhpnLuI+ABVNjkAYEWA2cXLRZE6WC2GlQ44i0HdZ7ngJVlAdOrnN7/I6Rp047ihJh
         xFxRd1BscLx3l/Dgq04Nj39IY09/Ii7M/rcz4cZk8UUCvXjBWRkwAdWW41K9+98ElhwM
         y/tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Z+6WbNb6rkKO3ZIBFonGW3nstn6HVvkDUHk8N+3tTeY=;
        b=Zq45AdJZjl39IqK/U6ok560mLAvU/8/wWamGVuHhA1MlhSgQJomSEYDtjx5LsIqWs3
         6ZWE9y7XzXHK8is46HqczZc1ZewYodBWVBBplWTO5PcNzxjE01wtu1sKjLRbRhP+BaDB
         OI/MTlsJxBXjnoOhTHRfH2G5Vm2KxQ4Ffcxal0tt98CYhVmznFij/i6D8FcgRwhPTt1b
         QeISVzYvct3MGu5K7xNq14tOD9CMGGhvalt4SckUt19tIIAgNHQZy76sAr6H7EqmmPA+
         mf5Pbbbz9ZAo3Pmfxg/dfcuGDNAn68YiAczRm3cpsWIMJuO8fWI04FXJsh7uMijdzXJV
         CXVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z+6WbNb6rkKO3ZIBFonGW3nstn6HVvkDUHk8N+3tTeY=;
        b=jiOVTqUiftLgxvBY75yy9r/Zfq/C242K6qUtwRkDcrckJ5fmFL2kZ8cC29QbJ+tncB
         goVMOe3vTOSInFPG+fG+JVoLlKAbhywZdvE/ArPRxAtpd51KgQ0EgO1BBEw3Rg5wtIkz
         IaAMIZ9mJgzMTCLPUcKQ+Fnw827eJykFqOcOFkhs3qZahEZJJ5BKQ6YoXVnFNTVMrp2k
         dLh5RAs5jyUpGKArLxgTMfKQI56kJDq9LCWvrwXpCV8oRecvR/xfpRfK5suhWy5iBuy7
         ECBgqYcmdItlZ6reC5WaoTFhDa45D7/wGLB+6srDkAUHPlcDIeSkmVyCVJUIzUmTNN+3
         iCcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z+6WbNb6rkKO3ZIBFonGW3nstn6HVvkDUHk8N+3tTeY=;
        b=pHHt+8eVfROgia6DELv4MLbGiZKckhfSu6LGZ43u4Rihog62QOPU2YXnAPewbn5PRO
         wJKsciq+PdldqWax0czxx+7wcUBGDoA3j7IuAOmWm4uHHGeyg1GMljh24cB+mgM9nu/c
         hzsc23d1emzUdTclpKuJVqhwDOlAFU9C/FYQFKiVWW9k6cX0UCJJSWieUvxqgdxQUAul
         ZeyeIn4IIahorXv2zkyHx3m134mU4kPonsb0lhsHtYmhABjMIpDNVdQz6KDjoiebuH9Q
         D8QMqP45P8zAMg4OTEEl9SJGG6cCD0b901CmXD5JU6jCkdV3ng0gVQkYi/cVGfhjMWrg
         FZjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HI2kTMD2i4SHXh6i7qIpuETtcvnQUWDec51V50ErlGkCyqRZ5
	zFEWu87FwzKrCMvhKCOYLJ0=
X-Google-Smtp-Source: ABdhPJwOyRiJdQUnB84F/3l4HswBQrzO4x5hoP7/vvLetGtgWrmqn79ktF/b6p5tOBMac6znh/qPyw==
X-Received: by 2002:a17:90a:7087:: with SMTP id g7mr11565300pjk.200.1610729766407;
        Fri, 15 Jan 2021 08:56:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7583:: with SMTP id j3ls4641728pll.0.gmail; Fri, 15
 Jan 2021 08:56:04 -0800 (PST)
X-Received: by 2002:a17:90a:4893:: with SMTP id b19mr11771150pjh.193.1610729764269;
        Fri, 15 Jan 2021 08:56:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610729764; cv=none;
        d=google.com; s=arc-20160816;
        b=qgdyYIIPZm6sIncJE61EN6X2U3141qtJAbePQrvz+3x5LIf84VZ/0Eug9PYoqPWrlg
         UuHf6scUZa//Z9oW2Gr5kfC5ZlBJZ0ZkRVBygWi8niSe7ZxUf6WUwO9oOW0vpOAZHVeA
         10kynfbk1KfX2+Z6lwNLgu5ikrLz13VZZixqfeUM9Gocll4FCZu5PQnBblv4HEW3fYPC
         7z5Ar0YKp625facRQkBDlif/7xwuGqCAokiu7T0LaqysvjqJNcLINQWjYUAvmFhV1PcA
         DBRcUGqLLktZde1Hhv6FZYfi0aNpKA7B+ZAu8cxT15NWdGvV0y5vKoU45RWMgiljmlcH
         R6vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=QobSKT0lC4t0ztOFFZ7yAzclYVOnZ3fxpnQWdGDGU7Y=;
        b=eJPruskWeUUIgM7+Q/Pl4m9UoP0jRLS9kLd9gP3b/zEqT2cUXOqZRnStwNiaCyC2y+
         LOheGll0EULbncUXFT+5XZhHIz8SX7blfOjhBOLfhdpB5UpDAfkcFuFjbk2xOiaWc2yF
         Mz3xUT6DOj8uvo3/EtcbO36DFtoNqtRhthMb6Zw8MhcdQLehsNKILV50EsGF3XFnu8f5
         GMeYKeOrbfkN/2OxlG5Bi9H5IAx3wzqchs96nJy+VWKAySkOY3mgEMQBvJTussKVfBlB
         /33M2PzeAp8tJoyp/SgIvO5a9WLKPeqvBRxE4Z9962TaiFLefUckpkBVg1VjNxm0z1ky
         Vqng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b18si613485pls.1.2021.01.15.08.56.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 08:56:04 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7DA3F20738;
	Fri, 15 Jan 2021 16:56:01 +0000 (UTC)
Date: Fri, 15 Jan 2021 16:55:59 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
Message-ID: <20210115165558.GF16707@gaia>
References: <cover.1610553773.git.andreyknvl@google.com>
 <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia>
 <CAAeHK+y8VyBnAmx_c6N6-40RqKSUKpn-vzfeOEhzAnij93hnqw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+y8VyBnAmx_c6N6-40RqKSUKpn-vzfeOEhzAnij93hnqw@mail.gmail.com>
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

On Fri, Jan 15, 2021 at 05:30:40PM +0100, Andrey Konovalov wrote:
> On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> > > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> > >
> > > Fix up the pointer tag before calling kasan_report.
> > >
> > > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> > > Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> > > Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > ---
> > >  arch/arm64/mm/fault.c | 2 ++
> > >  1 file changed, 2 insertions(+)
> > >
> > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > index 3c40da479899..a218f6f2fdc8 100644
> > > --- a/arch/arm64/mm/fault.c
> > > +++ b/arch/arm64/mm/fault.c
> > > @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> > >  {
> > >       bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > >
> > > +     /* The format of KASAN tags is 0xF<x>. */
> > > +     addr |= (0xF0UL << MTE_TAG_SHIFT);
> >
> > Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
> > was added, the only tag faults were generated for user addresses.
> >
> > Anyway, I'd rather fix it in there based on bit 55, something like (only
> > compile-tested):
> >
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index 3c40da479899..2b71079d2d32 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
> >                               struct pt_regs *regs)
> >  {
> >         /*
> > -        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> > -        * check faults. Mask them out now so that userspace doesn't see them.
> > +        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> > +        * for tag check faults. Set them to the corresponding bits in the
> > +        * untagged address.
> >          */
> > -       far &= (1UL << 60) - 1;
> > +       far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
> >         do_bad_area(far, esr, regs);
> >         return 0;
> >  }
> 
> BTW, we can do "untagged_addr(far) | (far & MTE_TAG_MASK)" here, as
> untagged_addr() doesn't change kernel pointers.

untagged_addr() does change tagged kernel pointers, it sign-extends from
bit 55. So the top byte becomes 0xff and you can no longer or the tag
bits in.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115165558.GF16707%40gaia.
