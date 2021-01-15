Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQMUQ6AAMGQENL3TFVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C072D2F8163
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:00:50 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 67sf4123006otg.15
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:00:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610730049; cv=pass;
        d=google.com; s=arc-20160816;
        b=NUDBRg7QcHJxE8Z7mQ7KjC9akyGFaUD/EpmW10XNKQSRzO39Zq1mHuRaWGQ0Hyqqrb
         DoVwYU0B8gV8AwlObpyxhosZFIpfeLPLPsbHh+nIHjrWf+waHXSi65mcfcABWBRGdWGf
         1MjAES5qHCUpjztQ2ucOypZeyGNEg9jWnhgSorGvKf2PpanT188fp0B5HWBaPWoGQAOq
         J4FAWS1jGeBn/byYO/1prSCpro51YdScL34/S189xiF0Scw6XCFKF7amDW/0PYoVWFu5
         OwaW4aPeXDcQODVoDAWjlDtgPJCBGZQ1jh1d6nquqmaY2ttBHnukCnxaTD8zl+JPNPZ+
         MVSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=W1d8gFxIoUeoSSalK9koi4OvXFHfgRnrvNS7mXfmTBo=;
        b=bDDHofuQMbYktxX7mHGdP7kM4PQ1gd+ZfdDQRHpKhz/6xXcWq2j2DvUZBnPeqwnFvH
         6KOpYJ8nDOIsqCpBo0XSPndbEvVbXb6EK3wDUn44YyhpW5opWgXV3+3LGOrdKjLIc5FG
         sQxEAlFJZkETj5Fyhh3uYcIdGNOR8+UCRtm6obfo8qA2i5cWiuqPFDCmj3S3+gEyJxel
         rsBEpnq8PuMOhYTTJgf0+Fvw+VyYdnGcJN5XfhzyWAit/kr2+RMGxSiUciK3QvVjyR5y
         43GP25P1fTd/cEiRqrg5kRnWCcNs+sHbVhvvgB7eUEMSFGKFZLyM2bRUqp6Zp0vVDY0e
         r6fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uyCixVTz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W1d8gFxIoUeoSSalK9koi4OvXFHfgRnrvNS7mXfmTBo=;
        b=c2hyU6TRcxwueVfGUyKFoGTDZhDEMwZwdUIbqcOVr3gr/NJI1NgERM76ScWiX0FdYj
         FYZrhk/hvFnnNN0e98JEU752gyD9tcvlSebQZ9OD/jXErOowuxkZYCIZW8LCXiF+tY1P
         4q6qv2REDUUvujGbVq5TsR5AN0u/75AoQ6i4AsbfdjDMlb+dlcq3W7rNk9p+YTi2iAMz
         W65rE+SBzhSilyvNBZJbWic+JmAJuA8MnuwlCFXzUXcD7eCE3k6GbqmaQzNWnaTpqAnZ
         SL3BjRPEPJl/u5pPBhil5r//TRJu3viSYcrISb8YTLqg7Bj+hzW96G7U8+7Pe8u+Yp0i
         +6Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W1d8gFxIoUeoSSalK9koi4OvXFHfgRnrvNS7mXfmTBo=;
        b=sgCfKG+bUGhutk7da35nDCdqST4ST3YSPRzKexVW6NrqAg1QAgtgBFw9+UWp4wg7BV
         V1RPdj0uKoj1nwp8/azQjT7zM4x76T1EWMPwXOMobTqli+/rY/h8Xerhqtsxb52T1ZLh
         858HqAQzcic6gky+Duwni9GBi7ynpSbdbwYdZ5Ohot1Cm527ahbX9BS6L6dlucruXZfr
         fDojS/4IjGahFd+6AD+tAFC6SAyG5gszbrlce24L080OMW2mZ4cMozkAER/c/XK3bhci
         V1png+QQn+3HJfyv4L9DVQ4ivzcDV0HvshTI0TN5lP7BJTl+XYOWZUpXCaGvm/PfuFDR
         VwHw==
X-Gm-Message-State: AOAM532mpNnO7FEuRvfT4kP8g7zdmzcXXieqxH5s/kood592xwuYkdM2
	MJ0gR2EM3VtxwFOf35q1mLE=
X-Google-Smtp-Source: ABdhPJxTspz/yXDu+//qvAo40RY2ltJWawWY+/1F5qADYhhxGWrTKyquunPAgGaxmvRLj/Gs/9PriQ==
X-Received: by 2002:a05:6830:20d7:: with SMTP id z23mr9058706otq.116.1610730049485;
        Fri, 15 Jan 2021 09:00:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:758a:: with SMTP id q132ls2322553oic.4.gmail; Fri, 15
 Jan 2021 09:00:49 -0800 (PST)
X-Received: by 2002:aca:7545:: with SMTP id q66mr1051033oic.143.1610730049026;
        Fri, 15 Jan 2021 09:00:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610730049; cv=none;
        d=google.com; s=arc-20160816;
        b=bmgeGwSdd6OK9yIZlAbODOEROwbeEyLhHnsFt+0jjkPkNl8VjjWieU7V3DP9h2KRtG
         Unm6/na+QwRcQy7btgVJULvXteoT1S0OChrjJ3wTt5cxQX0q8g+kL6gnoEesgYwjkIEY
         ZBL2TwdIFdl+ni52V8Dxsfxa6kFS7b1BhCzv0N62q6XSO93KOiVlwkeRMWCVCyB8nniC
         Yb32NKtg2xWIxmPK1ipLjygTMtzTPhBNBZ2daYox2mKUmAQiBKpYq0v/A4KTCTyKsKqd
         tGvWI4qpgEmVN5HrQE7EsY8tgDlIV1W5igA8bA+zx62oyuB4BtyUcTtO2ElaeqBI8Fsh
         OM6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PpClgSgoL5qlpfbaIDgx+JiK7CY1YGls1Kpu5D2pXJM=;
        b=YE6UvG+TFQzvdoV9mFDq+m867PUY3VQLVjbtZ952s64Tfru3krB+LtqeX02lJihUqO
         amq79ctQIY5IFm8vRmIyln9XlubcvYy9q93xGtyltedESepzeqtBQkYRAplV4qKF9W1E
         nXy4KP7vhTD6FJI4DCwtq4ZN3GIkzMzRfRfPMPACne4CjPQw2L1Eq/icht8XGgTxrar+
         glawUj3yG8ZdXU46DLLWyDVpo5IhTZS77cNWN/VpP1foHjWKpJDdkMlsheCqEmyIexSt
         cnUwPFUEduwoUXjxhMGGR2VNFEeB2fhTnMljvkYgxxTRIi+zP7G1BUSkYoLOEUO+36uS
         gyUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uyCixVTz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id f20si667142oig.2.2021.01.15.09.00.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:00:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id c79so5875718pfc.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:00:48 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr13254266pfh.24.1610730047501; Fri, 15
 Jan 2021 09:00:47 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com> <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia> <CAAeHK+y8VyBnAmx_c6N6-40RqKSUKpn-vzfeOEhzAnij93hnqw@mail.gmail.com>
 <20210115165558.GF16707@gaia>
In-Reply-To: <20210115165558.GF16707@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 18:00:36 +0100
Message-ID: <CAAeHK+wNOcA4Zgi5R8+ODMuDkLuMSYHoLinPhoeGstd78TsPjQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uyCixVTz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435
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

On Fri, Jan 15, 2021 at 5:56 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Fri, Jan 15, 2021 at 05:30:40PM +0100, Andrey Konovalov wrote:
> > On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> > > > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > > > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > > > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> > > >
> > > > Fix up the pointer tag before calling kasan_report.
> > > >
> > > > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> > > > Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> > > > Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > ---
> > > >  arch/arm64/mm/fault.c | 2 ++
> > > >  1 file changed, 2 insertions(+)
> > > >
> > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > index 3c40da479899..a218f6f2fdc8 100644
> > > > --- a/arch/arm64/mm/fault.c
> > > > +++ b/arch/arm64/mm/fault.c
> > > > @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> > > >  {
> > > >       bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > > >
> > > > +     /* The format of KASAN tags is 0xF<x>. */
> > > > +     addr |= (0xF0UL << MTE_TAG_SHIFT);
> > >
> > > Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
> > > was added, the only tag faults were generated for user addresses.
> > >
> > > Anyway, I'd rather fix it in there based on bit 55, something like (only
> > > compile-tested):
> > >
> > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > index 3c40da479899..2b71079d2d32 100644
> > > --- a/arch/arm64/mm/fault.c
> > > +++ b/arch/arm64/mm/fault.c
> > > @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
> > >                               struct pt_regs *regs)
> > >  {
> > >         /*
> > > -        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> > > -        * check faults. Mask them out now so that userspace doesn't see them.
> > > +        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> > > +        * for tag check faults. Set them to the corresponding bits in the
> > > +        * untagged address.
> > >          */
> > > -       far &= (1UL << 60) - 1;
> > > +       far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
> > >         do_bad_area(far, esr, regs);
> > >         return 0;
> > >  }
> >
> > BTW, we can do "untagged_addr(far) | (far & MTE_TAG_MASK)" here, as
> > untagged_addr() doesn't change kernel pointers.
>
> untagged_addr() does change tagged kernel pointers, it sign-extends from
> bit 55. So the top byte becomes 0xff and you can no longer or the tag
> bits in.

That's __untagged_addr(), untagged_addr() keeps the bits for kernel
pointers as of  597399d0cb91.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwNOcA4Zgi5R8%2BODMuDkLuMSYHoLinPhoeGstd78TsPjQ%40mail.gmail.com.
