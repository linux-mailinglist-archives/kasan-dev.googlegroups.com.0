Return-Path: <kasan-dev+bncBDDL3KWR4EBRBG67Q2AAMGQETNIOVHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id F01592F7EE7
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 16:07:08 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id v7sf15200833ioj.16
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 07:07:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610723228; cv=pass;
        d=google.com; s=arc-20160816;
        b=x2snkieWdqn/DlvLihb9I4kVsFAQua+zEFToY8BfXuaOfo3zCSVHo+Qog5iN2G6s5A
         Mb/gCM2ecfLaN33dNYUrJt7ElbjvRsEw6UOnnVg/1HCIqtvX3krrkDhhmnWKDDXlN/4M
         LwEklrTB86mUjwIlf4y14tcTgyN84PIIo9yorlWhN9ggh03jqWF4O5uHKJidOjf0dUpp
         m0x4+OUFxQgB8Myt3nGeIjKxxPvtFFFcy/N7XIlfRmQ3jhmCHZY5TKhGUGZoZFX8OgOf
         xrXHw9Hbhv3eZ0q+BqtqRIRTxXTK5m/R8Y6ns2uknGdxrLa5u3x+IFt5U18Jxm35OhtK
         mbdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=HXL+EIG+jFh7NVFEgoxXqZ0MayfdRjbgl+Rp4LO98ns=;
        b=FnejOmxrA7dYnRd70MkQB8NHVbLXwHCxJMBYr63bEgqHZuQdgCRfHJhQgUWriPRua+
         eQPCaSGjXpyRdNUnlzYz/OL/JkrHgWXCsYjXd3wVV6yCtd1DA4fnthaQwj31/Hi8cd+p
         vMZgr5YAcBn69xO1l9zafoeQrCvFV/CMn2Izz+mgY0n6HJcJzZb9bM4MehYntIZGxJtR
         GzJeAPXu3qX72Er8GFxc01/CYZyy93H5I4LOzgPwoyw78GDq/RJaEo/vaQQtyfryAAxA
         vBMwjf9C8Vqdg4X6XXrebD5EZI3QoTPTYO/apBo0Y9QmGCiea87o6sj9TGC18zbF83Eg
         FyaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HXL+EIG+jFh7NVFEgoxXqZ0MayfdRjbgl+Rp4LO98ns=;
        b=HGPazxB7pkmRsaEMFHBtUBfos/6Y8taWNQRfn1lFss6Xkj1ZWSyu4PGeZkeK8yon+c
         Fxp1Us771XRMVD1Qrdvs63F51YllPm7/nvAoHUUo8DGvxl+qPUm1eUedXMRRIxAp4BFw
         ASDqffvp8I3o2J/BVMo4cT0cFK7tOtSYibNJ1MKZe+XJMFS7J/M3jRoaOGJElI2lb1ey
         Yzop+cyIrP/6tJq8/UJQ6bcgrON7NWve1NkxCqfhK2l+0+Fm7Dxk+aFqOufV+6XXj74+
         oB4lnX8ep6I3qdM4KrWEPviYpRmhjkrEf1sARpK1OnXvd7eeErRyYdqHRKu8QQnQL5GL
         3WlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HXL+EIG+jFh7NVFEgoxXqZ0MayfdRjbgl+Rp4LO98ns=;
        b=Wc9YNyi/YMHR3fCgYyXYGee3PhW77RARlpWA5PYNMuaVI9Dm5Ga/tYOYSrQ7wmWKGI
         bz1ibZrNhxu2aygymHTqw+xq/1MF1zkXD0QdbocHNsakj/MnywJKGOSuy2nd1Kk3CEiK
         uJ1o+dEfPGTbq3HTvGAQ2Zy8pLMWQKIe7oQgO2c/VOyC98AWDqeEIR/Ltj0ojgBOUEV8
         humcFzORiG2AhLp1KMdeQXrWGLnFL8xTipUExbuHyi1D8ujODq+RKSUZfgV/IhrdObob
         Hdg+BlAqygXQp1/XIU+auWuRscUQS6pK79ohWOKhBzjXpAkAzI4S8F7lBezk10UK3yLe
         pjbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533B7c0aZtVFrlr3r3mh0pmvWP7k3dHnX6ak3C2Hc3sQYdJXICTe
	3pdE4bXo4rR206Gvi8Jh7Bw=
X-Google-Smtp-Source: ABdhPJz3Eod7KmXqKHzi7rfssldrrbAYY7ga8hjAHQD5b3zpSSI4mVyr0gudM0FoKIEf5IF23WiXBw==
X-Received: by 2002:a92:850a:: with SMTP id f10mr11402619ilh.279.1610723227968;
        Fri, 15 Jan 2021 07:07:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6cc6:: with SMTP id w189ls1153165jab.4.gmail; Fri, 15
 Jan 2021 07:07:07 -0800 (PST)
X-Received: by 2002:a05:6638:204b:: with SMTP id t11mr4655297jaj.87.1610723227436;
        Fri, 15 Jan 2021 07:07:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610723227; cv=none;
        d=google.com; s=arc-20160816;
        b=B2CMonnAvpCt0mCBEMgQ9MpeQS5aB/b4T0ueEQ/6kuEa4Y6ftL/CGGQ1n9kWWNCqZO
         sG+d2cBfgVlmwghswObI37G8o7fbiytIgT2X2JLW2N+P6uUfrlxmhZiaY6YDL8bhWoUt
         UYx6n5ywtvpUDzEXz71zK60d//s+WgQf8nZBvs6ljsg4C8EEsXNgCovAsPegHPXK3uQC
         UIefch920ai3b+IdGYAI3M11fEXTC6LRWfQd/AVhw18awblbnKvY/JPaXajbN/sZfxOF
         eGAaQISBr16+nWFRLv6mOzTKJxzGotnkyCiSuOT7w/LOMAMWwSew05bSac6vSQYGUtH+
         kw2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=pCs5h1mfEcS0Pn7smI9gzcSDG8qYef+VMQ4ZFddq10Q=;
        b=kLaQQR8tQ5OBzDmVr+ahwYhsIbSllDL4ga8bI3Z+T4OUs2a6wxnYLLo7Rl03ZuJiP8
         bzBJ9DRjd8BTyFbIRVzlvZE4qk6LSb6r3ysi5Wq2s8Va0HvxW4NZ/GD62q12Cvv6kXq7
         E/gD021DSaQ2/h606GffsBrs/7dcBIOAmtBCGs/w13Adb/lNWzqYpHWsJUmu5FBRYFX/
         xgfT1BvQMn2YOa/mgphRBwsOCA2BAb6Y3mJczat7HsRUaxpg4uXBGjRs8CU9GKrSK0ET
         EMA7Ji15gFynpm/SLZGWU0fdL7RvuAV0mDZxzkG3gMxV5crK4qEWXf/J3tjRwZSdZiCD
         2PBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y16si1017214iln.0.2021.01.15.07.07.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 07:07:07 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3D6572388B;
	Fri, 15 Jan 2021 15:07:04 +0000 (UTC)
Date: Fri, 15 Jan 2021 15:06:59 +0000
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
Message-ID: <20210115150658.GE16707@gaia>
References: <cover.1610553773.git.andreyknvl@google.com>
 <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia>
 <CAAeHK+zThyq7ApsRTu-En7pL9yAAOrEpV45KOuJV3PCpdjVuiw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zThyq7ApsRTu-En7pL9yAAOrEpV45KOuJV3PCpdjVuiw@mail.gmail.com>
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

On Fri, Jan 15, 2021 at 02:12:24PM +0100, Andrey Konovalov wrote:
> On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> >
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
> Sounds good, will do in v3, thanks!

I wonder if this one gives the same result (so please check):

	far = u64_replace_bits(untagged_addr(far), far, MTE_TAG_MASK);

(defined in linux/bitfield.h)

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115150658.GE16707%40gaia.
