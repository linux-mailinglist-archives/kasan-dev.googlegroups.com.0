Return-Path: <kasan-dev+bncBDV37XP3XYDRB355R76QKGQEXTGGPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2147F2A7CBD
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 12:16:01 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id b139sf1275516pfb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 03:16:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604574960; cv=pass;
        d=google.com; s=arc-20160816;
        b=DZGdd99pCUbXlEZSixU9i9wVNVNxRwnF9N4jP1R1pzoskHf7rfJ8UP5XMzZveYhQ6E
         SmgRKmrIbf0F7AlYpGsE84ZuC04bJdX2kD8xiNopEp9T4qJwpCbr3ZB+2i/AWfSUSTKS
         uLQ2PzmB/YHExv98hxdJFqNhR73vTXoJoKAFz/ius2gM94tqykzEGbPIl3sPXcmd44vA
         iD8aYydb7+cKaDPDrrI4R7CRF9JMjFCCFrOO42OD6gn6K42rnFtuTflOaASpgU+orDKr
         pATSZiQgowTpBpf0GzsKwFLD2WHA/Pjnxgad4OSi6sARSDIePm43//jIRN03KnuiRDZZ
         cy3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FTxAWapjTlnsJd1UPY9GywoOsag0UcnV8u+peFbXP0I=;
        b=oCnBGg1UEU4Hk6UO5uTD5lg0aLx63c5CKT2LQe6UMG1a49Ilu/u7yP9vr0pLFnQtOx
         kQM4HBg/M9t7FbxPQnRqSeix09VSMqiCK/AmDCo00pEke86w1yyUw+FuEHOuDyDQfikT
         QuGl7269X587fONhw2S0B4N744eTt3Q5cJ1xd2LOQG9QA47MksAtXVJbLZlasVYV/Gng
         iPZN5KYQxRVLBuENzN9NVRm8MsZxsR3cKLb6QVcnd9t2D5EyHlBHy1fq+qZo9zzpVyQF
         tZQ+7QNfCqSCQtqEEVeVeI8h1VQHalpRhBvyt2AeaN01B9O99FCpQAvaGcN4jOc7CLoL
         lLlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FTxAWapjTlnsJd1UPY9GywoOsag0UcnV8u+peFbXP0I=;
        b=FJP6Q4DuXajqfTIcy+xUSOgXbHQg057h73MFXZGZZo7CUKCDnfn2bBFIEPafD2Hfqk
         q95ZhNVFzVvSmtUBHei6JuneI2J5yc5/yPgpDanqW0BNTPylgfipN8qHtL0PAwR5PLLB
         Fb0b7hZDnU0HI+A7BJXGxFoMnqxUVjlKjG3UlpJwo+3zUz+mcQfNt45E3O9NHO+/lg9N
         osrPnOBDCL6E1dWAbnkXHUPhAA1U734cE5u1FarzkaMOq8lfX7iN2QthIkEEwMpR/DWP
         vmAYKc1+Z30a6ONANyDgAU9piRSxqb6Yiu86ry+3+NLNgWB5y/1UyrLcxMKiiH+PcpX3
         K7xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FTxAWapjTlnsJd1UPY9GywoOsag0UcnV8u+peFbXP0I=;
        b=DfQW4bH9GAmZ+OGQTXTdo8ZFmtu3GWNRpKPNLgXh9mDeUIw+ioq9A95+Z2nn28Pyop
         XQuGG+K2weWWh1ALseXQXTTti1nCfdH3MjgOaUjWbfoCeloue0qpPsT1ua4PuLcbntJG
         Koa2sp6xb4mP2P8q4DREay1s1AU3kTdoEcpS1RmZw35sbOkbnHSQodYCftgSXxhF2sM9
         2aiPuCp6utBjd8FEhZ/02/5xyzfjXXBQwrA2QQvGTaL3AohD/PsvIcTKm2MLotEElQpU
         KgLcfBWD4MlDZskXJnma17QnOClSG/HVOAV6lpwgyatVI+K65Sgz4h8Pu8jSoHnHCaj3
         KDgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532C63g+Tgk1oDeqxJenyDNYdd+0l+ceUw/58zkiwbnShFV5DkhG
	dcoSiv8hf0GeZF59Y/ti1G0=
X-Google-Smtp-Source: ABdhPJz6b/kE8MHgd2uiTrFak95NOjnM3VwXv8hILyW/UGUv9M0oBa2St3P4lcGzVpABMUT3Ccsvzw==
X-Received: by 2002:a05:6a00:c8:b029:18b:b0e:e51 with SMTP id e8-20020a056a0000c8b029018b0b0e0e51mr1870909pfj.37.1604574959841;
        Thu, 05 Nov 2020 03:15:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7809:: with SMTP id p9ls624826pll.7.gmail; Thu, 05
 Nov 2020 03:15:59 -0800 (PST)
X-Received: by 2002:a17:90a:f314:: with SMTP id ca20mr2032391pjb.191.1604574959279;
        Thu, 05 Nov 2020 03:15:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604574959; cv=none;
        d=google.com; s=arc-20160816;
        b=AVHUVrlK4Ex8LYhfezulsYbjoNbW3D3x+qjXYqBGU+3nnKR1fcQcHFrSd6T0XhrZ2y
         3mise25iiUTVfHbBl5zdQifBdIrYZMqEfC6YgVYXbbql4xTg+YZbA2lXjw8QPHk8b6Om
         S3PGgYv5BlAXYr4MVX4z/zOXn0QLcTp8Z68eXcAKqHNCYe26OzdJi7Zbe5d2GlPTrPHg
         BUD7yn4b/zXgXvzeS4me3swXbdE3dtDoNxcfdwmiPYuIeAAU5rD3zC+QjjhSJFWUnD3c
         iVtwj2KZvXWaYHZL7oHy1K+fYJ6z7h0QRDBA+gwF7oe9gdykWMng101hYjqGyQaAeP/2
         S71g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ziZl4T8kjNiLHlGfLpcAi0KB0HNTpeQRkauj0SyOXZk=;
        b=ZRanGSFqnqvgMFzaEkmlVFqxprGbk4UQ6C5hWZpHUXbGiM0d5tW7PUdUCijgZ7yjiw
         mXmc3WBbk2j9ZK45ew5JGke/Qe7afMq6XKcrN1Za/fHeZYhvcOhvm7XbX4rRB6RIp8kI
         fC9wE2vvXkacSnye6bQDp7JhfLuePwUQEbkhWFqMjFwyDGkcbxd2eobOmzloMWRdFDdC
         d4oshGWc9ZLDfBDD6dyrfCJrfFO/uNuhndQ0Y6I7O+gPkbCMaP08gsWSqW96o/CAGdt1
         CXP0IXp/c7sIZd9VADhBvhyWYoYI/xnA+5cZkLml1MmKdzWMY28PwN60LDC9MLoDuKqw
         +0cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p4si65342pjo.1.2020.11.05.03.15.59
        for <kasan-dev@googlegroups.com>;
        Thu, 05 Nov 2020 03:15:59 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 55E9E142F;
	Thu,  5 Nov 2020 03:15:58 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.58.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D5A9E3F719;
	Thu,  5 Nov 2020 03:15:55 -0800 (PST)
Date: Thu, 5 Nov 2020 11:15:52 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH] kfence: Use pt_regs to generate stack trace on faults
Message-ID: <20201105111552.GD82102@C02TD0UTHF1T.local>
References: <20201105092133.2075331-1-elver@google.com>
 <20201105105241.GC82102@C02TD0UTHF1T.local>
 <CANpmjNP+QOJrfJHC2P-9gFfB6wdnr9c9gPDgVFdgzbrCcG-nog@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP+QOJrfJHC2P-9gFfB6wdnr9c9gPDgVFdgzbrCcG-nog@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
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

On Thu, Nov 05, 2020 at 12:11:19PM +0100, Marco Elver wrote:
> On Thu, 5 Nov 2020 at 11:52, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Thu, Nov 05, 2020 at 10:21:33AM +0100, Marco Elver wrote:
> > > Instead of removing the fault handling portion of the stack trace based
> > > on the fault handler's name, just use struct pt_regs directly.
> > >
> > > Change kfence_handle_page_fault() to take a struct pt_regs, and plumb it
> > > through to kfence_report_error() for out-of-bounds, use-after-free, or
> > > invalid access errors, where pt_regs is used to generate the stack
> > > trace.
> > >
> > > If the kernel is a DEBUG_KERNEL, also show registers for more
> > > information.
> > >
> > > Suggested-by: Mark Rutland <mark.rutland@arm.com>
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Wow; I wasn't expecting this to be put together so quickly, thanks for
> > doing this!
> >
> > From a scan, this looks good to me -- just one question below.
> >
> > > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> > > index ed2d48acdafe..98a97f9d43cd 100644
> > > --- a/include/linux/kfence.h
> > > +++ b/include/linux/kfence.h
> > > @@ -171,6 +171,7 @@ static __always_inline __must_check bool kfence_free(void *addr)
> > >  /**
> > >   * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
> > >   * @addr: faulting address
> > > + * @regs: current struct pt_regs (can be NULL, but shows full stack trace)
> > >   *
> > >   * Return:
> > >   * * false - address outside KFENCE pool,
> >
> > > @@ -44,8 +44,12 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
> > >               case KFENCE_ERROR_UAF:
> > >               case KFENCE_ERROR_OOB:
> > >               case KFENCE_ERROR_INVALID:
> > > -                     is_access_fault = true;
> > > -                     break;
> > > +                     /*
> > > +                      * kfence_handle_page_fault() may be called with pt_regs
> > > +                      * set to NULL; in that case we'll simply show the full
> > > +                      * stack trace.
> > > +                      */
> > > +                     return 0;
> >
> > For both the above comments, when/where is kfence_handle_page_fault()
> > called with regs set to NULL? I couldn't spot that in this patch, so
> > unless I mised it I'm guessing that's somewhere outside of the patch
> > context?
> 
> Right, currently it's not expected to happen, but I'd like to permit
> this function being called not from fault handlers, for use-cases like
> this:
> 
>  https://lkml.kernel.org/r/CANpmjNNxAvembOetv15FfZ=04mpj0Qwx+1tnn22tABaHHRRv=Q@mail.gmail.com
> 
> The revised recommendation when trying to get KFENCE to give us more
> information about allocation/free stacks after refcount underflow
> (like what Paul was trying to do) would be to call
> kfence_handle_page_fault(addr, NULL).
> 
> > If this is a case we don't expect to happen, maybe add a WARN_ON_ONCE()?
> 
> While it's currently not expected, I don't see why we should make this
> WARN and limit the potential uses of the API if it works just fine if
> we pass regs set to NULL. Although arguably the name
> kfence_handle_page_fault() might be confusing for such uses, for now,
> until more widespread use is evident (if at all) I'd say let's keep
> as-is, but simply not prevent such use-cases.

Fair enough! I guess in future we could always revise that anyhow.

FWIW, for this as-is:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105111552.GD82102%40C02TD0UTHF1T.local.
