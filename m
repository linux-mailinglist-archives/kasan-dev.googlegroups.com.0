Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPVRW75QKGQE3YGY7IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 45E7427863B
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:47:11 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id l8sf1581390ioa.11
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:47:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601034430; cv=pass;
        d=google.com; s=arc-20160816;
        b=hFFvZ6/JIRWLxgtxzhprHmv7FFrgzeriVE2MEWWOdIatnSmyfNTj6bG/qPVzWZyu/r
         slnbebCh50jGqMfdWv3ivk6KSbfC18VWPJ3fQW6OiTrd4lFAEgHrq++DBmn8CsQwZ+69
         Y+pVfqcqQhSflKkxbSXfZMFjpXVpi+MaWXMJ7w2ZovoaIPJGKr4WqF69fLl3pjL2yEbD
         p8jfcXtfBygehgySBi3d0XSi1LBwwhehBa4ROEUQytwdU79omWWuXtEzTF7bnzH3Cajg
         3bOU77XjrKO8526yBj/dHkDrQSHmsk9PSYSdSTrL8Cjp6byudPcFUGUxYSG8uzqj3TN7
         byXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FyZNQkxSSKwxtBtuHvMNMDNcDTs2Gn4xBJwHLJyjvK8=;
        b=0GM5z9LZbn/iVXcL8WvSCXIRekMm4VKJCIifOSMjBTgNh/kLKtcPDuMC1NqnFN6dt+
         l7Dp4ByFRkYrFss8Wruar1jL2v8rVHsRXBUrG2/DdNWYB8Ag14R5L0R1jnrDTFqBjgi9
         qzQxLbBd0raPhixl89tV2wGbAXO/EbXLk+mgf25FzjabD2roNesUJBRjEzWStzJ1EVyt
         DkmLU557jF6mYYa+dp3NjL0FooFGieEAXw0SG61nAGHAMti8Q29/Kij5q+tV9FxeG8oa
         VBHbQgkMgTar9C2fxZ2/k4JrwHFxa4eIEXT15t05VJ7ATyvVMXXJNU4BHpj0/tPlm6uG
         wafA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FyZNQkxSSKwxtBtuHvMNMDNcDTs2Gn4xBJwHLJyjvK8=;
        b=aWyxJYubwCGF/XbbiWcYRlHZeZ0jqGsDUaBtpjaVOlAlvfBQ1ppCN9L/p5eiA7goxN
         qPwbMXy5fW8adDVfw8StBUotdpciOS165LkeqjHGfSp2ctup7ua6Ck9hDJO54xJkSHUy
         zqUyi8iZvN4feC+7Af+k6RS1zCgdVpnrwLbkSoh7+GZovrve9NWx4Giil4dszKDyDnD6
         7jIDoAyI4R7to/YUtVHJp6mWzlVXlevksV4tLujQJ/1LAfdpjF4mUqa5objUutu/rcEJ
         BPy5SKx3yY0ZcKPYdtsoDIFmuOICqf2XRUNheMF4h5dNwa2ltX0J/FA4Gh2u9qDPVGG8
         pLGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FyZNQkxSSKwxtBtuHvMNMDNcDTs2Gn4xBJwHLJyjvK8=;
        b=h5NVPmxH/+Ik/buGuawqWQM10YTfWRB1PRdDbxEFlig9EeHiDsK5OtIKUqVltudv4i
         PBtHztnD7W1nhUpsrWAh0Ecnz1tyWAZjMobDRyvxNus0yrw1Z15PV9TKdqon42E1/C+t
         oiqmhxcsBCC7PljzkSt/cRA1sUnBrbMP5l3hhQkMYGtcHqFuVAegOT3WPWOJM/zaAAOO
         3BUqIRKISNrUrRsnKGTcJYm4hyD9zAwQMOaGdN4e/wW7xkrL7A8HZ2gORbjD0v0yl4/C
         Tp8ahT/G+cJiWSRG6UXT7jMmcZbZG4IlHTzUwMeBvVETfhQ3ywf9WZg13ELNNBspclpP
         wpYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dNBF7IpSNe23PHWq2luEEWJ7yIoSmgqrCjmWkIIxJzTBTDHbw
	hEpxyjQimKwsksVl9bFSF4M=
X-Google-Smtp-Source: ABdhPJyvxWONTWr+UTyoKU6O7SFKyEnfDYPXdReZ/21oR8xXbj7HtDfKXHtWc0O+iLpjAxWtmO5S8g==
X-Received: by 2002:a92:d7ca:: with SMTP id g10mr2677840ilq.246.1601034430273;
        Fri, 25 Sep 2020 04:47:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c148:: with SMTP id b8ls597043ilh.9.gmail; Fri, 25 Sep
 2020 04:47:09 -0700 (PDT)
X-Received: by 2002:a05:6e02:1206:: with SMTP id a6mr2943647ilq.108.1601034429844;
        Fri, 25 Sep 2020 04:47:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601034429; cv=none;
        d=google.com; s=arc-20160816;
        b=T9K4OEdFZOfrzxtUQWXjSJjFLdtqb41gIdS61Unzy17khhPFsQZtKctCSRr/qFXHZ2
         ZdjgrY2/fw39Pa4yqzBjD2jOkQMPjVnMGVsIGZZG8ORCqdp5WP+Qe8PbttE2PlhjnbGv
         TBVOMBSvVvV0OArJM6fRoDEwaVwlkj0tMi+C4zznj2KvyVB1ARkz7MjpOFG/2YrpiOTM
         V23uso4RIL0sjM0zw3oWTeFoRyLPd89L7AEKk9C8xFv2rXBlGeNPBtUG/zlzD9tbBLjr
         BlNV8r8LDcf0MgtwAz7h6ySRxkyaWRXeockHIAL2r6CjAkRrPcGjOqpBVcAxoe7bkikb
         tFjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=dTRAJP5sT08cvrbBrEPFIOwj4KeDIoOAnQtFjx1XkgQ=;
        b=YlIsyPwnpeTxMd8FFT09Mo2WAI6bxQ8M0p2fCdGwQYawZ5cfEBEcRF4x4nYIC5z0j7
         RRgZnzVsOKNM85tHjryZmOETgNtSaSCDbp4gvMKIr32cFN/dZWUIgFG2W84+BRCos8BE
         OHiAg4BIu+pzZ2VIWiVVVqCiCKhuoNiOq/12TneZ7A4HBQlepS/wPgKyozu8F8/21LkT
         Xiz6kOr1XxrSypwpavHoNTe80Lg0lNLaRgPiQoi5wICaSS6lux+fqs6QiULmH/p/M8u9
         ncp7/ySSSF0cuZZNMmD3SXtUHIwlpksuMOV8L1yW6Cc8D1rH5qw5I2X6ndDhlZ/cKpy7
         3+mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a5si166800ilr.3.2020.09.25.04.47.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:47:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A4A792083B;
	Fri, 25 Sep 2020 11:47:06 +0000 (UTC)
Date: Fri, 25 Sep 2020 12:47:04 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v3 26/39] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200925114703.GI4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
 <20200925104933.GD4846@gaia>
 <CAAeHK+zLFRgR9eiLNyn7-iqbXJe6HGYpHYbBXXOVqOk4MyrhAA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zLFRgR9eiLNyn7-iqbXJe6HGYpHYbBXXOVqOk4MyrhAA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 01:26:02PM +0200, Andrey Konovalov wrote:
> On Fri, Sep 25, 2020 at 12:49 PM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > index a3bd189602df..d110f382dacf 100644
> > > --- a/arch/arm64/mm/fault.c
> > > +++ b/arch/arm64/mm/fault.c
> > > @@ -33,6 +33,7 @@
> > >  #include <asm/debug-monitors.h>
> > >  #include <asm/esr.h>
> > >  #include <asm/kprobes.h>
> > > +#include <asm/mte.h>
> > >  #include <asm/processor.h>
> > >  #include <asm/sysreg.h>
> > >  #include <asm/system_misc.h>
> > > @@ -294,6 +295,11 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
> > >       do_exit(SIGKILL);
> > >  }
> > >
> > > +static void report_tag_fault(unsigned long addr, unsigned int esr,
> > > +                          struct pt_regs *regs)
> > > +{
> > > +}
> >
> > Do we need to introduce report_tag_fault() in this patch? It's fine but
> > add a note in the commit log that it will be populated in a subsequent
> > patch.
> 
> I did, see the last line of the commit description.

Sorry, I missed that.

> > > +
> > >  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
> > >                             struct pt_regs *regs)
> > >  {
> > > @@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
> > >       return 0;
> > >  }
> > >
> > > +static void do_tag_recovery(unsigned long addr, unsigned int esr,
> > > +                        struct pt_regs *regs)
> > > +{
> > > +     static bool reported = false;
> > > +
> > > +     if (!READ_ONCE(reported)) {
> > > +             report_tag_fault(addr, esr, regs);
> > > +             WRITE_ONCE(reported, true);
> > > +     }
> >
> > I don't mind the READ_ONCE/WRITE_ONCE here but not sure what they help
> > with.
> 
> The fault can happen on multiple cores at the same time, right? In
> that case without READ/WRITE_ONCE() we'll have a data-race here.

READ/WRITE_ONCE won't magically solve such races. If two CPUs enter
simultaneously in do_tag_recovery(), they'd both read 'reported' as
false and both print the fault info.

If you really care about this race, you need to atomically both read and
update the variable with an xchg() or cmpxchg().

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925114703.GI4846%40gaia.
