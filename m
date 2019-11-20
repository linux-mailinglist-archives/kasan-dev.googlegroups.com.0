Return-Path: <kasan-dev+bncBD7LZ45K3ECBBAX72TXAKGQEJW7W62Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D4AEE103B5F
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 14:28:34 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id e12sf4801113ljk.19
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 05:28:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574256514; cv=pass;
        d=google.com; s=arc-20160816;
        b=rtcEJ/z6XSiBqOEORYZgiO4gQPqi8uRPrHVl5Py2thwn6chpIiWWr+1byASj/QhaWq
         Cpjn/0TL++U1w+RvZrxTakM2o6f0F9Cu2Njs50x6q5diwMPlzhEnsaxX2ctw6yzdpGam
         yVqII734Jr/9Zx5WvXLi/Q+TJlPladR8lTqFlTNQvf/louQ5y1FX9/1B8yLdNtuWlAGL
         QxAgrz9eqMxw9Y2Hq4FoQJqL7VZ7SH8vljCnMQFUWvejxOzAQmM/4nk8Qxe70Y2Wq6Ny
         9ttzJ1O2/GAsNVI/gzKmowLR1B6N0alNoSzCcQHaooWcEaPlL+WU74Cvi38LDKs/2CCm
         pFcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3O6/o4YRQPXb+zmL7U+ZEZ6B4JZDrWhzrB34PNVu1+E=;
        b=nBAe2SJbDuVZz9rMzei0zv0JPtUzJyMLOr6cCOYUGUtDXDFPygY+p3sfVBBHrY8Urc
         kqo5MF8KGcuiv2HwXq9+TuPmknIGOqL58ncbPLmEusnbZvkbGF/StrWiId8rZOkAC+6A
         Y51pwcQPe+RbPSQwiJ1K7Ps8RxN17u6tRKuBuymlJhhF7CbCrEauby76I4neqTl/bpKB
         Yf+kFGrVYG0rn1vXk2iN4H7OiSbi3dTiP6H5+S6jW7mYUXjOsEJfoNJjhLFsQbtb1Dnm
         dzJMaXVkbbYRGONLkLRa9+2LHNwSbMx//nd5IMigEBTNUvzi2QLOYq1CVv34GRDQNZBv
         FQ0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=TynL67zs;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3O6/o4YRQPXb+zmL7U+ZEZ6B4JZDrWhzrB34PNVu1+E=;
        b=b0wfS1l7EXhaHGuI9N8mJSgkLXI1wIz4xGKCzKpRSqyoi9MslzeW6AknG081sMAi6c
         AmUcLyOY0rWSBg+9B2jZCNuKOWiWrmrHeW87yUdE9xPigE0+h1qxrjF7xGmlZ2WnQM6q
         EKjGAn2m7NsUSOpuOdccF2ExybCIUjkE0TikmQTZoBlmpm9d25ebz676zfT4Zc6PKL7I
         Rdzu5aQarcIr4ZntINSo+IUfgVV25I56/6JI8L6U2e5MTW8fqafMdiOS0I58AW5M+K/x
         XqRH23CZfNx5bkxkhwGnNfY+GcN7sDPo4vIQrMQg0PSspdLQ6qoD4GSFjskp0xLyQsgn
         6HHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3O6/o4YRQPXb+zmL7U+ZEZ6B4JZDrWhzrB34PNVu1+E=;
        b=iutWeO61Jt6onu1GcvY4+rb7WVSirgQtTvUrvqudAPD9IQ8Iux4vAK0rIg2swQEF9U
         +vVf3z5ENMkstyLEDF0RzGCXXh8nf2TDjQOU+W+h9tnMgU9ikPB440GuPiUjUTv1nzSz
         NX7cLOqwIZAf9FbxH6Po78cIPklQvZV41F/WfjMcDMVcojJn+tYguQuPc5VCgKohYjk9
         QusCmbTQ92aOHfue5hou2dAFBTihvJ80Pc0NXKoxettPhxBrF6wKbzOB4b+l5+BsXyJw
         329b6jZDBd2TaM0a9acnLXB44tw+GnIj+f3K0+X0k5Cux/zLt4hqM/PcWnnpglK/fp9Q
         TrpQ==
X-Gm-Message-State: APjAAAV9MEmdOSfh+lTmb0EXpt4hn67FhFaMWcclGZuogmnjP9ufGOn5
	+kAGyo+wQyEnRgihNRVdWn4=
X-Google-Smtp-Source: APXvYqyN0dxnZGAS8OeBhS49kfn1GEVSuu2dECKgRqJv0WAeZAyWDmslk1EpZVYwYCDUZE5G36+sug==
X-Received: by 2002:a19:3f16:: with SMTP id m22mr495947lfa.116.1574256514441;
        Wed, 20 Nov 2019 05:28:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4e2:: with SMTP id s2ls303005ljm.4.gmail; Wed, 20 Nov
 2019 05:28:33 -0800 (PST)
X-Received: by 2002:a05:651c:289:: with SMTP id b9mr2863339ljo.80.1574256513669;
        Wed, 20 Nov 2019 05:28:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574256513; cv=none;
        d=google.com; s=arc-20160816;
        b=G/ILYZlTiatU/geDWEq8iPopF+c9msQhzSSPrBdjmL1+0UvCwTX+aBcj2OxOJjetlx
         5lA5LxbDsyleR+qW/D62ZqlvzDMl8DgT9QkrR/oeB5rqDFWHMIbB0omsFWYP0/J4npcG
         4YheeAUJVCZf7iZqaMYkW3fXLNT3TgN5sseIE5kgmrhY641HQi6liIyAs8weRIsxgE7/
         wVcDwIDj3HwcdR7HGg4ztuz32jNukRobpuiXHzGe1bSD1fivZvu0D/YLs1xL4pYGBV6R
         gaKlCvOZ2pVcCJAypBjvYbcQ1fVFtSuEKLxxsFlHTG3gOVlyzAifK1rNIboyH3Q4aOe9
         JQMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=f11bqYRLU8GEHJXNeBAMacLrDj3b4Fc6rBnmQVewYXs=;
        b=BGnEVLJDBCg2OlR3vVHY9/PLEzJpwPt4n2dDRRZAWCqwKVrIwSC1R1t8snnXfAWn7e
         bVd+RVegl0jCw9ZOea1I8LaU9q+lkxrZD9kI09M5dgWLeTpCiPyc6UOA/YF1Pl2FFhQ6
         8E6dJV4uks7cUB7+hSZQ2SMHCeSMmow0VOCL770B+eDlrwX0EHPTz+XRzGM8CppDQlph
         y9PUstgYU13WGzSid+l4tp5DSm2LtCCFDyqJlf7/YuisyuwtID0DeT7of466FkEZE9f6
         NyeiJhrBPx/e8iZVxHUpzDgCLtIkEf69irqW4uZA4fOI/+BPpbiAMkVWC2QxuI6wYI2X
         DRmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=TynL67zs;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id c17si1277691ljb.3.2019.11.20.05.28.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 05:28:33 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id 8so7847740wmo.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 05:28:33 -0800 (PST)
X-Received: by 2002:a1c:7d47:: with SMTP id y68mr3186364wmc.157.1574256513123;
        Wed, 20 Nov 2019 05:28:33 -0800 (PST)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id d20sm34607640wra.4.2019.11.20.05.28.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 05:28:32 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 20 Nov 2019 14:28:30 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Borislav Petkov <bp@alien8.de>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120132830.GB54414@gmail.com>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
 <20191120123058.GA17296@gmail.com>
 <20191120123926.GE2634@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120123926.GE2634@zn.tnic>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=TynL67zs;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Borislav Petkov <bp@alien8.de> wrote:

> On Wed, Nov 20, 2019 at 01:30:58PM +0100, Ingo Molnar wrote:
> > 
> > * Jann Horn <jannh@google.com> wrote:
> > 
> > > You mean something like this?
> > > 
> > > ========================
> > > diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> > > index 9b23c4bda243..16a6bdaccb51 100644
> > > --- a/arch/x86/kernel/traps.c
> > > +++ b/arch/x86/kernel/traps.c
> > > @@ -516,32 +516,36 @@ dotraplinkage void do_bounds(struct pt_regs
> > > *regs, long error_code)
> > >   * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> > >   * address, return that address.
> > >   */
> > > -static unsigned long get_kernel_gp_address(struct pt_regs *regs)
> > > +static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
> > > +                                          bool *non_canonical)
> > 
> > Yeah, that's pretty much the perfect end result!
> 
> Why do we need the bool thing? Can't we rely on the assumption that an
> address of 0 is the error case and use that to determine whether the
> resolving succeeded or not?

I'd rather we not trust the decoder and the execution environment so much 
that it never produces a 0 linear address in a #GP:

in get_addr_ref_32() we could get zero:

	linear_addr = (unsigned long)(eff_addr & 0xffffffff) + seg_base;

in get_addr_ref_16() we could get zero too:

	linear_addr = (unsigned long)(eff_addr & 0xffff) + seg_base;

Or in particularly exotic crashes we could get zero in get_addr_ref_64() 
as well:

        linear_addr = (unsigned long)eff_addr + seg_base;

although it's unlikely I suspect.

But the 32-bit case should be plausible enough?

It's also the simplest, most straightforward printout of the decoder 
state: we either see an error, or an (address,canonical) pair of values.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120132830.GB54414%40gmail.com.
