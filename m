Return-Path: <kasan-dev+bncBDV37XP3XYDRBJH64DUQKGQEMH23GYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 35B5F72D53
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 13:21:09 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id l4sf9822056lja.22
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 04:21:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563967268; cv=pass;
        d=google.com; s=arc-20160816;
        b=nVKZIPR+1IppWDlglUPkB9J0x6uFps/q8mdM8GqN/xaxvfF6PFvPpCJCZuUJ+sAkWX
         RKpkiXAMu95R75JHy59trDc0pifLghdJRncYet87W7KpBEc04qU6euHdPKJotVyHfSBr
         hB4fRhRrD8okTjLWvtuScIaRD19zKjoxo4hkjN2lmDiUr1hpmLXvCOBkTfUuSXwU9ZVQ
         72amFY3l54t/1L5RO/nA/fN2KGRzgl/Dp7T6yRueeMCCfDEmsKUCuihsv24KDE4dUz/k
         5m9Q7hlOgVNfm9hsLLpOkAGG1e+5V+SfMz+myTXIdeRZ3kUOCncBJjmbRTTUtvOkQQNf
         NLjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DOdRb6tt6OixuL6SvvmME+3fhggt9vuZiL56V/TXcSg=;
        b=KgP3m4u25IRS/2uK4Z27PWykZJYaIVZinOZs8dVHy+OtAuaxtRTEuvpjCM7Eyso2PL
         8UxMcFfWsR07nCzGEDbCu/QutrV29rqBmPgpxPJtNbFuLcD+Ntwr0ZjFS/YR3npMe0AM
         Rhl8GjzlTWYD6UFGTegErMBwikAtfvk+bhdLvZ9GjqZau1ZA8OvTU5JJWo3Bp21ejtij
         44SOMD3EW4Y+Toiiml2BRXjsjpObt+P/zgTWEqzLPApFB1HljK/TIeYZylIRnZTNL6dN
         +oO3JySyar+WKagxxB69YVO5bgW9m9dbAKf1SVZUOVgqZdXw2mnHjoSJklgC68rwBNgJ
         hE0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DOdRb6tt6OixuL6SvvmME+3fhggt9vuZiL56V/TXcSg=;
        b=sqbwBGkfBywH5PGKLpXIwIYZYf869xKJ4DCJSIovvrcSePCm+R/LXTDPfMe2Sk5nA8
         7MFhcf38LvAAxgfx7bOYBxnNdBygIQc6w7Co1pfWPuhTqKmCk68IDPHov72D3kbx9a3z
         +pDxgt0L6Qf9ee38sjiMqWX1yXYVcJ/wY4PXmg5A74Zlj4CteIRw3mwg36hnQZO3lrRa
         9qOe10mFrkQ9lGcQBnCBMCh05EzdvGx4czKWX9LrN3Qa6zKC3ied+gPNYyLVILAROF9q
         JCPx77/cy7WZmEWEPvxsHwDgic/l6o7ianPFx75HH5Zag9urRvwuS77jl+T+Co78Wlvy
         8yWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DOdRb6tt6OixuL6SvvmME+3fhggt9vuZiL56V/TXcSg=;
        b=c4Yy/P1vSFusQtJthE1knraa3xPWn10snVUIlM2dMsGNpYmlM/9EY03AaA+q+UHwiY
         EQZDJ71EMB1wjOxVHWbvFmoRYaj+tG4Bt22bh6SYNpCeKF5yj+GUXGPDOcXdL8WIk83Y
         c2626GnDR6ZEH+FhcwwtoDSDDFZroCjtHUd5abHhtrf3IVX1cU4GSsPut2S/SLJNoaDg
         WbxndMxwjhUz2Rlvq7qhTom13gELGSfs0cPhpmK/LULcYXMutNIEjdzlSRDYYKQJeMyr
         6qODma9//Yf2Ve/iBlvr0OYbBxdb6fhBy4tZnJGnbtu67DivbJnYEMJbCanrxIPlYlsy
         ge/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV2ynxveDtLUpoxI0hTczcS/jMNO77OtLtyZNiPEqd4QFgio1mQ
	cVeArqeNJrDdUUHX+tcFtZs=
X-Google-Smtp-Source: APXvYqyxfRy1h2Binic6mfJLHGUjDxvCy+gYP6/985Eojr11/QAR7TdX1mufyZhnbFrUdRZcuzRiaA==
X-Received: by 2002:a2e:8602:: with SMTP id a2mr40595218lji.206.1563967268767;
        Wed, 24 Jul 2019 04:21:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9714:: with SMTP id r20ls5249640lji.6.gmail; Wed, 24 Jul
 2019 04:21:08 -0700 (PDT)
X-Received: by 2002:a2e:890c:: with SMTP id d12mr41444112lji.103.1563967268013;
        Wed, 24 Jul 2019 04:21:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563967268; cv=none;
        d=google.com; s=arc-20160816;
        b=U/PX3qQLtMp6I5UbpAF41nrT8clQF39OyQCd5TD7clSBWthHM0vhbXS6eLa+B0lDjV
         WZ1h8M4zD8ptQRGiwypDUPxlfJ479y93j5zm/+6nRCspSDD6/dUfZ8seLvo0FNFQs6VF
         ORUbZ1RyQ+z3Ny3el5D+sWKVG7QDVewexmATjjkNPleoZKW9lXbhp/cOmM8K1OYeniFo
         QCCUs/hQhVuUpEjnUg5YndvTkel8VYZuzvLZGLhmtU1QbNBtI8XQQffcTunh1oxqESS7
         RdNQvjbEIUerrMidA6+qkH4LlnA46k/XKrbdyysCEaGeqFu4aduhMRnamQTd0MzXXWfJ
         sjhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=QHQJUaZZkzs4yscjNg3LzVbbsFpMOM8JY+junwLUnQ0=;
        b=Sz6cYhglR4bPjGHuFYmdHSJwJctZZFu27zJMiVb1b+LbQcUgNDKYIThmj5cjzZbZTF
         NPbUmeEHG0J8bKFgbHW9UmkTxGa5jMqWJpGg3PZ1d/H+kkORwEEWiZsIIDMCjwZRnoJM
         +1/IY/RXOKpGsWCGpxfaq2bcW2rS1r2Yl82kWH3Yhke64hP5WTpjMYFI7f2iCEzoiThT
         DGoN6Ltd4vi/vkxdb9OZUGSmubLrXsEqalvNyu1WFuWb7Z+EZSdj9GPX6ixc144q7p9q
         tnnaag2bQjz+jmKH8wUoGfJP7Yr1i8ySJbcTZ85i8+ywZgKt4ul90sEdYHNTdv8fq5+a
         4BUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z18si2020808lfh.1.2019.07.24.04.21.07
        for <kasan-dev@googlegroups.com>;
        Wed, 24 Jul 2019 04:21:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E4E2B1509;
	Wed, 24 Jul 2019 04:21:05 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3F4013F71A;
	Wed, 24 Jul 2019 04:21:04 -0700 (PDT)
Date: Wed, 24 Jul 2019 12:21:02 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
Message-ID: <20190724112101.GB2624@lakrids.cambridge.arm.com>
References: <20190719132818.40258-1-elver@google.com>
 <20190723164115.GB56959@lakrids.cambridge.arm.com>
 <CACT4Y+Y47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3+w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Y47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3+w@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Wed, Jul 24, 2019 at 11:11:49AM +0200, Dmitry Vyukov wrote:
> On Tue, Jul 23, 2019 at 6:41 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Fri, Jul 19, 2019 at 03:28:17PM +0200, Marco Elver wrote:
> > > Enabling STACK_GUARD_PAGE helps catching kernel stack overflows immediately
> > > rather than causing difficult-to-diagnose corruption. Note that, unlike
> > > virtually-mapped kernel stacks, this will effectively waste an entire page of
> > > memory; however, this feature may provide extra protection in cases that cannot
> > > use virtually-mapped kernel stacks, at the cost of a page.
> > >
> > > The motivation for this patch is that KASAN cannot use virtually-mapped kernel
> > > stacks to detect stack overflows. An alternative would be implementing support
> > > for vmapped stacks in KASAN, but would add significant extra complexity.
> >
> > Do we have an idea as to how much additional complexity?
> 
> We would need to map/unmap shadow for vmalloc region on stack
> allocation/deallocation. We may need to track shadow pages that cover
> both stack and an unused memory, or 2 different stacks, which are
> mapped/unmapped at different times. This may have some concurrency
> concerns.  Not sure what about page tables for other CPU, I've seen
> some code that updates pages tables for vmalloc region lazily on page
> faults. Not sure what about TLBs. Probably also some problems that I
> can't thought about now.

Ok. So this looks big, we this hasn't been prototyped, so we don't have
a concrete idea. I agree that concurrency is likely to be painful. :)

[...]

> > > diff --git a/arch/x86/include/asm/page_64_types.h b/arch/x86/include/asm/page_64_types.h
> > > index 288b065955b7..b218b5713c02 100644
> > > --- a/arch/x86/include/asm/page_64_types.h
> > > +++ b/arch/x86/include/asm/page_64_types.h
> > > @@ -12,8 +12,14 @@
> > >  #define KASAN_STACK_ORDER 0
> > >  #endif
> > >
> > > +#ifdef CONFIG_STACK_GUARD_PAGE
> > > +#define STACK_GUARD_SIZE PAGE_SIZE
> > > +#else
> > > +#define STACK_GUARD_SIZE 0
> > > +#endif
> > > +
> > >  #define THREAD_SIZE_ORDER    (2 + KASAN_STACK_ORDER)
> > > -#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
> > > +#define THREAD_SIZE  ((PAGE_SIZE << THREAD_SIZE_ORDER) - STACK_GUARD_SIZE)
> >
> > I'm pretty sure that common code relies on THREAD_SIZE being a
> > power-of-two. I also know that if we wanted to enable this on arm64 that
> > would very likely be a requirement.
> >
> > For example, in kernel/trace/trace_stack.c we have:
> >
> > | this_size = ((unsigned long)stack) & (THREAD_SIZE-1);
> >
> > ... and INIT_TASK_DATA() allocates the initial task stack using
> > THREAD_SIZE, so that may require special care, as it might not be sized
> > or aligned as you expect.
> 
> We've built it, booted it, stressed it, everything looked fine... that
> should have been a build failure.

I think it's been an implicit assumption for so long that no-one saw the need
for built-time assertions where they depend on it. 

I also suspect that in practice there are paths that you won't have
stressed in your environment, e.g. in the ACPI wakeup path where we end
up calling:

/* Unpoison the stack for the current task beyond a watermark sp value. */
asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
{
	/*
	 * Calculate the task stack base address.  Avoid using 'current'
	 * because this function is called by early resume code which hasn't
	 * yet set up the percpu register (%gs).
	 */
	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));

	kasan_unpoison_shadow(base, watermark - base);
} 

> Is it a property that we need to preserve? Or we could fix the uses
> that assume power-of-2?

Generally, I think that those can be fixed up. Someone just needs to dig
through how THREAD_SIZE and THREAD_SIZE_ORDER are used to generate or
manipulate addresses.

For local-task stuff, I think it's easy to rewrite in terms of
task_stack_page(), but I'm not entirely sure what we'd do for cases
where we look at another task, e.g.

static int proc_stack_depth(struct seq_file *m, struct pid_namespace *ns, 
                                struct pid *pid, struct task_struct *task)
{
        unsigned long prev_depth = THREAD_SIZE -
                                (task->prev_lowest_stack & (THREAD_SIZE - 1)); 
        unsigned long depth = THREAD_SIZE -
                                (task->lowest_stack & (THREAD_SIZE - 1)); 

        seq_printf(m, "previous stack depth: %lu\nstack depth: %lu\n",
                                                        prev_depth, depth);
        return 0;
}

... as I'm not sure of the lifetime of task->stack relative to task. I
know that with THREAD_INFO_IN_TASK the stack can be freed while the task
is still live.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190724112101.GB2624%40lakrids.cambridge.arm.com.
