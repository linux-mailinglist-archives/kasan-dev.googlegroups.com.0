Return-Path: <kasan-dev+bncBCS4VDMYRUNBBOEVXGGQMGQE2X6ZVDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A478246A31D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 18:39:05 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id v13-20020a056830140d00b0055c8421bd62sf4138004otp.15
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 09:39:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638812344; cv=pass;
        d=google.com; s=arc-20160816;
        b=X8vcOwu1C4QJrHRapqexehb1B/SHxMKuER4G5H8HHgCEb2HWm4bbju2MXw4QSYIROa
         0Tl34yBrmLnME2SRds9GSSYIpleKQGr9ZxrvyjVpMQMXOGi+Y7OECvQjOxW8LEZB4tm6
         2NgnrZQvJ5cq3Zp2iSlsqwN2ZUwXb/pWgF/UTuqPjygLsoWGSrMOSGMdbNoxewJKXMM2
         dZIO0HmWFb4QrwyJXgI6mijtXNcneLqeR8ddEiShELZ7Kdgh/9WqyhTQOljCGrd7ftmn
         FugMy7x73FyAb53fqACKa+LQjYVR/e1UvJW3u89Yq6LKuWfDskfqVswtMZrdqC9c2V0h
         lOiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=VBtRTBAYIzOK/1SXHVYLZxYG3fb6sgGgxGv3aZk2eX0=;
        b=KPHGTSco6Ea3hmEM4KcWxXRs88KjSxcVtssps0w4b+Z2PuowN/ZDUfgTLwR1GNBWfk
         Zl34FVa8+K34eM+dGQRhpBWv9fI07K13qn58u0r4/7hStNlF7JCW9MbtMdfJnRs038bO
         cQ88DPcfkGiAn0240vaTtj1k52fhiYNsZpSXOQpEEDLYs2dwT0sbBQYA3BxaGNb0wBex
         oIPFrKKrM6E3K98rhVlWa3v2zEp7nmovQNJaVorN9+63fmquVJ2ysFZ4MhqIHK4oq9ZG
         MzgoOjP+90mXzqy2M4HpdMVilr4liQOmasTJ3LpPp+8hk/Pgb2qynZnfOSz4mMzocdOU
         3RVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=exsO6t4p;
       spf=pass (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=S3CG=QX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VBtRTBAYIzOK/1SXHVYLZxYG3fb6sgGgxGv3aZk2eX0=;
        b=jhtBRq6eCfTsTSTTAq8kaXoR5+FmaEEJ826wlCErQLsf0FEXqdLOSOrB+oNG9xoQwa
         B3IO3kMVIJxrUUBGKKJnI9wLpUsx99RPhtTBeCChhSljZilJG6Bxic6BxsIDcBpNVjmg
         XxvDfozFynmajhQ8ob4ZglDwAKxU27WFj0mWhBmR026g/y2iwYFkPSmGR6d9RyIle4WM
         0qnCXzJMr9fS+3YquvqCt9mVRjdHff4JKiRozGIrsfI0yLO/KHYd19fxnmak4BXEKGAK
         0ZbqhDcEQz/r7A20Uv7+CAFBecAud5ri5rreRJRFKuLYvx1yS62G4Jual8BL1+Yj/ZWE
         O1hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VBtRTBAYIzOK/1SXHVYLZxYG3fb6sgGgxGv3aZk2eX0=;
        b=aV3SsGzt8jOpYt5tRCv7YEcuCjcTp06tE/K6Xpn41qw0kNEp+mzNcleXoHu5rOcEdj
         tBKyYj+fHIwIcbuMO0VQJSypKUPdEBcDuqzh0xJ1B5VUOc0tHJv/KP8EXBxA69UhhcfT
         WFUE8q7qUPpKi9aYYjwUuMiv4BCfdeoehEoZ1ZDwKGCC97r/WMpySFMYtF91E24/CBu7
         7VWXpoIGU+kPK5kICRxsVK87dFfSVUGOITcM/Wp6B7kZ0s5nvSfia9FAysUAQl4IWBQ1
         f/um9oTUnxkJbUKfF5XOsPDvO18hifTAYjdXuBwTcdQiqFgKD0mIKAgdVwHKEh3ofYYi
         a9Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VRwCD7jhUc509+8P1SKgOpzlVlw9kraUDYmylpaw3C6t8j6Zl
	xZASHYaj8IL4hkBp3SAxp9w=
X-Google-Smtp-Source: ABdhPJxaaLcIijbVmPvbC6YTmHN5bxZLGMgsgMyYLx5XuUP4l6aA3Am+pwEerHA6pRp21KFQGin40g==
X-Received: by 2002:a54:4d05:: with SMTP id v5mr25848557oix.16.1638812344645;
        Mon, 06 Dec 2021 09:39:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ded5:: with SMTP id v204ls6419618oig.10.gmail; Mon, 06
 Dec 2021 09:39:04 -0800 (PST)
X-Received: by 2002:a54:4486:: with SMTP id v6mr25430587oiv.90.1638812344213;
        Mon, 06 Dec 2021 09:39:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638812344; cv=none;
        d=google.com; s=arc-20160816;
        b=zFeDe1PzOt3jo7yl2cx2SN7o1czwWcW/FpvsdJTtGADI4Zmvdt96NwMMcHNj5IrBOZ
         NWONktj0xX1Vma3BzAfFS565FHhJ8nDc0ooTowmYQAofHRHgENIivdhum/59vhilfbdb
         5oGt0KcwuiWYn3adMA3Z6InnHLSZ3szYPgBbihNoRlOyPXaDEGhnVbA2sAJiNx5VNhzY
         uRSHP5lpmQ26vcwN5RoWukehdVP5FgxoauWI12qXQCsH52x6nuZxp+iEx/F1pjkQiN++
         8eE2I6WrNRtS8mdEZEDLqfOhANrlSyaC5z0/bxeuYw6JoY0szTHCvJxIo5ZsAWcPsX0V
         qSaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XYwuAuvNyCvBYZ4Ja4Yrn9rEi4cEkr8FmMiSQbMrZqg=;
        b=TWgVkoBeyXaVF8EutcX/isw6dhQsz27uqO/UkcIm8RGtfhtji5DrgnBZ5uoye6Zv0k
         8jAQf0sYzf0ZtEMO/yMDAZQUjOOaq5pFXKES5OgRCydaVFVeGbpKtmGKnDyuRyCslsDe
         FYeiRXG5ppRHSSA+buKN6sTO5D5ziUkPbOm4Q/4k3PYs7svCVRIbuGdeXRnax8skmkQx
         YuRoqleiLOqwQ+t8PYkC9rWdAxL9u9UyyChWwmpaGnbi+6Hra2Dxgs0ogSlqm+oY0x3X
         pM23oYWV0bnE7U6eRQneyrEO5B23ohUrYRI0IZek/u5shN4sPO821DIs6Im/gCmROAie
         B66Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=exsO6t4p;
       spf=pass (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=S3CG=QX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id s16si1015588oiw.4.2021.12.06.09.39.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Dec 2021 09:39:04 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 3EFD5CE170D;
	Mon,  6 Dec 2021 17:39:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 688CDC341C1;
	Mon,  6 Dec 2021 17:38:59 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 0AB175C1461; Mon,  6 Dec 2021 09:38:59 -0800 (PST)
Date: Mon, 6 Dec 2021 09:38:59 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 08/25] kcsan: Show location access was reordered to
Message-ID: <20211206173859.GA641268@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-9-elver@google.com>
 <Ya2Zpf8qpgDYiGqM@boqun-archlinux>
 <CANpmjNMirKGSBW2m+bWRM9_FnjK3_HjnJC=dhyMktx50mwh1GQ@mail.gmail.com>
 <Ya4evHE7uQ9eXpax@boqun-archlinux>
 <Ya40hEQv5SEu7ZeL@elver.google.com>
 <Ya5FaU9e6XY8vHJR@boqun-archlinux>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ya5FaU9e6XY8vHJR@boqun-archlinux>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=exsO6t4p;       spf=pass
 (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=S3CG=QX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Dec 07, 2021 at 01:16:25AM +0800, Boqun Feng wrote:
> On Mon, Dec 06, 2021 at 05:04:20PM +0100, Marco Elver wrote:
> > On Mon, Dec 06, 2021 at 10:31PM +0800, Boqun Feng wrote:
> > [...]
> > > Thanks for the explanation, I was missing the swap here. However...
> > > 
> > > > So in your above example you need to swap "reordered to" and the top
> > > > frame of the stack trace.
> > > > 
> > 
> > Apologies, I wasn't entirely precise ... what you say below is correct.
> > 
> > > IIUC, the report for my above example will be:
> > > 
> > >          | write (reordered) to 0xaaaa of ...:
> > >          | foo+0x... // address of the write to A
> > >          | ...
> > >          |  |
> > >          |  +-> reordered to: foo+0x... // address of the callsite to bar() in foo()
> > > 
> > > , right? Because in replace_stack_entry(), it's not the top frame where
> > > the race occurred that gets swapped, it's the frame which belongs to the
> > > same function as the original access that gets swapped. In other words,
> > > when KCSAN finds the problem, top entries of the calling stack are:
> > > 
> > > 	[0] bar+0x.. // address of the write to B
> > > 	[1] foo+0x.. // address of the callsite to bar() in foo()
> > > 
> > > after replace_stack_entry(), they changes to:
> > > 
> > > 	[0] bar+0x.. // address of the write to B
> > > skip  ->[1] foo+0x.. // address of the write to A
> > > 
> > > , as a result the report won't mention bar() at all.
> > 
> > Correct.
> > 
> > > And I think a better report will be:
> > > 
> > >          | write (reordered) to 0xaaaa of ...:
> > >          | foo+0x... // address of the write to A
> > >          | ...
> > >          |  |
> > >          |  +-> reordered to: bar+0x... // address of the write to B in bar()
> > > 
> > > because it tells users the exact place the accesses get reordered. That
> > > means maybe we want something as below? Not completely tested, but I
> > > play with scope checking a bit, seems it gives what I want. Thoughts?
> > 
> > This is problematic because it makes it much harder to actually figure
> > out what's going on, given "reordered to" isn't a full stack trace. So
> > if you're deep in some call hierarchy, seeing a random "reordered to"
> > line is quite useless. What I want to see, at the very least, is the ip
> > to the same function where the original access happened.
> > 
> > We could of course try and generate a full stack trace at "reordered
> > to", but this would entail
> > 
> > 	a) allocating 2x unsigned long[64] on the stack (or moving to
> > 	   static storage),
> > 	b) further increasing the report length,
> > 	c) an even larger number of possibly distinct reports for the
> > 	   same issue; this makes deduplication even harder.
> > 
> > The reason I couldn't justify all that is that when I looked through
> > several dozen "reordered to" reports, I never found anything other than
> > the ip in the function frame of the original access useful. That, and in
> > most cases the "reordered to" location was in the same function or in an
> > inlined function.
> > 
> > The below patch would do what you'd want I think.
> > 
> > My opinion is to err on the side of simplicity until there is evidence
> > we need it. Of course, if you have a compelling reason that we need it
> > from the beginning, happy to send it as a separate patch on top.
> > 
> > What do you think?
> > 
> 
> Totally agreed. It's better to keep it simple until people report that
> they want to see more information to resolve the issues. And thanks for
> looking into the "double stack traces", that looks good to me too.
> 
> For the original patch, feel free to add:
> 
> Reviewed-by: Boqun Feng <boqun.feng@gmail.com>

Thank you both!  I will add Boqun's Reviewed-by on the next rebase.

							Thanx, Paul

> Regards,
> Boqun
> 
> > Thanks,
> > -- Marco
> > 
> > ------ >8 ------
> > 
> > From: Marco Elver <elver@google.com>
> > Date: Mon, 6 Dec 2021 16:35:02 +0100
> > Subject: [PATCH] kcsan: Show full stack trace of reordered-to accesses
> > 
> > Change reports involving reordered accesses to show the full stack trace
> > of "reordered to" accesses. For example:
> > 
> >  | ==================================================================
> >  | BUG: KCSAN: data-race in test_kernel_wrong_memorder / test_kernel_wrong_memorder
> >  |
> >  | read-write to 0xffffffffc02d01e8 of 8 bytes by task 2481 on cpu 2:
> >  |  test_kernel_wrong_memorder+0x57/0x90
> >  |  access_thread+0xb7/0x100
> >  |  kthread+0x2ed/0x320
> >  |  ret_from_fork+0x22/0x30
> >  |
> >  | read-write (reordered) to 0xffffffffc02d01e8 of 8 bytes by task 2480 on cpu 0:
> >  |  test_kernel_wrong_memorder+0x57/0x90
> >  |  access_thread+0xb7/0x100
> >  |  kthread+0x2ed/0x320
> >  |  ret_from_fork+0x22/0x30
> >  |   |
> >  |   +-> reordered to: test_delay+0x31/0x110
> >  |                     test_kernel_wrong_memorder+0x80/0x90
> >  |
> >  | Reported by Kernel Concurrency Sanitizer on:
> >  | CPU: 0 PID: 2480 Comm: access_thread Not tainted 5.16.0-rc1+ #2
> >  | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
> >  | ==================================================================
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  kernel/kcsan/report.c | 33 +++++++++++++++++++++++----------
> >  1 file changed, 23 insertions(+), 10 deletions(-)
> > 
> > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > index 67794404042a..a8317d5f5123 100644
> > --- a/kernel/kcsan/report.c
> > +++ b/kernel/kcsan/report.c
> > @@ -317,22 +317,29 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
> >  {
> >  	unsigned long symbolsize, offset;
> >  	unsigned long target_func;
> > -	int skip;
> > +	int skip, i;
> >  
> >  	if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
> >  		target_func = ip - offset;
> >  	else
> >  		goto fallback;
> >  
> > -	for (skip = 0; skip < num_entries; ++skip) {
> > +	skip = get_stack_skipnr(stack_entries, num_entries);
> > +	for (i = 0; skip < num_entries; ++skip, ++i) {
> >  		unsigned long func = stack_entries[skip];
> >  
> >  		if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
> >  			goto fallback;
> >  		func -= offset;
> >  
> > +		replaced[i] = stack_entries[skip];
> >  		if (func == target_func) {
> > -			*replaced = stack_entries[skip];
> > +			/*
> > +			 * There must be at least 1 entry left in the original
> > +			 * @stack_entries, so we know that we will never occupy
> > +			 * more than @num_entries - 1 of @replaced.
> > +			 */
> > +			replaced[i + 1] = 0;
> >  			stack_entries[skip] = ip;
> >  			return skip;
> >  		}
> > @@ -341,6 +348,7 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
> >  fallback:
> >  	/* Should not happen; the resulting stack trace is likely misleading. */
> >  	WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)ip);
> > +	replaced[0] = 0;
> >  	return get_stack_skipnr(stack_entries, num_entries);
> >  }
> >  
> > @@ -365,11 +373,16 @@ static int sym_strcmp(void *addr1, void *addr2)
> >  }
> >  
> >  static void
> > -print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
> > +print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long *reordered_to)
> >  {
> >  	stack_trace_print(stack_entries, num_entries, 0);
> > -	if (reordered_to)
> > -		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to);
> > +	if (reordered_to[0]) {
> > +		int i;
> > +
> > +		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to[0]);
> > +		for (i = 1; i < NUM_STACK_ENTRIES && reordered_to[i]; ++i)
> > +			pr_err("                    %pS\n", (void *)reordered_to[i]);
> > +	}
> >  }
> >  
> >  static void print_verbose_info(struct task_struct *task)
> > @@ -390,12 +403,12 @@ static void print_report(enum kcsan_value_change value_change,
> >  			 struct other_info *other_info,
> >  			 u64 old, u64 new, u64 mask)
> >  {
> > -	unsigned long reordered_to = 0;
> > +	unsigned long reordered_to[NUM_STACK_ENTRIES] = { 0 };
> >  	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
> >  	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
> > -	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, &reordered_to);
> > +	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, reordered_to);
> >  	unsigned long this_frame = stack_entries[skipnr];
> > -	unsigned long other_reordered_to = 0;
> > +	unsigned long other_reordered_to[NUM_STACK_ENTRIES] = { 0 };
> >  	unsigned long other_frame = 0;
> >  	int other_skipnr = 0; /* silence uninit warnings */
> >  
> > @@ -408,7 +421,7 @@ static void print_report(enum kcsan_value_change value_change,
> >  	if (other_info) {
> >  		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
> >  						      other_info->num_stack_entries,
> > -						      other_info->ai.ip, &other_reordered_to);
> > +						      other_info->ai.ip, other_reordered_to);
> >  		other_frame = other_info->stack_entries[other_skipnr];
> >  
> >  		/* @value_change is only known for the other thread */
> > -- 
> > 2.34.1.400.ga245620fadb-goog
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206173859.GA641268%40paulmck-ThinkPad-P17-Gen-1.
