Return-Path: <kasan-dev+bncBDV37XP3XYDRBYV66X6QKGQEZTCL3JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA3792C30BA
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 20:30:43 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id y8sf16201035qvu.22
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 11:30:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606246242; cv=pass;
        d=google.com; s=arc-20160816;
        b=WHvCc1N8NwjuAjZ/kFUd8Vrp2qnN0MW/uVFAZSNGLtISmKwf8lUp1ORUyAejNo3F/+
         4wdIndFFXsW/G4AVCdguUOxhBMO46c9UQxFpPJsdbhPaEvg20nzfX3pY6+W+j6MZawkB
         4nXtlO6L7i/KZzSgRFmPSs81IUNRZ8YnB4q/kylVmpndCUdFeCnzw3iqVXjG4GHhqCSn
         wvFLe9yXdkTgwOhHWNizHOM2MOOg9zaX/JMd6K1lqQcYoD6EfABTZaGdjMmGM7CM1akt
         KGxZICMHmEZGcteQHtkV6f3ZVsNGAWlCYLM9k+gUeomINk3gCKy1D8m97ZJvuaOzbzQ8
         Sg3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oXLCEcHtnG8Utl8sFyglQ9FLrpCz4XkUfXh00nUYEMs=;
        b=etvx2ZhwfqnUiMQ9gT5W96w8wIDL+IevAp9gWHwsg1mHuMb/f9UbuklzW75tQACdPO
         Illnfz3sv37+ubuvuWVyJpcHtQDIED5l4C/xMZEU0+s4zDfeOvt9TBo0idBfmqzI/MPT
         NeHFD2MNjbEKFMvr9T413he44Vh8t5vsMVaLRcFsPL47A8Tk1WGC25f8OSwSpaZUPH3B
         /36wJWd1qUeYs9i7P0FLvExuB+09KxXazUhAwR4t0XTKhI5DbUxu6kyJEwYb5SA3lo1e
         g1GdARohq6beyzv3/EF0ulb64NZr2zP6BHi4PD4WjofWrLAIJ8FwtmC+KobY3/ylbFlo
         2lEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oXLCEcHtnG8Utl8sFyglQ9FLrpCz4XkUfXh00nUYEMs=;
        b=l/q5UfryqKEksQRF3uIiqfyQxMofA9m0FjskVik3JumKc0BcqlHJVBaLq+2k9AVysz
         QiZTlHtfj7As+VCGiYXs1Bvu2Pp6PiscWJQK+GcAiyKGG8er7A9aOW34kcs1/xj7IqdU
         nT7smIaL/W0ZPolLtRYEvxLaiAsVTKlqeocAhvGQynEewJ/LjyhsZeebx5UeH9QajFvm
         LZcKloOk6hHBfhh9WYepBUdRtkSAYMgg7LuhJnWMaB1n2FuUmOgfKlgkHMZNWYottI9B
         OiRhR95Oco7Q8Vo/Ud4I+4OzCC2Le9Pb8LiFDj0ViG+rlVUt/+DcoMqaG7zksklTdRFX
         3hlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oXLCEcHtnG8Utl8sFyglQ9FLrpCz4XkUfXh00nUYEMs=;
        b=ct+M8NynfwgHbtryNfdWN2LF+dyqi7a0+az4o11TJlNcwr/0EFjR50u5Ul8AFceDlP
         BJ0JbuCTrRUDsIbrzzFKVOpPD4ZnVwCEHW7am98OXgN8eAwrd5G/H5uFia0lmW5UDemu
         gUXbcVXIk3OncZQhYzXJY5FSKLqXpRZ6D5JYycjgiTsHLbnHuoRGFTCcW8uWmGAJOSTo
         WAYTsPxViRzZaFVD1TGSX5SgOZzpl3m8uRNqBVyttQYnhGGuLKS9wU/fBQEYMh7sfvZK
         nRhe/ZH1fMqF1aG2fklC5nB4VJ7JdvQZWMY/173gnp4w96+Eybj1ej836HXuE0L1NOl4
         eW7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531mrazEvW/mH5e1ArnCvNXF/U/P41hyqDXtRuCG3ITuDNzGP4CG
	c1i2A/UU2dh6jW2SFDwF9L4=
X-Google-Smtp-Source: ABdhPJztXRQXJpxFWGgmMAJRwwGJ9QTl/qFWbKWaxDS/1FJXN48qvtLtrBmf2CimGzv1qM3bnO8MBg==
X-Received: by 2002:ac8:35ea:: with SMTP id l39mr6191556qtb.182.1606246242344;
        Tue, 24 Nov 2020 11:30:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:36ea:: with SMTP id f97ls21007qtb.4.gmail; Tue, 24 Nov
 2020 11:30:41 -0800 (PST)
X-Received: by 2002:aed:3c42:: with SMTP id u2mr6053798qte.159.1606246241849;
        Tue, 24 Nov 2020 11:30:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606246241; cv=none;
        d=google.com; s=arc-20160816;
        b=dgvoM98aIsio6TJ+C/R6L6AEntdcs/rYyS/eUtYKr56aMP3D3QkNW2kadMxFeSbC6R
         USkIomLaVeHqP4pfFkBvHlhh5PcJfeQz/h/Uyr3/MrxIDIWl9tsATCnE3iIEvQi6z3A3
         gZdxF7qtjlrTbI3RBczR9z2O7TOb64cmp88yiQq6SZbrVSvnl+fH+58ysquKCaANP6+r
         l+I1gZySe+hMqXsU0g/0JiKVDFCZuT318b/4ZNayEdjj7xkM81NxsxSMlTEQiKkv6QjW
         QwRVCsIJ4hrpvM+NNxXi5svVkdLKvcBYEN2NTXCm4nc7zCBVa0ZIIzNLOY0XdpaZG3I6
         A7LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=MTu7JPVheZSrnStETROp4LHaogLrg9LGx+W88Unjdhk=;
        b=jw/eeOFB8sFNPrCMMRwNLjH6c7viNkvHJYLJPOS8FXqsditeRBPkzni9GmuYuUWVOE
         4nyYkEeXaYfVSVa71ErfdyebBV0vUsqfXwNGp3Gz+WwS/g2cSPo4OcizuHYV4MG4/nZ0
         KmESgERz5iLSzexlsglR/CqC2cUnj7rCHFKWgmgnEFZD+sEYzBWU5b22eo6tIftAsQnB
         zW8Vi4GSNqUn++y97qf9NwZtztY1oZf30cBNqH4gl5lPlSbF1maA3AiOSqVnNja0OQBJ
         l5NGbbaxMuy0LLUu1Tze0mM/k5jUKcwZGHsfTRbrBTiC7RMG4RobyGws87CurA5QP0ew
         KEew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j44si5694qtc.2.2020.11.24.11.30.41
        for <kasan-dev@googlegroups.com>;
        Tue, 24 Nov 2020 11:30:41 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 06E501396;
	Tue, 24 Nov 2020 11:30:41 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.26.92])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E2B6E3F70D;
	Tue, 24 Nov 2020 11:30:36 -0800 (PST)
Date: Tue, 24 Nov 2020 19:30:34 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org, boqun.feng@gmail.com,
	tglx@linutronix.de
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201124193034.GB8957@C02TD0UTHF1T.local>
References: <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
 <20201120103031.GB2328@C02TD0UTHF1T.local>
 <20201120140332.GA3120165@elver.google.com>
 <20201123193241.GA45639@C02TD0UTHF1T.local>
 <20201124140310.GA811510@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201124140310.GA811510@elver.google.com>
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

On Tue, Nov 24, 2020 at 03:03:10PM +0100, Marco Elver wrote:
> On Mon, Nov 23, 2020 at 07:32PM +0000, Mark Rutland wrote:
> > On Fri, Nov 20, 2020 at 03:03:32PM +0100, Marco Elver wrote:
> > > On Fri, Nov 20, 2020 at 10:30AM +0000, Mark Rutland wrote:
> > > > On Thu, Nov 19, 2020 at 10:53:53PM +0000, Will Deacon wrote:
> > > > > FWIW, arm64 is known broken wrt lockdep and irq tracing atm. Mark has been
> > > > > looking at that and I think he is close to having something workable.
> > > > > 
> > > > > Mark -- is there anything Marco and Paul can try out?
> > > > 
> > > > I initially traced some issues back to commit:
> > > > 
> > > >   044d0d6de9f50192 ("lockdep: Only trace IRQ edges")
> > > > 
> > > > ... and that change of semantic could cause us to miss edges in some
> > > > cases, but IIUC mostly where we haven't done the right thing in
> > > > exception entry/return.
> > > > 
> > > > I don't think my patches address this case yet, but my WIP (currently
> > > > just fixing user<->kernel transitions) is at:
> > > > 
> > > > https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=arm64/irq-fixes
> > > > 
> > > > I'm looking into the kernel<->kernel transitions now, and I know that we
> > > > mess up RCU management for a small window around arch_cpu_idle, but it's
> > > > not immediately clear to me if either of those cases could cause this
> > > > report.
> > > 
> > > Thank you -- I tried your irq-fixes, however that didn't seem to fix the
> > > problem (still get warnings and then a panic). :-/
> > 
> > I've just updated that branch with a new version which I hope covers
> > kernel<->kernel transitions too. If you get a chance, would you mind
> > giving that a spin?
> > 
> > The HEAD commit should be:
> > 
> >   a51334f033f8ee88 ("HACK: check IRQ tracing has RCU watching")
> 
> Thank you! Your series appears to work and fixes the stalls and
> deadlocks (3 trials)! 

Thanks for testing! I'm glad that appears to work, as it suggests
there's not another massive problem lurking in this area.

While cleaning/splitting that up today, I spotted a couple of new
problems I introduced, and I'm part-way through sorting that out, but
it's not quite ready today after all. :/

Fingers crossed for tomorrow...

> I noticed there are a bunch of warnings in the log
> that might be relevant (see attached).

> [   91.184432] =============================
> [   91.188301] WARNING: suspicious RCU usage
> [   91.192316] 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25 Tainted: G        W        
> [   91.197536] -----------------------------
> [   91.201431] kernel/trace/trace_preemptirq.c:78 RCU not watching trace_hardirqs_off()!
> [   91.206546] 
> [   91.206546] other info that might help us debug this:
> [   91.206546] 
> [   91.211790] 
> [   91.211790] rcu_scheduler_active = 2, debug_locks = 0
> [   91.216454] RCU used illegally from extended quiescent state!
> [   91.220890] no locks held by swapper/0/0.
> [   91.224712] 
> [   91.224712] stack backtrace:
> [   91.228794] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G        W         5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
> [   91.234877] Hardware name: linux,dummy-virt (DT)
> [   91.239032] Call trace:
> [   91.242587]  dump_backtrace+0x0/0x240
> [   91.246500]  show_stack+0x34/0x88
> [   91.250295]  dump_stack+0x140/0x1bc
> [   91.254159]  lockdep_rcu_suspicious+0xe4/0xf8
> [   91.258332]  trace_hardirqs_off+0x214/0x330
> [   91.262462]  trace_graph_return+0x1ac/0x1d8
> [   91.266564]  ftrace_return_to_handler+0xa4/0x170
> [   91.270809]  return_to_handler+0x1c/0x38
> [   91.274826]  default_idle_call+0x94/0x38c
> [   91.278869]  do_idle+0x240/0x290
> [   91.282633]  rest_init+0x1e8/0x2dc
> [   91.286529]  arch_call_rest_init+0x1c/0x28
> [   91.290585]  start_kernel+0x638/0x670

Hmm... I suspect that arch_cpu_idle() is being traced here, and I reckon
we have to mark that and its callees as noinstr, since it doesn't seem
sane to have ftrace check whether RCU is watching for every function
call. Maybe Paul or Steve can correct me. ;)

If you still have the binary lying around, can you check whether
default_idle_call+0x94/0x38c is just after the call to arch_cpu_idle()?
If you could dump the asm around that, along with whatever faddr2line
tells you, that'd be a great help. 

This looks like it should be reproducible, so I'll enable the boot-time
self tests in my kernel and check whether I see the above too.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201124193034.GB8957%40C02TD0UTHF1T.local.
