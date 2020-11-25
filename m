Return-Path: <kasan-dev+bncBDV37XP3XYDRB37D7D6QKGQEJSAL3NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A4A82C3D9D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 11:29:04 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id f49sf2021418qta.11
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 02:29:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606300143; cv=pass;
        d=google.com; s=arc-20160816;
        b=UvhJVJAA8UgyuBhr1Tu3EJxhTG7Ti36K4+d5ud0O3HICRfT7Q4Yk1QdrR72m27SGB0
         kcOp3tAAX7z2vpi/O7cTVWfqfsivRimvlZOh0d/15IxlvTNGMrGTTld5ik7IbD2BSRdk
         eW0MZ23NJA8BmbiFQchbTSyMkeGSKVvagWiU6KQIW+/vg0/XId4NrBZRZdCxP81AboGT
         COmoVq1idYO/3vA9hdA9z03BYtzWpW9LZH5C3dEKfUdvNR3gz22D78C5AFOCZ0jWNIgV
         TAdygDlL1mUCfkVmO73UCqZWHxQvLbSC7oOv7w8Kd9krWc7cqSduKy8vwnSSJvSMiLBa
         QtYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Rsoo0EL+mRkVJKWS6ZFsxgLXDrHKtpFaZ1EQZw+AIFc=;
        b=laJOQe87yMfmNTbfpQRSFhRRETJrN2cSLLlw8CUhxMlay0LvpZ68BN8/lZlcWa9LS2
         VqxoxOtRZ9C/P/JaqYjfU2k3SaTSkVvoKHKMSW9yjSvlZySXeuL6RWaDyiiuRMFHFuRV
         wXziWk0eG+GW1PCo8Nks3Mp9Mn6Lr5rqf3endKhrHRHbblueAeKaRByXYGsCkKdntKNn
         TU0sjfzFjWAeq1LItJUFYyp9tvD7Xhdd22RoxU7hPKRmqPf6Y5+q2b+lES8fO5n3g7sQ
         9AzFpIt1uwOK9zR4LHfmgAXw5QMCKxO5/XGp2gkaHNgZGgY7HznZ0Soa3AnkLasxiIDJ
         GRMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Rsoo0EL+mRkVJKWS6ZFsxgLXDrHKtpFaZ1EQZw+AIFc=;
        b=ehtzeInqET76FYPCFXJ1663y8UBvFAEluC1bg9FL2Gm16Y6MT5uvc6AeZhd8AReA95
         c6QSbqJdPt0bUIVGB15Jp8c1e72fZdyDdtjYKpYm/NfH2oRSAYPuGfa8Kr+KsNOoYpTX
         b9axI9HdcTIfOhyQMSZmxLZ408VS5Y7KsJxQFPZnvzwTLNrf0FNM2Vvp8u86buxlt7WQ
         qkn6nU4ahjJrXl+Wc6YIkzwQstsQUn7P/zEjBhHc4vWl+4Jm7uad4hggomt/klMkx/uB
         woi0TAZRcntKk8yHeDres/ZdLtIJnZ/wetfWbnf581+/pZIx1vJhlXbjJEUpdpvq8ZA7
         OjEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Rsoo0EL+mRkVJKWS6ZFsxgLXDrHKtpFaZ1EQZw+AIFc=;
        b=eopNxFPgM5b1uzJc4msvnZ9G38bZVaQxyfNwAzRQ5XBllVuRbrh982ySVFDCExUF90
         r+e5bYGowcBhUv193YZ1RaO5chVB1KkD+GtnWaDfUgwxI+ma74SdZAmHKIKoutUNwIEI
         lZySsq2XAEz5VKhrB7p6jKkGH0II3DDqGnSNjMp32KXKLhrLN6jwauN5qsxZ1r4PDhF8
         RM9ngdEW+jcmWaWjk+JLxsnswy7nFUlupMS3rSa70s7AG33Hv2Jqc+7wmAO+83iVTaCf
         RY1iqQYKbCXPDeHTj9mpnl5K99z3+AqIvLtGuwOtjxRLYfNMOSCgavCGvrTJQ+bUGv3L
         bFdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Emh4mIJ9oNcgKcZQLbGxnV640BhHQdBwOSvOqxiYynu+tZhZm
	4uAH+iTuHcpkJ5+QjFwncnI=
X-Google-Smtp-Source: ABdhPJxeVOxP4z9TncAmHVqP/LxbDs9nJbez4RQIhEElGjHcEmytHqBmL6ZAKxZyPWK3XWb6sVQ3Wg==
X-Received: by 2002:ac8:3707:: with SMTP id o7mr2376294qtb.344.1606300143587;
        Wed, 25 Nov 2020 02:29:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2985:: with SMTP id o5ls756396qtd.2.gmail; Wed, 25 Nov
 2020 02:29:03 -0800 (PST)
X-Received: by 2002:ac8:5c05:: with SMTP id i5mr2387387qti.34.1606300143097;
        Wed, 25 Nov 2020 02:29:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606300143; cv=none;
        d=google.com; s=arc-20160816;
        b=Y0FkZbiAVzkzIMHppSVVMOAsNYMcaRHaKof44d6ch8TzQpqyQ2J8QyvIksp9sxPMNa
         CqYUgf12EAmj0ev5d/haVo+NvvUVGZZqK+j7RO38u/lAjyPVH7TFGgAZ0EIG9JQcOx3D
         VA1MoWU5vLcv06Uhr2/4p4BS5wgtg/ReYM282A86GVSrKturzdgpPhgOFn5JJH/MP8Cq
         v6dX7sBHhVVJGxshIn4RwD2Up95fXT5c2bcBnqlZ9suPCCB/fHtkVAkVjoxFkFNtlfz0
         it1KDtJSCVwXiPAxPEaFKdrRS+X1NIWsws8PGYjpctJm0BYJIE9rQ18OoCT+RGAn0r2S
         VDZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=KPnf+xhuoT1tlGGYFO0fv8Y/xY06pY4hZe6ns6CWD/8=;
        b=C/5fa1LRK8/Ov3uEWvEy9zADRudfk8nyHXx+srMenV7DGOn6cKwHgB/ciP+f3hQiX1
         +scOgrxWB6BYjbV8ii3Cow6sj+mUn0G69dwQKBmLzcqQ5jB/rX0nIJptQvGiaSIGX19V
         QRLTUVuntzrzqkJUNG5dqyzo4hIByb5GK6p8Np8SAv2vDmIW7VdnggrlfM+UFwvSulFP
         wJMkZKYAnNevn7FT3gAvbfKEpyRbaZB3sQBPVtmVw9Dj61gjVPzWD7j/Rn8NCTv2ZhDV
         5qOp8xMg2eG8g1OjOPjQS3VosvuTLIPLmprshnuzVJSWjgIwppYR1zbBfHfQn8qKj074
         bMGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o11si73271qke.2.2020.11.25.02.29.02
        for <kasan-dev@googlegroups.com>;
        Wed, 25 Nov 2020 02:29:03 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9AE40106F;
	Wed, 25 Nov 2020 02:29:02 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BDFA93F70D;
	Wed, 25 Nov 2020 02:28:59 -0800 (PST)
Date: Wed, 25 Nov 2020 10:28:49 +0000
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
Message-ID: <20201125102849.GB70906@C02TD0UTHF1T.local>
References: <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
 <20201120103031.GB2328@C02TD0UTHF1T.local>
 <20201120140332.GA3120165@elver.google.com>
 <20201123193241.GA45639@C02TD0UTHF1T.local>
 <20201124140310.GA811510@elver.google.com>
 <20201124193034.GB8957@C02TD0UTHF1T.local>
 <20201125094517.GA1359135@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201125094517.GA1359135@elver.google.com>
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

On Wed, Nov 25, 2020 at 10:45:17AM +0100, Marco Elver wrote:
> On Tue, Nov 24, 2020 at 07:30PM +0000, Mark Rutland wrote:

[...]

> > > I noticed there are a bunch of warnings in the log
> > > that might be relevant (see attached).
> > 
> > > [   91.184432] =============================
> > > [   91.188301] WARNING: suspicious RCU usage
> > > [   91.192316] 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25 Tainted: G        W        
> > > [   91.197536] -----------------------------
> > > [   91.201431] kernel/trace/trace_preemptirq.c:78 RCU not watching trace_hardirqs_off()!
> > > [   91.206546] 
> > > [   91.206546] other info that might help us debug this:
> > > [   91.206546] 
> > > [   91.211790] 
> > > [   91.211790] rcu_scheduler_active = 2, debug_locks = 0
> > > [   91.216454] RCU used illegally from extended quiescent state!
> > > [   91.220890] no locks held by swapper/0/0.
> > > [   91.224712] 
> > > [   91.224712] stack backtrace:
> > > [   91.228794] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G        W         5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
> > > [   91.234877] Hardware name: linux,dummy-virt (DT)
> > > [   91.239032] Call trace:
> > > [   91.242587]  dump_backtrace+0x0/0x240
> > > [   91.246500]  show_stack+0x34/0x88
> > > [   91.250295]  dump_stack+0x140/0x1bc
> > > [   91.254159]  lockdep_rcu_suspicious+0xe4/0xf8
> > > [   91.258332]  trace_hardirqs_off+0x214/0x330
> > > [   91.262462]  trace_graph_return+0x1ac/0x1d8
> > > [   91.266564]  ftrace_return_to_handler+0xa4/0x170
> > > [   91.270809]  return_to_handler+0x1c/0x38
> > > [   91.274826]  default_idle_call+0x94/0x38c
> > > [   91.278869]  do_idle+0x240/0x290
> > > [   91.282633]  rest_init+0x1e8/0x2dc
> > > [   91.286529]  arch_call_rest_init+0x1c/0x28
> > > [   91.290585]  start_kernel+0x638/0x670
> > 
> > Hmm... I suspect that arch_cpu_idle() is being traced here, and I reckon
> > we have to mark that and its callees as noinstr, since it doesn't seem
> > sane to have ftrace check whether RCU is watching for every function
> > call. Maybe Paul or Steve can correct me. ;)
> 
> Yes, it's arch_cpu_idle().
> 
> > If you still have the binary lying around, can you check whether
> > default_idle_call+0x94/0x38c is just after the call to arch_cpu_idle()?
> > If you could dump the asm around that, along with whatever faddr2line
> > tells you, that'd be a great help. 
> 
> I reran to be sure, with similar results. I've attached a
> syz-symbolize'd version of the warnings.

Thanks for confirming, and for the symbolized report.

I'll see about getting this fixed ASAP.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201125102849.GB70906%40C02TD0UTHF1T.local.
