Return-Path: <kasan-dev+bncBAABBZHT5H7AKGQEMAHVCMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AE0F2DC83E
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 22:19:34 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id z8sf29402475ilq.21
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 13:19:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608153573; cv=pass;
        d=google.com; s=arc-20160816;
        b=RxvPuGAwKaxzNqtwlJDIXU7QPTYVrENPCN/MC+J1w78xhVxRhWxL404YwrzKzHAcwY
         hSc/pbrandEdY98FFxzkLJoX1koO+DwvpbDGXL79TCToV0MQrC/fPmDzg43Di10VR9Ju
         PGxLfGAwnUXo1KbU/W0BN2eOP7s5gTvjlnmramMK+2mSy03osQj60clodQVvR1BACXAO
         E0435E+X9v8OIA3xBRdHgZE0k+pQHETyVSf5KEFVSZoqvCe8XKihJpgDUq60LU2BTLd1
         +Y5t4ImIhX/LTTFOeO1lQYZOgmsTNtkeUb5VQ2dORMFFsb1C0QvLt+V2mjirL11uuXhN
         +k8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Y+tqceuLpiIhJ5cGtJERKnNwxqMxavsNktqcdBnxAY0=;
        b=Ph77GMEvDQEgKgXMrxC02VQw0bYXJ5YYxogeLZ7/1SrohtXvBLMj232BV2SmsVRitq
         0OdA5I4EhdSiJE9EWiFdT3rUE/P+yQhoi8gb/488GA0Ap2XvoH3g5GOIf9CxNHg80VKP
         ZQx6VdxuOlQbOcEcoeTWWqpBzgIfig4Dhji/8GI9P5OTMoX+oUG+8XNX5pPTSLrOLW8d
         jNwmde9L26mL8Y2tqMTsI2gYVuPbjTuJDtBpBRERmy8HOSkuKJ77wFAlX0EAcDADn5Q5
         vP1MmxO17uQGVDHCXyACtgfo+EezYQTXk+a9XZY5q21zmo8vC8S9UWhUbmjebAPRk6rp
         gR1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E2H/iXWW";
       spf=pass (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FHSX=FU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y+tqceuLpiIhJ5cGtJERKnNwxqMxavsNktqcdBnxAY0=;
        b=fMwhPobtNnKlQ05e4psk8306weAue0zeA/fIM7VuFmIr02lCbTQUMdViyseuNNIhXi
         pwr5rCXPngi7gbESWqIUOS5OJXp8sSD6Lc3ACFMU0Mh/0P1fERBNBtBFGIOhI6kFgG2s
         l97fO5wyaZ8Y9g5ZwVVr6i9f217FL1Ng/YolFqDqg+jab7rBgoDDJ5peQC6RTeLz14Kf
         +9/NUy2q3WFOzUiKtj57qfMGDhBN1meh2/VJGE2XOu+Nnr1d2MQkCxa8sFo+TQSfTPhQ
         xEG5C1/F0o/deFHqFKwr/0Q0Qkx6arpk1mjXHSHhroVreSKX92Apn2WkB9l3zqqIUTzC
         QHCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y+tqceuLpiIhJ5cGtJERKnNwxqMxavsNktqcdBnxAY0=;
        b=IM6wa8xAEFhZg7HPOWzx1FqaE1tYh7VmFXDEquldCSDSITzex5QdhC/iNmvyeyNvrU
         v6YT/vxn0SRUWnopqT9X5WwBCo3iUXcpRTEeuLB7812PwsdUtB7m5ag0rifE7fcetl2G
         VRPFZ3t01VdRhOsPVIncqwG0tG9DSm40/b5JCgPX/TDh6A8tKfAwy/Z9NCHzxk3ahYMz
         p+a1VUW1pJegapOGFNHIFB8ZB0XZi/xXKADj+KngoLrcr3cWdJQQH/vmOqAZSecQ6YyZ
         iQrHjyBdIiR5dPsFcDOHXyN9R5dMZ8RTZ5oYwsobZdNvLz9j11BURhVwqNyvbuzVaJ6Q
         pJMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HT8xKNIh3OmnGAMXm6QfRei+xcYWGLJwY3uY3Jx4CY8Sk9Fqz
	dj2+qsHAJ5qMYUWPUkZuj0c=
X-Google-Smtp-Source: ABdhPJxVEV2WiWru42/fDptKHPIIayfkSH2StjX37vGtkRLzOFURTjsHkHYUsxp+m7ggqlzWEQ+B0w==
X-Received: by 2002:a05:6638:50c:: with SMTP id i12mr45341863jar.74.1608153573020;
        Wed, 16 Dec 2020 13:19:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:25c6:: with SMTP id d6ls1819375iop.8.gmail; Wed, 16
 Dec 2020 13:19:32 -0800 (PST)
X-Received: by 2002:a5e:970d:: with SMTP id w13mr43959125ioj.166.1608153572529;
        Wed, 16 Dec 2020 13:19:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608153572; cv=none;
        d=google.com; s=arc-20160816;
        b=wSZ3E8XAc73c51sVqFlUSnL9tyUA1cJUUA/d9mPl9lD4JHNcesSMzaW+psThsctPOw
         XBurf1T2DjhJBaKyQspJRqc5HwHbKB70gxHEbSRfmBDuEZH1kIpLH3a18l2kEl6WVoz3
         ag1mZ7C5AZtyLOiwJ65Szl4tjlEJa3LFT7e3roed9y/n0YhqB5+ewtYUvMsziaxPd/Wi
         jTJFiXCjzlGo/6JVeHbpwkiUG3cEZrzBeKpYBv74sIccWmLMoT4P7NmcnrDfwpevUvZn
         fIBOqZqYAQGl4V+z4Ndne4B87lKSkSDg4cnv6NyRNIw+szHL0+IwtL6CMK9RVXQZIMH8
         54Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=ilk/J/qb8gwKkvaER5i3Z6eHfcGNayEIOpNnD7vCN4I=;
        b=rBmeQj7Qd4S15Uhf1ZkHpRuLZBpMuOGi/PZmZQtO3qP5byNfmeeykGzI/KwL0lbBSI
         j2PNnkQD3V362/pu9tusXiM2D8/cmUNz07Mvdpx+BqgrFEVI7jYciX+pQx3VYfN4FImA
         +7hNknFdalOZqCgFfHR1v8vn9tLT5VKYsu6pTGByYqCQgHoP403cjuT6DNHlpcqfl2o9
         nezwTRzyD+ydQtImsXSL0/3MvwaEN9ZMNGnpNJLlt3zO1TX36hNqvCmyUU5ENv/cbqzl
         oQYcnZwpkPXrJHVerMfW7ByiSq8ZiPJszhRoCK7wLiCk6Lyc6KBJP/wQCawzZh0jxa7S
         U+kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E2H/iXWW";
       spf=pass (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FHSX=FU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a18si183772iow.4.2020.12.16.13.19.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Dec 2020 13:19:32 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Wed, 16 Dec 2020 13:19:31 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201216211931.GL2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
 <20201208081129.GQ2414@hirez.programming.kicks-ass.net>
 <20201208150309.GP2657@paulmck-ThinkPad-P72>
 <873606tx1c.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <873606tx1c.fsf@nanos.tec.linutronix.de>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="E2H/iXWW";       spf=pass
 (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FHSX=FU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Dec 16, 2020 at 01:27:43AM +0100, Thomas Gleixner wrote:
> On Tue, Dec 08 2020 at 07:03, Paul E. McKenney wrote:
> 
> > On Tue, Dec 08, 2020 at 09:11:29AM +0100, Peter Zijlstra wrote:
> >> On Mon, Dec 07, 2020 at 11:44:06AM -0800, Paul E. McKenney wrote:
> >> 
> >> > Also, in this particular case, why data_race() rather than READ_ONCE()?
> >> > Do we really expect the compiler to be able to optimize this case
> >> > significantly without READ_ONCE()?
> 
> There is probably not much optimization potential for the compiler if
> data_race() is used vs. READ/WRITE_ONCE() in this code.

OK, got it.

> >> It's about intent and how the code reads. READ_ONCE() is something
> >> completely different from data_race(). data_race() is correct here.
> >
> > Why?
> 
> Lemme answer that to the extent why _I_ chose data_race() - aside of my
> likely confusion over our IRC conversation.
> 
> The code does not really care about the compiler trying to be clever or
> not as it is designed to be tolerant of all sorts of concurrency
> including competing writes. It does not care about multiple reloads
> either.  It neither cares about invented stores as long as these
> invented stores are not storing phantasy values.
> 
> The only thing it cares about is store/load tearing, but there is no
> 'clever' way to use that because of the only valid transitions of
> 'cpunr' which comes from smp_processor_id() to TICK_DO_TIMER_NONE which
> is the only constant involved or the other way round (which is
> intentionally subject to competing stores).
> 
> If the compiler is free to store the 32bit value as 4 seperate bytes or
> does invented stores with phantasy values, then there is surely a reason
> to switch to READ/WRITE_ONCE(), but that'd be a really daft reason.
> 
> So my intent was to document that this code does not care about anything
> else than what I'd consider to be plain compiler bugs.
> 
> My conclusion might be wrong as usual :)

Given that there is no optimization potential, then the main reason to use
data_race() instead of *_ONCE() is to prevent KCSAN from considering the
accesses when looking for data races.  But that is mostly for debugging
accesses, in cases when these accesses are not really part of the
concurrent algorithm.

So if I understand the situation correctly, I would be using *ONCE().

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201216211931.GL2657%40paulmck-ThinkPad-P72.
