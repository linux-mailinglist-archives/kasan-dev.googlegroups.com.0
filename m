Return-Path: <kasan-dev+bncBAABB54E4T3AKGQEMAAJNQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EA431EE672
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 16:17:28 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id ga20sf2179491pjb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 07:17:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591280247; cv=pass;
        d=google.com; s=arc-20160816;
        b=K0SHYutf3rjIIRl3hJrCIbK02yerQg/KDIFeMYMyZ9dpiiLBkH+ABl/kNTMyabT9h6
         iRTFTpLqGJJppzVb+F0SjskQ/IptaAGkb/3cJXrQ4GHdtM0xYQgvrOInBST6NhnuTCKq
         iZdlMyZ7F72o3FyP/hNlURxoOEg/LaE0y7T5w9PTLBBoHmZXddcSCYu3SX977scYjp3E
         osJ91mA7UYIkERWKLaJT+8v+dtv9SDeBeemK406akjI0nePa/B9Frvz8Dk+N9DQFp5Jr
         awiKUwV4n3hVDBZ6WU5dvJHtMg7ckVmwEzQEcBlq19OHbF1gswVEEcVtY0lnbW8PmYhv
         4KPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Xx/d36rQxGfAsYiVUgytrmifICuPYnyffwugKu2t1e8=;
        b=PtzNNTzPyaLquGsYAJZ2X8XoBPE7t4X1i1GNgrma9aBmoNw8CpbIFgaTu9+2iavYJv
         oiCZD8Jian5/cYOfWojiSTGX5rE28tu+t7hi6+FF/+P0xdqQU5u2d/s8LqkdzToXvE6t
         Vk1m8/odgodPzmVhxGLo1ddHClaW0ZAqxeP25ArpZF0AcOotKw0nkdJk3XGAk4zZZUZN
         FDQLYtMWE+J/gpv37mbsTHoNZE2ezARBfRDrS9pfqVYHNLS8Onvct6vxmVvDrQOvQez7
         HcWzmRNUIbWxAjesUOAFTvokWLBlJN3GUWH/NLmUiRfsmDzAwN79l9ZspU5YR5+pmjr3
         K7rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EdPxM+57;
       spf=pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xx/d36rQxGfAsYiVUgytrmifICuPYnyffwugKu2t1e8=;
        b=qj6jg94bfa5u0jDyxILXW1WyN8/SsxNP6Csgnr/D9aBfvOsPZG6druDnUYzkiOO3R1
         3m6toCRHZGUyyr2C/Q61W5mAphab6tl3O5MdOXGobqNR/R0U6JONSxzFmjflat0URR4T
         uGvQLY+o1KtiGM3uYwwOhn0NoPXUNQw5qhe8Q74Du49YOVPACk9PsXM8njIpUGm2oXyr
         5HncfkyBYBPF1VBdCVG783SCv1ebjkUAubjHvhp6uoh+j3DjfSrz1tD9PGd/rQ0y2hza
         Nj3P8uEpqRh6oblRKs1hRUmFvsMh3JJeL2vC1/WDrSiAH8u2o4jvjW1ajEoWnGEceVxO
         e/fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xx/d36rQxGfAsYiVUgytrmifICuPYnyffwugKu2t1e8=;
        b=ZB/xSKXrtXm6y0AxPrsMufymbgGfOtxRh/NfkkwAMSKmo6QhDvaYOnGHZeecjcOqvj
         zsxNRgyNZLn91qxLTUihr3KyQqVTwUtYZzLCe9fLnx05Aiuwba0ZeFzCraHNERzjZH+/
         BW8EXjbi1rQsQ4yN97gO6Ob2NTRFc2TRzJY5xB06uv5Om3/kc3qmIKfOB0L4YDimJZd7
         P4iV8AHJpixXE74ymhlghCwBsktfLUnhnh8Tp2vvLMHfwn+lxNVE/FKwTutHxoGsVx4R
         5TtepM1tTV8Uktl4DyAc0Rk/GWXN4Pj84PEaLEeOo0kW+S9L6sqZs7rT1Opv8xEB5Pbx
         IOzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533t10Ro3Hy223+QUGyr4rexHAHqTEBfCcPbDHQMERw+pjyC6jVK
	jK86ofsUiRjfwoKDJKhb+7Q=
X-Google-Smtp-Source: ABdhPJxAn45w7dzPmxUvR+nWPrsvYFTKGzpSDFUa6bhLWHEH+J/LrD4lkl0lgPFP2NUhItwLtwnSjg==
X-Received: by 2002:a62:27c5:: with SMTP id n188mr1505465pfn.127.1591280247301;
        Thu, 04 Jun 2020 07:17:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e312:: with SMTP id g18ls1898465pfh.9.gmail; Thu, 04 Jun
 2020 07:17:27 -0700 (PDT)
X-Received: by 2002:a63:f856:: with SMTP id v22mr4820374pgj.64.1591280246944;
        Thu, 04 Jun 2020 07:17:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591280246; cv=none;
        d=google.com; s=arc-20160816;
        b=rnTE/KPV57zaN4rFimtavDl24DDeZUSyPtg6u8RFPrHCFWogWyM2p/p00GfA3zPVzD
         bptuS/5PW39OWbBfJ4OhcMxfCRKTao4TB2qKZ1bxtqTszcsQbsy49Zg4DHBrix31Csfo
         OGuMTDeKUocCCLNi/rGpCU85VHmxD9GdVVmIObkpKW61rj9wYEqpglEVBDsVtao0HWC6
         5nt0nbjSbGbtXzf8SIVzUVNGimo/JMtv5lPUTTqrTqIdMx992q/0H3Mmk7wF9A1+bKhA
         yG8eWLDB64f0ybPlps00xpmir4lwg1f9sdbayfw82EclCtXu7KA6AeUBTG+elnvYcbYb
         zpFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=+pobFWs+0DvFU7cQug1zqKnLi3uIERafZOrjN1r5sfw=;
        b=FInB+rDBY8VWQiieNRb4kVCAL0MVq2Dk5yce+3CeGN9ftiojLM5LzuMuw1qaS42mf9
         JjrdH5VeLbi8sKxdF/jxZ3+/iAxTnyHGM7K21/aha6aA+RyiW6I7cXVnbv1qpP5n0+rA
         Q9e/jWNH0NOGkvr7OVaxApfYC4o8Lf6OyjvOG/BZjWEs9P8f8zfFID/+wd7tqfF9Oz1u
         1DTZ+eXtAqqQfJenw4d3Iy7P1e44/S24pa01qTq5nSHnyRZ9lKM28DBkmhie3peiaSFB
         COzY8aoe8+HPr/ePZG1QsSrd2lIEV6fT25NgzUcbloI1dUbIWi+v8E0EwmCahWmEK51a
         lPgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EdPxM+57;
       spf=pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i4si231182pgl.0.2020.06.04.07.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Jun 2020 07:17:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9D86920663;
	Thu,  4 Jun 2020 14:17:26 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 8558935228BC; Thu,  4 Jun 2020 07:17:26 -0700 (PDT)
Date: Thu, 4 Jun 2020 07:17:26 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200604141726.GZ29598@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
 <20200603171320.GE2570@hirez.programming.kicks-ass.net>
 <20200604033409.GX29598@paulmck-ThinkPad-P72>
 <20200604080512.GA2587@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200604080512.GA2587@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=EdPxM+57;       spf=pass
 (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Jun 04, 2020 at 10:05:12AM +0200, Peter Zijlstra wrote:
> On Wed, Jun 03, 2020 at 08:34:09PM -0700, Paul E. McKenney wrote:
> > On Wed, Jun 03, 2020 at 07:13:20PM +0200, Peter Zijlstra wrote:
> > > On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:
> 
> > > > > @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
> > > > >  {
> > > > >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > > > >  
> > > > > -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > > > > +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > > 
> > > The above is actually instrumented by KCSAN, due to arch_atomic_read()
> > > being a READ_ONCE() and it now understanding volatile.
> > > 
> > > > Also instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) as
> > 
> > Right, this should instead be instrument_read(...).
> > 
> > Though if KCSAN is unconditionally instrumenting volatile, how does
> > this help?  Or does KCSAN's instrumentation of volatile somehow avoid
> > causing trouble?
> 
> As Marco already explained, when used inside noinstr no instrumentation
> will be emitted, when used outside noinstr it will emit the right
> instrumentation.
> 
> > > > o	In theory in rcu_irq_exit_preempt(), but as this generates code
> > > > 	only in lockdep builds, it might not be worth worrying about.
> > > > 
> > > > o	Ditto for rcu_irq_exit_check_preempt().
> > > > 
> > > > o	Ditto for __rcu_irq_enter_check_tick().
> > > 
> > > Not these, afaict they're all the above arch_atomic_read(), which is
> > > instrumented due to volatile in these cases.
> 
> I this case, the above call-sites are all not noinstr (double negative!)
> and will thus cause instrumentation to be emitted.
> 
> This is all a 'special' case for arch_atomic_read() (and _set()),
> because they're basically READ_ONCE() (and WRITE_ONCE() resp.). The
> normal atomics are asm() and it doesn't do anything for those (although
> I suppose clang could, since it has this internal assembler to parse the
> inline asm, but afaiu that's not something GCC ever wants to do).

Got it, and I had missed the inlining.

Again, commenting this will be interesting.  And your earlier comment
about the compiler refusing to inline now makes sense...

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604141726.GZ29598%40paulmck-ThinkPad-P72.
