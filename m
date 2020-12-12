Return-Path: <kasan-dev+bncBCBMVA7CUUHRBYNV2D7AKGQEVX7F53I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 010002D83C4
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Dec 2020 02:20:35 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id m7sf1820300pjr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 17:20:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607736033; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nj6/khuc8S4jzR+f570Z+5uCiukrvzmAXyBFOLny8XaT+0HqNSrqLci99iGgQAzmsX
         vQ2UvqVM/4OQA744aiMzatTJxIX7BC32fE/MxNQiE2Xwz0oOCbqb/kmv8pDRkEAgqLwh
         5c238BnWlvH6shfCFd7vYefEFPW6XkIUpQJymoVS0JbbiGKItPhyX26Uo7GI5L5sCxyk
         pOLrfCGoHJnr+6GPOzG6MUbl0aiEtKFoEJL8IruWeQtVyXfxyqyT3eHRFn39JmGRxpPC
         EBnMoTg07VJ5vS/1LeNmSkcNAPU9eHfzIXbh9RFg2ba7esMVwffxkhu7rjgcp6yYE633
         BtgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ukGqOtMLXAiWztl0yRELHEl3vbqJe4ME8UbOo7sWfJY=;
        b=QpdwxOJzOCdJXphl0MusHNJndcPEIXJNwF6tT4XDMgaMJpcR+jjpkLFqBeBPfo8xpn
         I0ekcNOO42Z4jSJ2IoItvn08WsYkzMHHjTl2CCOWwxE5upWBEF4qpX/2m4zItp03WVoA
         MB5XBgCFCibTOZCwpNVFydAkF2RHqLOjUYhUxQH1W+9ymW6A8kS0DalsW2HA1DtOL2QD
         U/ds1rSqrJYtc+eYiplHdKTEsku33pIM/U1xpHEe0SoPPLx/O2Q8efcFL7Klr1r2UoK/
         7f7iwqd6lP9C8w9LZ2Am4LlHa8ZA6BIiovAL7RUz9Z2GKBa1D1f1XDA1KzkDo3rPfhjV
         wF7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rGX1DspL;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ukGqOtMLXAiWztl0yRELHEl3vbqJe4ME8UbOo7sWfJY=;
        b=d5Bvupu3yXzRCRH2BeiSfx7wyImUvYSR6CN44TtAj0IvRTqGa9x+byPNt52N6/a9XC
         dyNcnpXwhPhxRxC0ksOD/FiQEeSop9NkNybhbC4Cz7Rf5h1dm3LnUg2ZoanqH8/pl1d3
         XmZ+gUS9QtyKwr1Gk0RIHGDbUyzPKH4jliOLUXYodOGL0zlM8c76kaVSCgUhR5Ok2vZQ
         iITzADx81w8QpyJpSzGwkuWRaRqdeZH6j4CE5Ty7yltbEnwHioNcw4TNczEGlNsPUL9j
         BU/rkx9+KYQkMw2Tg3x+YFE2gkcuvUDQeuIhyf2v9rL8QXkJrcIv0PzlEi4hDpNutaPz
         nvEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ukGqOtMLXAiWztl0yRELHEl3vbqJe4ME8UbOo7sWfJY=;
        b=IL+chYgKWqMed1M4Rz5/el8K5hqR6L85UxiUhN5H4k6NoaMD72VLvGKbks/ShvlvXp
         RK1zMhySVTXh/zL4xwjU7/luHgDtNHqXHwhDfmcgp2YtWxODHOli6iQTbgt4xFlge0qF
         Lz1LZ0Fz513PtSY+9idux1TNnSq/z/Rf1ya0Ig+3WYfCVtkWuOtB5025IV0bu0gmxhJW
         EASXUuXHldDtmOeIk35wRrZz9+wtZd2ZvRpVGluxcsHPL6iKH2PL2NZBOWwgPnVp6F4d
         g1k0q8tgavMf0qjn6X3Fhujo/DS49QbcihvDO9FCgDruEW87xdgpv53GzNA3pNep1Tn7
         znNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/8ZxHpK+C+n6BMRZ833+ZvUnmpf0C/SgvTqUROK+pwqAU9dcx
	6LsDNFx7HQkOgBgdvtomIDI=
X-Google-Smtp-Source: ABdhPJzX4xFzkCeGCIQcYb0rqyk3RJpKK0sy8HrcnY6bARbDGPHy3VY3WIBtyBPC6dp9G9Q8MqDRVQ==
X-Received: by 2002:aa7:928c:0:b029:19a:de9d:fb11 with SMTP id j12-20020aa7928c0000b029019ade9dfb11mr14436732pfa.21.1607736033695;
        Fri, 11 Dec 2020 17:20:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3192:: with SMTP id x140ls1302263pgx.6.gmail; Fri, 11
 Dec 2020 17:20:33 -0800 (PST)
X-Received: by 2002:aa7:8254:0:b029:19a:c192:5ddc with SMTP id e20-20020aa782540000b029019ac1925ddcmr14022398pfn.26.1607736033183;
        Fri, 11 Dec 2020 17:20:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607736033; cv=none;
        d=google.com; s=arc-20160816;
        b=CSVim6R7MgkNG+zsM8UnBxANQluqXg2Li1C0XGpWmcsF3GaSM44xS53YK5aS2ywOTX
         6rV3jcv2YFnXx3MS9Bx9cBMvV6RJ361O0S+JdjWCllDhG260SGCFWAQe4hA8fFQ4zp7u
         hFi83lAvNZd0UrKybZj0DvzeuEK4nLltLpLO63FOfx8WMMElL68BxNLdOKZgoh5DehJU
         G7R970U0mbe83Igulpx7CadQm8oHiM+8EZsuT8reUbzuLhRJ1+IElXTcIn3Bf0+RhMLI
         H+3eG86JiPFQ9sIeh013ARf8K5hkH4zmYbQF8JKRONl395pTXal1QaSKRcymH19z7sqx
         xkfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=/s9Ft48zijP//NZ3cF5eB8LN59NQB+To1D0BLpiPrPU=;
        b=pV8CvbiG4oJN2XyecMtTOkFQMkS1NQ35LOgfm+17m92KnNaJ5jXNJrC/bqnzgbsYlW
         T0T0+CxZFxELCr3YNfHwo6CJw6Srm+SVm5QwLRhMaeqDPTOzJs/TeRPzjzQ85zmcer7o
         03SMwj81L9lZWG1E2wDxyJryAe+wf0BfnoMqms8SrIX6N+3xQnbmyAnX1xOn5KCC85wc
         4YlXN/s++VsBZYyxhfE2xSvooDCayvkTevvKGSqXLuCEJR0SexHNZ5X253bu2HzjHpTI
         l1J7CIl8gZNatV5bqsNhgwYhKYIMhguuxeQvy9KGCOtlBj1RkcKIApnS4eW4LIMSupe4
         0LKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rGX1DspL;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id ne6si646128pjb.1.2020.12.11.17.20.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Dec 2020 17:20:33 -0800 (PST)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Sat, 12 Dec 2020 02:20:30 +0100
From: Frederic Weisbecker <frederic@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [patch 1/3] tick: Remove pointless cpu valid check in hotplug
 code
Message-ID: <20201212012030.GE595642@lothringen>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.582579516@linutronix.de>
 <20201211222104.GB595642@lothringen>
 <87v9d7g9pv.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87v9d7g9pv.fsf@nanos.tec.linutronix.de>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rGX1DspL;       spf=pass
 (google.com: domain of frederic@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Sat, Dec 12, 2020 at 01:16:12AM +0100, Thomas Gleixner wrote:
> On Fri, Dec 11 2020 at 23:21, Frederic Weisbecker wrote:
> > On Sun, Dec 06, 2020 at 10:12:54PM +0100, Thomas Gleixner wrote:
> >> tick_handover_do_timer() which is invoked when a CPU is unplugged has a
> >> @@ -407,17 +407,13 @@ EXPORT_SYMBOL_GPL(tick_broadcast_oneshot
> >>  /*
> >>   * Transfer the do_timer job away from a dying cpu.
> >>   *
> >> - * Called with interrupts disabled. Not locking required. If
> >> + * Called with interrupts disabled. No locking required. If
> >>   * tick_do_timer_cpu is owned by this cpu, nothing can change it.
> >>   */
> >>  void tick_handover_do_timer(void)
> >>  {
> >> -	if (tick_do_timer_cpu == smp_processor_id()) {
> >> -		int cpu = cpumask_first(cpu_online_mask);
> >> -
> >> -		tick_do_timer_cpu = (cpu < nr_cpu_ids) ? cpu :
> >> -			TICK_DO_TIMER_NONE;
> >> -	}
> >> +	if (tick_do_timer_cpu == smp_processor_id())
> >> +		tick_do_timer_cpu = cpumask_first(cpu_online_mask);
> >
> > I was about to whine that this randomly chosen CPU may be idle and leave
> > the timekeeping stale until I realized that stop_machine() is running at that
> > time. Might be worth adding a comment about that.
> >
> > Also why not just setting it to TICK_DO_TIMER_NONE and be done with it? Perhaps
> > to avoid that all the CPUs to compete and contend on jiffies update after stop
> > machine?
> 
> No. Because we'd need to add the NONE magic to NOHZ=n kernels which does
> not make sense.

I forgot about that other half of the world.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201212012030.GE595642%40lothringen.
