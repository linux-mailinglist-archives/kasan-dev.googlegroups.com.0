Return-Path: <kasan-dev+bncBCBMVA7CUUHRBXXGZ77AKGQET2LGZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id B40532D821C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 23:31:59 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id gv14sf2784685pjb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 14:31:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607725918; cv=pass;
        d=google.com; s=arc-20160816;
        b=nth+vmO/M0qYkc8cpZAGf2oV6Bpa8R0KVBQzGdQDeGOygKXxNeHOgTPbsyhhw89kAF
         hw7Zz4Xs3HC5LMi1Udk8mh2hsvQeZDJeGNd1ggCKPZg/VTGwX2NU4c0nnTPa0G//xbVW
         iOh/aiDmk4LZxiDgtyK4HAqoIXBYUlIUATwgw+v+O5nuW8R6t5O2D63gJQScsGctwYox
         fFJ/f+ydnIIrzw2QZfJdsXYtegvUTcrXEnFchNGchra9KqFDo5kbYLo/fG2f5mkjtKFG
         7T//HNSMN2eB+FdP6FLZAxgZeJ/MyvlRfcAnpiwRuq6HwWhmFal4vDP4QBdwJaBZ79r2
         Pmzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1E6QGD+/0giwIVegU8k04OWX8ba3Y9Cp9OVI21nIM/8=;
        b=QAiZC9gbJ3oGTGyKmX+dHSzGRtAT76YYDziAo6JPlORT7WtosknUSCsvqTrEoP77VD
         bVFPkdGWN3ZaOu3R8zHdDZpTGOlcAj1/w3ecT6B6ljC3S/57EENo3SnptYs6psb7RGcQ
         afcxZYCXw7+Ql0FzcZYQdTVE7rJ4K/z/9JuQjxPVw/faMBSEEpnhNonqGVXqPC1fFykM
         mRJM1nQJDuYQ8FrIzlLgFIh6rmWyPZtNAuHXCsoFl1oGvAcIJ69iM+3RRePrs2mRbb9R
         r+lMyFqxRy2vk0CGK5LvNuytxZ5J2gwYx/UrKa9l2+d6iuQSFPK2E2l7+Iix5YA9bdOQ
         jNPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eKhSc8az;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1E6QGD+/0giwIVegU8k04OWX8ba3Y9Cp9OVI21nIM/8=;
        b=lALn8k11LfR9IcHVVYBNn2d3i8ulH8LWf+zii7J6OgFdMXByvv9ZLRXgtZsGdjEb8A
         jrSMge43xres9xa3Fjq6z8BBkSi+ZEOeuq989vDeBoeEIwTj9h2PEv2wZnWDTWvRMx0t
         aTzoP1AVMWrH5Qv0hoHSGNwgkQxES7lqw4NfZz8AZnEZF4PY+UOEOX/ZqgxGIYb5Sccs
         qbOHy6GukeV+jztNHInCTlcmyOZHK8Aa/yu8gBunmHCaMSlU1MAE3/992crLucrZhlqS
         yQN8p7nWbYBfamOChOFm+9xparXL9qmtz6bXCxJ+JWQl29y0bV9Wn6njcuIjWKYX69aS
         hRWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1E6QGD+/0giwIVegU8k04OWX8ba3Y9Cp9OVI21nIM/8=;
        b=fj6RUIQ9WCLZhlUbkLKmpmMVIhJypZ8UlWf1S6F3jITcWE89dUed1GEuGVyKWe+LX/
         UqoncHhWUintl/ETn+YMgMd6Ns5VCTyiHVN3BCE3pkzNJvKvLNjkBZFNQQRXJumJqxql
         rYxSGAJH8xBltVtUNFx2MxRGpSna3RnBdNk66KVhbl9fi5dBOv9g1i4hrHJOa/GS4jJx
         58MeJK6+17vokKw+oDjC0hSockq/fSqAs2Z2ZXuFLGCV85UpGamEUBH4dG1j961nnILN
         lJjastdtSvrNK12GwQW3p9/OADU6p29SqNV47ub+MQ4qvu91rCxevcTtOzST+rQ+xg2l
         jwQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BHN0v65Dw7Gouo0GBZd+BkR3mUYBOJ8GC/CkA2XTA+QK/ZHSe
	Z8fIimV1Nv6c2hoxdtizRQ0=
X-Google-Smtp-Source: ABdhPJx2v718X2lJUy3YOLIl8UPcHCblsUJFe6XM9IVAAuKtP45GDPErUm8h+lvm+MMADfsXGnRXXQ==
X-Received: by 2002:a65:4847:: with SMTP id i7mr13787669pgs.223.1607725918335;
        Fri, 11 Dec 2020 14:31:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3192:: with SMTP id x140ls1154834pgx.6.gmail; Fri, 11
 Dec 2020 14:31:57 -0800 (PST)
X-Received: by 2002:a65:5948:: with SMTP id g8mr13891671pgu.51.1607725917768;
        Fri, 11 Dec 2020 14:31:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607725917; cv=none;
        d=google.com; s=arc-20160816;
        b=Rg7QMTwT2QnYZb52wqUvhzs2EM77zPTFDZuy+Agtg63+Ns2+ph/2OCnauxuZgtznnz
         XG0dCx/Oo6ymoIetGsSEmLMRK3WRgCYabQcB9r1uFqS4G4DjDg1R/v4iASAlnk2EAryw
         wwhOVRUZ7gLJhifrqnsRgNADiueXVcoGzm3JklzRjVOwmUyfikdpffZPzEh3z5xpiD6J
         8ZHOxSO4uwvwNkz1/PpmJc8tADzx9z6a5wKjUVzkC9C2F/+OIfJ0dJMFBZ3QiyfnFFvp
         XBehKsQDifJCKctDrALwF/Id5/X40ObrynyP7eR1Nq2pdwCa45mKlMWfLydpg6oDQh2v
         3rLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=S7DK6nnlalIt9NrZFwKuCIpmsjHJD2IVAeV6Ft3Z6bk=;
        b=Jhg0/7AUDM/3r90hI+Isn6hCLgCkkesWF/XVRF+GyXvaEjOoVYXACHmKE+pG3IRuzv
         SALq4HUGQlHaYRr4flIigviuI6wyeBZQpI0lEyN4Cj07i/tf7XIUq9qeYJOENon/5wD4
         NWpv/Wjb14euS6k7EF1+2/R/DT6yCBVU/Ie5IMRZRtnnuZ/vEW4CT77NTf2wBepTyXEY
         JYd5AZe40CUkKxYqfPOy28QtplAaKcZ3Dh9/hkuV143K/AxU9yyMegJAGzSrQ+Qzbhcb
         RXQy3cv6DbB5XGSrnmxX0wfuY2jgi/KW6/nOkTNVltndD57q3lNt31FgWhM3WFOsbGLL
         ca2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eKhSc8az;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e6si819410pgf.3.2020.12.11.14.31.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Dec 2020 14:31:57 -0800 (PST)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Fri, 11 Dec 2020 23:31:55 +0100
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
Message-ID: <20201211223155.GC595642@lothringen>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.582579516@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201206212002.582579516@linutronix.de>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eKhSc8az;       spf=pass
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

On Sun, Dec 06, 2020 at 10:12:54PM +0100, Thomas Gleixner wrote:
> tick_handover_do_timer() which is invoked when a CPU is unplugged has a
> check for cpumask_first(cpu_online_mask) when it tries to hand over the
> tick update duty.
> 
> Checking the result of cpumask_first() there is pointless because if the
> online mask is empty at this point, then this would be the last CPU in the
> system going offline, which is impossible. There is always at least one CPU
> remaining. If online mask would be really empty then the timer duty would
> be the least of the resulting problems.
> 
> Remove the well meant check simply because it is pointless and confusing.
> 
> Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
> ---
>  kernel/time/tick-common.c |   10 +++-------
>  1 file changed, 3 insertions(+), 7 deletions(-)
> 
> --- a/kernel/time/tick-common.c
> +++ b/kernel/time/tick-common.c
> @@ -407,17 +407,13 @@ EXPORT_SYMBOL_GPL(tick_broadcast_oneshot
>  /*
>   * Transfer the do_timer job away from a dying cpu.
>   *
> - * Called with interrupts disabled. Not locking required. If
> + * Called with interrupts disabled. No locking required. If
>   * tick_do_timer_cpu is owned by this cpu, nothing can change it.
>   */
>  void tick_handover_do_timer(void)
>  {
> -	if (tick_do_timer_cpu == smp_processor_id()) {
> -		int cpu = cpumask_first(cpu_online_mask);
> -
> -		tick_do_timer_cpu = (cpu < nr_cpu_ids) ? cpu :
> -			TICK_DO_TIMER_NONE;
> -	}
> +	if (tick_do_timer_cpu == smp_processor_id())
> +		tick_do_timer_cpu = cpumask_first(cpu_online_mask);
>  }

BTW since we have that, why do we need:

static bool can_stop_idle_tick(int cpu, struct tick_sched *ts)
{
	/*
	 * If this CPU is offline and it is the one which updates
	 * jiffies, then give up the assignment and let it be taken by
	 * the CPU which runs the tick timer next. If we don't drop
	 * this here the jiffies might be stale and do_timer() never
	 * invoked.
	 */
	if (unlikely(!cpu_online(cpu))) {
		if (cpu == tick_do_timer_cpu)
			tick_do_timer_cpu = TICK_DO_TIMER_NONE;


We should only enter idle with an offline CPU after calling
tick_handover_do_timer() so (cpu == tick_do_timer_cpu) shouldn't be possible.

Or am I missing something?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201211223155.GC595642%40lothringen.
