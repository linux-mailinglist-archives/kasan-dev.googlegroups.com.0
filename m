Return-Path: <kasan-dev+bncBDAMN6NI5EERBTUX2D7AKGQE5MFZFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6014C2D8353
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Dec 2020 01:16:15 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id e16sf3011620lfd.19
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 16:16:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607732175; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eb47C16vQ6cAVBG2MBpcLkHoEiDGMpQ05kNkSuB6l7JpQUfWPlCyl7Cn3cqFBeQHSJ
         iiTUFKCgNn+qyQR1PTpJgJB/zpt5MRmtpe/ZCYOYEiQZ2JnO8Foukw3fzaDMHYFR9Ww2
         LmuLE842+bCXCWhpC/joH8zAML4wtfzELVuprDuprRZZfuRIvQHP7IFAu5Qm3jVlLgON
         8PcrJpKpOs0PJseyr0oTRVrZB14/HoKnASeop3pbx8obwQTx08h/ybTjv9b1MM5UIVmX
         eSAyB7xEsqLz251kc/jf3WF3CoR69gqxrFvnXFeoL15mPO4Y58ycijsqSjydwuEPn1vr
         qyaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=e1FzPx0hJ9vndm4rBZe6YPjXbp3TXoM3x5YCZAvw6NY=;
        b=cL2AzPnfA9XWtMhKJtdWjeJGvSPfLw19MfEqWo0dqXVtKIl+AtJVUdMJ5AeS+ASSol
         5tJgqJ6nq2cxXunxv9f5LobMss7Hen961Xrko8YteQCOoJ6ysWC0S6eOM8V2/Uv8W79O
         kxghP0npeOwWz8fUfF0vWgp3HsNEs26O30+wRgyFkXDEAe6p20GcbHqt/meEjDfX5TNZ
         ZP7/0eQvD1UhEo5NVduIleCEeoDjFBKzz6bxtAUeamIx3AxpnJK64d2fu3tH/Hpy0Oog
         e9L/Z/QSMj27lbGaHSRyA9w5i1FqZpySfdu4PNzzPurMrGEaxaTXui1vsLs54M0slSIV
         j+hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=MTPSXyZN;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e1FzPx0hJ9vndm4rBZe6YPjXbp3TXoM3x5YCZAvw6NY=;
        b=NWJAiKgTW/FttPAHUNGCLNuvBfrq3WZn9AwtcRd0yzcT92Y4/hv1wtmHKBR/YSJMuG
         5agVSDLqntCIvESsXG6xg85mNBqzzfXYdSE1EnW6TGw/NN86TwVIAIbO9k4NCNO/EFKb
         OLjahu67ngiMutsJWQ5maJSX6EiGOk3Gy21QBmiIwpveHliZWDwuyf2ZTxK5v0iy596q
         3Yhl8uc/KAPv123jgHj8ODo6JkKdUkRB3HHMzJMzkj6fpSWU7oi4ow8v3JDP+u8Ctkxx
         fFohU1Gm7HWnVsDc6nB2WBWkGH/43g9gisrjpSYgkiD01D0RDvGymPDlotFtKEI2y/AB
         3vlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e1FzPx0hJ9vndm4rBZe6YPjXbp3TXoM3x5YCZAvw6NY=;
        b=kI1jsLqXTp+1Eq7qWGHs/COuLAjxJXDoWb1VLVWunCFddZJ/c1DUU+88xJE1EGChh0
         0PyykX1opXuvKHgcpu1eIFCnxQbWcEm44tpT28I0+Kvv7TCd989HGgzHzNFA2rx6rvPl
         oi74Tv296ex7Tz90DPqFWiKJBiL/24ch1vdasTcWxd9uxQvRkxpJYZB41xCuhDkV+Xec
         gMmiaksuUT+pubY9WQZNCqsnT8RBhuX0UBIbSrdtij2umEOJPSnvF+lt2OW66Insc5MU
         5VZiLlKXtuAJOhPSlBEeOd6LnpL8NWYW9nZM440Z3CVVa02ynccGuLXw1sssipdqBtoy
         CTPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530K42zEes1pwg6/RlkkPX/8qtVFCHrhxMLlmiqYps0OQ/t7gVxg
	o2cFKqEZC0evujUdJDbMNi0=
X-Google-Smtp-Source: ABdhPJy2CHMv71zZSptgBr3emuoYKLxPoSd4ciT+kqVrkgIGDuO/214koiNd8P2wIVdqlWZsr0NdUQ==
X-Received: by 2002:a19:385e:: with SMTP id d30mr6098288lfj.187.1607732174914;
        Fri, 11 Dec 2020 16:16:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c1cd:: with SMTP id r196ls391451lff.1.gmail; Fri, 11 Dec
 2020 16:16:13 -0800 (PST)
X-Received: by 2002:a19:c7c5:: with SMTP id x188mr5310717lff.289.1607732173896;
        Fri, 11 Dec 2020 16:16:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607732173; cv=none;
        d=google.com; s=arc-20160816;
        b=TvFuoiaAo/kXxMYG3hQ+TkyJPbw1tJ5WELdAgv8RpYe6jEsjcD/6jGP2TNral0SkvS
         jqe/EkqUUNq6jY5MiysRepE42LgkLzAnXX8qEq/ElW4E7mcm0FwR7kBevtelzyckmkiT
         4GI9rhj6QvPIbw4tcOAy/87bfVsJkiCmAOB4wSF+hrU5x9TQMWsj2lWyObfCbhxhonLw
         +grhacQXqZ9VlCgdcMYgSQVjB/tL2YnFGgibwEwWhNs20Q/VuQa0iPzE2ggcbX6p0yhL
         AHlQUhhDkcGkdHROwctYHGW0wQgyWm347ZhBvDtsZ/ovYnBQ8t7HTbZ4KhsBIqDrkpVc
         TauA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=hqbFRYPDhcqtawXKx6n1the+OBNiDCmjIGiR3orx8EA=;
        b=FbLN8V0ccFKV6DfeyPj+t09/rVpSXGDFYhdPTbpknxqfu6g3/UbifKVXMgBFQ1A5UO
         Xlq9NeQionzQTxgQhj2Xczo7N8LgwxeFbVwi1ydnwgxLP/RHOQ5hQdG+cBDLQAsDzAQk
         m5u71JLEf52Jv7ZEqVBsZPhjtduHulob7bhTRCHlOt/z2fE/Q+B4sztMuDg6BGV1jHCd
         Bhxq5VSCWg7rO3ZEv9FCbHunSUgl23TTwwe2Pxhxfk8afoqjIipuWU+zQmeIVqbUZBaz
         TGyNERQhwZRwITBZME3xOAYb4JKh9YOJ/N/tnbcAf0oK0wV6DpgMQNFSR/M4TOmNvBuY
         AdHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=MTPSXyZN;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id h21si421710ljj.6.2020.12.11.16.16.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Dec 2020 16:16:13 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Frederic Weisbecker <frederic@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [patch 1/3] tick: Remove pointless cpu valid check in hotplug code
In-Reply-To: <20201211222104.GB595642@lothringen>
References: <20201206211253.919834182@linutronix.de> <20201206212002.582579516@linutronix.de> <20201211222104.GB595642@lothringen>
Date: Sat, 12 Dec 2020 01:16:12 +0100
Message-ID: <87v9d7g9pv.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=MTPSXyZN;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Fri, Dec 11 2020 at 23:21, Frederic Weisbecker wrote:
> On Sun, Dec 06, 2020 at 10:12:54PM +0100, Thomas Gleixner wrote:
>> tick_handover_do_timer() which is invoked when a CPU is unplugged has a
>> @@ -407,17 +407,13 @@ EXPORT_SYMBOL_GPL(tick_broadcast_oneshot
>>  /*
>>   * Transfer the do_timer job away from a dying cpu.
>>   *
>> - * Called with interrupts disabled. Not locking required. If
>> + * Called with interrupts disabled. No locking required. If
>>   * tick_do_timer_cpu is owned by this cpu, nothing can change it.
>>   */
>>  void tick_handover_do_timer(void)
>>  {
>> -	if (tick_do_timer_cpu == smp_processor_id()) {
>> -		int cpu = cpumask_first(cpu_online_mask);
>> -
>> -		tick_do_timer_cpu = (cpu < nr_cpu_ids) ? cpu :
>> -			TICK_DO_TIMER_NONE;
>> -	}
>> +	if (tick_do_timer_cpu == smp_processor_id())
>> +		tick_do_timer_cpu = cpumask_first(cpu_online_mask);
>
> I was about to whine that this randomly chosen CPU may be idle and leave
> the timekeeping stale until I realized that stop_machine() is running at that
> time. Might be worth adding a comment about that.
>
> Also why not just setting it to TICK_DO_TIMER_NONE and be done with it? Perhaps
> to avoid that all the CPUs to compete and contend on jiffies update after stop
> machine?

No. Because we'd need to add the NONE magic to NOHZ=n kernels which does
not make sense.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87v9d7g9pv.fsf%40nanos.tec.linutronix.de.
