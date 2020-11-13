Return-Path: <kasan-dev+bncBAABBI4SXP6QKGQESJ72TKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EB9C2B2318
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 18:57:58 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id p3sf6523530plq.21
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 09:57:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605290277; cv=pass;
        d=google.com; s=arc-20160816;
        b=w3aZUVE922W7+OLeSC9yMz+d5coRpxBEStEwg2C215uRSGbS3oXqHhjmIJwbcj61HT
         cisawIhw6rdSVxQTtI3vbcEAFSZFIUwxOOLXAyn5LUNM6DzKWAG0qvYyMKobnmEk+jl/
         3L8kJY32U+IV2/sqciBV8GsTY19w/wiPdDWRdDY/x0/P2JhgnvHztWk7+6E4jvL+3tNc
         UZPRXtQh+Yn2fzNEeX4C+H0hx4t/Ne3sRA9SQYyK5QA4arG5IFhmcWY33u55gB9ZTRl7
         hHgP3u7oHS3IKvGDzkY8PPiVJI6KstujbfLrH8cQ3+V25LT5OenP912OeeqPK0FiuZ6l
         CCMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=8a+DLNWztbrZ7FcNiNBKZixi83iy7FoyYpu2E6VO5lY=;
        b=xPh964QTlewP5xgVa6KTO7XJEYLzstfag/KB1mQXOz7U6CaWce1TiBbt0fgno3rLEm
         OtHJv3WQTbXCvdwYpI5SVwYBABYLjcyMysFD+a322BbtlGI5MM5nBkkQf5ht9mvPXpXq
         kmVE8G9MkTg2rXp5ixOTDlR2hz52KRUb//zQgs/wXzLtDP/HwiF7oHr7twnirDCMwFd6
         vNh/7XcLoiI3DbbsLyxws5ImjAQHBm9ZNTA6sDcqLfFENQt+dvp2+obVWDxg0tZcNsjx
         cmA+sgSFIz7L9lDt3GOHIrfHRPHa7VWXty5WRczwHZAQ/LggEdEBWhdfv7iIYZAjsS5i
         k+uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=l+E3WoS3;
       spf=pass (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rZTf=ET=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8a+DLNWztbrZ7FcNiNBKZixi83iy7FoyYpu2E6VO5lY=;
        b=ZBHjiljhjv+X0Pk1y9JGWGxWZXCS29p8FGyZ1knaVO33tLFPJ7404hiHzKv09NXWsS
         5RCtfl02A4FuQoHX5HFiul+3JCR2e3kwMhl5ZKH1apqi3YFDDEUEOSUtcJBYSadSWvT5
         hhjY1k68KQLeu5jz/ayJmE6uO9nfTEX14tDK4BRSaotoH0lxs3uHnKcHivrTsG27nAd2
         OmmJqdIWbgZzvzE08yxxsEXft4p3iTVTYPJIT/PoXpBAK+8989f6YjjHvHDJQ29BvIvR
         GwhtMS9JOooCJ4B6mN4BsukjS95B+kpuRkPBaMv+3037AhqZyRnrUMCGxzoUgMCpH3L/
         hosQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8a+DLNWztbrZ7FcNiNBKZixi83iy7FoyYpu2E6VO5lY=;
        b=lyNJfG43F7qV4e46FJmiJ4m3j9V4Pdr0chV72hQaSFjdZB1QcPoBIr05KjgJts2pXD
         TjNbMYdxDE+XHN4CDTh64hl5us2GBD5OB1Jp5NnpDDITwRziEaWebZ59hD+osc0QUHWH
         34DTbTjIzrfrJagu8YAlYSd6X+VmJ2z6O9l6Q3H6vzPPqEcns79MYEgVLJzdqI18anOd
         ntiELsU497b+ShN5MY83dtu0tcLgpeEDcQk5Matu79YKeO3g8LRbH3rawL0EOmcCbRqV
         Q+k7VYoclh5DHX6nx1IHig51ekalfnjhJl8tAyecMMYR0C6Hjybp82hrbJg/Q34T1tta
         HN7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uTyJ/294+69POJ+BD7nIV+emQov1sCzoQMXAOChMAN8OZBZFx
	pnKeSnB1KCixX8BmFmcQHtc=
X-Google-Smtp-Source: ABdhPJwHTzzGcfTWE4RB3+XD9wEqZRMWC9fZ1TylENbN4n1RSzcShjCLMhQM2WV/AZ0PD03WC4Kb7Q==
X-Received: by 2002:a17:902:7006:b029:d8:cbea:d3ba with SMTP id y6-20020a1709027006b02900d8cbead3bamr3023878plk.73.1605290275646;
        Fri, 13 Nov 2020 09:57:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6a85:: with SMTP id n5ls3386182plk.9.gmail; Fri, 13
 Nov 2020 09:57:55 -0800 (PST)
X-Received: by 2002:a17:902:24b:b029:d6:cd52:61e3 with SMTP id 69-20020a170902024bb02900d6cd5261e3mr2912728plc.2.1605290275134;
        Fri, 13 Nov 2020 09:57:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605290275; cv=none;
        d=google.com; s=arc-20160816;
        b=VHbVdpDB4DxZ1WY2b+Rkhqf5eLQM4OdUuUEotNWQdPrijOc1MAgF3s5ghAOMXtAeBG
         9NuUMB9dCcL4Qgvx4cTjMK9x4mqqQVv91Th6LbV2EEMSAfvkHLvzAcu/2Uw7Umh6WHx2
         CzRVBNwCwoLf6S934z0NVVIh2l+aN5V0LYVFN9f4sUKKjZb6v2rgEfun396dJu3JKaXH
         v6s2zjGefkaIcKiraL1UhDoMYoYNMbh8clS+Qj1dZJfC0l9aoQl1+XvXDXqAuv58YlTP
         f5iuBKdt9w85jt53Mf2mC0fqJNoxW+X75/k4OW8ULmGmj/3QCwtitZ1TgKhar2JgNNXe
         3IMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=S5YvRFRZMxsWgD31cXBQamHkmgAgVS7zwUG1Nz7ZrK0=;
        b=A2+5nX6jMwLB/0E8Pq90ZBOQdRUXZJdBdFKoRyfw7QSHZHFAGRAc1Ah+wlKhVHyanI
         jp41QmLBnY7lUlRF9ELHBAmVkWJS3NaO0vxAvXqj6VdIkGjifx+Qv/fO/39VfnVA92WC
         7hyMFe7i3jHAfy6SRr2q9NCIs9FhAOEanByy1UC7GDnhqMgkGw/TxQa012A7fwW2r2Ye
         Tq5Q1Z1sUy54i5q1j4jlz84tbu65m/Yrtb8X+qy+UIo8XYXnvXyh/8P/Q63CJKFeJCPd
         zO8dqoONooFmRRha1Vi+n0Wi8KggEAoU5GWrGSbnGGRxoSjxHV3x0qsIVrd+DKOX9lYZ
         zMdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=l+E3WoS3;
       spf=pass (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rZTf=ET=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o2si543845pjq.0.2020.11.13.09.57.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Nov 2020 09:57:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9F5A6208D5;
	Fri, 13 Nov 2020 17:57:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 4C48D35212DC; Fri, 13 Nov 2020 09:57:54 -0800 (PST)
Date: Fri, 13 Nov 2020 09:57:54 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201113175754.GA6273@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201111133813.GA81547@elver.google.com>
 <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201112175406.GF3249@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=l+E3WoS3;       spf=pass
 (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rZTf=ET=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Nov 12, 2020 at 09:54:06AM -0800, Paul E. McKenney wrote:
> On Thu, Nov 12, 2020 at 05:14:39PM +0100, Marco Elver wrote:

[ . . . ]

> > | [  334.160218] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 15s!
> 
> It might be instructive to cause this code to provoke a backtrace.
> I suggest adding something like "trigger_single_cpu_backtrace(cpu)"
> in kernel/workqueue.c's function named wq_watchdog_timer_fn()
> somewhere within its "if" statement that is preceded with the "did we
> stall?" comment.  Or just search for "BUG: workqueue lockup - pool"
> within kernel/workqueue.c.

And I did get a small but unexpected gift of time, so here is an
(untested) patch.

							Thanx, Paul

------------------------------------------------------------------------

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 437935e..f3d4ff7 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -5792,6 +5792,7 @@ static void wq_watchdog_timer_fn(struct timer_list *unused)
 			pr_cont_pool_info(pool);
 			pr_cont(" stuck for %us!\n",
 				jiffies_to_msecs(jiffies - pool_ts) / 1000);
+			trigger_single_cpu_backtrace(cpu);
 		}
 	}
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201113175754.GA6273%40paulmck-ThinkPad-P72.
