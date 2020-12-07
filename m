Return-Path: <kasan-dev+bncBCV5TUXXRUIBBO5SXD7AKGQE2JSG2NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 59F7F2D0FE0
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 12:59:56 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id u17sf912779edi.18
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 03:59:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607342396; cv=pass;
        d=google.com; s=arc-20160816;
        b=qKyF/MwI7r7OnIURHWD2I/0zBPYy+/ZpPhSXY/zAhymvB4aeEKfqGgH5ihtdWedGfr
         FRugqNAU2tKT940959P1+lQqmTORAzkzLBlTGJM7kLuNVuR48uvRdVqwLWh6gYOackOi
         P/oHrcHgufHCojihqlmctN5WWOyETGN3Po2rUOVW4jgM3LrYlDIN1V+/jU1LXbXufhn9
         cwRc/1YOiDtqyJbSvN3MQz8SuQ1kypf7GezMubQ4ccJlvbW4jbnt9wM6qSCOILHlTlb1
         0F4OFeiM741HQxnZvUpJOrEmaaavxz3oQMAPGMBwphu2oOMOg1J413Kby4vSCV0gEMP/
         b+Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HdsGqqUaf4k0IBh47WU7ipZByF0cBO28YGs0m9FBuRg=;
        b=HPg1AQdKlvfVQxrCT/lxhOccNA1rzMMCerlQh+FLCxu9TfAJejBIQvts+/hL/EaBEe
         NB5ujTsAShl8hNd1/HwySn5WyOw5cvoHIhRwaViVm2TbUhBtugx6bjUiFZSSXia/Kaid
         euSM5PfCGt0/KrFXiRaQPBfdnySc631hmiDl2+6f4tGpm9/x6h+zFV8lul5quu+CG//7
         RzaCNd0ZjYoZeCftGRYUPH35w97+JyyC8Y6WQiLMOAQNmLgIZO0naq/ox4px1Kdf3mZo
         1G9h32JUR/ldUDqDNS2MxqFsnC/cRBlzcKCzKC1xAKN+1bGWvMyPAF9/8Jk7/unzfqKp
         pK9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="XL/kUxg7";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HdsGqqUaf4k0IBh47WU7ipZByF0cBO28YGs0m9FBuRg=;
        b=if15chkwWc1HjryAVoKsXoJzdPtdBth3t+cOWufBJp1aJVU9ioSdOiJh82ZPjG/itx
         nysw7d58nUkIG2losL1Q4ZXvBSNQ7osG2DXMNZB8tx3HAAAfRLrZ62IwvbDb6LI+wBLy
         owAxxFb+VcnmD8Rg9rqOOz04jL+aSO2sRhZcfRDSN+JhYZVhk0crIQVtprdTpNm9nmAt
         KkyGnL6PyavYXrcmSfd8CsMx12D7KDdjepfEvLELcbA10eQC+xruXxYWNlEtDFWxraDN
         mHvbvE5FS6pF0j6WYA6XNWhaTznIBuX036n+QRi9NIjt1MElC5md1Ez9j3u099xdazOu
         Y8GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HdsGqqUaf4k0IBh47WU7ipZByF0cBO28YGs0m9FBuRg=;
        b=UedMJki3053csxj+Y7rTen01vLjXrLr9Hh1iGAslg/oaXQluAP+h022fAvSOMK4Noa
         ndhc0Hw8n/PZ4r8wKN2mJIXFeeyHBGiMsx1Opq5u3Uh7q0M9szPhM+JnFCXoMFovuW37
         zmNmTThngZnbl7l8YFOvrVbxn2FUAOL8GQpO/aP14a1RqWnlgOYeK/m9yoXBqAsia5MN
         0+4jaZLr2KtWiZ8aCSXZyTgdVFcIJaaERpQ/WmWF/s6caScRGBXEcVISTFuqJz76CjFq
         dDJoJiioZm94bcjugFImUcrTFCpYIGfUJwRNtAdsP1mY9FMO5WQymkzgEEhZfGkRpDjS
         na4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QAwqFzYTiAfZeWkh7PTFS1dgTSsu1TfU/uY27vW3pIXSkkniL
	5TGX9TwZT8Sqg3JB5aPeXq8=
X-Google-Smtp-Source: ABdhPJzD8n0IXR0mSMrVLf4Tt9B+iR+Mq6GddGS/x1IcAH9MuhJ6FCCiaBivz7xYQ7II/NM17UE9lg==
X-Received: by 2002:a05:6402:128d:: with SMTP id w13mr19133441edv.56.1607342396150;
        Mon, 07 Dec 2020 03:59:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:82d1:: with SMTP id a17ls4792935ejy.1.gmail; Mon, 07
 Dec 2020 03:59:55 -0800 (PST)
X-Received: by 2002:a17:906:3881:: with SMTP id q1mr1114321ejd.490.1607342395186;
        Mon, 07 Dec 2020 03:59:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607342395; cv=none;
        d=google.com; s=arc-20160816;
        b=I+0dsWR9ynQLW3smNtwibKUaM+WjPmPEt37/CViPGpivSCqY7Ax9RHhnPabB54R0kc
         i+ADYUaycvhucfzDInKx8fOoKaZZTss6mqJsWDZwr45thd7hNPQLvv4n5Z+DzG8rbDPx
         s3gSWn9n+9eXKO+EwnizzMOrBY4xAWauq4NFndLh+fRPCeIXfawnRtGeowinjZNtIT8r
         ndEvyBXyjtTI/2I/Jgcm6Llwnq/tZm9jXhUkF+Yvu//QfI5tkjH+OPkhDAY5mJ9Qb84u
         887to7s87wWZM98u/cQxLUD2JWAR85n+DzxxiGFpILghz9K3IhUUERL7M7F3N5FtMoWx
         QCgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ruiN8SJtTuUIP3pb9sg0hgod0TOT8rORb9N8dDgUyWY=;
        b=QUGlIg7w5WaMGBtoG1llwmZOBaFDGA0IsmX4bFELxkl5txGPJj9PekJdTwQPctqPFz
         tRpS97wfXxDWHzBpQ5sOYS5KlJyL1DerGWNic6yWV40uTeyq9SPsC3SH9e5c44Kt/4mB
         rcdgJ8UZr992AR62dCJoNg+qqvlSYF88YlK8F/In/M7K2cO615ITM/f6a4Ddw0M/6Y0F
         +E/R//0Gq9dTkeNrnBkPVdb6zUTG68TA5qHEmRVFF164MP6fFbJIdZhp7B7dTijzkmV8
         IETBRQBhZay71PaUsLUpP5HuNIQJjq4lHTDxXD91rMaQ+ZT7HgYY4ZLjM0Lp0frgnfZm
         7Fkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="XL/kUxg7";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id cc25si135983edb.2.2020.12.07.03.59.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 03:59:55 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kmFBJ-0000rG-MP; Mon, 07 Dec 2020 11:59:53 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 48A5730700B;
	Mon,  7 Dec 2020 12:59:53 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 2E8A52081294F; Mon,  7 Dec 2020 12:59:53 +0100 (CET)
Date: Mon, 7 Dec 2020 12:59:53 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [patch 1/3] tick: Remove pointless cpu valid check in hotplug
 code
Message-ID: <20201207115953.GR3021@hirez.programming.kicks-ass.net>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.582579516@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201206212002.582579516@linutronix.de>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="XL/kUxg7";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

>  void tick_handover_do_timer(void)
>  {
> +	if (tick_do_timer_cpu == smp_processor_id())
> +		tick_do_timer_cpu = cpumask_first(cpu_online_mask);

For the paranoid amongst us, would it make sense to add something like:

	/*
	 * There must always be at least one online CPU.
	 */
	WARN_ON_ONCE(tick_do_timer_cpu >= nr_cpu_ids);

>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207115953.GR3021%40hirez.programming.kicks-ass.net.
