Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJ4GQ6BQMGQETDHHQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 81A5F34CFB5
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 14:08:08 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id t79sf4235659lff.17
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 05:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617019688; cv=pass;
        d=google.com; s=arc-20160816;
        b=qmDuaB4zbYXWw57KJLGZwjtUGlVdyYCOLFGD34hZLoHbI8HBMV7yGFmtmfCRyLEwPj
         8tUWygWL4C6Fzx3167BaVhZO9et1WGm1Qasgc8xVTZDHC2CGXqqj8d6LlgXYF6yKdccI
         shtf6XMHRUH1OeH50FDgRz2L8mwxTUHM9mc9m3Abg7RRGCYSlMAd9N3BekyYnwymrfID
         Dq5rldtvXjvQ/a3M3r3u60PrmT6PzHz2ApGNAlqN7bMQQjUsBW+rY7cVwZHaXMv9d0Ax
         Zio+SpInkc5YFfpfI3WnzRfIg5Xhk8NlEb+cUEdXGWhqW0nFB5hI9aAbMxrT28I6hlhu
         KDfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=36kbJ5+/HK1xKqbaSBfneusEv0rmgQmOeL1Jy62Km4Y=;
        b=BfGqNme9iE3tJRYLScRuJkaTjTt0SjPv4TzBEAOEhHt3A0yUAGe67R5+0/GLGQxarV
         +i7+TWo8tGmSlLtLEbkRl+3TufHU41PV4hx4MvxkoCRtRqNSWJ7hAnXI7KMYNQhksshY
         SyphQAWAwopK7F3SDQSgaDflU05IAH74h1pHJLm36p9MD4wO5EnRaEA+hWuWVhV1hpx1
         Zhn2qRUYotLr8N61b6HydtaYxu1OooBzwAa96/oV4D6dddjk/Q8UNxwIdMr9HgmemvNq
         SUZXBZZKsoAFvuzzxsQ8wYc4xtSPjLsCZOHC+i5bzcALU8AzEhrKcJ9USwoPZI7woH2c
         KpBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=HItK73o0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=36kbJ5+/HK1xKqbaSBfneusEv0rmgQmOeL1Jy62Km4Y=;
        b=GdLupROASyeQyeyu3ik7CwYnPJeemDrzcb7bBRBQBL4xce2rxsIVSuikLcwCC0FhkL
         bGoo0xWseQqkyp4R/fVanIN9dSr/4i4yveN5P4Xy1GLVEN2ZlRIClYikSwbTLrxSYXdO
         +DS8E1snLBtwvP7OiiqXTdBkjmhBQOot36R8liEytEKGN23u5b6PaGH5FsOkdd1tzymH
         KpXr+UN+LJbNJVtLSgiUI2JMFCkcX9/C/is9Fb0ms71WyKen8d1vvlbYotuVVqzsO7dA
         dfPcoELqVezV/XFXoPk3vAD22uzbzc2xrTTP2VV2PfzWwnGO+T5bYcfA8keQEkx6vDr6
         zTaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=36kbJ5+/HK1xKqbaSBfneusEv0rmgQmOeL1Jy62Km4Y=;
        b=e5P2P6YS7ZPTHKYiPAbuhnmpJ19Ntznri3ksVDZrWhuwPkQoVKjhU8yUPhvCdjvcBS
         UWaqjI5YkjYY4aT48VLRjE/U8Bijx55Hw6Td5zCxjZ4+gpjhd25VGiU3zJZk6SB/6T9L
         knT7DzwEeoHhHubRmwvLmHuGMtu0cBeemDougxzhK+9GHLnG64+04RrZoDViD6UuQnSG
         gMrfgg3olcu7gY4pCYabhjVNbyIxVyxdtcb19T8UrHquJRb6B7gOGPnxegsQ31vC/jHd
         3iKoaCSJXnA5Gat6zVe5wzWw9zlyy2Qauw2UsEkwtzGbaCfJ5sJy3eTE2u+H8HmRwEiM
         IpvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rHV5I1W/44CS5PQfhRHAtFJ28xjKusw619RuwMmAt8xWQHpQ2
	3H2P9ANv2QGhjmRO0eubbyQ=
X-Google-Smtp-Source: ABdhPJwdEbTehWLSdeg/KldrrQnlFusFYIPk4vBz+DiZux2RVWAOZYqLAzA3O5/8+l1xlWQeYFEc9A==
X-Received: by 2002:a19:740f:: with SMTP id v15mr15670864lfe.247.1617019688107;
        Mon, 29 Mar 2021 05:08:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b603:: with SMTP id r3ls3117180ljn.5.gmail; Mon, 29 Mar
 2021 05:08:07 -0700 (PDT)
X-Received: by 2002:a2e:81c9:: with SMTP id s9mr10905076ljg.366.1617019687088;
        Mon, 29 Mar 2021 05:08:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617019687; cv=none;
        d=google.com; s=arc-20160816;
        b=Z0472giPnfT5uXiJrnYJVoW/BONsqPQIUU0Bvb34Idbn3qns0QwmSZ2T2Lw2ycpwLL
         fpk9WF7A6f/1ZiQ4QDreoX+wI2/xyURUe50hKjxO+RuI4w2JqtAzkiEeDIa0XvqIUUpy
         JNq/yWVlcZQKJzCRmsT2r5AvQazyLJpO0MY4mt7A3fT1A3HZkJkLSWZS6+rzBiWVaNkV
         AzKWjFLrJVWkysmpJiQTvLlWaQwbYButD0oy2uTLh7uOzjOFX/K1sPWhSoIjfcP7J9K3
         9ElvO1Zt/4Sjxj9vAGTDvEZTHOK2ss1vOAwneaCvcBlQWwJX002mpuO9zN1AtCVhJSd+
         k5FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Njn/KvV5Snuv3RW7HAFUHdZEr2iaxCFGr7M1vBWlqyE=;
        b=IiA33s/Wdnj9c03x3gIyikrMHH9XVOvbJ29E3iSojrSHy9Dh5+XrMMXTPbvjlbFgzF
         8LvwsRcKBDSaN7hpDA1HvvektZcuHLMOW18LPehdgpUiBSxRwE/wCWRDuZy+5xIJWFn8
         BwOAkzAaBt5IhPk1IRuB5bAr9zVLISTlwJb1NuP4h5wOtlQQM7BVjW3fbbcioM2Wl1WG
         ywKZlkLRd/jKNkzZt0FVCG3kTAJxdsaUjUTxbo0Audjjg3UebKVIRwpBYdVW0TdAORZU
         GbaIS559hKEC+rND0EEXNl6cGwWViOIZOW8SycDX+LdgG5SS8i18OtoNERtmCDkmsGw7
         Y89w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=HItK73o0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id o10si734639lfg.12.2021.03.29.05.08.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Mar 2021 05:08:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lQqfm-001WyJ-TV; Mon, 29 Mar 2021 12:07:18 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D5B5B304B90;
	Mon, 29 Mar 2021 14:07:09 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9D5F52071A3CB; Mon, 29 Mar 2021 14:07:09 +0200 (CEST)
Date: Mon, 29 Mar 2021 14:07:09 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org, Oleg Nesterov <oleg@redhat.com>,
	Jiri Olsa <jolsa@kernel.org>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
Message-ID: <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFxGb+QHEumZB6G8@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=HItK73o0;
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

On Thu, Mar 25, 2021 at 09:14:39AM +0100, Marco Elver wrote:
> On Wed, Mar 24, 2021 at 12:24PM +0100, Marco Elver wrote:
> [...]
> > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > index b6434697c516..1e4c949bf75f 100644
> > --- a/kernel/events/core.c
> > +++ b/kernel/events/core.c
> > @@ -6391,6 +6391,17 @@ void perf_event_wakeup(struct perf_event *event)
> >  	}
> >  }
> >  
> > +static void perf_sigtrap(struct perf_event *event)
> > +{
> > +	struct kernel_siginfo info;
> > +
> 
> I think we need to add something like this here:
> 
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 4b82788fbaab..4fcd6b45ce66 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6395,6 +6395,13 @@ static void perf_sigtrap(struct perf_event *event)
>  {
>  	struct kernel_siginfo info;
>  
> +	/*
> +	 * This irq_work can race with an exiting task; bail out if sighand has
> +	 * already been released in release_task().
> +	 */
> +	if (!current->sighand)
> +		return;
> +
>  	clear_siginfo(&info);
>  	info.si_signo = SIGTRAP;
>  	info.si_code = TRAP_PERF;
> 
> 

Urgh.. I'm not entirely sure that check is correct, but I always forget
the rules with signal. It could be we ought to be testing PF_EXISTING
instead.

But also, I think Jiri Olsa was going to poke around here because all of
this is broken on PREEMPT_RT. IIRC the plan was to add yet another stage
to the construct. So where today we have:


	<NMI>
		irq_work_queue()
	</NMI>
	...
	<IRQ>
		perf_pending_event()
	</IRQ>

(and we might already have a problem on some architectures where there
can be significant time between these due to not having
arch_irq_work_raise(), so ideally we ought to double check current in
your case)

The idea was, I think to add a task_work(), such that we get:

	<NMI>
		irq_work_queue()
	</NMI>
	...
	<IRQ>
		perf_pending_event()
		  task_work_add()
	</IRQ>

	<ret-to-user>
		run_task_work()
		  ...
		    kill_fasync();


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YGHC7V3bbCxhRWTK%40hirez.programming.kicks-ass.net.
