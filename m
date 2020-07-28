Return-Path: <kasan-dev+bncBD7LZ45K3ECBB2EYQD4QKGQEYH27CVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C80D2308B0
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jul 2020 13:30:49 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id h10sf5528971lfp.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jul 2020 04:30:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595935848; cv=pass;
        d=google.com; s=arc-20160816;
        b=z2kSvWmGjq/kxzwld/KTsL+HFuuEIuyM3YsRi8Fd4LHHnmnnmFBMrmQHufwfivsdDb
         wkUBAkkPJe6LG6xy8xoIOPUgZAGVPI/5izFgzij6C0l8xNqeXrn72RihDdHpUASO8mbK
         o0xQ7nd0LloRoGIuq/v1AGRmRYE0ro9xLc/g0MQPnqePfEBmgbGFbDas9Yny6qsAFRNm
         sLZtFZPu5dV1s+o3oeqWdwkSaUT7nXAPZ9u0RWDxVxlvSorxlxDC3QpIxvU84rBDvLqa
         0a0bnnJtsYvtJqhLgSPJPpyaHyMVn/uieIC211MiNb3oXPiahn7BH82BL5b7jYxQ3IrL
         csjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mdUKr955omYEac4idTvbt3/czyQT/m0rk2cY18YWrcU=;
        b=VRgWPkkJdp5yeBMFzEQScD4M9KN9M/8c5XGA3Ot+S/j6g3WSGRtWIZpLwzxP5UKxYk
         cHgaAyoze4lvVS/Rhd8q3zhb2ubliWmmFnoggS+YLoksY05kkeQMscABbSAfbyRIFg6b
         g62hTXJU1OU5BEmYrrRWPg/2Uz5NT+pFy5KZYkr+AChR7YQSkKvkX7cqYI7+4xt98g1+
         bZwY2u7MKzJV0AwKVICKGlsh8DAiULQQhcdrr/WGjPs7zwcaDO0Tj1ldNW6+b0TeO9Xc
         /gERjA3SAjRu9jEQOR6F0eWg09e9HV8Y1PT5ma4QcxTfnxZlZ6aYzLwh0ahLDfyCCyAI
         st8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Zk9V5lU1;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mdUKr955omYEac4idTvbt3/czyQT/m0rk2cY18YWrcU=;
        b=O/m8fzBDZVqVxuBoSCQUEbEnsRT16sEPx+pNOE+6KJaLE5p7LLkF5/0xBcU9n5RN8D
         vFqKs6iAdOrkyEaJytswCztZnIvEfQzEFbGhHIfgfP5hj9u1M/04xZM3jl9a2p0zHYf+
         /op9pGE6B1KN2GSdlzLnQ06nYTHtCmKRm872fGII8Ss0R/QoT3QU6nn8bsBirjimvHM4
         V4ebrZ3ufMfQe5Ypdd/kmfAqPIr95Y0gGJR5kr1AfqbTaj83Wc2APvx2R3l9xVtek+o4
         KF/O77tmPNpmekeqQZulOz9mGWiYCBYTz3hlrLmhnbuuEREajDqvR306QwPF+1yP2e0L
         P1Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mdUKr955omYEac4idTvbt3/czyQT/m0rk2cY18YWrcU=;
        b=BbwbUh75h2MomJ2IbGbbufKOBeySiJoijyk3rHO96odAZ43EE5blY/eUAJGDVZ6+A9
         yXbTADxVIekfeSy1+wQkc+RGX9fyRDBkmewF1B6MDR+joLmd2PZu5WLR1n9BAsvFzGLP
         IZ0S4jzEUhPHmSiaMqjkA9z6RJC6/BFiVW5sXHWm3WPXnWJeMxuMR9063Y9nTaprRcmX
         wtuPNMnvTNnUyAFz4C+62e3uNHfw9BO3ZpWnb6kVz6BAfeCzOxAGgO2S5WsxxWHyWUWk
         a1i5RRXANfrL7iHSjQBGBICS9iGd+26hBpi+GWv2i1Gvtq2pdnltKaZ9pw/MXqroKxIo
         WdPQ==
X-Gm-Message-State: AOAM531/GcgQUVWrI2iQjtqV2+NujNguSjDgcOrO31PCaeDpYVwNQ97o
	YCzhvI2MQhUw9VGxcOYwuEM=
X-Google-Smtp-Source: ABdhPJyAYfVpfx8msYkx4p8PEFeTqn2SvAhHFmvZPCPrAmpKPTrEmTN0SmEStGkgn8/fUKe8IsZyng==
X-Received: by 2002:a2e:b4d0:: with SMTP id r16mr12664940ljm.332.1595935848654;
        Tue, 28 Jul 2020 04:30:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1182:: with SMTP id w2ls1697510ljo.2.gmail; Tue, 28
 Jul 2020 04:30:47 -0700 (PDT)
X-Received: by 2002:a2e:a17a:: with SMTP id u26mr12735586ljl.322.1595935847676;
        Tue, 28 Jul 2020 04:30:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595935847; cv=none;
        d=google.com; s=arc-20160816;
        b=QykbrKd3I4izgg2vnWwPJ7Eh28LN/wjHf2iaTsOLhA6N6PXA8yh5BUr51AFyDmT/WA
         G15lZHy/D30Fnxa49QPDjEk7fexoeaEO9jae9sQGif0ZeTVPaFu3qt/cOq2E7x9f9kt9
         m9eDskuiHlPDx6p01LUjddaEHJV8xg6rVsjhHEAg6jbaAxrRoZMWi62hL0vHJuIZXbaa
         Wt68w4yh0nRALup3BtBFdjjJ6FKhMMtJME6orLiXtbK2wcvk9Ri+ZLwK4bv+CK26Nbkw
         3M94Zxbdrk5B59rAg1qlhMffR5IKB7behF8Ff7gnjbu59FyWL1HylOKBAzhdL9dUR1Iw
         5PGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=FelnoziPl1weCVcahTpNmRZ5eU0TVIndxX9sUgwgWPQ=;
        b=drUSqhOdkoXzfz/ebWNKXiWTZwB5H2LRbKucK8D43EtYqAHm3ht4gV3sQz14Nk4nEv
         w1FOIgZ2LTrSpxs3Gqc5ruxubJMTH7dsujnpgE3HUCQajdhqpRNGvA07GWWNNRjpUuTY
         T4h2yIKD4cyhTjtWaONPTGBuaNHUO+vspACx+OZJ3OiqfsDBFoRytkS5B+F9yH5O3Z+V
         FHBNEKiibAJts1Uwy1RJsak+iYwATGu2Nm8+hS7n6KsbPtbuYSwQFbdNCoJ/Keqgeyk7
         gwdQa7RztwvJEJL5Acs6BLtmngHyruiF9DWxWH4AtHCQ2eo0rIYVH9rvRXy1v/E7wCLq
         WsjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Zk9V5lU1;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id k9si427943ljj.5.2020.07.28.04.30.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jul 2020 04:30:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id g11so8511121ejr.0
        for <kasan-dev@googlegroups.com>; Tue, 28 Jul 2020 04:30:47 -0700 (PDT)
X-Received: by 2002:a17:907:100f:: with SMTP id ox15mr12454058ejb.323.1595935847173;
        Tue, 28 Jul 2020 04:30:47 -0700 (PDT)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id s2sm8792001ejd.17.2020.07.28.04.30.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jul 2020 04:30:46 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Tue, 28 Jul 2020 13:30:44 +0200
From: Ingo Molnar <mingo@kernel.org>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de,
	paulmck@kernel.org, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH tip/locking/core] kcsan: Improve IRQ state trace reporting
Message-ID: <20200728113044.GA233444@gmail.com>
References: <20200720120348.2406588-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200720120348.2406588-1-elver@google.com>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Zk9V5lU1;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Marco Elver <elver@google.com> wrote:

> To improve the general usefulness of the IRQ state trace information
> with KCSAN enabled, save and restore the trace information when entering
> and exiting the KCSAN runtime as well as when generating a KCSAN report.
> 
> Without this, reporting the IRQ state trace (whether via a KCSAN report
> or outside of KCSAN via a lockdep report) is rather useless due to
> continuously being touched by KCSAN. This is because if KCSAN is
> enabled, every instrumented memory access causes changes to IRQ state
> tracking information (either by KCSAN disabling/enabling interrupts or
> taking report_lock when generating a report).
> 
> Before "lockdep: Prepare for NMI IRQ state tracking", KCSAN avoided
> touching the IRQ state trace via raw_local_irq_save/restore() and
> lockdep_off/on().
> 
> Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> 
> 
> Hi, Peter,
> 
> If this is reasonable, please take it into the branch that currently has
> the series around "lockdep: Prepare for NMI IRQ state tracking"
> (tip/locking/core?).
> 
> Thanks,
> -- Marco
> 
> 
> ---
>  include/linux/sched.h | 13 +++++++++++++
>  kernel/kcsan/core.c   | 39 +++++++++++++++++++++++++++++++++++++++
>  kernel/kcsan/kcsan.h  |  7 +++++++
>  kernel/kcsan/report.c |  3 +++
>  4 files changed, 62 insertions(+)
> 
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 692e327d7455..ca5324b1657c 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1199,6 +1199,19 @@ struct task_struct {
>  #endif
>  #ifdef CONFIG_KCSAN
>  	struct kcsan_ctx		kcsan_ctx;
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +	struct {
> +		unsigned int		irq_events;
> +		unsigned long		hardirq_enable_ip;
> +		unsigned long		hardirq_disable_ip;
> +		unsigned int		hardirq_enable_event;
> +		unsigned int		hardirq_disable_event;
> +		unsigned long		softirq_disable_ip;
> +		unsigned long		softirq_enable_ip;
> +		unsigned int		softirq_disable_event;
> +		unsigned int		softirq_enable_event;
> +	} kcsan_save_irqtrace;
> +#endif
>  #endif
>  
>  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 732623c30359..7e8347c14530 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -291,6 +291,36 @@ static inline unsigned int get_delay(void)
>  				0);
>  }
>  
> +void kcsan_save_irqtrace(struct task_struct *task)
> +{
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +	task->kcsan_save_irqtrace.irq_events = task->irq_events;
> +	task->kcsan_save_irqtrace.hardirq_enable_ip = task->hardirq_enable_ip;
> +	task->kcsan_save_irqtrace.hardirq_disable_ip = task->hardirq_disable_ip;
> +	task->kcsan_save_irqtrace.hardirq_enable_event = task->hardirq_enable_event;
> +	task->kcsan_save_irqtrace.hardirq_disable_event = task->hardirq_disable_event;
> +	task->kcsan_save_irqtrace.softirq_disable_ip = task->softirq_disable_ip;
> +	task->kcsan_save_irqtrace.softirq_enable_ip = task->softirq_enable_ip;
> +	task->kcsan_save_irqtrace.softirq_disable_event = task->softirq_disable_event;
> +	task->kcsan_save_irqtrace.softirq_enable_event = task->softirq_enable_event;
> +#endif
> +}
> +
> +void kcsan_restore_irqtrace(struct task_struct *task)
> +{
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +	task->irq_events = task->kcsan_save_irqtrace.irq_events;
> +	task->hardirq_enable_ip = task->kcsan_save_irqtrace.hardirq_enable_ip;
> +	task->hardirq_disable_ip = task->kcsan_save_irqtrace.hardirq_disable_ip;
> +	task->hardirq_enable_event = task->kcsan_save_irqtrace.hardirq_enable_event;
> +	task->hardirq_disable_event = task->kcsan_save_irqtrace.hardirq_disable_event;
> +	task->softirq_disable_ip = task->kcsan_save_irqtrace.softirq_disable_ip;
> +	task->softirq_enable_ip = task->kcsan_save_irqtrace.softirq_enable_ip;
> +	task->softirq_disable_event = task->kcsan_save_irqtrace.softirq_disable_event;
> +	task->softirq_enable_event = task->kcsan_save_irqtrace.softirq_enable_event;
> +#endif

Please, make such type of assignment blocks cleaner by using a local 
helper variable, and by aligning the right side vertically as well.

Also, would it make sense to unify the layout between the fields in 
task struct and the new one you introduced? That would allow a simple 
structure copy.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200728113044.GA233444%40gmail.com.
