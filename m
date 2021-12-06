Return-Path: <kasan-dev+bncBCS4VDMYRUNBBYWUXGGQMGQEWE3LTWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id CA36446A619
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 20:54:11 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id y17-20020a4ade11000000b002c9cd91f98fsf8571557oot.13
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 11:54:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638820450; cv=pass;
        d=google.com; s=arc-20160816;
        b=S/MCqH4JceSblIOXuiHOtdMP9Bwz2B9pLwONKH0fPqlIqOVlMrzMcIs5m9YUQG3+q0
         vNHrxaAcg1SAtzfqiPJw8LxUe9nIneP2jiCukNeq6UCkGAUHxYYj+bnQ95pjqm2dSBq2
         8A8mvutkCdLqwAbXY2nwK26wI+mZgMrfk3jSoVd2xW232jhK2feAclMiep3YeSLn23o6
         0EZrj/dgJmwxiC1gIzpsncHC3sLfQ94rdIQj42QF5hGJUQJIAmCczZ36wPISiDJLyCzx
         sXwrcEt4Yp62fOwNxAXqzvMCjUR9eyVE8ipDWlWghs5WdK6F9qWw33nOHGJ0AubFr57n
         DOTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=N/EiRDLiQVkYY+4FE0dLe3a5beJQ7ofS6dqi8nI0Oec=;
        b=Ou7W/Gx4W3xhixbe/wmd/hSGAExZzdkWd1PaAjri0dhQUQH3C27Kpx0prVhK6G5EwI
         NZqp8J9SdKTiiaXBZR/py5nA8ctQWolSpQ+USceAPl8cjoMnQbJoVX76UJ/gWE5aDWXh
         CEr1ZoH6MUVSEvYCopDo3wNzoMpQX2MVpFnBb+JU/qD6P8gdRyjgPOUAndFmiHEbRTaH
         CBN4UDAU3PYXm4VnYHRPqbN5dTZtknqr9TQszod1SMCGy1i6S3fLIT4CsXZKdbBZmWb5
         IskvoLn8MYuTd3uYopv0RguGxuw5tvqn2OR3z0+DJuDW7GbhoRWUScLqZNggV1/DMQCo
         nVcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iBLGGzEf;
       spf=pass (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=S3CG=QX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N/EiRDLiQVkYY+4FE0dLe3a5beJQ7ofS6dqi8nI0Oec=;
        b=njYhS8wp90r4HNMHDoyBEmMDG8apydUaJSlGMNucQE40z3Qd6wuLz536aUU3UV+Eof
         nQ428yrcfvca8MHB/T44y5LAJmvMMbKksSp/65RVsAza9VFYd14/OLM9uNe8bJ1TIS/S
         in08RlpRO1Mkwcj8p/dVGpm45DYbMI4uKEgwyXF4CpBGM/dqOsPyenF9myOexVoQOJZl
         styCaVR3D9fEfNjMC8lQjLUmatdht2RRUbCF/gyVjU1dKKdSKiLpM/XjIDD5gLT2bQ5m
         5IaY4bG8OX6eW8Y7liO/RAqA2iTEXWka2Ww2Dl3jk0zfPE7LY4DZDJ6gAQukWGyGrTUl
         llBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=N/EiRDLiQVkYY+4FE0dLe3a5beJQ7ofS6dqi8nI0Oec=;
        b=AyJEGWClhlS2siFcIuMKItk7/LLoXaTEVPNXUHPCDCkYVeVOs+m2a1/ulMVuRUD4be
         fAT9SQ4Tx2DTNN3hkCMXFti4R1xSH0M4yk1OvmOiK1fo8fX8BeuNNI5RXxOKEP5qPnEF
         S+7L4TLZHcJxZKLGlVe5BrwhollZKyIN0jB1Kd8h+vRcRvIOFjD1xMuJFuhk5zz5hevo
         fwBwxXRQX13IUUqczKqSDPYLao9IpbUg18xjndkkNc8kLW2l1ulKzurxfTOeTaMsTlAl
         5afr/qejqeQKURW355l9tsiGlGGU43JrowUdSUm5gx94glKJHunnuT8KniVwQqPqU3wy
         WwCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530diFRBW3HdthxUf1kW55r7WoiNmgZwzQheQr9FKhXO8KvJ2260
	WqjMIpGJWS8w2F/BRO0U4ow=
X-Google-Smtp-Source: ABdhPJwGwWoSyq/ZqlPrnEeQjxM394KBFaz4b9hIjRgckqeTu0inlNC+UuNA6ij3/0ysVh9AsMPe+w==
X-Received: by 2002:a4a:d9c8:: with SMTP id l8mr23605699oou.81.1638820450441;
        Mon, 06 Dec 2021 11:54:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:15a1:: with SMTP id t33ls6577557oiw.6.gmail; Mon,
 06 Dec 2021 11:54:10 -0800 (PST)
X-Received: by 2002:a05:6808:4d2:: with SMTP id a18mr682352oie.99.1638820450101;
        Mon, 06 Dec 2021 11:54:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638820450; cv=none;
        d=google.com; s=arc-20160816;
        b=ac1Md/LMOvkHdlqW/o44Hb0eIlLcc20PKmXZ/ox9NjOyLlq7U5QT7LSDBp5nEMgW6k
         4XlkralQ57r1fm/wMyrnLkF/vbrcDnxn12x/TK+z0paDD/mPI6lJ7zd3HDRnwcAhAeCk
         +XaV97tSV6jfkaoA1uW9lKQwn2/3gLxYv4H0+Zpidin3Wpf5OgWPN4HyiwsBDeeUBc+8
         uP+Sj/lLRp7aeTJj7GbIU3clX6ogyRXsQFuk/6y7BL6WHx0jVWtD2LOI4Vvsg5PDBlKz
         YHRlB0utXCr9j0ZHye7qnHL9yJpK6TMJDskCWsCEI3LV36aHn+8xRQswHnmRVZcYoj/+
         5AIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UiNrPFGke/TRo2nKsWQIB+xpct5KNWXc9ZdXbqJWlqE=;
        b=P/nQqhCnINejZZERW4QfxlG+uUy65b0xJlCs8Z2P26ZnR8jMV6Rmikk/PmRpCswbTH
         RZiSjzUYdwHuNz/Yb/E8Z8IRLFVUkwGL4qFafenOizXRlaW3j7vFFlpWdW6QBt/A87/B
         /SNoBahlaBw+qH7L/HBZRVjKSYjgbBi5dD40FgILLd07yASqi5ImQygULpcuvZ1n0PaS
         1WFc+6IuBcJdT9uQaUVwVacizilegZzgQTtgKrBm36hsuJGOLm9gatjHlTiQrDHUqlYp
         LPpLIRSKe3NsKLJ/A5eFPOMZ/OGFCeFLPFuapvoI9g6siuKuWl2R6uIqILrvbw9MNkI7
         DFGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iBLGGzEf;
       spf=pass (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=S3CG=QX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id n6si994282otj.5.2021.12.06.11.54.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Dec 2021 11:54:10 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 87396CE1810;
	Mon,  6 Dec 2021 19:54:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B7519C341C2;
	Mon,  6 Dec 2021 19:54:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 81FBD5C1461; Mon,  6 Dec 2021 11:54:05 -0800 (PST)
Date: Mon, 6 Dec 2021 11:54:05 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH -rcu 1/2] kcsan: Avoid nested contexts reading
 inconsistent reorder_access
Message-ID: <20211206195405.GD641268@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211206064151.3337384-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211206064151.3337384-1-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iBLGGzEf;       spf=pass
 (google.com: domain of srs0=s3cg=qx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=S3CG=QX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Dec 06, 2021 at 07:41:50AM +0100, Marco Elver wrote:
> Nested contexts, such as nested interrupts or scheduler code, share the
> same kcsan_ctx. When such a nested context reads an inconsistent
> reorder_access due to an interrupt during set_reorder_access(), we can
> observe the following warning:
> 
>  | ------------[ cut here ]------------
>  | Cannot find frame for torture_random kernel/torture.c:456 in stack trace
>  | WARNING: CPU: 13 PID: 147 at kernel/kcsan/report.c:343 replace_stack_entry kernel/kcsan/report.c:343
>  | ...
>  | Call Trace:
>  |  <TASK>
>  |  sanitize_stack_entries kernel/kcsan/report.c:351 [inline]
>  |  print_report kernel/kcsan/report.c:409
>  |  kcsan_report_known_origin kernel/kcsan/report.c:693
>  |  kcsan_setup_watchpoint kernel/kcsan/core.c:658
>  |  rcutorture_one_extend kernel/rcu/rcutorture.c:1475
>  |  rcutorture_loop_extend kernel/rcu/rcutorture.c:1558 [inline]
>  |  ...
>  |  </TASK>
>  | ---[ end trace ee5299cb933115f5 ]---
>  | ==================================================================
>  | BUG: KCSAN: data-race in _raw_spin_lock_irqsave / rcutorture_one_extend
>  |
>  | write (reordered) to 0xffffffff8c93b300 of 8 bytes by task 154 on cpu 12:
>  |  queued_spin_lock                include/asm-generic/qspinlock.h:80 [inline]
>  |  do_raw_spin_lock                include/linux/spinlock.h:185 [inline]
>  |  __raw_spin_lock_irqsave         include/linux/spinlock_api_smp.h:111 [inline]
>  |  _raw_spin_lock_irqsave          kernel/locking/spinlock.c:162
>  |  try_to_wake_up                  kernel/sched/core.c:4003
>  |  sysvec_apic_timer_interrupt     arch/x86/kernel/apic/apic.c:1097
>  |  asm_sysvec_apic_timer_interrupt arch/x86/include/asm/idtentry.h:638
>  |  set_reorder_access              kernel/kcsan/core.c:416 [inline]    <-- inconsistent reorder_access
>  |  kcsan_setup_watchpoint          kernel/kcsan/core.c:693
>  |  rcutorture_one_extend           kernel/rcu/rcutorture.c:1475
>  |  rcutorture_loop_extend          kernel/rcu/rcutorture.c:1558 [inline]
>  |  rcu_torture_one_read            kernel/rcu/rcutorture.c:1600
>  |  rcu_torture_reader              kernel/rcu/rcutorture.c:1692
>  |  kthread                         kernel/kthread.c:327
>  |  ret_from_fork                   arch/x86/entry/entry_64.S:295
>  |
>  | read to 0xffffffff8c93b300 of 8 bytes by task 147 on cpu 13:
>  |  rcutorture_one_extend           kernel/rcu/rcutorture.c:1475
>  |  rcutorture_loop_extend          kernel/rcu/rcutorture.c:1558 [inline]
>  |  ...
> 
> The warning is telling us that there was a data race which KCSAN wants
> to report, but the function where the original access (that is now
> reordered) happened cannot be found in the stack trace, which prevents
> KCSAN from generating the right stack trace. The stack trace of "write
> (reordered)" now only shows where the access was reordered to, but
> should instead show the stack trace of the original write, with a final
> line saying "reordered to".
> 
> At the point where set_reorder_access() is interrupted, it just set
> reorder_access->ptr and size, at which point size is non-zero. This is
> sufficient (if ctx->disable_scoped is zero) for further accesses from
> nested contexts to perform checking of this reorder_access.
> 
> That then happened in _raw_spin_lock_irqsave(), which is called by
> scheduler code. However, since reorder_access->ip is still stale (ptr
> and size belong to a different ip not yet set) this finally leads to
> replace_stack_entry() not finding the frame in reorder_access->ip and
> generating the above warning.
> 
> Fix it by ensuring that a nested context cannot access reorder_access
> while we update it in set_reorder_access(): set ctx->disable_scoped for
> the duration that reorder_access is updated, which effectively locks
> reorder_access and prevents concurrent use by nested contexts. Note,
> set_reorder_access() can do the update only if disabled_scoped is zero
> on entry, and must therefore set disable_scoped back to non-zero after
> the initial check in set_reorder_access().
> 
> Signed-off-by: Marco Elver <elver@google.com>

I pulled both of these in, thank you!

							Thanx, Paul

> ---
>  kernel/kcsan/core.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 916060913966..fe12dfe254ec 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -412,11 +412,20 @@ set_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
>  	if (!reorder_access || !kcsan_weak_memory)
>  		return;
>  
> +	/*
> +	 * To avoid nested interrupts or scheduler (which share kcsan_ctx)
> +	 * reading an inconsistent reorder_access, ensure that the below has
> +	 * exclusive access to reorder_access by disallowing concurrent use.
> +	 */
> +	ctx->disable_scoped++;
> +	barrier();
>  	reorder_access->ptr		= ptr;
>  	reorder_access->size		= size;
>  	reorder_access->type		= type | KCSAN_ACCESS_SCOPED;
>  	reorder_access->ip		= ip;
>  	reorder_access->stack_depth	= get_kcsan_stack_depth();
> +	barrier();
> +	ctx->disable_scoped--;
>  }
>  
>  /*
> -- 
> 2.34.1.400.ga245620fadb-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206195405.GD641268%40paulmck-ThinkPad-P17-Gen-1.
