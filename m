Return-Path: <kasan-dev+bncBAABBBXJ3X3AKGQEPDUW5PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A6381ECD09
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 11:59:35 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id t13sf167532vst.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 02:59:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591178374; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZswbjGKTiYZVBV7mPsfGZaa/HKKvNDMfCHScEl6dN6exFUHfsf30tp57LgO8lYKipM
         bGhZYgG4xll78rq0Vu4/k2sMNotll4sTC1+PVUBIHC51nP04/2O/tG5THnJVN5b+vYCY
         mfFoM1ZPQyURnrpfzgeeNuw42o0Lc+rKP/lnPFdZzhtkhFVvrNrOHDlb8IJCxYv7rXyx
         SIGU895Lpg7AdwFFuzWHRoApC/ib3h3a/UQI4kCn2B16rXzKGTYcqLSHNe4byeNHuPNc
         inQTcgdQKU0MXDD6Wq09ebPT4Aq/5FAEBfQvISRQxI/UwGTEkukOPFJQuzI97ZDszQTH
         3Qmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=fABh9trXIN8eDSMabh5Y+bFFpXg+bfHtmpUkqVDPiDI=;
        b=wQSmeQGKoftymPpYvE80qjERqPiREgvfFC1j+9ILklBvIZXFT8Pl7WRRT9gxcPIlM9
         JY8G0R6sT+oVJlZORCK9I9NF4PlF4gQOQcRBhsgbJHAli0aApYlohpf6e8p/5CcI/Jbz
         Mx19HKahrjdr2QzFR92c2Md2M1VcInYmTGBshIPn/mhn1hO6Ij2WJKEPISY6fEuGIHYN
         ipHGZAX6sHBT7z0rxI7t6XC/gL4EIsiZkKmqzJc5kjJ9d6FFLh4vjbMnxaes99GCHplV
         uSbhE52rE8mXf6w4YLN03niJ3RTzXnycSZXHUx/Hciw/wLh19oEjkeLdDU7BpU9Afn62
         4ZMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CQ3ENkUi;
       spf=pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fABh9trXIN8eDSMabh5Y+bFFpXg+bfHtmpUkqVDPiDI=;
        b=EYTepiLQajuegb98yf1gLlveDiAmFASi6ajgyw/M7JbcB0x23rvtdU65Oj1xtdqJJm
         Mka8FbrZUB8J8u/alQFW8NkRZm0/3TpJSy7jK3CZqodKRnhdGVWZSq8whLDCrGygFVJD
         KxT9tqKgMgiv+gDCJYwbiJNlo2TA2s2fAt/BMBl6q7c0kouc2B02Y5Y9jeCz58H7xTHh
         7COUgzW8kcqHPYq4yoV70igpUMlQNzzMYFemcRY5FmUJ/2li77x6LUFJEsE0oJN7p5CP
         JVQBPAL8bPYpV/iBrUXzlLBHVepk/2l7EfuQnkaC2qVAKOz9uqKiwSa6uPUZnUkYYbSF
         kU7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fABh9trXIN8eDSMabh5Y+bFFpXg+bfHtmpUkqVDPiDI=;
        b=odW+ZvWM18+0eu1wYtueN4eKAiLedFIiuOLKgMVG0b1xRRZJXg8m6cUV6QkoMuydVq
         alNcpuRER0tA1RHaeTXXyhPVx5rWXp7pTvaIZc4Wf+bu9vn0ap80swO9pxKXE7fA6EeQ
         Sgy37LQlsliPIGRJ/4T327MBKggxU975yOtGHTuY2yAJ/WYSQ7zxG5YXfOUAjHO5xPXx
         zMG9dcDY1tGpEc+vvEfnZNg55rXB56k94Nqah1TKsAxia8+E3CvvyTQntoy0GSbHrqgl
         oZlkz/Jg21pGwfhSE5T18wi9IA1mnTglX9EOScVEqliiHAvP1nsuo79CcbSyjXOf4Iwo
         pn6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YmzTB0hDDPUCA3/tbDBMi9ONAhbw9goy2r2tpCaK2QAsQhNJ9
	vJilRgrtwQfndBVJOaH399U=
X-Google-Smtp-Source: ABdhPJzt1cKs6MxWK41UBxGjztKYLL+jv8+QBszvE4/+TYjaq6HH5XrOYgTeLyRlp7CGEWnDLZJiMg==
X-Received: by 2002:a67:6582:: with SMTP id z124mr4873611vsb.24.1591178374162;
        Wed, 03 Jun 2020 02:59:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7c0b:: with SMTP id x11ls232028vsc.2.gmail; Wed, 03 Jun
 2020 02:59:33 -0700 (PDT)
X-Received: by 2002:a67:1c04:: with SMTP id c4mr22305159vsc.133.1591178373894;
        Wed, 03 Jun 2020 02:59:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591178373; cv=none;
        d=google.com; s=arc-20160816;
        b=ne6LGhWyunt5NEdVwko0DG3QnYMrMjtqQk4OnVixOcGMwAmGkrcEt4O03cR+trMSmF
         Zh25zMULKVHYsQS0ZLOVPUD3E4FVOk/LQpc5R3t2zKrjEiK8+a5SOSlWXzML/YF9+0UL
         Pkk5NSylvGIiocAmneIVR5rMC7v+d+d2sR1ZZIw1piHOuD+Ch+4YjEofiYCWMfqIP043
         4izevcyoAO0G3e2jEs1Ypy5tv7wtafGA9B2otSpGEbcgyHA41VkrSlZ6FpcJkVRe3sgf
         nxIa0sxxhhABwhAI9N+IX45GcH7l+tn7K3Mza/AYDFNAlGz9t8FnIVtz3PzIdChvfYWi
         zAWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=N6k03mZOf1ftiB88hi2ahL30XDBOo8daa7T39zy0Rso=;
        b=g26DbGiM0Kg+YUnqwwcFdlPpdKPwO4zCd4uEIoWLSMePYilDiRwnH5Z0JPFWhO59hB
         WChGl8F+N5lpvsNUIJGMzt+bfg2NIMqAQJEF2XI7n8aAlyL6li5IAdsZDE+6PjKWKNVy
         57AlaiHWiC11helVr1N8hTJFqj+f/fpONDPwByCk58zH6lUO5pZ8t5g2Az65YB1eMftR
         08dtSspcFC76xUqBrq+Fgy7YoIbOzDvIxTiunNAqTuYV298XSojk2lze8bQOM3dr/xGl
         YViYxr6NIwVy8ylsxibglWdJbIHat87LWJ9k09nl3v1uxwdnWxzrrN5n9uTnKxbRJvj3
         mdMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CQ3ENkUi;
       spf=pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t24si94810uaq.0.2020.06.03.02.59.33
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jun 2020 02:59:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B958720734;
	Wed,  3 Jun 2020 09:59:32 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9D36D352281E; Wed,  3 Jun 2020 02:59:32 -0700 (PDT)
Date: Wed, 3 Jun 2020 02:59:32 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Will Deacon <will@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] rcu: Fixup noinstr warnings
Message-ID: <20200603095932.GM29598@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200602184409.22142-1-elver@google.com>
 <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
 <20200602191936.GE2604@hirez.programming.kicks-ass.net>
 <CANpmjNP3kAZt3kXuABVqJLAJAW0u9-=kzr-QKDLmO6V_S7qXvQ@mail.gmail.com>
 <20200602193853.GF2604@hirez.programming.kicks-ass.net>
 <20200603084818.GB2627@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603084818.GB2627@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=CQ3ENkUi;       spf=pass
 (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Jun 03, 2020 at 10:48:18AM +0200, Peter Zijlstra wrote:
> On Tue, Jun 02, 2020 at 09:38:53PM +0200, Peter Zijlstra wrote:
> 
> > That said; noinstr's __no_sanitize combined with atomic_t might be
> > 'interesting', because the regular atomic things have explicit
> > annotations in them. That should give validation warnings for the right
> > .config, I'll have to go try -- so far I've made sure to never enable
> > the *SAN stuff.
> 
> ---
> Subject: rcu: Fixup noinstr warnings
> 
> A KCSAN build revealed we have explicit annoations through atomic_t
> usage, switch to arch_atomic_*() for the respective functions.
> 
> vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

This one does not apply cleanly onto the -rcu tree's "dev" branch, so
I am guessing that it is intended to be carried in -tip with yours and
Thomas's patch series.

If you do instead want this in -rcu, please let me know.

							Thanx, Paul

> ---
>  kernel/rcu/tree.c | 11 +++++------
>  1 file changed, 5 insertions(+), 6 deletions(-)
> 
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index c716eadc7617..162656b80db9 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_enter(void)
>  	 * next idle sojourn.
>  	 */
>  	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
>  	// RCU is no longer watching.  Better be in extended quiescent state!
>  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
>  		     (seq & RCU_DYNTICK_CTRL_CTR));
> @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exit(void)
>  	 * and we also must force ordering with the next RCU read-side
>  	 * critical section.
>  	 */
> -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
>  	// RCU is now watching.  Better not be in an extended quiescent state!
>  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
>  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
>  		     !(seq & RCU_DYNTICK_CTRL_CTR));
>  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
>  		smp_mb__after_atomic(); /* _exit after clearing mask. */
>  	}
>  }
> @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks_curr_cpu_in_eqs(void)
>  {
>  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
>  
> -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
>  }
>  
>  /*
> @@ -692,6 +692,7 @@ noinstr void rcu_nmi_exit(void)
>  {
>  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
>  
> +	instrumentation_begin();
>  	/*
>  	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
>  	 * (We are exiting an NMI handler, so RCU better be paying attention
> @@ -705,7 +706,6 @@ noinstr void rcu_nmi_exit(void)
>  	 * leave it in non-RCU-idle state.
>  	 */
>  	if (rdp->dynticks_nmi_nesting != 1) {
> -		instrumentation_begin();
>  		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
>  				  atomic_read(&rdp->dynticks));
>  		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> @@ -714,7 +714,6 @@ noinstr void rcu_nmi_exit(void)
>  		return;
>  	}
>  
> -	instrumentation_begin();
>  	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
>  	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
>  	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603095932.GM29598%40paulmck-ThinkPad-P72.
