Return-Path: <kasan-dev+bncBCV5TUXXRUIBBDHJVD3QKGQEOKN4UKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 432B01FD0BE
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 17:19:42 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id n20sf1711430plp.8
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 08:19:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592407180; cv=pass;
        d=google.com; s=arc-20160816;
        b=gK9z+fn9lDKlmCIsNEpFFRWrfD0YBlOBlpkzSVTs8BzNDitmb/p18DVCIXUCV1mzYP
         Bgh+vgYEAXrDEB5dEDHHIVr27KERhA7/HnLrOTcDbmV8uRGh4o+E4C0I/DmKCVEamr7C
         IuHW5SwxXBAfmIzszRa+JfSd1A6a6fQ+HkapX0vjowWAaFwiF+2YfBLzUEckOQ3s+GJp
         4iu4xH/d/iKez54WWgNWP4Xn9utaRaENkRyphB8zkd/8cT2/A5sh2CQE3EuE4niWYENI
         eODJHBqSsMTkev+KPpk+Y0tq1I16ib2IW5h/yZaaig/6W5zwpsr9zIgsdGumYCBohF+5
         uV9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bJUiN8uLHdnZWSZ+sds4OWPNRbDK8hl1FmVGimMYcyY=;
        b=zj7WlGW/KWgqoLqpnMtKrnO9p3oXUeInkQhZ8v4NFkG4GiyEoaKMZlKPHps0KVdyKy
         3U4373FQ94hm3n2x6YqyHu8Y6n1d2fYbiPNsBS/dbEoGZqZT7lXBb6EXWSio9eo5S4Gn
         Z8rGGlOi4WEeOWUUqca489UWC4ZNYFX9yFM/Ek90j0MGpehm1TuwLLaexvsAtuoGNfRw
         BkRBadIKRPR/bYnnbioLkP3FfAAnz/kaEZRgm9Tq8HKHV9aqXkkTZEM0la0+9nC4zmRy
         8PBUTrqLxIMCphnevB3oXFS7dNGR2KTC0GEBWVTeiZMIcBOaGbtDUKQeBkrrSaLYITJj
         ruIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=eOiyRfkt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bJUiN8uLHdnZWSZ+sds4OWPNRbDK8hl1FmVGimMYcyY=;
        b=VzAfBROQyxaM1TXr9uDxSnYWKDqtGxeBnNJmgMfGN6Knm2s22X7BlKkcY3aGygcC6R
         8+P+ggc8Y7rwWAeEqjQX3V2KRtYudJnQ4CGRH0lZr88VGgMazpFVNV6h2PYWGpPC8CKk
         I66AugNyy7Z7oj+2aHRXzJWYxlUvoN+iJ7qAsTVXG1QwY5jZVXEUyMpdsSnwxU4JP55E
         SzqdqoXqjEFodouIVYedVbAiEM8ZNPV3KJyKpw9GHwGzpGO8uXL7GDYa5lD/yLjdKvb6
         GbJMXzOuuqrpTNCnLanel7qV2K5O1WsR56C6Rt8JHsLHj/gtZdePWlBcrrnDyVAH6seG
         y5Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bJUiN8uLHdnZWSZ+sds4OWPNRbDK8hl1FmVGimMYcyY=;
        b=gywWn1IvNCHUAwdD1iATHlrrIEHJd7d3Htpm+rXV/RkUoIJQBVOtz/pfT5lycGRaxb
         E8x7lwgI8If558JrMLRvc7UMmqQ1elKHOWMBY/FV6IyJBRJmx7gf0NVsjBcdFdWARlmm
         oSbGERws7Cu05E3yIqv6vNbeEGz26go954GNfBJPBWwImCMqG/8wA2wilHzvc4L+0OTS
         MXpgU/Ph4E7ohuVOK6jpL6JytYNH7Jh8YzSlr0QqNihBB8ooN5OsShlz7e2gaUA+pRym
         djBtbeGyQtJmctSn6g7KUbMoFWLkm+9hRetwRvUsJe4tt8nixDiyAYniZU2icC5EvOIk
         oUtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xnM3svzHYmAqKC1x67Ymz2qgGMj4TVtWE2Lz36mIObPs2uo0r
	LHQmkSRh4KMAVypGpuTxF3s=
X-Google-Smtp-Source: ABdhPJx3xH7FJX524ZBQRKogMRhs1sTLteegM2Sps9qhDI6ZtDSMvzbb7ueh3T6jOKId/DDC2nuhEw==
X-Received: by 2002:a62:d106:: with SMTP id z6mr7128698pfg.215.1592407180330;
        Wed, 17 Jun 2020 08:19:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:63d0:: with SMTP id n16ls707972pgv.6.gmail; Wed, 17 Jun
 2020 08:19:40 -0700 (PDT)
X-Received: by 2002:a63:591e:: with SMTP id n30mr7023761pgb.429.1592407179986;
        Wed, 17 Jun 2020 08:19:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592407179; cv=none;
        d=google.com; s=arc-20160816;
        b=YU3ShgiJkx3/CgO31u+R7BRdERR/csKFfp1KgbNhpNj3eWZRb1P0x28e8urflVLQL7
         4t7/Bev4bjlihXAShd4NajsoixGMal8SFGcSHbEmLtcQJ9FpLKAY+MfsdmIKyRO03uJo
         ySx9XR7QyUBig5JXzGKHYqBJwGP0lt6t98BjANQyfgV4wsWyexP3bTRpko8Ep9fuXqdb
         uonR9MT7q4ukylrpYd+bj0b3y0ZawvI/nagJz91s85v+PMShSPc1Dmsbs36HDD1dzMso
         o8iDE2qaUUJTZxXUUoT2YWJwNKuWIydmT6Uh1GRnKJXLjENVGvzuw5S2wxKoOB2PWY+n
         rEAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9xgWNrz/EjgA9082VEmXpJMV85vsTTWYygZBrxi4Mgg=;
        b=Q7L8ZyzLbCqUGTErPN/xdxHaJl1ZQigIDhXFpb4WOf9NLrfcPIeIMsQ9JORGHOf3nG
         coQQjI3kb0PVhh4cYCmUYErD4npPcaH61Ca5+puVkjdd6yecOON3yBdlgbg2FUBcbMQh
         gz9XpuQOuMTx+zvhcXLTfF8M7Qko0Y3hFwsQ7KLzXkdyh+rHVE3fj0P9YAP9+pw8OUwa
         yo/KEBgnpXOtZMhAo9EVY04/q0e5E3tuTL4Rj7WpambrlsiCRUNBi7f5m0re3V9qF4hW
         pwtxA3x1jd05UlhkLr7Mem2Ta2fjBrWahjh6Dm71qJZ1tgW2TW43N4mYkWZ0+bNQzm4Y
         j/jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=eOiyRfkt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id mt8si286625pjb.2.2020.06.17.08.19.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 08:19:39 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlZqd-0007cZ-05; Wed, 17 Jun 2020 15:19:31 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 42D57301DFC;
	Wed, 17 Jun 2020 17:19:28 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 2DDD220C227A8; Wed, 17 Jun 2020 17:19:28 +0200 (CEST)
Date: Wed, 17 Jun 2020 17:19:28 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>, ndesaulniers@google.com
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200617151928.GA577403@hirez.programming.kicks-ass.net>
References: <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
 <20200615152056.GF2554@hirez.programming.kicks-ass.net>
 <20200617143208.GA56208@elver.google.com>
 <20200617144949.GA576905@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617144949.GA576905@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=eOiyRfkt;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 17, 2020 at 04:49:49PM +0200, Peter Zijlstra wrote:

> I had the below, except of course that yields another objtool
> complaint, and I was still looking at that.

This cures it.

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 5fbb90a80d239..fe0d6f1b28d7c 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -2746,7 +2746,7 @@ int check(const char *_objname, bool orc)
 
 	INIT_LIST_HEAD(&file.insn_list);
 	hash_init(file.insn_hash);
-	file.c_file = find_section_by_name(file.elf, ".comment");
+	file.c_file = !vmlinux && find_section_by_name(file.elf, ".comment");
 	file.ignore_unreachables = no_unreachable;
 	file.hints = false;


> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index af75109485c26..a7d1570905727 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -690,13 +690,13 @@ struct bad_iret_stack *fixup_bad_iret(struct bad_iret_stack *s)
>  		(struct bad_iret_stack *)__this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
>  
>  	/* Copy the IRET target to the temporary storage. */
> -	memcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
> +	__memcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
>  
>  	/* Copy the remainder of the stack from the current stack. */
> -	memcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
> +	__memcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
>  
>  	/* Update the entry stack */
> -	memcpy(new_stack, &tmp, sizeof(tmp));
> +	__memcpy(new_stack, &tmp, sizeof(tmp));
>  
>  	BUG_ON(!user_mode(&new_stack->regs));
>  	return new_stack;
> diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
> index 56b243b14c3a2..bbcc05bcefadb 100644
> --- a/arch/x86/lib/memcpy_64.S
> +++ b/arch/x86/lib/memcpy_64.S
> @@ -8,6 +8,8 @@
>  #include <asm/alternative-asm.h>
>  #include <asm/export.h>
>  
> +.pushsection .noinstr.text, "ax"
> +
>  /*
>   * We build a jump to memcpy_orig by default which gets NOPped out on
>   * the majority of x86 CPUs which set REP_GOOD. In addition, CPUs which
> @@ -184,6 +186,8 @@ SYM_FUNC_START_LOCAL(memcpy_orig)
>  	retq
>  SYM_FUNC_END(memcpy_orig)
>  
> +.popsection
> +
>  #ifndef CONFIG_UML
>  
>  MCSAFE_TEST_CTL

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617151928.GA577403%40hirez.programming.kicks-ass.net.
