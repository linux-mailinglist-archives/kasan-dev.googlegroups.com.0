Return-Path: <kasan-dev+bncBCV5TUXXRUIBB4HZVD3QKGQE7KJ5B5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC4C51FD159
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 17:55:29 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id v8sf1195833oiv.16
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 08:55:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592409328; cv=pass;
        d=google.com; s=arc-20160816;
        b=wk0bS89q+DKvYknbx+mN5/ajOkD5N3OYEUZP5DAV90LzVsfh/HD9BBkPU/ez7Mv2sy
         o13+lDT+VSjY8VS4k+6tRSnGACWc3si7ZTU3WkKdge84Gz2VxDykOzfOn18w494URXWQ
         aH0pHpIWrzhDnFKDO4xyirkMPVXYqCeuTQ9ZeKKiIZC+yUyiUewptL0uNSYmUPMM/YY0
         KkWlEXOlw9bwcPd/eZ/jZL9pA8WFz1ABbUn+vGG22YMdh3QQMt4D7hrGQSdvwygSrJ6w
         x0F3b7TwTjOS+5U99F5KOQlgdn57f+eOIKduzHbtBTWMUAJW0vi/5SA5IU+fzZkzb5nw
         bFzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qF3/aIhidVu0ZDpuFPzb/IyJuc5bSkVVpFFcMHv7xK4=;
        b=F8nFVny0EozGJkuB80L9kKnqzVy4vPc7/0DjYzoZG1HILUtAOrQGBavVrVrBN0PkhE
         wd29HzTmb2Zt/kBYPMppNZVN25jOOzhH6ZLct9T2k4BYuhwr/lRubIjsL4+UU7C6S2br
         LYxsv6IRv4bw8n3DqhgdrX26Xk8CRmtX2BB5vGmQXTEsTvDb1Kgh60xH924kqFoGrIUJ
         dsJpM8XM1sej/cuMWUae0bulMKNmTr9MUa4E7Ih9/bc9L3AHae5DbKWuA2xMfm+as0tr
         p2sn4uD7+8JrU2qL4IyStH2II+skFEeZiAMPqwa8aNesLu2TtNaQwXGuDxj1K546eyFK
         8WjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=QJorX77s;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qF3/aIhidVu0ZDpuFPzb/IyJuc5bSkVVpFFcMHv7xK4=;
        b=bRzhIqYPu3ukO1BW3PrdXuR3ifC6BaggkItHkaQnPA2KKjO4dJqvrnpQ2zumY2TV/G
         UQ3tZmjXmRNTg5W/D4V8Q6hOPoZB+CsC6TTYm1sTicXi3lhQa3set6LHdpPEtVi+aMQO
         xXH1QCXKncPVYG1whdiVlp8BoiwMTJV3VF2EpdiTcIkhURi7PuzcAIuYSiCfb1+cmd2d
         +Bf3Z0jJJ14szT1OXy2+pQy95xsTl68mqn0nUD3MN4/TZm0EvgS4nW4tgs+Rs6bqJDbx
         SBS70u02kWWdF3ZL+ttl84CdVvlkhAp7Zkyj5SwViuyg5npTBSCkimtFx4jC/tfl0KsW
         ahUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qF3/aIhidVu0ZDpuFPzb/IyJuc5bSkVVpFFcMHv7xK4=;
        b=IWyLeR824WpAtcTgSr3NrJ0lJxmj4vg4H5t/OVCFZSwe+Rzo0gGMC3N7QyYdXpjVDd
         kL7lwbzIopNlj0mnNZkgjMQTnCWITx6cJKJkUX+uQId3rpAARqlFmCH8bhoGgha35i86
         81kADEsAsbX9QJLDNr//Zgg64v7FXUDOGg4+I2oS9sdWe06zxHW1Xo1yJWvnU5n3XDUv
         6Jj9eD4KW5cy2w2YIr210VaVYzBT3VsF3JEiCn2+e7Tis1wdn/OFlFFVl33jJg3F47H4
         Vi5kc2VoPWShHULaTxd7Bps0h0dCAg1LhG0LIAyPayRbrnG0HRmRfjOZ2p76k2fZU2B7
         S3qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BczSuxlKtdc0Y/0b5meXo0HVgVb44ZJ8YlTuibthVwpHq6/MU
	gRoKu6Bephh0/xceGig/ggM=
X-Google-Smtp-Source: ABdhPJxpsFanNL8yTsilwrb1Z7eKmTL52o+GXnokj6Tqo1NrPzYCQs7Vi2+noPlz9ftQf3fO32NnSQ==
X-Received: by 2002:a54:4102:: with SMTP id l2mr7903358oic.29.1592409328614;
        Wed, 17 Jun 2020 08:55:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5ac3:: with SMTP id o186ls528376oib.5.gmail; Wed, 17 Jun
 2020 08:55:28 -0700 (PDT)
X-Received: by 2002:aca:f141:: with SMTP id p62mr8144156oih.136.1592409328154;
        Wed, 17 Jun 2020 08:55:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592409328; cv=none;
        d=google.com; s=arc-20160816;
        b=DDyYdovdBQUJHRPFYC4rfNh6bg3x1IfEbEvbKuOc7JhZx7n4H+1ABWGaEWy5X+iRHh
         zWfUQ7cSLz1yYBrkS+X8/3ik1mq4dkoZsiD9VWzsvOPtcTfp4ypbo4EjMGyyFa7dzHLG
         K7xaqdiTSj+AlfKtP/QYG8YWFWzXqCO6y6/pO8HGMX7f69OgXeV7ySveycUm823cmm8Z
         d76MicvXSqOceJrdSlEBVvBJy8uC9jXkCRO6y+IZ2VXdSwd0eGVM0g94urRlDi22ihw5
         89kT1QKvU10oJbpeX7S7hFoP4CzqAbsGuTsG4XQSp4snCclj4GuXiFLuyUB/JXpVxsNP
         JKQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZSPAp3VauC2iLtFOlqrXko5KarTwOTs5rDR2BqCF0EQ=;
        b=Nk/dm62s81DE+0pCnadGnQeHQF5v0CYBtVjVyJ+Kk+SDYPJHLQOZHJFn8aVsS56WQ4
         daePKQf4VMUEppvdFwGInC+UjIILclF/ifEvaPR0PobI02Ch70DUvO82kQt7/fYzgqNR
         1nt4roXnyrtEZoWV7bolPf83Y9Msg71x5YT5aBC/gLNUKtgNMu0ZTmzaz57Vku84YVcu
         Hu2a5YWyxwALnXMJlWXcbRWNsqYR/5BhM9O52dkQbHQMhn0z7IrJmzxXZj69G5JuJK0K
         rcG7fo5X2BNH4v2y5BG20hH0o4NXPXmwrAWopAVhb5ArBa9WKwFL4F39gX8EF5/8IuAA
         uKvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=QJorX77s;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id y198si5169oie.1.2020.06.17.08.55.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 08:55:28 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlaPI-0007Fz-27; Wed, 17 Jun 2020 15:55:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A1FFD30018A;
	Wed, 17 Jun 2020 17:55:17 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 91CC620707D49; Wed, 17 Jun 2020 17:55:17 +0200 (CEST)
Date: Wed, 17 Jun 2020 17:55:17 +0200
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
	Josh Poimboeuf <jpoimboe@redhat.com>, ndesaulniers@google.com,
	Andy Lutomirski <luto@amacapital.net>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200617155517.GB576905@hirez.programming.kicks-ass.net>
References: <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
 <20200615152056.GF2554@hirez.programming.kicks-ass.net>
 <20200617143208.GA56208@elver.google.com>
 <20200617144949.GA576905@hirez.programming.kicks-ass.net>
 <20200617151959.GB56208@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617151959.GB56208@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=QJorX77s;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 17, 2020 at 05:19:59PM +0200, Marco Elver wrote:

> > Does GCC (8, as per the new KASAN thing) have that
> > __builtin_memcpy_inline() ?
> 
> No, sadly it doesn't. Only Clang 11. :-/
> 
> But using a call to __memcpy() somehow breaks with Clang+KCSAN. Yet,
> it's not the memcpy that BUGs, but once again check_preemption_disabled
> (which is noinstr!). Just adding calls anywhere here seems to results in
> unpredictable behaviour. Are we running out of stack space?

Very likely, bad_iret is running on that entry_stack you found, and as
you found, it is puny.

Andy wanted to make it a full page a while ago, so I suppose the
question is do we do that now?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617155517.GB576905%40hirez.programming.kicks-ass.net.
