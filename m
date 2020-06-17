Return-Path: <kasan-dev+bncBCV5TUXXRUIBBGG3VD3QKGQEWWNIOHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id D25C41FCFF2
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 16:50:01 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id c3sf2775050ybi.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 07:50:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592405400; cv=pass;
        d=google.com; s=arc-20160816;
        b=moii4APHdR2Zea7eSfUlW49Gs7Tl4p+oR6HnSWcNzpJH2MwVoPa3MO+LIOfc+KT4q8
         IJ5COxRUeuRzgRB/TF6Zz2mpYe/vuBkiGP4uZDWU2OVxfgg8adTxSg+idu2XCjhyNXTJ
         tEjGklwR6TbQzESaYby6kxxRwmYNsgf08hvux2kqU7ASUT1PMTv8qGCLW2EoHzlmFkQj
         ugudU6qerzSGiQoP2ifUiixBpMpHXDqvmL/t/UYw4ddzQ0knxoGU9M8AUW8AjEyhjzOd
         lCbTbrvhh3Dr5bb2YbQ4/d9rvkReDu5tjC1pt6JZ8R8iQOLH4BddCjblRtEw8Z/JFFFU
         F2JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wURaQVITgTWBgIjjAy6xwZxhXi28OCr1GXcg8+8QXho=;
        b=M4uzCeuvgNIr5Zcp9ANTgYzJUptPQ6XGbsxq6boJUkusmAiEUpNWXVNwVneifzn1c+
         L+q3JJ3usMJgAkUyLNaz5nt4qbN0pd9hckNxYzsEDQog1WMmjzcLjoLmCg1XrKcmI1YT
         99GN0jO1+xIfNygDVXMd5Foi8pKkf19Y5Amks7NAlG2MD5VSN6KTp6eg4vjcweNtWSMN
         XXzf4TLCMoKdLW2vg4lRsv2s4/xzTFvmKhR543fqe8Owcsd/73fT8fWHl2vWM8k/I0NJ
         LvV65HCZCdJ2Lb9y0Rer7EdcQr+OyDEM1SR3gGuiGNKvYKp93ioCIrhcYLR+423nrLwu
         l0yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=l5S4jMfS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wURaQVITgTWBgIjjAy6xwZxhXi28OCr1GXcg8+8QXho=;
        b=I1DtayREGycAR4sTAkMQMn0xSeUToW9lfowKTQRB+xHlGJdZPTuhRXhdes4ExH05Q+
         tCPmkBxWy3vq9gvitKr6tDlo06jtL9Dvkz5hrvcPF46k/UTmHbe6TSOSJS5M5hw+/DIC
         gcMTeyOG8/PhR+b40XzEUzCkMiQwafX61WzKq0fo1+Jf/TBkylHww8M2rvDBpnzC5DiB
         t6G+h0EOY4Y148w0Kk1lrBCC7F2Gvd4hvhWpvFjK3x+Znkffx/5SPR0RRmnBU/n+QZgQ
         XLvYRKmf2QwM2ZLipWaP402vx0JsO+iFF5TqPcSrOqx20TL2BeNHQEn+y8n57BsqJHl+
         BtVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wURaQVITgTWBgIjjAy6xwZxhXi28OCr1GXcg8+8QXho=;
        b=MUSvEb3I+qnoyJauafbDouxB5e6hvjAPJIxEWdUUTf+E5XwxTe4KVDoxT8WEQ4IrLU
         9LUf15N7VIF0WzijABI8kLZ7k0Ztuwnr3NasZPgcHK+vORUtKA26cXH8N8ONWQtj9t3J
         7t8rsTbzCJf0rrrNBWk+QdEsYjvmxIzDP2rqvQpXwNqIFblgf8y0Q668rWq9sG41RYxw
         CqPvljN+Hy1G7Tv0pKPlZivkva/8Q19xPeNUFoJhL+gZxxzDVQC8qqAIcZRgLKK8LsBO
         Xh6n9jHOb4NwLdREuL7nhHPkINnFMSRaPi89WOf9p90rtsJ6k6VysoT9L2YiPi7y92SX
         OuMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309CFR5z8OQuvTDLou9qGLxaeHrG8nmbHonFlKgxFRZ21Oda8Iu
	gcUNLyNyIjY7HbzeQozN2fU=
X-Google-Smtp-Source: ABdhPJwajVC01f6UgI0nZhFAox5iGquBGGDQFoB/yh+eHdoIIZ3N80fPNDOa6oGf7suiLQ2n9J41rQ==
X-Received: by 2002:a25:bd4c:: with SMTP id p12mr14114941ybm.471.1592405400595;
        Wed, 17 Jun 2020 07:50:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d603:: with SMTP id n3ls1015471ybg.3.gmail; Wed, 17 Jun
 2020 07:50:00 -0700 (PDT)
X-Received: by 2002:a25:c508:: with SMTP id v8mr13459567ybe.497.1592405400230;
        Wed, 17 Jun 2020 07:50:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592405400; cv=none;
        d=google.com; s=arc-20160816;
        b=csDMcvNPlJlj0CZ6veBqKg4mRRsPPuHcVLkO1b1maezTsYTh8plDSpxJgLDm87hqIk
         Q6JQqklSt38mbnV8rf7wWMW4Q/mwViLqhc5IR69P8rLQ2aCub4dpgfdw7cTnZRGdtfU7
         iEH3zw17/4xY+YYxkaPE2xfDqIcnmC93J9BCwHXz2zTQGpIpewYbYaQxbJ73czb1UxGA
         AGIuH/mc+ApxLhKXajfrt37X/72HLCFyVnMTVmiyS/SVTSGz19zWQbBxZbBeo7h3l/mc
         CANVOngK8cHfXABe65DzN9FCvubW1n9kwyY//b6OmRNJTYkO3xijnOt+0FCpQ4+N/44T
         yaxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8tV90J3ommZlSIBCa9GxO7kk+JI83XJ4xYdDZnD4Ijc=;
        b=M+wixqzC9lXCcnwpR6UjpvwTwpi71J0b1Dtb+Zym87v7jiX3JHiqN0wRDnnC2bFzOG
         r/+na0ZqtsiAoiqd9ofkY+ub2eyHRb9gA0NA/OVsnwHLJGcuDl6AvlKWI7PMcKf87Sv7
         VkcITnhReS6xX5iL4WbchCP3S5BYoNAr9hkncT+n5Xk+ENwqGJGtBb54SJcpcg1saSvA
         DC46GgXlE1VGjX1jvqAHrSsl7G+OmpiI+BRei/VLlZqCfqqrx3sDE72HT02/qXeEmL/y
         ZmfkVjwKSZX0+n5bf/81gXrJSsgF3GwU12ALj6VtbcQbsFL597HEgeZhkMIOxZ8MdQ/W
         153w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=l5S4jMfS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id n82si5852ybc.3.2020.06.17.07.50.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 07:50:00 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlZNv-0005BJ-Ds; Wed, 17 Jun 2020 14:49:51 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 91214301DFC;
	Wed, 17 Jun 2020 16:49:49 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7D29A203CE7F6; Wed, 17 Jun 2020 16:49:49 +0200 (CEST)
Date: Wed, 17 Jun 2020 16:49:49 +0200
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
Message-ID: <20200617144949.GA576905@hirez.programming.kicks-ass.net>
References: <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
 <20200615152056.GF2554@hirez.programming.kicks-ass.net>
 <20200617143208.GA56208@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617143208.GA56208@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=l5S4jMfS;
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

On Wed, Jun 17, 2020 at 04:32:08PM +0200, Marco Elver wrote:
> On Mon, Jun 15, 2020 at 05:20PM +0200, Peter Zijlstra wrote:
> > On Mon, Jun 15, 2020 at 05:03:27PM +0200, Peter Zijlstra wrote:
> > 
> > > Yes, I think so. x86_64 needs lib/memcpy_64.S in .noinstr.text then. For
> > > i386 it's an __always_inline inline-asm thing.
> > 
> > Bah, I tried writing it without memcpy, but clang inserts memcpy anyway
> > :/
> 
> Hmm, __builtin_memcpy() won't help either.
> 
> Turns out, Clang 11 got __builtin_memcpy_inline(): https://reviews.llvm.org/D73543
> 
> The below works, no more crash on either KASAN or KCSAN with Clang. We
> can test if we have it with __has_feature(__builtin_memcpy_inline)
> (although that's currently not working as expected, trying to fix :-/).
> 
> Would a memcpy_inline() be generally useful? It's not just Clang but
> also GCC that isn't entirely upfront about which memcpy is inlined and
> which isn't. If the compiler has __builtin_memcpy_inline(), we can use
> it, otherwise the arch likely has to provide the implementation.
> 
> Thoughts?

I had the below, except of course that yields another objtool
complaint, and I was still looking at that.

Does GCC (8, as per the new KASAN thing) have that
__builtin_memcpy_inline() ?

---
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index af75109485c26..a7d1570905727 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -690,13 +690,13 @@ struct bad_iret_stack *fixup_bad_iret(struct bad_iret_stack *s)
 		(struct bad_iret_stack *)__this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
 
 	/* Copy the IRET target to the temporary storage. */
-	memcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
+	__memcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
 
 	/* Copy the remainder of the stack from the current stack. */
-	memcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
+	__memcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
 
 	/* Update the entry stack */
-	memcpy(new_stack, &tmp, sizeof(tmp));
+	__memcpy(new_stack, &tmp, sizeof(tmp));
 
 	BUG_ON(!user_mode(&new_stack->regs));
 	return new_stack;
diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
index 56b243b14c3a2..bbcc05bcefadb 100644
--- a/arch/x86/lib/memcpy_64.S
+++ b/arch/x86/lib/memcpy_64.S
@@ -8,6 +8,8 @@
 #include <asm/alternative-asm.h>
 #include <asm/export.h>
 
+.pushsection .noinstr.text, "ax"
+
 /*
  * We build a jump to memcpy_orig by default which gets NOPped out on
  * the majority of x86 CPUs which set REP_GOOD. In addition, CPUs which
@@ -184,6 +186,8 @@ SYM_FUNC_START_LOCAL(memcpy_orig)
 	retq
 SYM_FUNC_END(memcpy_orig)
 
+.popsection
+
 #ifndef CONFIG_UML
 
 MCSAFE_TEST_CTL

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617144949.GA576905%40hirez.programming.kicks-ass.net.
