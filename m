Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4GSVD3QKGQEYUKZKJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 115611FCF9A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 16:32:17 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id a17sf844988lfr.9
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 07:32:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592404336; cv=pass;
        d=google.com; s=arc-20160816;
        b=hZ1kxinvz/M2TBfIfT3TXs3leoUlTQd7jE3AnyvKaP2GdwsjMsOnDs/wEBarWwhss3
         oa2WD+v50FGa8q8IOTxxHDEog0NOlmow191UW5W+DLN/BS830pM1eN+1W0NC8dQSYmRy
         SEcEUwYKRbCG30jl/vKHD5RaacPNQ9q/uyGYwq2raJQ2sJoLtwYm9/N96RI6h/+Pv7BZ
         iGWNwe7p/5v0wEsRllqVao7skojV//Ey0YBBnzGdC2hBLPDjoNVwyaJZs7ZYuznA8jJ7
         dDeUJvu/0VAZIkyKI0GZr9raye64dFxr8B6IGzepXaHApfJ16gsvKD8qkoCmqzqHY5tb
         SSTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AriExDJ8s1Lakbw7ZI4tuCIxeWDJ7MboT3sUWfqeH5o=;
        b=FBFwsu/mf8IAnVJbYKluo16ebzKE4jdCHyy+KqD9ueExDsZo3y1rBZBFvi/jAt5UJV
         lxnmvWK+FSCCqVIB+owfUNU67lH1qI1gZqNwp1fP14grSZUSLLSOrn5OgOzOCjW+aq28
         DC2YZf8J+mlaY8qQ6JZiz0uYxzmZpZThQn9abtUAwgq5x4SXVodM7+fnHHeP2aTtt8h3
         xdOJvt79u1qVKR86s76M8PyT3cJKis0NWK03oOGfqnWiUeelT2hv7/UMomPJUiLxaZLB
         esn0U+DzBRlyW4lv4sYWpT08SXr8CbnAS50KqOWPd2Y1VDYqKVyr5x5XgxzzjnE3w92p
         WtPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CKfuFKGD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=AriExDJ8s1Lakbw7ZI4tuCIxeWDJ7MboT3sUWfqeH5o=;
        b=b3MgPgLVHrgNMw1PtI60Ex6PQiJoZGRRubaec7xm71r9CR2VLs/5NvJEQdtNCZGN1T
         GQ4MbQcvSPy1nnll5g2Jd2bicJwvHR1CrJQ6s81VZv25CR0wVvK4NiMkqxgWz0MIclyU
         vxarCulZ2YetIyDW86hnRsbiYu5cXc5L/p/Cq+W0Jz4p7Hzh1E2TacqdFKPY1iO1gbE7
         RshwDsMW5NScg29nd+Mn4bFRKbT+1wpBnJbpmySGdZPWgy9cGFnO8rACd/ZWpvhUCbSf
         u1vJuJfIv0wbuq6PzN+M+/5X10q9idLucOW06tLXzp6oJiHW9KX9TT49G7XznGhaEPPV
         exEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AriExDJ8s1Lakbw7ZI4tuCIxeWDJ7MboT3sUWfqeH5o=;
        b=CjwciKBbdHHD2JEWny90XO1PwykPYHqhQ4yjqfE+9oTfHipJ0VG1n9ePVQ8m8WCrgw
         wJIsJSU3rf6xAVMouxrcPxJfqchVtFFuoEcoblMMmqaoRShDL9i5Bd4VV9iQgIerS0cB
         t4PxOxwq1O06+uLQUM+8Td9Nnh1zYDRmavOPKzX3BLktFZmUkeiJ2bcUdcSiIn0W3Bjt
         P6UgYYPzJZPVKMciFVvYhYeRULzGN61dl1I+xC0c9Pw7yhZXrlu5L3K6dvQ+E2RrM9wn
         62z1SmXFlELvhle/IKlr7BjCB0oCcjuTnL4wTIvBdnKbIYYBc4kBd+dktB6AMzgqde59
         AHng==
X-Gm-Message-State: AOAM533ZzbFtFk6YqmLJqDG69TShR/uK1Gywv5cEUpAOBb/ZcZuSv4s1
	dxsjNT+5S4W0Ldw2WKKtapE=
X-Google-Smtp-Source: ABdhPJws2JWKsTvwBtB31ahsAgJF+lSU2Jzwi3zEvB3Gi3vO5UNe4s+lctVMWaDrjRgmrbtAyStT3A==
X-Received: by 2002:a2e:9258:: with SMTP id v24mr4034804ljg.418.1592404336602;
        Wed, 17 Jun 2020 07:32:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6a04:: with SMTP id f4ls552474ljc.7.gmail; Wed, 17 Jun
 2020 07:32:15 -0700 (PDT)
X-Received: by 2002:a2e:b4c1:: with SMTP id r1mr4466716ljm.370.1592404335896;
        Wed, 17 Jun 2020 07:32:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592404335; cv=none;
        d=google.com; s=arc-20160816;
        b=qo7eceimDXM/kuwywccY3zVYsjo7325JX0FTq8K51fon7Ge6mrjwfulVoXJ6suDBNK
         J6wazVFeVGkIsmCkOdyDaiMKcFltjQWfd84oqvFq/YxicAQnSwmC2J9mPz2x/BbDb3rc
         ll4YA/faae9BePVy6s2tSPSCfNmjzbKE3iwMeM3PKzlmmMf+cFNp8cN1BHHfn5XiXYFz
         mBWOopTT3dCQkcESqOKtYKXvozEplb47BWhdKJU0y8eicYd3dDhyy8+44bKUyGq7VOOL
         5Hzy2ciBAgPoqmYrY11MzyitwnCLuF0LTmu9O2E+XwT3ttCXVkkpzoulAriXVreJ3ALV
         bA7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/NUSA9pglzD7yNhWCpeHZkfqenFsYSN7ZT6sKeOF1qQ=;
        b=Yzq2jBh3imEd7ZQd4eYaAAd60Vvlqrd3NOMeTO7GlEO1yc2O/fA607KJMTP6wab6Ac
         INhW7UY+7TYUfSCG07RAuh3VVka6/T4xPMtAaV/7z8bL38C+JjZc6PnX0nkx1Nv0mPj1
         5EXmXvCqQzExfKOCYfx2GR079v/Cq7RYNNsAnRCLR3LXoMJL0cjrF5qxYtD/w8RAHkkH
         Syikgj0O7TATIkR9wWceRhPHT/UXUPORrj0YNE2yC0GLe7bOjXQRyToSIeIW9Eh7XeHn
         Z2Zr0O+6tbxIU/vUVyUOcXkj0NgS0ZND8lFI3xIx4LqPHulSbzCt92gr5FY3WfkHvleI
         SzEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CKfuFKGD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id w6si6036lji.2.2020.06.17.07.32.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jun 2020 07:32:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id d128so2247341wmc.1
        for <kasan-dev@googlegroups.com>; Wed, 17 Jun 2020 07:32:15 -0700 (PDT)
X-Received: by 2002:a1c:2d83:: with SMTP id t125mr9257993wmt.187.1592404335139;
        Wed, 17 Jun 2020 07:32:15 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id h7sm628623wml.24.2020.06.17.07.32.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 07:32:14 -0700 (PDT)
Date: Wed, 17 Jun 2020 16:32:08 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <20200617143208.GA56208@elver.google.com>
References: <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
 <20200615152056.GF2554@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615152056.GF2554@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CKfuFKGD;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Jun 15, 2020 at 05:20PM +0200, Peter Zijlstra wrote:
> On Mon, Jun 15, 2020 at 05:03:27PM +0200, Peter Zijlstra wrote:
> 
> > Yes, I think so. x86_64 needs lib/memcpy_64.S in .noinstr.text then. For
> > i386 it's an __always_inline inline-asm thing.
> 
> Bah, I tried writing it without memcpy, but clang inserts memcpy anyway
> :/

Hmm, __builtin_memcpy() won't help either.

Turns out, Clang 11 got __builtin_memcpy_inline(): https://reviews.llvm.org/D73543

The below works, no more crash on either KASAN or KCSAN with Clang. We
can test if we have it with __has_feature(__builtin_memcpy_inline)
(although that's currently not working as expected, trying to fix :-/).

Would a memcpy_inline() be generally useful? It's not just Clang but
also GCC that isn't entirely upfront about which memcpy is inlined and
which isn't. If the compiler has __builtin_memcpy_inline(), we can use
it, otherwise the arch likely has to provide the implementation.

Thoughts?

Thanks,
-- Marco

------ >8 ------

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index af75109485c2..3e07beae2a75 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -690,13 +690,13 @@ struct bad_iret_stack *fixup_bad_iret(struct bad_iret_stack *s)
 		(struct bad_iret_stack *)__this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
 
 	/* Copy the IRET target to the temporary storage. */
-	memcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
+	__builtin_memcpy_inline(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
 
 	/* Copy the remainder of the stack from the current stack. */
-	memcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
+	__builtin_memcpy_inline(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
 
 	/* Update the entry stack */
-	memcpy(new_stack, &tmp, sizeof(tmp));
+	__builtin_memcpy_inline(new_stack, &tmp, sizeof(tmp));
 
 	BUG_ON(!user_mode(&new_stack->regs));
 	return new_stack;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617143208.GA56208%40elver.google.com.
