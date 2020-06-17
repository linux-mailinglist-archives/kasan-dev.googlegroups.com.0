Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJFXVH3QKGQE2TZC6LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 25A161FD414
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 20:06:29 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id w16sf1690995wru.18
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 11:06:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592417189; cv=pass;
        d=google.com; s=arc-20160816;
        b=YwgvZ9fqp1wMckihwM2PKsZn/Ig8rC0sj+RqkAiAPLcikDR+QK75lkEfraDbjLmaFg
         vg5wv3xFPSECnMHEZCxUphql7C7/74vywW1yP7MAobKdQ0eepeynTDoTGm3dsSaAQYO1
         XPJmOcbcrlEN40Q/wYYD6vmMUibVvnWX6fiDlyLKCpjlrbyd7SeopyZWSCosxOVt5h0/
         pytdUcE84O8A4nlTp0uCPZuGeAKX8gq1GDL8J+TxMhc3+NZmqOc8dN8VekSNsCaDa+cg
         ytym4Rf/uezvpk2Se+fnJCICajSwmIfxM9VI+fBt4XcZRKmL1OEzfRVERDf7ySaanyBh
         4YBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=m2VNKQmgD93MraOfxlO1J//4gQ3ioP1Bl8iPj0Zkuww=;
        b=Ptdl6FNAhVzbqRpacnmUEJ0fEkLJezZyk9pD3te/r7r5arjMPU6c7045RudmzVNuIm
         L8rghKSE3/qrglsWgzz8XZTuBqKNW7up/qKBfwLAQ3lPwZi8rX1FgaTrzTiLitIUvyu/
         YqaiIVB2CbWnpSQfnQ/J0zTIdzKx7sggXfzrgzAgMipvgvg04O/nKdiCd0JyDM1NL8oh
         44P2jPgDqFyHT/ag0320kS+9XY7xFdmYaqy9YvDtcb9fbyOgZ/U29KunGje2Qs13/Nqf
         XrcIUhryUxQjNPp0eDsLOEqmCHRoYr2EQX1UIfFFejDEAOXlT1Tzjcopz6K6kGblQDoZ
         TVAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kNUKj3I5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=m2VNKQmgD93MraOfxlO1J//4gQ3ioP1Bl8iPj0Zkuww=;
        b=GNKuDg4w5ShxgLS6nB9DOvR7yaYSAqQyLcYiCPiNKWbzB7vZ0sQqOxqHhjHBdXNWRj
         bpH9MIkHk9oOF9MWJdz9L+JC23fL0MYdZ+VKBP42rxPLbBhWO+NnmCOWUQ2Ir3eMg3i6
         3NaOiuqJ9iSEVhbMYIPzDNSB2+QLy+I+DfjFji6/Jm/64E8ZHCSw6YeMkQ8/HifWZy5/
         RjQ98PZf4fIWMcsXkuArh9F7isRbcQNDVuTfjUSFC4Y1oRpUzAumKeqqLNUlpS7zf7Az
         R9Mb76P26tR4qnNLFOBOzhohBAsqFdVqqcOvo4G4XHkDwF9NEdqsWxDDQtpCsdRIdY8V
         RMNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m2VNKQmgD93MraOfxlO1J//4gQ3ioP1Bl8iPj0Zkuww=;
        b=Vkcb1gEDGqC6sKTwQYYk1EU8psHnqdX+e0/6r6uYg/IVdb9GxWWLHCNfxD4DF47Rt5
         enIC+mMfWoDMQxejVEUjqgIe5bSocBXvMlUd4Zai0RhK1jGjie0X1h1o+GmRUvJlAdCK
         6IcC02YnWoIqjddCLhT64Pa8FS4t8yMahpmbfVYVptGxjHEXtyOPnUguGY/lMWoWUFI4
         PC+EQA9jj5WkEGok3x1Edw3cDCX9tNF17vaX59AI3wYt3qqmcyMtFtcwlmScz5UNEXdM
         Czw0aUZAb/lAmROg3KdhkmIyXgILU6+Mkcs4LLKMgL913D91Rlj60SmRZHz4gj8Ihm03
         OeTw==
X-Gm-Message-State: AOAM530N1wQsZ1LLch9WPhAePjMucArApVutgoJ1Fqo991oE4oVdKemZ
	qJCnIhP2wFCmMGwsx8Jgpgo=
X-Google-Smtp-Source: ABdhPJx2lDgZSE34YpEUVEb7q4ySthB4oq5P6M7JB3GgEVp5Uve/JbS/YyThbewGCpSKa39XUKTozw==
X-Received: by 2002:a5d:5490:: with SMTP id h16mr520686wrv.394.1592417188906;
        Wed, 17 Jun 2020 11:06:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e510:: with SMTP id j16ls4237490wrm.2.gmail; Wed, 17 Jun
 2020 11:06:28 -0700 (PDT)
X-Received: by 2002:adf:e850:: with SMTP id d16mr498508wrn.426.1592417188282;
        Wed, 17 Jun 2020 11:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592417188; cv=none;
        d=google.com; s=arc-20160816;
        b=hFwwegoGV1098QX6qc8X5tpxa72BdJ9niJ5tT+UuAY/X17798oXFUdnu9nnp4GmcBj
         kEBiMOF0bWRkbPDn/XgNw4ZvadMr08iQ0tgRj8C+rktG15+6/sEbbqlrL99K57gRmvYi
         TBagAIilm5ntw1LPYwnYJS3oTKA/YFVsYvRRR+r9Dqt0mk8fRUIe/f094sC/dG8/u/Jp
         IA9JuuBaDoYm8ZcElR5oGZ6Xlkwk09ip4CiZF1RhnL0dge5dkYQW7ACOKACkLQ07MT20
         NjsXZOMJSWms8IaBlFheqKlK6j2zuRqP5dZaLtOR0rEEMCO0HZbFtpFlyNQqpg2f9L5b
         Tkow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yum1itbYwGCVmrfngXbrZP6sf+Nn+eNmWkfS6zoUuA0=;
        b=jlXKXq0IlcoFVtTU/PRnVqthmiU5aEh61hcq1rwoqRQOPjQkBki8nExNReqbKUt8ce
         rjJqp64ckaJ7vlApF2WzPiQeK3TFBPGkkHi/72WvMEeNKYyGvIPDAvaD64hnIvSoFG4T
         cpTfUb7OPCzq3rgNi8Jz0ZmuJJTYUrR/TrC4/gr5GOipcIiHJCagyOWExa7ipmSQ6aZb
         Qhe/nE2QJ6QQd6vC4RahinuxIYvRb6rdt8TSNyDMhDS2G3RFZ2BrPh65fxvUgi5qTtLY
         I/mArjugsZTB08LHHwGKMjkW0xSWJLCPW+6+0zoh2hRXJ2m84Z9nK/qCK46fuOBklcaX
         BJLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kNUKj3I5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id o14si26721wrx.2.2020.06.17.11.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jun 2020 11:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id y78so446950wmc.0
        for <kasan-dev@googlegroups.com>; Wed, 17 Jun 2020 11:06:28 -0700 (PDT)
X-Received: by 2002:a1c:3b8b:: with SMTP id i133mr9658094wma.111.1592417187758;
        Wed, 17 Jun 2020 11:06:27 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id 5sm477701wrr.5.2020.06.17.11.06.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 11:06:26 -0700 (PDT)
Date: Wed, 17 Jun 2020 20:06:21 +0200
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
	Josh Poimboeuf <jpoimboe@redhat.com>, ndesaulniers@google.com,
	Andy Lutomirski <luto@amacapital.net>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200617180621.GD56208@elver.google.com>
References: <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
 <20200615152056.GF2554@hirez.programming.kicks-ass.net>
 <20200617143208.GA56208@elver.google.com>
 <20200617144949.GA576905@hirez.programming.kicks-ass.net>
 <20200617151959.GB56208@elver.google.com>
 <20200617155517.GB576905@hirez.programming.kicks-ass.net>
 <20200617163635.GC576905@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617163635.GC576905@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kNUKj3I5;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Wed, Jun 17, 2020 at 06:36PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 17, 2020 at 05:55:17PM +0200, Peter Zijlstra wrote:
> > On Wed, Jun 17, 2020 at 05:19:59PM +0200, Marco Elver wrote:
> > 
> > > > Does GCC (8, as per the new KASAN thing) have that
> > > > __builtin_memcpy_inline() ?
> > > 
> > > No, sadly it doesn't. Only Clang 11. :-/
> > > 
> > > But using a call to __memcpy() somehow breaks with Clang+KCSAN. Yet,
> > > it's not the memcpy that BUGs, but once again check_preemption_disabled
> > > (which is noinstr!). Just adding calls anywhere here seems to results in
> > > unpredictable behaviour. Are we running out of stack space?
> > 
> > Very likely, bad_iret is running on that entry_stack you found, and as
> > you found, it is puny.
> > 
> > Andy wanted to make it a full page a while ago, so I suppose the
> > question is do we do that now?
> 
> Andy suggested doing the full page; untested patches here:
> 
>   git://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git x86/entry

Yeah, that works, thanks! I think the stack increase alone fixes any
kind of crash due to the reproducer.

Also, my guess is this is not a hot function, right? One caveat to keep
in mind is that because it's not 'memcpy', the compiler will never
inline these memcpys (unlike before). Whether or not that actually makes
things faster or slower is anyone's guess though.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617180621.GD56208%40elver.google.com.
