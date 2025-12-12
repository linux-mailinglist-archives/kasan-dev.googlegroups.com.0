Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJPG57EQMGQEJLE3JNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 77ABBCB8A4D
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 11:49:11 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-297df52c960sf22051975ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 02:49:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765536550; cv=pass;
        d=google.com; s=arc-20240605;
        b=RfeDqKEWl51rH1z0Wc3DFwYbuoq+caacCI8CmefOi//jK7E+QifQMTqA6G6+V+9fAe
         lNIk6kqHImQomS/1NYtz6IosWkdMykMLfH/+gdwBxpvyZUAeFEZ+H7+6SW3+yJ+4F9WY
         fE/ATJrTqvdstxJG++vrprxqwW36cwbyszIONkl6pGxU+otrG97zOOswvMIUdOl6eQg5
         RuRpSmyg8P8oJMgEnAqvdcLS6l4G9MhUISaYpwTsNc8U/g503HbHCrG1z4U23maKl8le
         vRN/7FpYDTP4D5WPYuRqSshe009a7/KfobOcAGvMOMwrgo0Ywm4NE6QPTKV7gwXtyQcd
         R9Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UxlyQH8+WREcFCM7yNxhwMCOTvcqNz61jxxENhMA6NU=;
        fh=kCht9lpR35ilddGDc9vOEouw9EDo9xQwVyOIqJ1cQso=;
        b=hByN9ilVquv8O1SLpL+3zG7kMropvXhSP9q7zSL76dqZLdXQpS8KhvoQu2Co6ri5m6
         5bJGiDkVQvP6GHz4rtZcw1/rPnIt6bjLtA2e68w8L9OD/Lsi4NkSNGhbRmNbtOHSNfb2
         2h7xoyQ+Dg+9WxQplqYwPL1I59xeeS4u+UCUcsLY0Y/W68vJ6l7+MQ5viCFZ2Km8c8YO
         hW2Am8WWVHxhvnIO5TSJNfTE02+iK5/+BXsQOV3F+lLpAPKqFZdCkIbc8p8hT7A/6Hqt
         i0Miv48PjXQr9JHuZjr3frT4kpJbOd/b9rXyH0/a7Vus3mSr5lAgDjficr2J1ru/azGk
         UA9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iu9fLzpd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765536550; x=1766141350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UxlyQH8+WREcFCM7yNxhwMCOTvcqNz61jxxENhMA6NU=;
        b=ru+9NQ6TXQPMIGguwBb2hNsZg7AGBwN6x+eGFOqRmJnCcmT8rY9qRen8Kk61o2vX1J
         9icTAWMtqlorZQtLJy4k5toZyJKxbKyGyFEqPLlADdjq1npwDrDIK3OD3bLWWvJbvvL7
         GG9BCSgSsfvLXQ0kV/Ti14IGOemIQutXFT+SiN2Rcb6FyGhKWvSYmZW4JKMvPolkFD1W
         aJU56adwwCQ/X0S8GA39Qq7rnng2JKWc2ZaRl1WTTH+e75CI6J6CSQbSLG+y67QahfNC
         UY2T784+8DbpwSLuklTq9Uj7MEZiohUga88An+MeGGoo/EBTN0bThwywkWPjNgeaf1Fl
         o5dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765536550; x=1766141350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UxlyQH8+WREcFCM7yNxhwMCOTvcqNz61jxxENhMA6NU=;
        b=e19NsPZKq1egx99luKsK04f9LQQq7iYoatc5UhSIGBCNqQVQeleT0PYcfR3iBe1W+i
         7flv3k4iJUnPcNF2KuGsFxPVcOntEcqhk/sLNOSWSZCDiFL/veArfoSEX74BWSNkkWUn
         JFB+W/afpS9QJHhxb9Q/tgCd/wT5xTSamq3KLzcM1g+JCtzRjjjqCJ5jE2xoHuYyqoXq
         1gVMLBqk/O/NH3qZPS2c0efLhTzerTECGoW/RnpEn/2enckM7cpygPLMDs+ws2/+qz2w
         hTKIRZuvi5dM7FFhFHQ2Ys55A35fLqVDZGxCR+a/deYAIoo817JsgGxAvKce0x3W6w+F
         dOdg==
X-Forwarded-Encrypted: i=2; AJvYcCXpKT+apkoY9UCt7jZDwIytDkb2ioopCp6qt57s4q1M5/DOb+WdGlwMhRjnfo9mpK8BegyJkg==@lfdr.de
X-Gm-Message-State: AOJu0YxWIx5jFW+KYuiIThaYOLWgGFKsAiwQVjhjiVReC/z/sThQetL8
	KMUb8o5LG0dsh0TNPK3bTktLmLoxcee3L4F+N2W+4UYgGUKpp+DYtM1s
X-Google-Smtp-Source: AGHT+IHkWRtNfuTxC9bLCm/Gj4te5xUURf9IiXK60u6u01fi+nDP4H/5DONfgyGBNfyW1Bol1DzDSA==
X-Received: by 2002:a17:903:1aac:b0:298:5fde:5a93 with SMTP id d9443c01a7336-29f23c677edmr18215315ad.32.1765536549658;
        Fri, 12 Dec 2025 02:49:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZiZGrpdhFWqZFum3YQnM7UzZ3/JJOmMcK1xKblVx8PlQ=="
Received: by 2002:a17:902:8504:b0:298:f12:862a with SMTP id
 d9443c01a7336-29f23356229ls6419125ad.0.-pod-prod-03-us; Fri, 12 Dec 2025
 02:49:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUmDlwzSqV2YUS0ThhTXLynWOHOWS/G5tqEznj7kBdhCcA6Oz6Fp96seXTDJVlOszBFRuzaBKChJ/s=@googlegroups.com
X-Received: by 2002:a17:903:2ac4:b0:29e:fd60:2cf1 with SMTP id d9443c01a7336-29f23b5ece7mr20258915ad.21.1765536548115;
        Fri, 12 Dec 2025 02:49:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765536548; cv=none;
        d=google.com; s=arc-20240605;
        b=IaG7ng8qMIp4Np2A9DLkpZMCETrko4qFZh77gWNkDedWDSACckFWZDlkEPXBUUfolm
         AdpWfCZKwTANkLx20F6Rf0oNPTLyvsb49lFIy3IBRFfCvfhGC33OeYRSDx5bKa1RQrHG
         VkY624FvEd0Hlcl7AjaVHYQu4+kaZ8Z23H/sT29doWV3vYDb7CibAgQMShqTWej/VWLh
         9wb7PSGHX+6YmaPf2hOahmu5r7Zv7UU3nEIejHUs0iBRBaH1kO7MBRykAp7T3K6GWD8X
         YAROJYYbo+gQeRAPMUA0b4LF0s7evVewlVkdg/QsnulvUI2rUwsZCUYlR19gkqbRcIst
         Upfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SA48npp6esm0XDSNny8uE3VVilMK0KzCGLSxi6mYbKY=;
        fh=3bmEwr6o6gyJFe0J5XDi0Up40brAxv1eC4jYrtKUIh4=;
        b=JDtcHJzPfieUrwLMlVC4NhK0Ur7hIiBdpVI84XE5Sy7f+672nWTG9a6C3SMgXID19C
         ek4nVwEzSB/MStVNE+8T5n+JRZomFs14EtJ6bOi54l99Bzj9K0w3EyeXuZdvPJ1qoayY
         yQEQut8fzVl3VK6+Ol8jTqRG4CrgH98KFcp5iT9g+qYVk8G07bmjf0TCQSQtNa1DIvxr
         vmcCjE1p8JfuwUi/TOzRzo2folsU9+9VhS5biTrt91lerCkEdolEkTLs0cwn85ZL5YIS
         vyOVAmPGcpAaoAx/qM667ThT60FY0as+K4iX767eSAKfUHXsn2uK/cL+E0NFyHWp7RnA
         /KQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iu9fLzpd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29ee9b17462si2066195ad.2.2025.12.12.02.49.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Dec 2025 02:49:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-bf1b402fa3cso1033859a12.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 02:49:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU/L23eeBnnqk2iGDZ+YrzfVH74UZYeZku8WcEZaYEhiTtOCLGXGpwUhMC+GX+KzO2x/k7dkecE7Zw=@googlegroups.com
X-Gm-Gg: AY/fxX6GMiLUPkxK02YAJXRwB2zf7DzaSiLhZPSR7BdHtfd+ZTHxHrdFHi1HIH6Lgdi
	NS3M1hZ25DnZ+aJZHOKin499d6owrXPsXm4MyNBYgvGzekv5JAkOIuCvvCMEFKpNSUHZJsfCf+R
	hXTFq0PwxpBmsUTA548NcQgRnYcIR6xTNHIIXNK75gNmU8oKkX+Kz2IEKv2Q3/kkgNiUf6pJYlX
	QqcWTpYL77y9T6WblBzk2sAksCYZWlb2q9NnJiF8neWiylgGne0zk1rv7X9OcAsykOy7Bj49Kfq
	2zTZXYZ2wFnbcgLlpVgEhTiUYGY=
X-Received: by 2002:a05:7301:6781:b0:2ac:2e93:29bf with SMTP id
 5a478bee46e88-2ac300f946dmr1219192eec.22.1765536547134; Fri, 12 Dec 2025
 02:49:07 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-8-elver@google.com> <20251211114302.GC3911114@noisy.programming.kicks-ass.net>
 <CANpmjNObaGarY1_niCkgEXMNm2bLAVwKwQsLVYekE=Ce6y3ehQ@mail.gmail.com> <20251212095943.GM3911114@noisy.programming.kicks-ass.net>
In-Reply-To: <20251212095943.GM3911114@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Dec 2025 11:48:29 +0100
X-Gm-Features: AQt7F2qCLUKQusRsTOkfVyHaXl__KgFtQ_SoVZmDpwKuRXcKmzXhASdee3aZVrU
Message-ID: <CANpmjNMY55ytuWPh15O-tTe5zEQx3AN6LqrvB9NJ6dm6BsPnsA@mail.gmail.com>
Subject: Re: [PATCH v4 07/35] lockdep: Annotate lockdep assertions for context analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, 
	Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>, 
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, Chris Li <sparse@chrisli.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Johannes Berg <johannes.berg@intel.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iu9fLzpd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 12 Dec 2025 at 10:59, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Dec 11, 2025 at 02:24:57PM +0100, Marco Elver wrote:
>
> > > It is *NOT* (as the clang naming suggests) an assertion of holding the
> > > lock (which is requires_ctx), but rather an annotation that forces the
> > > ctx to be considered held.
> >
> > Noted. I'll add some appropriate wording above the
> > __assumes_ctx_guard() attribute, so this is not lost in the commit
> > logs.
>
> On IRC you stated:
>
> <melver> peterz: 'assume' just forces the compiler to think something is
>   held, whether or not it is then becomes the programmer's problem. we
>   need it in 2 places at least: for the runtime assertions (to help
>   patterns beyond the compiler's static reasoning abilities), and for
>   initialization (so we can access guarded variables right after
>   initialization; nobody should hold the lock yet)
>
> I'm really not much a fan of that init hack either ;-)
>
> Once we get the scope crap working sanely, I would much rather we move
> to something like:
>
>         scoped_guard (spinlock_init, &foo->lock) {
>                 // init foo fields
>         }
>
> or perhaps:
>
>         guard(mutex_init)(&bar->lock);
>         // init until end of current scope
>
> Where this latter form is very similar to the current semantics where
> mutex_init() will implicitly 'leak' the holding of the lock. But the
> former gives more control where we need it.

I like it. It would also more clearly denote where initialization
start+ends if not confined to a dedicated function.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMY55ytuWPh15O-tTe5zEQx3AN6LqrvB9NJ6dm6BsPnsA%40mail.gmail.com.
