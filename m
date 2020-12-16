Return-Path: <kasan-dev+bncBDAMN6NI5EERB37V5H7AKGQEZRK7MCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 40C982DC849
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 22:24:00 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id j70sf8782462lfj.11
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 13:24:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608153839; cv=pass;
        d=google.com; s=arc-20160816;
        b=PRV7TKtBT6ns1+Md3mui4v9UVKrli65m/ZVbFsVTwLDhi5vO/NtSs9FEZ3kEXPm6nv
         gOQwKDmSHH/3BbQD2tDStMF7GlkE1nqJw6eiIYDbAEr0jlqHPO15GwCkQzW/MuFM0I+T
         tE1ng8VheIrN7olvKo+G9ebBpUgPR0nYJXZAe5Wc8pXI+dVTS4HXS5mhDPLM4aI9beuX
         FtyLNODdzgd3CcVSrSuTuCOMkFqEQSQoOP78eJWBJWtc8z5oxVzZPVCl0ygDq+Y2V+9c
         BLeEduuaf9mwDed2aV6dMNwWY/45lgLRJGxqAp51szVb4//pzIxhsBVMzASU0nKkHmeM
         iXVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=LL1EUGtc7IlQeHFGIWCJwOTsRVUnlTS8kd7ldY/OYYU=;
        b=bVhqE1JY9bTC+rhqv2ccuvw04fWtO7m27aLQ7uXpXBKoUlxC8qZ+IzueCa6IX3SZJy
         Yj0k58hGmNwCEfCjuHLB22aZWz8KEk4gxwEHHthuG21sPXsz/Zuaj9N88U6QVTvOFi+U
         wsAvIyB5zUGwwXI4/S9pUDmVYbLfwCGYWxUY063umSgySNCGjSqFSz4Vlc3fvAK81FQ0
         oeKE+2dtVfprBERopsnmoSWEtxEizPamfG2pc885ldwCLxG7jBdkv04QdhkObXnKihfy
         kJVltqb9CLGT/NE5f95bhkvp2Y1RmmviqAqTJcLrgBDwls8wTyYaPryDQNgFH+Lu2wV0
         2EFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Ub79IKit;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LL1EUGtc7IlQeHFGIWCJwOTsRVUnlTS8kd7ldY/OYYU=;
        b=tWWVTp7Cocs4Q1Cq34AQX4dBon61SPZ7u1cWrGf/IKUicIie7/rZn1VDf8GYHxvj6z
         MPy6MdqiJ3vToSZWXG6pODWYTAsvkwmyY5ykEelYzSE48sG0E5oHUtSgCYkExuNkOgOg
         L501ArXmBqdInZHiVF2wz4P/QhXzAW98fwmUU5aOHiflSK8Q9SEi5h5BJ8Ixf8Z7Ar6A
         v1pETFADMAOS1L5No8XJQuX4liKORVK1hJeWD1DkyMYStjzeZZQQLL4E+pm5jW3zkb22
         I29wB/PYq5HoswqLD0OXYj6q6FksrySntHQRSD2hrranTwq5KD0lhiyWUMloMwYx6jEt
         zdzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LL1EUGtc7IlQeHFGIWCJwOTsRVUnlTS8kd7ldY/OYYU=;
        b=Oob590VdZv/fHuuONo5gGGWngL/3x/N9pEt119IgbZMcUcdFLJfGlcS8fR+5j3ycsf
         p2piP6vHdxu3LndDb500kf1CxmwKmEqvxfaNdPxijgoYcg93y+d4hFrSL8jNLIfsWneO
         2OL9sPRFhyYPBhzKsUaXPXnISaWWEmaWzwm5aIcMhIMJnM1D6+W6b7HgLHgzKLlq7XUm
         Bs4TKqk8bbPPx7N75oMlsJvJqo/7UJR0vM17l+BQdpeEZHgyPH/NLe8gzDXmZtQWwFzL
         JwIOlYTVLT+gekJQ1TAvONOAXD044TNd+6LyBGUoCSATyymnNY6D+BqLkk6lQlX9JPqT
         mBfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304NxW1bva4fRJhUPkhQe3aQWpM/QgeXXRh3foR+UIi31v4k3+3
	PQva2JolOjTwV6j4a8JR7IM=
X-Google-Smtp-Source: ABdhPJxS1FjP5N2P16cbyW5lpNyls0T7m/+uLozwAS2RehO5srt2hZg8h1f77fhbRPRcJtl+5CM13g==
X-Received: by 2002:a05:651c:211a:: with SMTP id a26mr15658706ljq.308.1608153839826;
        Wed, 16 Dec 2020 13:23:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6145:: with SMTP id m5ls4659295lfk.2.gmail; Wed, 16 Dec
 2020 13:23:58 -0800 (PST)
X-Received: by 2002:a19:641:: with SMTP id 62mr13459603lfg.424.1608153838657;
        Wed, 16 Dec 2020 13:23:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608153838; cv=none;
        d=google.com; s=arc-20160816;
        b=lus7Ip6yxgwvi8Pbm09+OcQymAXTExkaDJDflK4KLOArCTnyxTJk3ePkTAyUmt6xUm
         wuXl0ymXBqKpEWX1JlG4NKm8KcQ+xawSu2MhaUW7u1h9MeoIvfefeC3zJKC1/CjXVJAf
         hRvqhTq2Xf50yoRXPY91Z9nTTWEnmkzpH3GWuwtqeh5A/Audotg3zMbxQDvfYMJxDjJG
         CY5WWXAuF/sMpqVWvcvb6Kz7wM9XxgJ8PskpHLtn0cVmyncugu7IZVFUCkUnMQDwSAvC
         1PzTLz44zB5l2+hNpEYqqY0S0G4Y9mDYwRyktgrTFk5cRevK+bSu1pciqaYOXPpDoUKK
         k0sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=CD16dqcpUQKgPHdjRPxV49zv42Pzi+VzliQWGRIcOig=;
        b=uQHaduy/5dLy1ToSMD8OeXbYAVUQFp+wqdCQWeIlRydfAlx8lxkUsA9oW1pI3wxvxs
         lEVJ1H62AIpIuxUJRm5vvOZp1TDyxT3iqAA5gltFTpsThtThj5AzDu8iUqCOJFbhIFf1
         6u2Lxd6oJaJl9l4jW25VOSgT+qtkNzGae/SodYFtATEwsYG111b0+4o2SqEaeamSF6IK
         EGwM7XMcGTc8IQ2W/vFO8AnzyKbt8DDF9P3AU7j4g1IwZIkuujsgXrVhghhT+sQ5tDit
         DWDs2fvjbnSmSD+JdtYCtrGKHPdZR46uq9JjcgGvfc9PDnh0yxw0VMxittJYrflOt2GK
         JoLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Ub79IKit;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 70si194385lfo.4.2020.12.16.13.23.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Dec 2020 13:23:58 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: paulmck@kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, syzbot+23a256029191772c2f02@syzkaller.appspotmail.com, syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com, syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
In-Reply-To: <20201216211931.GL2657@paulmck-ThinkPad-P72>
References: <20201206211253.919834182@linutronix.de> <20201206212002.876987748@linutronix.de> <20201207120943.GS3021@hirez.programming.kicks-ass.net> <87y2i94igo.fsf@nanos.tec.linutronix.de> <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com> <20201207194406.GK2657@paulmck-ThinkPad-P72> <20201208081129.GQ2414@hirez.programming.kicks-ass.net> <20201208150309.GP2657@paulmck-ThinkPad-P72> <873606tx1c.fsf@nanos.tec.linutronix.de> <20201216211931.GL2657@paulmck-ThinkPad-P72>
Date: Wed, 16 Dec 2020 22:23:57 +0100
Message-ID: <87czz9savm.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Ub79IKit;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Wed, Dec 16 2020 at 13:19, Paul E. McKenney wrote:
> On Wed, Dec 16, 2020 at 01:27:43AM +0100, Thomas Gleixner wrote:
>> So my intent was to document that this code does not care about anything
>> else than what I'd consider to be plain compiler bugs.
>> 
>> My conclusion might be wrong as usual :)
>
> Given that there is no optimization potential, then the main reason to use
> data_race() instead of *_ONCE() is to prevent KCSAN from considering the
> accesses when looking for data races.  But that is mostly for debugging
> accesses, in cases when these accesses are not really part of the
> concurrent algorithm.
>
> So if I understand the situation correctly, I would be using *ONCE().

Could this be spelled out somewhere in Documentation/ please?

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87czz9savm.fsf%40nanos.tec.linutronix.de.
