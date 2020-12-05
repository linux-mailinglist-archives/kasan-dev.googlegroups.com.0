Return-Path: <kasan-dev+bncBDAMN6NI5EERB545V77AKGQEXR7ERJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 234AD2CFC5B
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Dec 2020 19:18:32 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 74sf1775554lfg.20
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Dec 2020 10:18:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607192311; cv=pass;
        d=google.com; s=arc-20160816;
        b=AtAKMkN4A/GqwMD1JalMUPH2O9QZcOqK8BHhz7jiNTVCuj4AiMOdpO4+xLpL/yd2QJ
         xIKBHlpHhPswBN5eQO9zFrwB+MuqCMJnGzlPY1Lu0c/IgyijrzI1aEH3ovbinFBrZetX
         ilM/awzwl8bYp+P1EEKUbmRVHa+1kP2icGXB8YSB/f1B4wCbQ4zufakydKqbx/GGTZp2
         9JnU6R0BSLuzz5na9rjJLtnShbiOJP/RxxaRUAW9wCT3sEgRsJC5b6IKLfEexyywq7wE
         SvJSsCZdcIIEbl0x2H9JBcg8xJ1cWjL0TzGG5b6bIVgOsiE6N4Q0oec/nT45TNilgq/5
         2Ccg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=zN/9UAUi82pRFNpoQLmCR4/3fSkkOxJfUlLNwaSmbaE=;
        b=YTygWSTCOPgqAU4TXOntwRBexQK599sfhF4ZoeAWtH009QAxPNduMRKH9H0KV7Qi3Z
         brvK7SkTJTdvAyjw/LCThU2UIuhuLsMFaINLjr1QOl6L88D0lmXNGPuLWw1ESyjLu3HJ
         n5oyDhQfMXdzJven2BkKZRov+obg2Px8YhfgkNXssfddixVvR8eBWhRb9QwWp/nwxpQl
         6RkXyJygPjxE7tsnxTHYAg9tNi5xOv2EuOU41yOkSRV+sZ16UBQwFdYXG+eUuZgnDSwM
         4XkJ7ZG0UN2D28h2+FISbPmOSzyReqaYEu6MzfLAbTJGA+w6CuIEMG7p5H+V8iZO5rPQ
         lliA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=EseygTQi;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zN/9UAUi82pRFNpoQLmCR4/3fSkkOxJfUlLNwaSmbaE=;
        b=tINgST+rAJBU+uDim6x+q9jxC+zMk3Lpgc6lww685AOCELMGw07WSca1G32EF+TtgX
         7JrVVjsdbjdvQSIvn57kHRMg9yS2j2dLc009pliRGtPUh7eJ4vSC7JNjTSO69b+ZVdoi
         U01h4B/JfS5OvVaqubFS7UTnKLwxYz0EC9Vo0qvE2KBsIZ2XSgSkzkFj5HlINnK8/rR6
         6DENAs3SIo16+D14PMvcaokcruYRjY3KYULF2vZLH8++dKc5wdKeIQN8qg9w0s0qtzqU
         +Sff+UT53P500W1dAUrObhfr+Bcdbea8NT+A+hrIX1Epeh8eeiBTs5RsRkWxXCdOkei/
         WvgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zN/9UAUi82pRFNpoQLmCR4/3fSkkOxJfUlLNwaSmbaE=;
        b=Hb9SqqHyl+1nOGV0Fmk5myGuHJDF28U8O8vtPz7Ojv/F9QvJxCxA7AXVXq2Xtqljio
         mLDsnHpDsM3SAMkWbT59D0KvEqCFTZC3cCi7mm425WVcCnETCJLxzAJqEjGq2Tn+KBX3
         KdUVW1ho71pyDU63AbMJaMtgYPV0njMETHX2MXn4R0SijPm4AniMJ0q9EOvxHY/A1WZs
         9yVBbemMnytGn6FYnEMIxDOPhXl99uVwVM/L93NPnNSOoKCag7nBxIs2ykyejGAnVaIg
         E2rDr0ZkkNW8XLLMQukw9B/h86Am1L3g86TFWXDwm+TOdhoGbBVli4BkyNtDUNzVxKqW
         RFCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZV32+ak3ALNzzsFIcaKm+ThzMRkTGQxv0PIwwOGSbjDtRJZmw
	XAiThpOqqXDggVHxnsCb2WA=
X-Google-Smtp-Source: ABdhPJzrDc6bpzELzQ5B7F4crxEdi4M1KRWwJYgrlYBkSr2sy7RSLCDkKBS4GCJmc9hrBbpy0aKtkQ==
X-Received: by 2002:a19:8292:: with SMTP id e140mr5175482lfd.110.1607192311621;
        Sat, 05 Dec 2020 10:18:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:: with SMTP id v13ls101297lfo.2.gmail; Sat, 05 Dec
 2020 10:18:30 -0800 (PST)
X-Received: by 2002:a19:89d6:: with SMTP id l205mr4171015lfd.297.1607192310539;
        Sat, 05 Dec 2020 10:18:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607192310; cv=none;
        d=google.com; s=arc-20160816;
        b=spWJ8R8296eFkyjrAFy7NNeD36yvdssGjwJHmrJAdKo3n5oQ1oMxma5sjbvXFBPXts
         gWOnsx+TnkHcDRu8h4g+yGwDuiG+MnrfftNCeuja3DcgXiU/XkDGv/zeOgPLTY/DgpAk
         gsxiLkE63SxlNTzaVSTdTTsCd+ksO46XBb17z5gD4GMM1xmg1dqMVHRoaXUuyCpLYfV3
         3LYwregpC5Xcdf9sHR5WN4iVRPaiD90aK/vMbCQCb3NLEFXtf0CQHVZK8MwrGI4f1gaL
         VTB7VNKYpBx/1G6sxMeUqB4JAky6xuLb8rIc33CpY93NnLrNyrioNBzDl9IJRfqz5Yxx
         NeqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=k6EZpf68f2D39vWu26oe3L/pHbnRkNlnx273kJRBoik=;
        b=E92l1Qb/QVcC+LNXVfZTNOc+pE5FzOgI/EnhjZPgmrOUubrTJkzu46COQe7USzeU3p
         OEUL3E1hHh1cu7EXow5mJ/EuNgpzWiZBYmNX0TI7T761bv6IdHLIeNLCSOO5W3OxLzQI
         G1y7pg5JCDM7HaK5GwTNFe/wBvrpR/lTEeoS3D3yJQ9oaA/tD6dM6fjLBa+zODQ4zqiJ
         nATNJEAwkKz4C7OopyAo4McYbJ2EEEH0pNGfvWDy0qIes3ZSkEjC3mnaDT/ZUCT/SXAV
         glxk/tuw6si86kLHMCqBTqpij86+KArl9DDr0hXD6dL5u+erMUYCwO0SggGLZIrFJS9A
         XVbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=EseygTQi;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id y21si346114lfl.7.2020.12.05.10.18.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Dec 2020 10:18:30 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Marco Elver <elver@google.com>, Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, lkft-triage@lists.linaro.org, Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, fweisbec@gmail.com, Arnd Bergmann <arnd@arndb.de>
Subject: Re: BUG: KCSAN: data-race in tick_nohz_next_event / tick_nohz_stop_tick
In-Reply-To: <CANpmjNPpOym1eHYQBK4TyGgsDA=WujRJeR3aMpZPa6Y7ahtgKA@mail.gmail.com>
References: <CA+G9fYsHo-9tmxCKGticDowF8e3d1RkcLamapOgMQqeP6OdEEg@mail.gmail.com> <CANpmjNPpOym1eHYQBK4TyGgsDA=WujRJeR3aMpZPa6Y7ahtgKA@mail.gmail.com>
Date: Sat, 05 Dec 2020 19:18:28 +0100
Message-ID: <87wnxw86bv.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=EseygTQi;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Fri, Dec 04 2020 at 20:53, Marco Elver wrote:
> On Fri, 4 Dec 2020 at 20:04, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>> LKFT started testing KCSAN enabled kernel from the linux next tree.
>> Here we have found BUG: KCSAN: data-race in tick_nohz_next_event /
>> tick_nohz_stop_tick
>
> Thank you for looking into KCSAN. Would it be possible to collect
> these reports in a moderation queue for now?

Yes please. This is the forth or fifth incarnation of report for that
data race in the tick code and I just did not come around to work on it.

> I'm currently trying to work out a strategy on how to best proceed
> with all the data races in the kernel. We do know there are plenty. On

I think having a central point where the reports are collected, i.e. a
moderation queue, is a good start. Reports like the one at hand should
stick out because they should reproduce pretty instantanious as it's an
intentional one and on NOHZ=y machines where CPUs are not fully loaded
its hard not to detect it :)

> The report below looks to be of type (A). Generally, the best strategy
> for resolving these is to send a patch, and not a report. However, be
> aware that sometimes it is really quite difficult to say if we're
> looking at a type (A) or (B) issue, in which case it may still be fair
> to send a report and briefly describe what you think is happening
> (because that'll increase the likelihood of getting a response). I
> recommend also reading "Developer/Maintainer data-race strategies" in
> https://lwn.net/Articles/816854/ -- specifically note "[...] you
> should not respond to KCSAN reports by mindlessly adding READ_ONCE(),
> data_race(), and WRITE_ONCE(). Instead, a patch addressing a KCSAN
> report must clearly identify the fix's approach and why that approach
> is appropriate."

Yes. I've seen a fair amount of 'Fix KCSAN warnings' patches which just
slap READ/WRITE_ONCE() all over the place to shut it up without any
justification. Most of them ended in limbo when asking for that
justification.

But the problem is that it is not necessarily trivial to understand code
when there are intentional data races without a lot of comments - guilty
as charged in this case. I actually felt so guilty that I sat down and
annotated and documented it now. Took me quite some time to comment all
the racy reads correctly as I really had to think about each of them
carefully again.

OTOH, in general it's a good exercise for reporters to do such analysis
and maintainers are happy to help when the analysis is not entirely
correct or comes to the wrong conclusion, e.g. assuming type B when it's
actually A. That's way better than just reports or mechanical "paper
over it" patches.

Just getting the reports over and over is not going to solve anything
because as in this case there is always more important stuff to do and
to the people familiar with the code it's clear that it's A and
therefore not urgent.

But that causes the problem that the A types are staying around for a
long time and blend over the B/C issues which are the real interesting
ones.

> This report should have line numbers, otherwise it's impossible to say
> which accesses are racing.

I just had to look at the function names to know that it is about:

tick_do_timer_cpu :)

> [ For those curious, this is the same report on syzbot's moderation
> queue, with line numbers:
> https://syzkaller.appspot.com/bug?id=d835c53d1a5e27922fcd1fbefc926a74790156cb
> ]

Confirmed :)

So you have quite some of the same report collected and there are a few
other patterns which are all related to tick_do_timer_cpu, so I assume
there is a stash of the other variants as well. And indeed:

 https://syzkaller.appspot.com/bug?id=03911d1370705fe3667dae48c9cda46d982cea30
 https://syzkaller.appspot.com/bug?id=440c51f56c3f3923f9b364679da48b0c1a0bdfe7

It might be useful to find the actual variable, data member or whatever
which is involved in the various reports and if there is a match then
the reports could be aggregated. The 3 patterns here are not even the
complete possible picture.

So if you sum them up: 58 + 148 + 205 instances then their weight
becomes more significant as well.

/me goes back to read the tick_do_timer_cpu comments once more before
posting.

Thanks,

        tglx



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wnxw86bv.fsf%40nanos.tec.linutronix.de.
