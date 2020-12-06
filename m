Return-Path: <kasan-dev+bncBDAMN6NI5EERBRUWWX7AKGQEYK5H5GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id A63AC2D0746
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 22:21:11 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id r5sf4274045ljg.4
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 13:21:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607289671; cv=pass;
        d=google.com; s=arc-20160816;
        b=XudzkdduJ0w0jGXRSXd/D5HnnaZN1cpLziUMTXl9yknx3UftmjwAUGBfVz2UdYgRKR
         gcV/+dPrg95U69bm3Ma4JwOO7mlq6mv/pUVe02lI0Gn4XVX5JcIVtpqC9w1Ak0VrUVGj
         kCL3jvDMTql9eoLLS5NUIMY2i6OswOOg+QWwVNVuJb/G6TTx1bXs6kwoTJ8MmIw+49zx
         Irprd/MpdjZwopk2sBypaR0Q3dAGo/L2/Zdkr81ZwU/LEQ9zKM1TuxmfR0ZEXSHMMhdT
         Uzlxt94daUds+8wIjrjfO7sSynH4Up89ZhLFXpLp+mPuHBDulqqQpqh69eveDQWD7U9E
         uuZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:subject:cc:to:from
         :date:message-id:sender:dkim-signature;
        bh=cqCwdAkZVhDwXE9GLDC38mZuzhvcKgOL8ThCybyrMc0=;
        b=t+DjWMS7zC/zurUeluMC6Cv7VQXh6NsGNDEghDoe8uRw5UreAaG4qjhxh9o7eFRBne
         a3OE+uSEWvdCEhX8J9wAnYR81CHsEkj+y+eWiwg15r3OcDW5tZsh2PfgQmepzqrIXo0k
         U8BH0CrSZAB8LJST2LcyaiXrLWvC+XIA0CtFLHUwz3eeBFEZWYTPqJjlnYAGcAD8Z3GI
         tbt2PM8CK++Gs04zaxdNtchYDLwfvyzFL4jwLsPB4fcdv4pJnkLsUyFx2kBxz4YL6GX8
         eshOZOI0Kk/6lwSo5t0CFiDbg/+3+WzwTJvb6DbZZNYwX0NqXnaaXMD4VaAu1hYaN+ZD
         kh0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="r7sQkm/v";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=fsGxexKc;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:date:from:to:cc:subject:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cqCwdAkZVhDwXE9GLDC38mZuzhvcKgOL8ThCybyrMc0=;
        b=a98fdMlWY+2zygHXJRFwm/X1xNjX0Q8w1f0HCB3im9huPBpEZbSimVrX8o3bWRHGHg
         wXl8cCFY3Gsqpvr5WpXfjdcDielkRNF+pRNmKJCh68pneadIjLKFfFgPYLM7eSbvP3Ho
         mSB9CACI4KJr7+M9mQ6pQnYlbKSlTF+GCnfYsXUQNXE0nUP2B/4eAH5ma7ht/dF30h6r
         uNqsLL0XfCOJqT0LPsgqOUqWEoBqDmcC9gc/D4Vqght8/DI3kem3aijaa+cqu2IjBsN1
         9lJX5ylGQgm3Uh/hOOp0vV3ZbCvItaJiJuIRGjtmr7xNzMXMfIOyfMQoQGuJTnfQA/qt
         rSxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:date:from:to:cc:subject
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cqCwdAkZVhDwXE9GLDC38mZuzhvcKgOL8ThCybyrMc0=;
        b=m6Q6s6f9mqKsjYz5AQjt/ugUEN6667ZBODXjT2K9LCbP6v96xWpV0bOLufaT8Eo0JO
         1jktjpiOqM1CgK4xB1xOKQcaxkWndXHmHE0tSXXWlg2FSL9MyhhOBt9BLVHRdEJSrn1G
         tDE2Yb1y6obHIByE4egjOZEdzMGFLKIWe+twyWxNyC4Q5NPGpH9DAA5ULz0gMrJuDiGj
         /jId8ski7jEig1Rs3fredEwlALJ0VVP6ab9KwxmGxTndhKl85c34Pw3Eps3175IS4a6I
         dlsu2cgqes4BnXXL0czTvWQMxM5s6WxN3C10rw7XR5ZiMbwFQxWvE7pOh8gnI6JzOzO2
         AsvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XSArWDIbQpWBVBdpAu9nY/gRKUHhm4SMfOLILZYtE4UM9/q70
	g3GrM0vIKcFc+coIVywBefM=
X-Google-Smtp-Source: ABdhPJwaltlFcOdOokq2a1DKnX/ZNEbiN7sxBq5v6R+7y8M8tsmnKjDHs6c+oHQVa34udJxRneIVzA==
X-Received: by 2002:a2e:750d:: with SMTP id q13mr8354891ljc.92.1607289671171;
        Sun, 06 Dec 2020 13:21:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3608:: with SMTP id f8ls175447lfs.2.gmail; Sun, 06
 Dec 2020 13:21:10 -0800 (PST)
X-Received: by 2002:a05:6512:1090:: with SMTP id j16mr7111424lfg.543.1607289670201;
        Sun, 06 Dec 2020 13:21:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607289670; cv=none;
        d=google.com; s=arc-20160816;
        b=ELdyK0+8YNqP10jDIJ9kg+qWrlESzFd0AsvxBhJGHwNqMuaCYRdO6j2F1rX9zB4RM4
         w0geYqxOodwT3yzb79mYjEVsXGVbZ8TnZ48VoCZsS2MPqoluC1yDgnBrTlyFdwh9kNwD
         uo4ZP6adRjD1aKTmiJc+Ih2H+3XNDDryRuYzB78jzL2zQpr3OHjgY7AugOP2nz2ffT1D
         j/4GEaPpYUCtf0rd+QTK1K5/6851zyGYGkFvizdxzvFwVXqzgWJ5ePggh/w58deDEwUW
         1aLFxZFzJL0c6eqMR13Fz6F6YtvYVs08bfeYlgE5NKtsm/1vpdZMxhsjzRhyPBrZxi+F
         +wlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:subject:cc:to:from:date
         :dkim-signature:dkim-signature:message-id;
        bh=78N4YASvionDygjdJyxpH+khdroZX1Ca/lN2xuO3Y+M=;
        b=HrxmvenG8PvTr8WZwCzBDbCVTCDhwmoMQX6zf3BJKWDWELw3qoLMbSvBaJ2r0fPK2J
         8Kko3ydLVGm6BWTi3vq8OTwNRs8RyxP4wCi7EaERTKN0dai0oYCcOErUaUlXtdNqC6WD
         ps5qcf4mFMu5VPCkRREQlTm+aH3W4UCg3Q1E2B6NIrlzQAkZZLuOHkDltMupkcbX48n1
         bsEwVxn2Af0iteFapGQEXwG0Jtecn549Wt+V4AX3Nu7bJ8SCWru2QzVTrscLP7IHFA25
         La/ynTSPUS0UV3cfpkyMeR9qvcq2baK6AEkQpadhP5Jc1LmQ4p7PaeqUA6hCHDJUTItp
         wIxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="r7sQkm/v";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=fsGxexKc;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 26si408941lfr.13.2020.12.06.13.21.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Dec 2020 13:21:10 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Message-Id: <20201206211253.919834182@linutronix.de>
Date: Sun, 06 Dec 2020 22:12:53 +0100
From: Thomas Gleixner <tglx@linutronix.de>
To: LKML <linux-kernel@vger.kernel.org>
Cc: Marco Elver <elver@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Peter Zijlstra <peterz@infradead.org>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Ingo Molnar <mingo@kernel.org>,
 Frederic Weisbecker <frederic@kernel.org>,
 Will Deacon <will@kernel.org>,
 Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [patch 0/3] tick: Annotate and document the intentionaly racy
 tick_do_timer_cpu
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="r7sQkm/v";       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=fsGxexKc;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

There have been several reports about KCSAN complaints vs. the racy access
to tick_do_timer_cpu. The syzbot moderation queue has three different
patterns all related to this. There are a few more...

As I know that this is intentional and safe, I did not pay much attention
to it, but Marco actually made me feel bad a few days ago as he explained
that these intentional races generate too much noise to get to the
dangerous ones.

There was an earlier attempt to just silence KCSAN by slapping READ/WRITE
once all over the place without even the faintiest attempt of reasoning,
which is definitely the wrong thing to do.

The bad thing about tick_do_timer_cpu is that its only barely documented
why it is safe and works at all, which makes it extremly hard for someone
not really familiar with the code to come up with reasoning.

So Marco made me fast forward that item in my todo list and I have to admit
that it would have been damned helpful if that Gleixner dude would have
added proper comments in the first place. Would have spared a lot of brain
twisting. :)

Staring at all usage sites unearthed a few silly things which are cleaned
up upfront. The actual annotation uses data_race() with proper comments as
READ/WRITE_ONCE() does not really buy anything under the assumption that
the compiler does not play silly buggers and tears the 32bit stores/loads
into byte wise ones. But even that would cause just potentially shorter
idle sleeps in the worst case and not a complete malfunction.

Thanks,

	tglx
----
 tick-common.c |   55 +++++++++++++++++++++++++++------
 tick-sched.c  |   96 ++++++++++++++++++++++++++++++++++++++++++----------------
 2 files changed, 117 insertions(+), 34 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201206211253.919834182%40linutronix.de.
