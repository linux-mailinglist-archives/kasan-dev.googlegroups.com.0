Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNHVL7AKGQENCFARFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 627E42CF52D
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 20:53:50 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id 141sf6216941qkh.18
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 11:53:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607111629; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDyPVfAzEPXjuSJWOwnqQibPER4mA37uG723zKgOAK6wv5+oU65kzjbDCY2ObmxK5o
         IMzji2HBGmd+CS/yi8OJCghVojM8qobjmY6WQHkjAhC4oXQ5pyrHJ4NME6AG0y4gF2ar
         xKBAJu0nNWr0MprPGf7a7lDjBNc9EkPQBdOuyLfl163ZUpb7juX8FyzgKykMUY2/BBsw
         G6t9AouEEqTc0D8PuNMTJ0v2ePdXp8/iQT5wGhzS0V9Gyz4j8ekkUYMpFL5NbD+Zzd1J
         RE9OsRlv7txWmhtJMPkz4xlO3qUuAZ7HXvCIkWIOowOO8ibSq0bOzGtzzmEXDffTKkNg
         EZoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3VijnU7Q5ModtvetefwIQJ52FNl63CK+3U4mMXOzU84=;
        b=ZjEKJvlbLp/BnKjuEIw57H6rnmr+JMrsKm0IyXGFzzOuCQqAphhgtTwdQQxPymjXkE
         kVkN0w5wnmmzjuTcQqG4Y+5PsiDYpzdoi2VLgyJ0dkX1BMxx1tBtvk7tfIbX6E0zoHlW
         hVIPpRnFM7T9PppPyagWfMQmUTSjfc8aa02/vE7CgKnGUnQkvklqkZm0VpZVX30jbCUX
         01p2X5dJ8X3w0U9LxwV0t87ynRiipcyEfhu9/Dh9ToKfvun9iAp2IsyzjVnhrH74pMlo
         05zaub+5gIjp1TJ0jwiNdjjLSEElcKTzT6U2MRee8N0yLIgE3PMTjeWU4eEAEIlj+hnk
         WFWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nA2GNzWP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3VijnU7Q5ModtvetefwIQJ52FNl63CK+3U4mMXOzU84=;
        b=oTQOnT8Mln2oyhmK94kLyxssnC24raBw0NHkUMAaTFwylHmSVRaglaNd5PpZATTzE9
         byaWYySQCStj2p2K0qRhSb2C7gkuBec8c9s3MHi0bi6hL1YeySWAq4RNlzAGfMuzMIwW
         oJRqfQWWUhuxQFlq3jzjFM+pKwptbKomiWJG+fAy77Qw2rzvpJ9TDBWQQOeQQuUbQqJq
         rY7Ac8jdFJTzLuEnYICJn4pG6F3hLLN0QTzbEhrKNXifWvhEZM0myR9ISOrv0Cmbd/v6
         9ZFVuoHGGbWRfgxq/iuPI5XZQwPqGhjJWurhENilCUABW6M2ehk4MDLDMxh4Lm5gJjEA
         XxqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3VijnU7Q5ModtvetefwIQJ52FNl63CK+3U4mMXOzU84=;
        b=onGeLvuTvIWsnYZrabi8+U7OFAEaw8EtM6RCTyrsDUNyzRM7ihyOcawvdIvkbNiW9H
         s3MEDVMLoKI+V12dymkFdixtTt1OyqUt/4lXui3ff8OctrVqVlRtPnEAkZBA1RfArxMC
         g6gnKVAX7OlFINdd0+DmRlTu0OM7JNS8wQ6VGld+P9L7N1k9Sa/1wEdc1fLsWH3Uw2NL
         G+2Lq5B1ps18ovXYYJNnJrcF3z95dPn8UROM4IMrgH40lO4o/+h7WNHNGybr3ihFspUY
         vpjDswnBD8q3keaFb3DvcoWNBOEWcH/EFoksnkABYCrB0VTBs9vuMseN/Jrzt8cfdHnP
         TmnQ==
X-Gm-Message-State: AOAM5336RSKJSH5Xg4yTVyAbmdXssRbyLeSNODqgTb7b1q/h/3q67WvZ
	sPz32AKWH1OlH2nqziIsLFA=
X-Google-Smtp-Source: ABdhPJy55FMpt334i/VRTL4GXWO5EcakNik/8DUf1SOxwzyRM6/ZS/OhYfWkij5BKIquRQqZpAgHgA==
X-Received: by 2002:a05:620a:6a1:: with SMTP id i1mr11079333qkh.136.1607111629369;
        Fri, 04 Dec 2020 11:53:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5647:: with SMTP id 7ls3702730qtt.8.gmail; Fri, 04 Dec
 2020 11:53:49 -0800 (PST)
X-Received: by 2002:ac8:6c36:: with SMTP id k22mr9038711qtu.62.1607111628890;
        Fri, 04 Dec 2020 11:53:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607111628; cv=none;
        d=google.com; s=arc-20160816;
        b=Ed5ptLvK9DoP0A2V99RLZnbQOHedHqLVxSwuhRtyvXi/N0VrkhK88AYscgAoEHSVKY
         muNhFfkAxw+aLB147dyYYnnZTCyGZORjHb1/qXQRytoEus9m9zVMy3w71069GHErM8GQ
         ofcPhVGgaZDxNwa61jv9GQGGQxCB6lk3oaCb2elaayImx8Tcpgl8ELrsc/4zL7cntvLI
         jEhQzeyO7FtUJD+wLe9ANCbmx2+q+rLWmMaajBZRw/GjWhLYwkdJSubOsBDjrgar0mrl
         Jvw5LgD492IqInSZ1YZc+X3DMRlxC1gQeYCI90YbAlIgm6HGH18/jpDkb7BQIO1ss+v4
         aO8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uovmCUxUV2XC7RFIwwrup7x/dcZweDNtrR8W3IZoNxo=;
        b=vTtv4pyrGmcGdeTsnIImhaMNPfa25X1qffd6IyQLT1t5BocEvgNsntwhr3xdqGR/4l
         yNShi0z91T3DOymyjKKDFvdmnPMCbbT3qLFQ9YtbeRNDTckHJq4mSxuqyCM1QdnwLbL8
         +Frp/E+K+V5Pow1NnI+/9dDKieAVYNm2OY1ObzkHxl0+O5JZizoglNnnug8IDscyOvmh
         UKW27HMBYYoJ0xFQ/NGhb7j5YdaXGXwnzXuHHV/yM6rWjOrDjRtk51CQulg+PK5LeYjH
         3/r/BXMlvz4RkYA73zCR5798HVe/duL9kW144WRPGDbz6L+HUHbIV+YaSAizsmWV98LZ
         74bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nA2GNzWP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id x8si124575qtm.3.2020.12.04.11.53.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 11:53:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id h3so7462929oie.8
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 11:53:48 -0800 (PST)
X-Received: by 2002:aca:448b:: with SMTP id r133mr2307367oia.121.1607111628147;
 Fri, 04 Dec 2020 11:53:48 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYsHo-9tmxCKGticDowF8e3d1RkcLamapOgMQqeP6OdEEg@mail.gmail.com>
In-Reply-To: <CA+G9fYsHo-9tmxCKGticDowF8e3d1RkcLamapOgMQqeP6OdEEg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Dec 2020 20:53:36 +0100
Message-ID: <CANpmjNPpOym1eHYQBK4TyGgsDA=WujRJeR3aMpZPa6Y7ahtgKA@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in tick_nohz_next_event / tick_nohz_stop_tick
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	rcu@vger.kernel.org, lkft-triage@lists.linaro.org, 
	Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, fweisbec@gmail.com, 
	Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nA2GNzWP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as
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

On Fri, 4 Dec 2020 at 20:04, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> LKFT started testing KCSAN enabled kernel from the linux next tree.
> Here we have found BUG: KCSAN: data-race in tick_nohz_next_event /
> tick_nohz_stop_tick

Thank you for looking into KCSAN. Would it be possible to collect
these reports in a moderation queue for now?

I'm currently trying to work out a strategy on how to best proceed
with all the data races in the kernel. We do know there are plenty. On
syzbot's internal moderation queue, we're currently looking at >300 of
them (some here:
https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce).
Part of this strategy involves prioritizing certain concurrency bug
classes. Let's define the following buckets for concurrency bugs:

A. Data race, where failure due to current compilers is unlikely
(supposedly "benign"); merely marking the accesses
appropriately is sufficient. Finding a crash for these will
require a miscompilation, but otherwise look "benign" at the
C-language level.

B. Race-condition bugs where the bug manifests as a data race,
too -- simply marking things doesn't fix the problem. These
are the types of bugs where a data race would point out a
more severe issue.

C. Race-condition bugs where the bug never manifests as a data
race. An example of these might be 2 threads that acquire the
necessary locks, yet some interleaving of them still results
in a bug (e.g. because the logic inside the critical sections
is buggy). These are harder to detect with KCSAN as-is, and
require using ASSERT_EXCLUSIVE_ACCESS() or
ASSERT_EXCLUSIVE_WRITER() in the right place. See
https://lwn.net/Articles/816854/.

One problem currently is that the kernel has quite a lot type-(A)
reports if we run KCSAN, which makes it harder to identify bugs of type
(B) and (C). My wish for the future is that we can get to a place, where
the kernel has almost no unintentional (A) issues, so that we primarily
find (B) and (C) bugs.

The report below looks to be of type (A). Generally, the best strategy
for resolving these is to send a patch, and not a report. However, be
aware that sometimes it is really quite difficult to say if we're
looking at a type (A) or (B) issue, in which case it may still be fair
to send a report and briefly describe what you think is happening
(because that'll increase the likelihood of getting a response). I
recommend also reading "Developer/Maintainer data-race strategies" in
https://lwn.net/Articles/816854/ -- specifically note "[...] you
should not respond to KCSAN reports by mindlessly adding READ_ONCE(),
data_race(), and WRITE_ONCE(). Instead, a patch addressing a KCSAN
report must clearly identify the fix's approach and why that approach
is appropriate."

I recommend reading https://lwn.net/Articles/816850/ for more details.

> This report is from an x86_64 machine clang-11 linux next 20201201.
> Since we are running for the first time we do not call this regression.
>
> [   47.811425] BUG: KCSAN: data-race in tick_nohz_next_event /
> tick_nohz_stop_tick
> [   47.818738]
> [   47.820239] write to 0xffffffffa4cbe920 of 4 bytes by task 0 on cpu 2:
> [   47.826766]  tick_nohz_stop_tick+0x8b/0x310
> [   47.830951]  tick_nohz_idle_stop_tick+0xcb/0x170
> [   47.835571]  do_idle+0x193/0x250
> [   47.838804]  cpu_startup_entry+0x25/0x30
> [   47.842728]  start_secondary+0xa0/0xb0
> [   47.846482]  secondary_startup_64_no_verify+0xc2/0xcb
> [   47.851531]
> [   47.853034] read to 0xffffffffa4cbe920 of 4 bytes by task 0 on cpu 3:
> [   47.859473]  tick_nohz_next_event+0x165/0x1e0
> [   47.863831]  tick_nohz_get_sleep_length+0x94/0xd0
> [   47.868539]  menu_select+0x250/0xac0
> [   47.872116]  cpuidle_select+0x47/0x50
> [   47.875781]  do_idle+0x17c/0x250
> [   47.879015]  cpu_startup_entry+0x25/0x30
> [   47.882942]  start_secondary+0xa0/0xb0
> [   47.886694]  secondary_startup_64_no_verify+0xc2/0xcb
> [   47.891743]
> [   47.893234] Reported by Kernel Concurrency Sanitizer on:
> [   47.898541] CPU: 3 PID: 0 Comm: swapper/3 Not tainted
> 5.10.0-rc6-next-20201201 #2
> [   47.906017] Hardware name: Supermicro SYS-5019S-ML/X11SSH-F, BIOS
> 2.2 05/23/2018

This report should have line numbers, otherwise it's impossible to say
which accesses are racing.

[ For those curious, this is the same report on syzbot's moderation
queue, with line numbers:
https://syzkaller.appspot.com/bug?id=d835c53d1a5e27922fcd1fbefc926a74790156cb
]

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPpOym1eHYQBK4TyGgsDA%3DWujRJeR3aMpZPa6Y7ahtgKA%40mail.gmail.com.
