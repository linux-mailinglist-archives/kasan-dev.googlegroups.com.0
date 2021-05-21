Return-Path: <kasan-dev+bncBCMIZB7QWENRB4GBTWCQMGQE54C2SUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B3E1738C0B9
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 09:27:45 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id f16-20020a0568301c30b0290332c8d61b47sf4749311ote.19
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 00:27:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621582064; cv=pass;
        d=google.com; s=arc-20160816;
        b=TuXUiuDltaWCy5nDADp9jn0PxPl6zPgnlHJvThSxnLMyPiOIy8tIoJJ5TUwG6GjxR3
         ss8DvSVSZWUCMGA3bDb3iVtHYVBrK3hnocUBO9gimgYU2yZGtihqcQYF/HtG+l8lHmgE
         gHAC/r2JSklbMTpIdQEQUqCEjR23qBWlT1len0eYvb5rYGt2Y9ffCdn1e8iq6GRQW/CM
         ZLm+/kmjPlVqG63Kk95N8GdzOXF4LzqUXZ4VuoWxqBi+aPMG8nIXX+KzKk6s6yZisYMu
         s/g4nR8T5e5YumN2uNqqdb8AQ9n3U55YH7su4ZPXGc9Nbg+1EaquXZnZ/bnltgQfSAs+
         YRfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BZdJWqdxi7sInsQzCvIZrwO2IFB0xUeo+jqghkzCYhU=;
        b=q+HgOVlxV+mtTo1Y6FIZlfs9GHtk7bRB8L6ER/sWo/m+ShcH1T8DAFClMecOdBXzsf
         mj/2xvx5YIB6kX9yQWmGz8GvhqLLxyQfvZtU3Dx0hMiGVgrK8Mcg5w+AY1s1I8/YJLFA
         u9TljSXfK1/8AqU2qyNi7M9FwAH5W0kv1GanlP0x77WBlMRyPbBPCnu8LWfHIO9Me/Cy
         8oAqc2CpzWi2Z98E52rmre4aDkOhwtYOCqNVGA26Zo/yhKdd4nVq4IIxy8TzZj6Gewb/
         mXnwZGOi4E2iYybyfLVpObjTAsfNiLoXzlZjOSFi6fxXNCyi2bTer9ib1TVGNJLdcEon
         CuYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iC4OEtpJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BZdJWqdxi7sInsQzCvIZrwO2IFB0xUeo+jqghkzCYhU=;
        b=IkFRmkfyrj/zBJ3RKAkfT2ybjx/sUs41u+lcitWHiEaVc1MyUHPVL4uLIT8EP2V3No
         l6sDJyPcn8uG5zJnGaz6jO8ITMUJrXGq/89+1s77xI5t27Kpbk8nbiD6nPXK0+N6+WLB
         SBFkyRalZGxUXClEJaeofctNg4y8N4lRxeVjMSZlOC51pg7CRuHbFpp3xPCRU/jTvbmW
         H9rBSJoNg0cP6SSZi3ISvFcDCpjZiEmyWTQBMOGYLB2yppRyzdl+fJH2GBB214OENo1D
         G3gNLM51EauOls/g5i/dtkYnhbxs81hUToF2Jt893iJ8ZECmzJCQ0FjkuriVFmo6DCvI
         jP8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BZdJWqdxi7sInsQzCvIZrwO2IFB0xUeo+jqghkzCYhU=;
        b=qoU1nFb/AAUh8z5LOiG11LYMJl362jQF+U48qP/O60vT81pVIkJHVdEqnV7DZHx2pt
         8YJtAXX7DscJGOZAZCjYjj+UjvjLrjE8E07oYM6caDdiL7ONWoyry8+s3bhxqoMS9akK
         Fx8OtBaplm4X3/2cKc7ewkANiLxYbo51PSVK4OrDHJmquglqvhcg4CvXtZxlx8/gSPHn
         gS7f3M5Vkp3JMQgj5Yc/SjgwPIYujo4UIZ1QItD7/PpM3SQ3V0HMw+x9/cifxV/Ko6Uq
         DtBADJdqbRO91kWqbuCkGmptQrNQnoMRJUJm/xQxYoyNLbK4hruQvaC1Ukh9hv09lYP2
         e+sQ==
X-Gm-Message-State: AOAM533V6eadb7vdKP7rCil48M9EZOFsDxYV+tDyVNHJYxhBoLomNqw2
	uzH2iQdwOX+r9+HW2Qn9CD0=
X-Google-Smtp-Source: ABdhPJzVYZPAA3BsClk1BnUy4rqA+GiLanbbiprWfox4EZXIf5EY7Jj49T4uYl+QnpnNUAImrzBlKQ==
X-Received: by 2002:a4a:9199:: with SMTP id d25mr6934339ooh.29.1621582064555;
        Fri, 21 May 2021 00:27:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9c8e:: with SMTP id z14ls440692ooj.0.gmail; Fri, 21 May
 2021 00:27:44 -0700 (PDT)
X-Received: by 2002:a4a:b3c4:: with SMTP id q4mr7056126ooo.14.1621582064125;
        Fri, 21 May 2021 00:27:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621582064; cv=none;
        d=google.com; s=arc-20160816;
        b=GF3hzQCkrS/pD+0e42hiMahMO7Zs3CLtTRQ4Vw4eCDb0fcuYnDplomOvpP21+xIMg7
         GIzT4mHzbz5V0nzxFRiPZSrvRMAvLIAFa9IwinnT215H8ZkK5KO9FAn9+tBtAH+dU9oi
         2RaIT/EGdNGpi9S+d01JLSeieG5nVsKadjgw3gnQt8KbN2yj0wZD2mfBvwPO8NoIDbHX
         FsfJyMytX/WBUbkU2qxBQAhqXzWUhkLPFILfB61+qXESzdTMG3Xq7WuikJhNllTjihuG
         fd9RS46tIy8fuSX1F9hIOcj/5NXbXbGvz5VO/maLEDNZ8dzj/Wr1YFM0FonVoZ6w0wMj
         +UiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qFNffcXQ47jOSjWfDsJYJH+Krl7opYR8Qi9wzliY4CE=;
        b=GFfN04X2xOXNpKv97egdbJ7RbrPxKs+5rkpBhiVqMgdLaDVwdC0zfuqj99XYeLDPbU
         ha676sV3Kjs0uhHaVhpzgLUoh85Op9reAGpebKKakIYDSdGaTl5UOcKZ0mO0S6Lrb1HG
         D7dH38apvY8HbcYAl3Y8w5B0uTj60qMK4I94Ih8DyyCt+2zV2bqKPjfuEh9ahV5YNaLU
         amyAMMZqymAyAPfAkkifD2y/t50sNDVu11/lKIyM4BCtTYo8DBYbw6OActrzTF0wqFMZ
         e/W6LGr+x7DlEaeirT3LXm3G9Bne8qUjJIpyb50Oy/UKEKBiUUhQV3k2WBaVc704wmK/
         wV1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iC4OEtpJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id c22si510784oiy.1.2021.05.21.00.27.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 May 2021 00:27:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id t20so14678842qtx.8
        for <kasan-dev@googlegroups.com>; Fri, 21 May 2021 00:27:44 -0700 (PDT)
X-Received: by 2002:ac8:5b8a:: with SMTP id a10mr9374277qta.43.1621582063190;
 Fri, 21 May 2021 00:27:43 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <5650d220-9ca6-c456-ada3-f64a03007c26@oracle.com>
 <CACT4Y+Z9DuS6aKQdTb1mD6sVbnz_KPFeRK01zmutM1bmG9zSVQ@mail.gmail.com> <e7654527-74fb-a5b5-885d-b9f8a26c1055@nebelwelt.net>
In-Reply-To: <e7654527-74fb-a5b5-885d-b9f8a26c1055@nebelwelt.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 May 2021 09:27:31 +0200
Message-ID: <CACT4Y+byqpU1VFGyxMxweeY2Xh56xN-7p1TrNz4yvUNZO0T0BA@mail.gmail.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
To: Mathias Payer <mathias.payer@nebelwelt.net>
Cc: Vegard Nossum <vegard.nossum@oracle.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iC4OEtpJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, May 20, 2021 at 9:59 PM Mathias Payer
<mathias.payer@nebelwelt.net> wrote:
> On 5/19/21 9:19 AM, Dmitry Vyukov wrote:
> > On Mon, May 17, 2021 at 8:15 PM Vegard Nossum <vegard.nossum@oracle.com> wrote:
> >> On 2021-05-17 18:44, Paul E. McKenney wrote:
> >>> My hope is that some very clever notion of "state" would allow
> >>> coverage-guided fuzzing techniques to be applied across the full kernel.
> >>> Here are a few not-so-clever notions I have thought of, in the hope that
> >>> they inspire some notion that is within the realm of sanity:
> >>>
> >>> 1.    The current coverage state plus the number of locks held by the
> >>>        current CPU/task.  This is not so clever because the PC value
> >>>        normally implies the number of locks.
> >>>
> >>>        It might be possible to do a little bit better by using the
> >>>        lockdep hash instead of the number of locks, which could help
> >>>        with code that is protected by a lock selected by the caller.
> >>>
> >>> 2.    #1 above, but the number of locks held globally, not just by
> >>>        the current CPU/task.  This is not so clever because maintaining
> >>>        the global number of locks held is quite expensive.
> >>>
> >>> 3.    #2 above, but approximate the number of locks held.  The
> >>>        question is whether there is an approximation that is
> >>>        both efficient and useful to fuzzing.
> >>>
> >>> 4.    Run lockdep and periodically stop all the CPUs to gather the
> >>>        hashes of their current lock state plus PC.  The result is a set
> >>>        of states, one for each pair of CPUs, consisting of the first
> >>>        CPU's PC and both CPU's lockdep hash.  Combine this with the
> >>>        usual PC-only state.
> >>>
> >>>        I could probably talk myself into believing that this one is
> >>>        clever, but who knows?  One not-so-clever aspect is the size of
> >>>        the state space, but perhaps bloom-filter techniques can help.
> >>>
> >>> 5.    KCSAN-like techniques, but where marking accesses forgives
> >>>        nothing.  No splats, but instead hash the "conflicting" accesses,
> >>>        preferably abstracting with type information, and add this hash
> >>>        to the notion of state.  This might not be so clever given how
> >>>        huge the state space would be, but again, perhaps bloom-filter
> >>>        techniques can help.
> >>>
> >>> 6.    Your more-clever ideas here!
> >>
> >> Somewhat tangential in the context of the paper posted (and probably
> >> less clever), and not based on state... but how about a new gcc plugin
> >> that records which struct members are being accessed? You could for
> >> example hash struct name + member name into a single number that can be
> >> recorded AFL-style in a fixed-size bitmap or kcov-style...
> >>
> >> The fundamental idea is to just ignore everything about locking and
> >> concurrent accesses -- if you have the data above you'll know which
> >> independent test cases are likely to *try* accessing the same data (but
> >> from different code paths), so if there's a race somewhere it might be
> >> triggered more easily if they're run concurrently.
> >
> > Hi Vegard,
> >
> > Interesting idea.
> > Also +Mathias who was interested in dependency analysis between syscalls.
>
> Thanks for the include and hi everyone! I'm running the HexHive research
> lab at EPFL, we develop techniques to find bugs and also target the
> kernel. So far, we focused mostly on spatial/temporal memory safety and
> type safety.
>
> As I'm late to the party, I may be missing some context. I assume the
> goal is to develop fuzzers that explore more complex kernel state and
> find unsynchronized concurrent access to the same state.

Hi Mathias,

There are now actually several branches in this thread and some don't
have you in CC (hard to synchronize now), but the whole thread is
available here:
https://groups.google.com/g/syzkaller/c/yFtW39rcWyQ
It all started with Paul sending a link to the "Learning-based
Controlled Concurrency Testing" paper.



> > A similar analysis can be done statically as well... I can't make up
> > my mind which one would be better... both have pros and cons..
> > However, again, I think we are missing some lower hanging fruit here.
> > The current collide mode is super dumb and simple, I added it very
> > early to trigger at least some races. It turned out to be efficient
> > enough for now to never get back to it. The tracking issues for better
> > collider with some ideas is:
> > https://github.com/google/syzkaller/issues/612
> > I think we need to implement it before we do anything more fancy. Just
> > because we need an engine that could accept and act on the signal you
> > describe. That engine is indepent of the actual signal we use to
> > determine related syscalls, and it's useful on its own. And we have
> > some easy to extract dependency information already in syscall
> > descriptions in the form of /resources/. Namely, if we have 2 syscalls
> > operating on, say, SCTP sockets, that's a pretty good signal that they
> > are related and may operate on the same data.
> > Once we have it, we could plug in more elaborate dynamic analysis info
> > that will give a much higher quality signal regarding the relation of
> > 2 exact syscall invocations in the exact program.
>
> There were a couple of static analyses that applied to the whole kernel.
> K-Miner from NDSS'18 comes to mind:
> http://lib.21h.io/library/XHEQU6AX/download/SLDEJFQG/2018_K-Miner_-_Uncovering_Memory_Corruption_in_Linux_Internet_Society.pdf
>
> Now, such researchy approaches may be a bit too brittle (and imprecise)
> if we do it static only due to the potentially large amount of false
> positives. IMO we can profit from a combination of static and dynamic
> analyses: dynamic analysis to get an idea of how control flow connects
> different parts of the kernel (due to the massive amount of indirect
> control flow transfers which would make static analysis next to
> impossible) along with a marking technique such as the one proposed by
> Vegard. Then, based on "matches", follow up with a static analysis that
> tracks state along this observed control flow state to see if the target
> state is feasible. Not sure if this is already too complex though...

We can tolerate some impreciseness because our end goal is triggering
bugs at runtime, which is ultimate proof.

For very targeted provocation of concurrency bugs dynamic analysis may
work well, because we don't care about part of the code we can't
trigger (so far), and for the parts we can trigger and plan to collide
we can as well do precise dynamic tracing.
And dynamically we could as well trace actual addresses rather than just fields.
However, both addresses and struct fields will suffer from common
background noise (accessing common shared facilities, kmalloc,
lockdep, etc).

But having some notion of relation statically may be useful when we
generate/mutate programs and need to select syscalls for inclusion.
Say, we have 5000 syscalls and want to generate a program with 10
syscalls. Which ones do we choose? We have some analysis for this, but
there is always room for improvement :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbyqpU1VFGyxMxweeY2Xh56xN-7p1TrNz4yvUNZO0T0BA%40mail.gmail.com.
