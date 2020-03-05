Return-Path: <kasan-dev+bncBCMIZB7QWENRB4V2QXZQKGQEKO4HN5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id A2BE717AF93
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 21:13:39 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id w1sf3723331qvp.23
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 12:13:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583439218; cv=pass;
        d=google.com; s=arc-20160816;
        b=tqrWVuf5kWz7O9Q8VeB1bYBC77Uz18UAAo7HIOxaWytzNHs0P5RZAAXXZN66sbE6Vp
         Z8D8AyQSqAOEy/wbIfB+ckAFA/jduTPP4Lgj9oKQKWpYy8k5RTScIr46G22tC8xVT/g4
         twnIl5WXiAPCPLethRI7kJ9MMBRBTJ+n34HA3ZGyKm2g9M3lYX12S1IjK1Zo3U8oKIVS
         5hq5Q9p4w39juHrMjgu13kFIQuPlv3UPRwUoOergvPqgVmtk/3HMTej7TYU17LY5scC1
         Fpdv0P+NjbMNyi32fXSXvIHb7U92eE7eiGr07Abl0jBmqVeKEzjf4mVV4UwF2GP72cyp
         SObQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ya6vGsuIKePjZOvBalbEcPbSP2m/wZA08WiUuVZ3LSY=;
        b=oZSb6JcEpcj5eYBH0QC/KAys1SGTiBG++ocsexv6m/nRL9T9FJV9K8SzO7qDxEAzuJ
         1yDyfICTUS1KPomwxaPy2fvempdPR9ilhN5tnu62RQbp5hJbD2wDEcpMFj7EwAWBUtC9
         GCYNUMMfK/6qEkOUpb65Zed/UR/fzne+D3OBNo+VCAcRY0hr8PI6pNV+8JEK01yVTFFI
         WrJuX7IU9VICs367GOedbosOGlEmMgJ1RrP8OsmIvKcRxB5LXndOgX3uEdNl2jyrJKoW
         PKp8Y6cIts3Qg6JaEvur1jfIOljmUXifeVfFOKwa8MA90xyhSRx0CfEhE96mHj24RpEi
         pkCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PK2hUOcl;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ya6vGsuIKePjZOvBalbEcPbSP2m/wZA08WiUuVZ3LSY=;
        b=P5Zs02Vp9o7Ztn4Fb61Ltsv3BDw0bCg+rvuPbUuE9IozFV1zybo9ejPXCpxA4CoV/O
         R+ZE2He7SsO0Nkp9v01K8/mvHu9ieSZtuUXZaDfjdLdjxrbqw8zKTf++fnbMsc+my0HL
         6aZRCTueS7A3LLywwfYRT/tP1jQapXo5rrn6MFLZallT3IZx/vGaa1IOC2c5OR2nyzte
         F7eAbwA5xY50yTp17sRWBHkbeMPTMUdrgTMWigRRLqr4pW64blOM2KrblBgw5KOzyN6f
         fhMbqKg+zAxoVt53Lu5X1683raNva4+isNHbUP9kvPcPVb8Lpt6I2JHCw4QnprkelPpP
         VdxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ya6vGsuIKePjZOvBalbEcPbSP2m/wZA08WiUuVZ3LSY=;
        b=Zli1+OMwdnC8mw+TGW/kbkYgvXQULayA5foc+ZGsPIg2YA9KhlKUmyBBM28S1zrHzh
         sts/rJXrghAKG4mfzFVxHjPy3jZD0sw+1s7Pl0p+M4rDdlQdDN/s+Xxpz6RzFfjvDkZj
         1fusCQMLyojjJ183PrW4XnWV8zJY8ebZZGeFAi/zH0BjW6BaNQ/g8rC/cKG6LPW0vdUD
         afGLUj67IKMqKMp47ku2HAbkHq35U0Sl2lduO1fLizUoT8h7g/rWIXJeY1png48bTwB5
         1VfLDM99zzxckMUaS2/e0fI7nSkJAVjwahfL5C0QiOFF2xndBHCKsS4fuRhC74W/Vyw6
         nPvA==
X-Gm-Message-State: ANhLgQ2e92Wzr5hCEUdGh4dSKuMVoAz/ojaz+yxdX/vhIJ5MnrmGNK53
	xZlOsNu5ku2g0dd/5NA/W/E=
X-Google-Smtp-Source: ADFU+vtDWYa8PIf5GaXaRHg5zzjEvdZCdx6NPNiQkBEak5tJEwSi7PsT72R6kgx9I8WGCbjxMkGNbw==
X-Received: by 2002:a05:620a:1482:: with SMTP id w2mr9784458qkj.170.1583439218704;
        Thu, 05 Mar 2020 12:13:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:518d:: with SMTP id c13ls1400505qtn.10.gmail; Thu, 05
 Mar 2020 12:13:38 -0800 (PST)
X-Received: by 2002:ac8:4509:: with SMTP id q9mr437609qtn.374.1583439218380;
        Thu, 05 Mar 2020 12:13:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583439218; cv=none;
        d=google.com; s=arc-20160816;
        b=F8rXp7sQsokMWjytIwuKQCu1SSkrYergR9ED8I8T4DXfqG41xPfDMujEBa3SFULnMC
         c9B1hntD1kh+R6023RKDTFj4bk4brFI1CZyL0brs6LdKH8/if0IZK9vAM/UPk5fp21c/
         /TRCrn+ZqV/TvDbGdJOs0/NmwgI+oTES0VUFOrBI95rKCJ3qyku3NU4Xhm6kaim+Zex2
         R80VE+4ht6KRVD5Pm1xkFpevU6PFEKu7DxYkEmGB26q2c4kPr0lLe2AJC7n6kr53Xo9F
         BYhTVwXHu2Eq3xzeoEq7LS6Nza13acY9OQpOpc0TeUvG/ap1I/p4fG5UHJkkZxt64eP1
         jAsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J0V5HIGDjuqcu6wIaTE5bGFT4we2mdwsjpAf6FZcDkA=;
        b=hOqq7G37I8UJ1iYGN3NlcY4nSUS5HjEXGSV0QXcMNPbai2CC2zSZtEI5PxX+ppZXbI
         01byzXpNv0yV9KCadUXdU6gOkYunvj48dD/9/L+GWwwU2Ey7akpj0brVuAUQTu3he8GS
         Hq+Be6Gmp7QuR1qdN+3dmKTqWbuMpXo+NjB5uMEXFyaxAIavsdLTuFkxGbuDPVjnLv6t
         IicdSNDDyu4qsfuh8yGZPgYiVEzA45mEb7uGayjJW9Zg7fZ/KxcuNA8yd56O0xP60IDZ
         B4hN8bUEENU0xLxdVwPtXH/Y+0m/gYh2O+7owDf4DQ93aGq/BpgEMiU3TThxY9Q6gw9J
         NUlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PK2hUOcl;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id o21si6028qtf.5.2020.03.05.12.13.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 12:13:38 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id b13so3014227qvt.11
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 12:13:38 -0800 (PST)
X-Received: by 2002:a0c:f892:: with SMTP id u18mr421447qvn.159.1583439217625;
 Thu, 05 Mar 2020 12:13:37 -0800 (PST)
MIME-Version: 1.0
References: <202002292221.D4YLxcV6%lkp@intel.com> <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
 <20200305155539.GA12561@hirez.programming.kicks-ass.net> <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
 <20200305184727.GA3348@worktop.programming.kicks-ass.net>
In-Reply-To: <20200305184727.GA3348@worktop.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 21:13:26 +0100
Message-ID: <CACT4Y+axD4ZjEPdekgVkkUGu6V0MMR9Q1RNcVA9v6dOSi8FHzg@mail.gmail.com>
Subject: Re: [peterz-queue:core/rcu 31/33] arch/x86/kernel/alternative.c:961:26:
 error: inlining failed in call to always_inline 'try_get_desc': function
 attribute mismatch
To: Peter Zijlstra <peterz@infradead.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PK2hUOcl;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Thu, Mar 5, 2020 at 7:47 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Mar 05, 2020 at 05:29:27PM +0100, Dmitry Vyukov wrote:
> > On Thu, Mar 5, 2020 at 4:55 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Thu, Mar 05, 2020 at 04:23:11PM +0100, Dmitry Vyukov wrote:
> > > > Compilers just don't allow this: asking to inline sanitized function
> > > > into a non-sanitized function. But I don't know the ptrace/alternative
> > > > code good enough to suggest the right alternative (don't call
> > > > user_mode, copy user_mode, or something else).
> > >
> > > Does it work if we inline into a .c file and build it with:
> > >
> > >   KASAN_SANITIZE := n
> > >   UBSAN_SANITIZE := n
> > >   KCOV_INSTRUMENT := n
> > >
> > > Which would be effectively the very same, just more cumbersome.
> >
> > I think it should work, because then user_mode will also not be instrumented.
>
> Right, but then I have to ask how this is different vs inlining things
> into a __no_sanitize function.

We ask compiler to do slightly different things in these cases. In the
original case we asked to sanitize user_mode. If we have a separate
file, we ask to not sanitize user_mode. A more explicit analog of this
would be to introduce user_mode2 with no_sanitize attribute and call
it from the poke_int3_handler.
Strictly saying what you are going to do is sort of ODR violation,
because now we have user_mode that is sanitized and another user_mode
which is not sanitized (different behavior). It should work for
force_inline functions because we won't actually have the user_mode
symbol materizalied. But generally one needs to be careful with such
tricks, say if the function would be inline and compiled to a real
symbol, an instrumented or non-instrumented version will be chosen
randomly and we may end up with silent unexpected results.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaxD4ZjEPdekgVkkUGu6V0MMR9Q1RNcVA9v6dOSi8FHzg%40mail.gmail.com.
