Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVWRZLXQKGQEJUVJQNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 503C111D81F
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 21:53:43 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id q130sf338247ywh.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 12:53:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576184022; cv=pass;
        d=google.com; s=arc-20160816;
        b=TbohNILQWMtWCV2loGJu6pdncc98/ZoWvhLqMoq39fVH5xez/qj6rgsrdTA3DIvbGx
         Jz18sneqiWpECdBvQMpq6R8AFVk/j3+S6o4E77Hbp+eDCRQYFjZtThshcA1O2BIHcAhe
         1J846oxBBNXVbzBsiyxb7bSzyh95uoAh8qMSJH71vEvenmpUFTvR1hVXOeKwgytyMBiy
         HVnunIPEw/msHhbT57W5PmdmR9B8LeWhVV9DJIVnwTXKB7d0ZC6wZJm+K+Arc4N31S8d
         lthAIEskUox2zHdAjA7nbh/gifAj+/VlZJcMqStXQg4TM6Gog5KAcacBNv5rbtSWOgH0
         Rt1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Wqz37BeQ+NPEfc9QtJWInbfDXAOQfjBFdyy62pdNn3I=;
        b=H8K3+WxDe0Rsyng6PsI8y+ci69k0EHiVaJP+Vw5KvBWSVXVNdj0yd3eBwWucFi9nqU
         ICkb7hmOmUaoOfNh61t/2ipqKAZrk4/bdT8B2OHFkh+qwAw+XsFsVRPULD7fHq26peWo
         j0Rv68ZI8IANCXaNS9DnTrkFdZwzl7UCVch97OGnfzSi1DuG7wltsA6AqtA373D/zaXd
         Bi/E5qXN+brPqWGVYF2/2zOhZ7Nmk3EBQxTGtCHg0S/SCXuJk++DWfHC5mMhhlUx2Rvr
         8f93RN3bflUwss3pz7e8RdbS1P6zCDvpXf4a2akDwBvV2/4geZVgMX43zgfW2/xwj8fV
         BOAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CXoo+nHL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wqz37BeQ+NPEfc9QtJWInbfDXAOQfjBFdyy62pdNn3I=;
        b=cxLDyDUs3WV99CG5eH78Pcb/pOdAiKQwHiD59gs8Wqec0tTTIIwZWjm5tdhDL1x1ZT
         5nwZdorLO7xP0j/H95KiVb7TpVj9dfwaFFjhsUnHmdEhy3Dl1ecnTpJBtdaj+NAlkuEU
         oW8fTp8RBDEmPMrSQWIS0zJqqrx6Onu8vSZYwCgaKx0tJ1wxhar2Kwoydjrr1flXXlPW
         /sQ/mEb4996SmW2W0kO50gWzpKDN1z2Rq7xAMKkxU5FgBzv32E9+qz58DATB8DPPpF/w
         e0MFxJlTGLTflLm20ZLTT40xq/uHLPOeP6FnIWE45g/NOV/V8ifk09n/DmWug1a0RWZX
         Yrhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wqz37BeQ+NPEfc9QtJWInbfDXAOQfjBFdyy62pdNn3I=;
        b=PT88ISKbbVsgpzujI3NTVcjkrKdCOCWsf/Xp6yvwxTzwTxfk9UnZf5U+/0r1mg8ot5
         xkPRTXHPqOhKYZbk2AFfXbzC9Xe3PwOnHzc7bQdq894vWeWZ8hwtk4oqFospf0eY6c+w
         sgSyUpCmkxJyMP0iSywRkP+CDTBx0TGBHlQDDjmoQ8soDuDtmDovginVSN0aXy8iW28j
         Zw4LRlvv9lIilT1/9dELDGQWkMtyg2Movp5gLe33zxwSmMA2Bs5+x8kSIdeC+rTCY7uh
         z5IhVmhNVLtfqiQ7UpWYTNCdiRCoSkv8u305Fn4KLK3P0qsLA+rlSCq7PJAUOiZ3ew2a
         PU1Q==
X-Gm-Message-State: APjAAAVkzmoPsf9cSz6omiYLUJ2hxuV0IktcMbAMWS4DeU3bJ2DU3Ey2
	7uC6ZlfPts93+Ml2IDEl59w=
X-Google-Smtp-Source: APXvYqwrDUkbkrp75TejzNVebj3dmky+hlrxtVKOCm++CHLHFqUWnpOLbAeskJehPZfwgFrfs9BkYw==
X-Received: by 2002:a81:4e12:: with SMTP id c18mr3020477ywb.154.1576184022261;
        Thu, 12 Dec 2019 12:53:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2397:: with SMTP id j145ls1084391ybj.7.gmail; Thu, 12
 Dec 2019 12:53:41 -0800 (PST)
X-Received: by 2002:a25:5008:: with SMTP id e8mr6060382ybb.277.1576184021846;
        Thu, 12 Dec 2019 12:53:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576184021; cv=none;
        d=google.com; s=arc-20160816;
        b=Ru91KSEV130N7CJCBGqVUTh/i3N79cLI+JT9YI1NV6iI2viiPeUPHz0vWzPxN1G28G
         4iPqDUETQvxg7BHVqBc+A97bGrgLYG5/X+50p0BgvuMXwvXtO2yh4PgudqP+UVmOBbwO
         K/dtew1GTyixNlBH6DJn8PGhsewspUSWKt4zAJodvE9iR1SrM+rPGVA20aQQvKHPBbxG
         O8a1cnMI93TTvO0BvSAKaApfBp+Vy/UcnxzefY2IZ5sDrltScFBTFAt3kyfDmQXQ+rh4
         22IiJ/uYJFu6N9HVl4BgHjIRML+pNIOglpN8sXSnV0cdSUw+O528IkYNDRyiJMq2VbpT
         QFfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q/kJv8AZtrQ1tJoTlAjQBJyNXaZYs14RTc7efEcCC3c=;
        b=uvjODIE20DMGWiZ8oKgI3Ew20zEiSu0m5oawoUYJFUtwohxuKMdEhhKayLL+F0uvxg
         ie9srX2kJi6NzvJslEW/vHyCJdZ8v6Z6Q128+OV+4H2In8Y3Iv2NjfGPSc62SNPymuqg
         KZpxPWJ4TDSyBpQ4Jvp9pjQJnHPoGLS0Dd5B7bC3f2DrO1TwUoez+U2qrxX8mXQ9OVtN
         XdVg0odkWxOPbhYwKhm4GYfD8UJFnWMvkA35Unbkd3gsZTJ53+Z0iLeUEz5+7TM+UbmP
         YtKZatYiq8p/MjHlT4dUskAEj5oSg7dLCKCB/OWN/QJRHlPkfAkKeeB/cw7GMw+9sand
         kWCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CXoo+nHL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id r1si470396ybr.3.2019.12.12.12.53.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 12:53:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id b8so196705oiy.5
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 12:53:41 -0800 (PST)
X-Received: by 2002:a05:6808:8d5:: with SMTP id k21mr6465600oij.121.1576184020952;
 Thu, 12 Dec 2019 12:53:40 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <CADyx2V6j+do+CmmSYEUr0iP7TUWD7xHLP2ZJPrqB1Y+QEAwzhw@mail.gmail.com>
In-Reply-To: <CADyx2V6j+do+CmmSYEUr0iP7TUWD7xHLP2ZJPrqB1Y+QEAwzhw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Dec 2019 21:53:29 +0100
Message-ID: <CANpmjNOCUF8xW69oG9om91HRKxsj0L5DXSgf5j+D1EK_j29sqQ@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Walter <truhuan@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CXoo+nHL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Thu, 12 Dec 2019 at 10:57, Walter <truhuan@gmail.com> wrote:
>
> Hi Marco,
>
> Data racing issues always bothers us, we are happy to use this debug tool to
> detect the root cause. So, we need to understand this tool implementation,
> we try to trace your code and have some questions, would you take the free time
> to answer the question.
> Thanks.
>
> Question:
> We assume they access the same variable when use read() and write()
> Below two Scenario are false negative?
>
> ===
> Scenario 1:
>
> CPU 0:                                                                                     CPU 1:
> tsan_read()                                                                               tsan_write()
>   check_access()                                                                         check_access()
>      watchpoint=find_watchpoint() // watchpoint=NULL                     watchpoint=find_watchpoint() // watchpoint=NULL
>      kcsan_setup_watchpoint()                                                          kcsan_setup_watchpoint()
>         watchpoint = insert_watchpoint                                                    watchpoint = insert_watchpoint

Assumption: have more than 1 free slot for the address, otherwise
impossible that both set up a watchpoint.

>         if (!remove_watchpoint(watchpoint)) // no enter, no report           if (!remove_watchpoint(watchpoint)) // no enter, no report

Correct.

> ===
> Scenario 2:
>
> CPU 0:                                                                                    CPU 1:
> tsan_read()
>   check_access()
>     watchpoint=find_watchpoint() // watchpoint=NULL
>     kcsan_setup_watchpoint()
>       watchpoint = insert_watchpoint()
>
> tsan_read()                                                                              tsan_write()
>   check_access()                                                                        check_access()
>     find_watchpoint()
>       if(expect_write && !is_write)
>         continue
>       return NULL
>     kcsan_setup_watchpoint()
>       watchpoint = insert_watchpoint()
>       remove_watchpoint(watchpoint)
>         watchpoint = INVALID_WATCHPOINT
>                                                                                                       watchpoint = find_watchpoint()
>                                                                                                       kcsan_found_watchpoint()

This is a bit incorrect, because if atomically setting watchpoint to
INVALID_WATCHPOINT happened before concurrent find_watchpoint(),
find_watchpoint will not return anything, thus not entering
kcsan_found_watchpoint. If find_watchpoint happened before setting
watchpoint to INVALID_WATCHPOINT, the rest of the trace matches.
Either way,  no reporting will happen.

>                                                                                                           consumed = try_consume_watchpoint() // consumed=false, no report

Correct again, no reporting would happen.  While running, have a look
at /sys/kernel/debug/kcsan and look at the 'report_races' counter;
that counter tells you how often this case actually occurred. In all
our testing with the default config, this case is extremely rare.

As it says on the tin, KCSAN is a *sampling watchpoint* based data
race detector so all the above are expected. If you want to tweak
KCSAN's config to be more aggressive, there are various options
available. The most important ones:

* KCSAN_UDELAY_{TASK,INTERRUPT} -- Watchpoint delay in microseconds
for tasks and interrupts respectively. [Increasing this will make
KCSAN more aggressive.]
* KCSAN_SKIP_WATCH -- Skip instructions before setting up watchpoint.
[Decreasing this will make KCSAN more aggressive.]

Note, however, that making KCSAN more aggressive also implies a
noticeable performance hit.

Also, please find the latest version here:
https://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git/log/?h=kcsan
-- there have been a number of changes since the initial version from
September/October.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOCUF8xW69oG9om91HRKxsj0L5DXSgf5j%2BD1EK_j29sqQ%40mail.gmail.com.
