Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXXFXW6QMGQEL7RPE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id C51CEA36358
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 17:44:16 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2fc318bd470sf1962761a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 08:44:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739551455; cv=pass;
        d=google.com; s=arc-20240605;
        b=NFIpNNAi70NzMuoFMSr07lolCb26CjkzEt+QbCZWt8UNIH13qHtbuJI/UMo7P7RTWK
         GiHWdmUFojgskyg/HqioutbumVMSvlF1pjoVTGsuyEStG6y1EEPE/Cd+8GTkX1Og7D+/
         ifNb85sCYD2FcIOqXdN6b/HYrItWGst7x9KeREdkjbkLb0gnirH1hjpDANZyrO6mj/Wn
         XJACiRCb4GMx7Admp2VsAWQrBcbjaL/ObJCSSVOFh4I9qW9dDjHeelycXWxgb2X7lXuV
         3BhEl7ugKrrJw1V2rfcAAoxFme+Wb6d91KxHJKuNwIPXo7UE2pogOd9bbcmoLTvCuEDz
         bC/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=92kFxi0c+srrcS71J+8956KLhS5FlBwstM4miCbk554=;
        fh=qkCRkNKNRPJqAhYTlrTOUmXzZ+v0ipaApRZx6R1+Ukc=;
        b=D0WCvS0mY4jwgTdTtA25YzVxu3IYMdX6nxlzp7GLu7/AWd8poHNZC8TbxZvziQodOI
         5LDTtHPK2BZh3gS4yLs7ldGs05idOHPBSUY6huyke3J38zCZlhhRACXK8OoBoj5/8rXD
         q0j+kPQsN0dHAG+ebdWqsT+jxO1lebfkn/uJtKF+M5WoY93qb13UpxTBpYzFjLvDtJ5g
         q8onT1xo1TrS9zuIXgNyH/6tDrf4ZDOo9ndErYo3gYamb4VcTBMX85ANd59+ml4TEa3j
         FRf7kwORCXDWqVMOA6Y8aiphz4h8gJPRV+7XZJ16XF4GTzgke6qg26ffqWS8Xi6sP5EM
         CElg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fxvV02qK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739551455; x=1740156255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=92kFxi0c+srrcS71J+8956KLhS5FlBwstM4miCbk554=;
        b=qdL012xeAxbUzSrrg9VwbkN083WwxS3VycjxGumI4MUvqjkpUkzlp2AbbiVOszvjca
         O7mPb2Ba3Fs1X9tiCrmu1P6tJK/Y6bEh1FMnryfCD6WI7ssml6iwYXHI8bv3rEdkB/dM
         XgctJcat+d/NK5QMIjuPH18FAGWq/syiQhigV4B4SHH/WKR+wjAibfwi7UnF3OJ/LoKg
         SZKYNdfU6dhfeXkbSM6WjRuXERubqFCNfjMq+Hb3x8Wsmc4iU6k105LawqjKUDMxcwA9
         GZFJavgu81/t4pwkDeI12NerCBxB98AVZsRYR7uPfd1gKDzCGpSJZ02EWwIHJonRujb4
         4F7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739551455; x=1740156255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=92kFxi0c+srrcS71J+8956KLhS5FlBwstM4miCbk554=;
        b=gD8GC4Vv+FH/kI0ANQqzW7GEU5iOfvS5zXc3fCmBIGtAU76wBSqOWMYad4k643cklt
         PCuPDnSoGYDLlVvfIiZDq9KuD8d1hy8bnKyID5orTkgQ4PDcAyuxVjpzvrEInFIt3s4r
         EN2rmNS0bTZP6d98c5MXPc8oTMPs3gUyhSWicf/dBCXXWU7QOLYdAIfInD76FNcjMWnM
         FbYAgdGFVTPMVx1UAUc+54nMZsnN2lWPk9IlsZfRf7wlY6WcTahuysuIWbUqfppwwZ8q
         ZBClxcpaBOxVeGAOyXuBhZ/f6JP+h1ElmtBHB9yW6rAOG/4hJDpFsc2RDhZ0UYu+1z78
         BKtg==
X-Forwarded-Encrypted: i=2; AJvYcCWq4nen4gDfVa7Ot3tUktTYpZ64knduWq7Ptf5Ro7ZparUfo+Dzm1gGTe0U3kxJd3cWepicEQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx0mdJpJKuutblReHyb/MdFrVZIHOEw8dpBIi/ox6DCEgM3hV8y
	Qi2Ofb5a2bDVNxZlKnNDGLcu1EPaYy9k9kxmJxiF1hfwOyK2dpYQ
X-Google-Smtp-Source: AGHT+IFhHAPXXr4l1Nrukq/zjixxrJo05TOc2pQ6Fvy3F7GloAgaqUh6yzW091mH8dAeT/jEQRdCfg==
X-Received: by 2002:a05:6a20:2d23:b0:1e1:ce4d:a144 with SMTP id adf61e73a8af0-1ee8c98f0b1mr329835637.0.1739551454919;
        Fri, 14 Feb 2025 08:44:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHWIrea8L7oE8sCkte+OBM4+OJ3ZJC3WndYeLslyyaKFA==
Received: by 2002:a05:6a00:6301:b0:725:ed76:c8a with SMTP id
 d2e1a72fcca58-7323bdd7097ls2409453b3a.0.-pod-prod-01-us; Fri, 14 Feb 2025
 08:44:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUc26NVsgXOquN6XosjsNuQK4xiV+DejOIHme+VuH5yBQdX0ipJt2ZdSgiy4OOUgWILrNlMNgPnu7A=@googlegroups.com
X-Received: by 2002:a05:6a21:33a7:b0:1ee:8894:cc74 with SMTP id adf61e73a8af0-1ee8cb4f75cmr218697637.18.1739551453504;
        Fri, 14 Feb 2025 08:44:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739551453; cv=none;
        d=google.com; s=arc-20240605;
        b=hrQ5WkelD1/4jxRtUwaZVG/KtAgAK+RaJoyZ19HaAlL/riRsBVFManfmIVaHp32x23
         ZZ5fzPcpm6WMoHbcDaQd8+Jby/i6lF2kHx4n8U7EHUipchbz8dFFaBCHluxT3i40RdqJ
         0eC7vdTQ+tEd4heOpEtZ5AoXmAfdPMqCpeXy5xBJMT0Lgr3VH7I5d2uyqMuKxfrpFrU+
         CfHuu26kpSgjfxrRgS8eeK4z838ezY3jUXDgE/5M4D32tnBXwmxdzT5SPe/991K6BLdH
         mn0yyzsw5mLWrhndyQ0SAxeq77H5RubyW7uCTUrlW9a01jS8t0UTFGzpTuboKm1mNxh8
         93IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oO9d0oAKrGz4vkv7SRxKDd5I1l3i0mTcuTEqRSmTOSM=;
        fh=8ODX8c+cJWTIdkhGm5NbLQwkFvWGx7GV92WjumAZ88w=;
        b=fOPbK5s/LLfZ1Ipg3rkDmwgFQ/47SNHUmWnWLXbD0lhpEicwrWLIjzh21rO4hhYtes
         GlVej1FuuPdj0WiSppIE6M6sMBP1bEtfGJaw+25PcQOSWEzsWpE1q1xfqDF21W0Cel4A
         YkK2ttFoYuIZY9LnDFw0SFJJ9wrWQxZKseZ1VAP8Id3LDYdP9rVDWILBFdUuKHsZNC9t
         axGxXGq36uKuFnMcjyiPhu7iaaOfKn50LJw4xqSAjjNnoEmbrNDs1796eGCwGgVo22Jz
         VvpTjhzmFTvEDIgkN0q8dxjcR5vjOVJA29/ZIhmc5BtKKIIonvsyEPjp8OFQmNryE8lq
         3FgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fxvV02qK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73242766706si191146b3a.5.2025.02.14.08.44.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2025 08:44:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-2fc3db58932so467196a91.2
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2025 08:44:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUl5NVBm/y7geWY42TpEvyZ4at3ir0Z/bAg9o+7UgfHNS60OlrkgPgJwZ2IiauorMuFvkXusPO8IfI=@googlegroups.com
X-Gm-Gg: ASbGnctACq0o9EC3mMjlFaRNPNkcpHLlpe8JRW3PWal/JBWhomizbpuKL/J3eQE07lM
	zZkbHKeJwuwur3WYewtTKbjLZikJHPaqzVQSkzejY0TTeqYco5z8gDn2i45mcuQ/NTaCHYr8x3m
	ZDOv0FwODmoNPQej1/+w4fXnwxF/YX
X-Received: by 2002:a17:90b:23cf:b0:2ef:33a4:ae6e with SMTP id
 98e67ed59e1d1-2fbf8f32e01mr20276708a91.12.1739551452914; Fri, 14 Feb 2025
 08:44:12 -0800 (PST)
MIME-Version: 1.0
References: <20250213200228.1993588-1-longman@redhat.com> <20250213200228.1993588-5-longman@redhat.com>
 <CANpmjNM-uN81Aje1GE9zgUW-Q=w_2gPQ28giO7N2nmbRM521kA@mail.gmail.com>
 <3d069c26-4971-415a-9751-a28d207feb43@redhat.com> <CANpmjNNLn9=UA+cai=rL+6zsEQyppf6-4_YL4GAFi+dLt+4oSA@mail.gmail.com>
 <f2f006e8-3987-4aa2-b4f5-114b4e869e86@redhat.com>
In-Reply-To: <f2f006e8-3987-4aa2-b4f5-114b4e869e86@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Feb 2025 17:43:36 +0100
X-Gm-Features: AWEUYZlhsid88jbBXlrCRzO_gVgGmSd_N7t21Ty9NLxBg4_xXnC-cahHoi81xvE
Message-ID: <CANpmjNPYFjv4TTCG+t0zyr2efCtjPKV7zQQu-ccsgX5XtGtDLg@mail.gmail.com>
Subject: Re: [PATCH v4 4/4] locking/lockdep: Add kasan_check_byte() check in lock_acquire()
To: Waiman Long <llong@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will.deacon@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fxvV02qK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as
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

On Fri, 14 Feb 2025 at 17:18, Waiman Long <llong@redhat.com> wrote:
>
> On 2/14/25 9:44 AM, Marco Elver wrote:
> > On Fri, 14 Feb 2025 at 15:09, Waiman Long <llong@redhat.com> wrote:
> >> On 2/14/25 5:44 AM, Marco Elver wrote:
> >>> On Thu, 13 Feb 2025 at 21:02, Waiman Long <longman@redhat.com> wrote:
> >>>> KASAN instrumentation of lockdep has been disabled as we don't need
> >>>> KASAN to check the validity of lockdep internal data structures and
> >>>> incur unnecessary performance overhead. However, the lockdep_map pointer
> >>>> passed in externally may not be valid (e.g. use-after-free) and we run
> >>>> the risk of using garbage data resulting in false lockdep reports. Add
> >>>> kasan_check_byte() call in lock_acquire() for non kernel core data
> >>>> object to catch invalid lockdep_map and abort lockdep processing if
> >>>> input data isn't valid.
> >>>>
> >>>> Suggested-by: Marco Elver <elver@google.com>
> >>>> Signed-off-by: Waiman Long <longman@redhat.com>
> >>> Reviewed-by: Marco Elver <elver@google.com>
> >>>
> >>> but double-check if the below can be simplified.
> >>>
> >>>> ---
> >>>>    kernel/locking/lock_events_list.h |  1 +
> >>>>    kernel/locking/lockdep.c          | 14 ++++++++++++++
> >>>>    2 files changed, 15 insertions(+)
> >>>>
> >>>> diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
> >>>> index 9ef9850aeebe..bed59b2195c7 100644
> >>>> --- a/kernel/locking/lock_events_list.h
> >>>> +++ b/kernel/locking/lock_events_list.h
> >>>> @@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)  /* # of rt_mutex_handle_deadlock()'s    */
> >>>>    LOCK_EVENT(lockdep_acquire)
> >>>>    LOCK_EVENT(lockdep_lock)
> >>>>    LOCK_EVENT(lockdep_nocheck)
> >>>> +LOCK_EVENT(lockdep_kasan_fail)
> >>>> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
> >>>> index 8436f017c74d..98dd0455d4be 100644
> >>>> --- a/kernel/locking/lockdep.c
> >>>> +++ b/kernel/locking/lockdep.c
> >>>> @@ -57,6 +57,7 @@
> >>>>    #include <linux/lockdep.h>
> >>>>    #include <linux/context_tracking.h>
> >>>>    #include <linux/console.h>
> >>>> +#include <linux/kasan.h>
> >>>>
> >>>>    #include <asm/sections.h>
> >>>>
> >>>> @@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
> >>>>           if (!debug_locks)
> >>>>                   return;
> >>>>
> >>>> +       /*
> >>>> +        * As KASAN instrumentation is disabled and lock_acquire() is usually
> >>>> +        * the first lockdep call when a task tries to acquire a lock, add
> >>>> +        * kasan_check_byte() here to check for use-after-free of non kernel
> >>>> +        * core lockdep_map data to avoid referencing garbage data.
> >>>> +        */
> >>>> +       if (unlikely(IS_ENABLED(CONFIG_KASAN) &&
> >>> This is not needed - kasan_check_byte() will always return true if
> >>> KASAN is disabled or not compiled in.
> >> I added this check because of the is_kernel_core_data() call.
> >>>> +                    !is_kernel_core_data((unsigned long)lock) &&
> >>> Why use !is_kernel_core_data()? Is it to improve performance?
> >> Not exactly. In my testing, just using kasan_check_byte() doesn't quite
> >> work out. It seems to return false positive in some cases causing
> >> lockdep splat. I didn't look into exactly why this happens and I added
> >> the is_kernel_core_data() call to work around that.
> > Globals should have their shadow memory unpoisoned by default, so
> > that's definitely odd.
> >
> > Out of curiosity, do you have such a false positive splat? Wondering
> > which data it's accessing. Maybe that'll tell us more about what's
> > wrong.
>
> The kasan_check_byte() failure happens very early in the boot cycle.
> There is no KASAN report, but the API returns false. I inserted a
> WARN_ON(1) to dump out the stack.

I see - I suspect this is before ctors had a chance to run, which is
the way globals are registered with KASAN.

I think it'd be fair to just remove the lockdep_kasan_fail event,
given KASAN would produce its own report on a real error anyway.

I.e. just do the kasan_check_byte(), and don't bail even if it returns
false. The KASAN report would appear before everything else (incl. a
bad lockdep report due to possible corrupted memory) and I think
that's all we need to be able to debug a real bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPYFjv4TTCG%2Bt0zyr2efCtjPKV7zQQu-ccsgX5XtGtDLg%40mail.gmail.com.
