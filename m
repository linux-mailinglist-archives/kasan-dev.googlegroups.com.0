Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4VNXW6QMGQEJBMHLDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id A275AA360BB
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 15:45:11 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-471cbd8bfc7sf30700241cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 06:45:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739544306; cv=pass;
        d=google.com; s=arc-20240605;
        b=bGt5uXe6/p1qHPLybXcuoFZA8kJbHhJrygf2hv6DXaZ7kaojmRXlmd7kXDdlRc0emp
         Z3d2soFDIMWPm3EfbDuyVEGXhXzyc1zRLBvzVkJqHSrmLZK95AllbIlj9CdR3328JeoG
         lpqkM7lbIeb/8ErStbENE2DE4wPKJE372YhyFFelj7w3nIDwpB/e4R2vMtfjtJz5+X/P
         9TgHKingteGPFRH7JVecYpeviYDcDl8zvZpWFskRLX/CMecvL4NCUm1MNQYdYCsjmM4P
         1KWinrQIjh/oxtDcW9feN2FwrBLBXUOyIEWzK8lKByLOKfk8evTVJUj+SBglXD4xkhB6
         DgeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Zy74F9EoY+y0ba2KarDOuhL28fTk/+j/+9dWZELbZx8=;
        fh=GLCaHyDGH7iDXQAGJhW7OFdy/dccrAAHGWnGFM2cXFY=;
        b=J7vNJgCc50/0q13oslDqtLoOJ37pVOKCW/It0nOyAEkMODyPXggFn6c4lgQD6ilCCC
         Cdp1fPWzXc46xIChu080DDw0tJjXEcnZJ8HRPgG9ePhkeSjZcrml+e9d+pLMGcWJd/XR
         ZjqywS1R4AuyLEebfH34N49v56WMSeXt55l7eWHF1RZFXrPLV55RU0sS7SfD9vhKUbfB
         +s8e/nAQlIZxxH4hDkiLvur6L9GCZL3Ik45Z+sVKH6ZWrUDMJbzNBfxFdMQXfn2xan8P
         /83YtROvfk6tYWtFgZjlPanGyTrCR53JQGXI16dQkO+neGWw2mbf3TyqB7wEOKOrR6bG
         Il4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jeMlePdi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739544306; x=1740149106; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zy74F9EoY+y0ba2KarDOuhL28fTk/+j/+9dWZELbZx8=;
        b=V9K5sUoNYsG9FMsjOmT3iOJLhI98zpqPMAmovMDzgBg91Fipzb4LLZzO0ONZ8WY6i3
         Thd9AyhJBtnuub/WTu2Oyk9pIc4ADnzRLD3nwmSJaVW+y3XSPXZauiXP85h+1lIQTaXu
         1fzzLEflpvOM8Q6d2OBysf7AfwSTXQUTGB5U7dHt8hqQZhuqDg8HTCzZydJ/f1upPNr+
         nCQxUkVGbe5GXdzLSESzE2RroADnCDVTm0ay0gHr/llpyrbKyC69TYzaOqsJ+QnI/iWL
         W5wN8jxI8YCILaijhZRjS8fq+smJW9+gUgNhYax5LoXKiWsDl7welYKV9S02Vus/yy98
         rW3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739544306; x=1740149106;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zy74F9EoY+y0ba2KarDOuhL28fTk/+j/+9dWZELbZx8=;
        b=IN9aB9SweB+1Gf732ktbULWTZZN3GvhQcJ46kKXb6giJTWJAxZSJVXwJg8MvwiexrC
         jNDz/kE0UL5DcBwc446IbrpqOEggu7cDfFr5yeUtITQkXLSpi2WTSSQahgKS4OxTZ/da
         RXy3wqJgs5GbB+VHVaWw4kAxVUysPUfY1gbuB8Jp2Y+hPx2XcqYmFDqOfHuVg67pbNuR
         D+KLhYfcdnGEFwXZmgQUm0RL8xk3npEKph1S/GjGAtSi6iZF2IHRDURQ5TqGoppjlVYR
         a5/sVqocKfCBaEX5tz3rzDqVNnpvbQ6kMZmAHiHNQJriHPrwOrF3M9OPpuZTYSE/cz0B
         YPQg==
X-Forwarded-Encrypted: i=2; AJvYcCUGAga4Ptt8mcSAGXtTXE5emVUCEngF+ps3O8e+BbhTJSFt/HscFlgxZqA7se4WSvLBxMiUQA==@lfdr.de
X-Gm-Message-State: AOJu0YwNf3dPxy/U3HsT/LiCK4Ixnv7LmkhG5Mqmfu8Gz0pITsLGyMq5
	H24bm7l8pYT5HalcZ5X2bwj5O23+1KP/Expsckcpz30/OV38RNja
X-Google-Smtp-Source: AGHT+IFXQmHLcrIC9+OsdRfhY5ZD6LmvOfRBXuX4YYTdgLZ6FmIvkdootaCrKJ/gUIWZrO1KPWfGpw==
X-Received: by 2002:ac8:594f:0:b0:471:c14f:5ef7 with SMTP id d75a77b69052e-471c14f612bmr76744361cf.26.1739544306471;
        Fri, 14 Feb 2025 06:45:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGGwd3vz7AbkhXJD2WBeAmR8bjb5htLWvRMQAFPjdSECQ==
Received: by 2002:ac8:4414:0:b0:46e:5db6:4f6d with SMTP id d75a77b69052e-471bf2dfea4ls30866031cf.1.-pod-prod-03-us;
 Fri, 14 Feb 2025 06:45:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXXXw8gCngyBw0FCg3cxtiIRDrzZKJYnzyy7Ha92dmXDcMsSgOLnyibmb5t0ZPDSRasJjnS0ng7PLw=@googlegroups.com
X-Received: by 2002:a05:620a:1787:b0:7c0:808b:1c77 with SMTP id af79cd13be357-7c0808b1e13mr705508185a.43.1739544305549;
        Fri, 14 Feb 2025 06:45:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739544305; cv=none;
        d=google.com; s=arc-20240605;
        b=NIGR/rTbxzPVPwMvZNBnggsyINejZKImP4uY3Vm206vOpsubr3VfP04ZECk2FNMhdx
         dW1/XMa/L30vASY1qTCnDeQLqhvvTiuNY7AQTCtDtfhICegntJNIq1fgNwCtTc0ZelZg
         YizlI/G46fGjiG3gjseiW05WSzcqPozgStF4vCyTMH00J4B0S5AihjtbA5NODNQHaa91
         FBiYRm4MIiS0zRqSiryP6Dfr4S6Rva0rrXfYRBR5tNJpx+tRXpz7ogCFA4Wl8N3uSw83
         g6I8RuS2mYjBXgCpFNI35lg9TVts3E2/rhnnRdw3auC1WHctcYqnr2A1s5U/5LjOr4UI
         H5cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qAfs/2wWZw1nrswKtLLAZKfz4qKwgA4SGanKMqohMA0=;
        fh=jX9DMIshLa2odHBJ1vlo7ctGX1xsuzMrnwqzlxHzrTQ=;
        b=BmKoogJbMZnQK0wWcy2za56zCmmB/lsLTFVFNHO/8BbhvbJn7ObW2a3Sy3tFEBQCgz
         UXplJ18yRAPhNWZk1mK1lKalUifaXM9jpoNvjHXaOAWgZ0075JraMAbuHFh6xYYQAoaO
         Qi6nbujaVpoqCmTqsPXnRMkVMK8ZkdMjMHaBeXMzK0SJYrB84kE9XqlaNUmHnPa0bJSt
         WiDIFqbOCEvLoOs1y1ubnwAJ98T2+Rt4fHBcHBSJssWrAHzuMECxpeSUOULFUJ7EJHSY
         SBXDyYQW7R7BifmYMB7zqezFVnJHONCJpD8mB3/Wf9kAClxS7XY8Nf8/qczNbEZLuuOQ
         QDVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jeMlePdi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c07c861329si14610285a.7.2025.02.14.06.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2025 06:45:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2fbfe16cc39so4059941a91.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2025 06:45:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWjOXM1zqcymEUP6knPtIomuwVi/xMMkoSNeOK7T6rYR9c2nK45q1vVpRLmft4IhEbCgb5YQupeTuA=@googlegroups.com
X-Gm-Gg: ASbGncsp1LCNxePf2SalMs5dYVGGrXNTjrJWgx141KKmWDH18H8dkrFaxwflAAMdt0L
	f9vSWb9d4HXvJ6X6tLs1MVR/MmF4rwd6d4Kxf9ZcBzP8TgTacfzOvUoj6WE3YAzzbNMWzd69FLJ
	hTU3gFEGDHiWX4eWfXigg9E5QrOS4=
X-Received: by 2002:a17:90b:5687:b0:2ea:77d9:6345 with SMTP id
 98e67ed59e1d1-2fbf5c5ec93mr15482217a91.22.1739544304873; Fri, 14 Feb 2025
 06:45:04 -0800 (PST)
MIME-Version: 1.0
References: <20250213200228.1993588-1-longman@redhat.com> <20250213200228.1993588-5-longman@redhat.com>
 <CANpmjNM-uN81Aje1GE9zgUW-Q=w_2gPQ28giO7N2nmbRM521kA@mail.gmail.com> <3d069c26-4971-415a-9751-a28d207feb43@redhat.com>
In-Reply-To: <3d069c26-4971-415a-9751-a28d207feb43@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Feb 2025 15:44:26 +0100
X-Gm-Features: AWEUYZkjFehohssArY_udscwBKWHL2QvdhXQ1Ql8mqX56GdhkL6wCNSxpM9NVHY
Message-ID: <CANpmjNNLn9=UA+cai=rL+6zsEQyppf6-4_YL4GAFi+dLt+4oSA@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=jeMlePdi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as
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

On Fri, 14 Feb 2025 at 15:09, Waiman Long <llong@redhat.com> wrote:
>
> On 2/14/25 5:44 AM, Marco Elver wrote:
> > On Thu, 13 Feb 2025 at 21:02, Waiman Long <longman@redhat.com> wrote:
> >> KASAN instrumentation of lockdep has been disabled as we don't need
> >> KASAN to check the validity of lockdep internal data structures and
> >> incur unnecessary performance overhead. However, the lockdep_map pointer
> >> passed in externally may not be valid (e.g. use-after-free) and we run
> >> the risk of using garbage data resulting in false lockdep reports. Add
> >> kasan_check_byte() call in lock_acquire() for non kernel core data
> >> object to catch invalid lockdep_map and abort lockdep processing if
> >> input data isn't valid.
> >>
> >> Suggested-by: Marco Elver <elver@google.com>
> >> Signed-off-by: Waiman Long <longman@redhat.com>
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > but double-check if the below can be simplified.
> >
> >> ---
> >>   kernel/locking/lock_events_list.h |  1 +
> >>   kernel/locking/lockdep.c          | 14 ++++++++++++++
> >>   2 files changed, 15 insertions(+)
> >>
> >> diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
> >> index 9ef9850aeebe..bed59b2195c7 100644
> >> --- a/kernel/locking/lock_events_list.h
> >> +++ b/kernel/locking/lock_events_list.h
> >> @@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)  /* # of rt_mutex_handle_deadlock()'s    */
> >>   LOCK_EVENT(lockdep_acquire)
> >>   LOCK_EVENT(lockdep_lock)
> >>   LOCK_EVENT(lockdep_nocheck)
> >> +LOCK_EVENT(lockdep_kasan_fail)
> >> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
> >> index 8436f017c74d..98dd0455d4be 100644
> >> --- a/kernel/locking/lockdep.c
> >> +++ b/kernel/locking/lockdep.c
> >> @@ -57,6 +57,7 @@
> >>   #include <linux/lockdep.h>
> >>   #include <linux/context_tracking.h>
> >>   #include <linux/console.h>
> >> +#include <linux/kasan.h>
> >>
> >>   #include <asm/sections.h>
> >>
> >> @@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
> >>          if (!debug_locks)
> >>                  return;
> >>
> >> +       /*
> >> +        * As KASAN instrumentation is disabled and lock_acquire() is usually
> >> +        * the first lockdep call when a task tries to acquire a lock, add
> >> +        * kasan_check_byte() here to check for use-after-free of non kernel
> >> +        * core lockdep_map data to avoid referencing garbage data.
> >> +        */
> >> +       if (unlikely(IS_ENABLED(CONFIG_KASAN) &&
> > This is not needed - kasan_check_byte() will always return true if
> > KASAN is disabled or not compiled in.
> I added this check because of the is_kernel_core_data() call.
> >
> >> +                    !is_kernel_core_data((unsigned long)lock) &&
> > Why use !is_kernel_core_data()? Is it to improve performance?
>
> Not exactly. In my testing, just using kasan_check_byte() doesn't quite
> work out. It seems to return false positive in some cases causing
> lockdep splat. I didn't look into exactly why this happens and I added
> the is_kernel_core_data() call to work around that.

Globals should have their shadow memory unpoisoned by default, so
that's definitely odd.

Out of curiosity, do you have such a false positive splat? Wondering
which data it's accessing. Maybe that'll tell us more about what's
wrong.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNLn9%3DUA%2Bcai%3DrL%2B6zsEQyppf6-4_YL4GAFi%2BdLt%2B4oSA%40mail.gmail.com.
