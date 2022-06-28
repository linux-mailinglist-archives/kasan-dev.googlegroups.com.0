Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSGL5SKQMGQE3MHAU5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FEDC55E5DA
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 18:01:14 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-2eb7d137101sf107317307b3.12
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 09:01:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656432073; cv=pass;
        d=google.com; s=arc-20160816;
        b=kfg+KO96JxIHzKGXdD2YX81puDhnK5Knwgd2yCHXVtKolnOEEc/P/XeJNes1rB8vkD
         NGMT9NhqhfehI5HOrXGo6yQt8pTmlvYfISDz973ciV8uhVcAwU3YEZNeQ9mAwzbMDtlo
         zVeEZeq/Xgqtk6D7mWL1OW7A37S5pbjPVf9iC8NC+eTNk8zd+m8B9HoSgyaB7EAhdzvt
         Bwz7o3JjZAahYfh4TajiCbnOszFacRBndAQiH9VwcASK/m9INAL4pWJEb0qBiy/niUaU
         n4aSwjuDgYi+JHCeqhgHwANRXIqfkXE2y7lhD3+PbUh5AZRBj/te88xJ73jAUme/oYUw
         YsLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oEOAkVi1fJYGKVS+HKZe2toj+n6HvKco82edjrL8Z9A=;
        b=DSDNVyQ41T5sBrad0GMoSfpfAGDDrLuY/R7NWlY/CENVqvbuXz0mPAjZgSzIrZNPl6
         4H6x+w/9KIV/347sYRg+Hnjq0awwgEH+2sRlDcCZeciTTyyLsdpAJaFCj8yysY0AieOA
         y/hLds7ZOExARCORGzP0ddpuAUqcmysksgo4AKR5FshsGb+8LBiTsx9gJq368eX82LA7
         HxZW8Sx3Bl6tkfc72Jq3GhTe8O2WzH5Wv4KZNDes38i31OFdomhlQkiyV6TazrnBd/Qp
         Bjf98rdVYHsma3N8E/Sl/FI3aJZmIomVBihNGU1zxM7xZl56E9nWn5uE+/X2xc/8pQMt
         G4Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dD7Wqxrx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEOAkVi1fJYGKVS+HKZe2toj+n6HvKco82edjrL8Z9A=;
        b=c/aR8nQR4rfy4XJMQxlod1FRk4WV7jlxMHDjGHw11WXNQOFrdL/uKVG4Tysn+OSu9i
         yAF+y5vB4ql4iCYcb1JgnlnlWDW7L/xgodpZCUHE0fwtK1pm5DDTBV0jru9qpgiF9+45
         uatLcb/VYjV34QDLQYDieHjOjgfWFZT9zY2METGEyiHCO0xyKLB2zjcCpjFSdhPr1RVI
         kkl7HNO+paBrETZkyDl48upsZlLDnTQHJY2I3l4cqtyDvZkGzPtg+quBF7UnCxs0wrpF
         m3nuGGcYV5M5VbjhPUIqpLvWl3RisKAgDZxKDb8nrIXlgNrHxR5ewwr6AOtnap6fSPEC
         nMZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEOAkVi1fJYGKVS+HKZe2toj+n6HvKco82edjrL8Z9A=;
        b=m1VP4eNNN3nKUI1pGmC8E9AjTgiqG0jfk8793/b8PshfpP6/iV8Ty/VVlMfN1ciX7m
         pTsDEdGMnA/v4SUwW8/2hgNhECFyDCATMWw9fMvW068TkUaedJKOvt1S6DBXKAIO3Pdz
         YPzNDUPiqzh7nnYtctUyKqNt/SSuVsZn8FE02J/lbaYn8wHQzPQTDeAvjxf1U9BUyu/s
         seM2rmJHUj2/4KH3H4kgoC8sVApQ270vWQiI+Ypwh82g7GF82qR83QcQ5c/CDcRoqWIO
         Va8EP0ovJ+QXjAIhh4t/rreL2c5HFun2Ar9jhWzO8yRsJPOI+ly/THUF9DZDfJZWu40S
         JdBw==
X-Gm-Message-State: AJIora9B8Guqmamfhx22+SjH3VxNy4G0tDX6Zj2fhZlBLgalt+rQO3ig
	U/ShjKYTqeP+RDt8AYCS9WU=
X-Google-Smtp-Source: AGRyM1tB9dVm52lJcIDt+FsMItqo+iHk9G3mBwDWudwTW63tySlgJNVF8LTX+DI9PXGh8oBBV13H/A==
X-Received: by 2002:a5b:98c:0:b0:64a:d5c3:4422 with SMTP id c12-20020a5b098c000000b0064ad5c34422mr20482236ybq.638.1656432072947;
        Tue, 28 Jun 2022 09:01:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:40c7:0:b0:66d:4bcf:a1f9 with SMTP id n190-20020a2540c7000000b0066d4bcfa1f9ls400633yba.3.gmail;
 Tue, 28 Jun 2022 09:01:12 -0700 (PDT)
X-Received: by 2002:a25:9ac8:0:b0:64d:fee6:1c8 with SMTP id t8-20020a259ac8000000b0064dfee601c8mr20966957ybo.344.1656432072310;
        Tue, 28 Jun 2022 09:01:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656432072; cv=none;
        d=google.com; s=arc-20160816;
        b=m4IcuF62RPZrssHvGPaGtNG7qK+ByFbw+w6oLvqboG3jRK7yqqOsbrhXfwivB/4PlQ
         R3Tvgf0P6PxGJ2NhG36oMIj1rsZpQ/lkgtdB2MnsiZznZj5Y40N/nXbtnuM6qHOqL92E
         +oqLp1aCoo/7A6V4tQ9mFMUaRfDYd1MJwfWYFex//qTo/Gtmk3f/3IKxWg3fJPNAGDnZ
         AY9bh6VJkPgiKZwhL25jDVFNZ1kpwU1O5a6jB/MfHEhWmOo5I0YCXHdkflRuZtwq1lAA
         lTGxmH+e93tyHvcvI0sVYUwjn//gk4nJlGLyAadM13rbfhFxFJbkNnBAQG0+VxfE15MF
         6n+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JSgkWuUAADlOM6Jw2JGSpNYb73+UZZR8Ny928REi7Do=;
        b=q8ywRcZYm8zLodBMx2+OE9BmB/UHVTKml2hNtQXxX5aB0x7cB0vFFE4AfxBl+FGnzB
         1OrSMOItUm7NdzxAyGE09ptdbaeOXZiHTRS+pp+zBvzv4QwA2isipa8SDiP4fUZRD1Ov
         TP1GVNwW5SdLaDR7Jn3fa2aRGWznDpF22ZgguHtqflsFWDODBhtc8EMtbpMFknPfFl95
         NxNvLjhMFZyMG0v3lYtxHmENgZWKEF0anRHmKu6i1SO1OVQs2yUbaaFr3ClUMJ8Ssfp4
         Dr3V1wJ1UYyNnauiXovlBKS6IEx0k+cAw23hsE8SxA8QoShOzafJgymiNBh01NpSqrCt
         iarA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dD7Wqxrx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id n68-20020a254047000000b0066472d2d476si436108yba.4.2022.06.28.09.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 09:01:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id q132so22940499ybg.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 09:01:12 -0700 (PDT)
X-Received: by 2002:a25:cc56:0:b0:66c:d0f6:2f0e with SMTP id
 l83-20020a25cc56000000b0066cd0f62f0emr12156904ybf.168.1656432071758; Tue, 28
 Jun 2022 09:01:11 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-14-elver@google.com>
 <CACT4Y+aJZzkYHc+YJRApOLG-NYe8zXMaqxpQgQQFAy5WY97Ttg@mail.gmail.com>
In-Reply-To: <CACT4Y+aJZzkYHc+YJRApOLG-NYe8zXMaqxpQgQQFAy5WY97Ttg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 18:00:34 +0200
Message-ID: <CANpmjNOh9gzzC7sOOOk1q7Ssj2dFxczj1bmufarYS2KupZQthg@mail.gmail.com>
Subject: Re: [PATCH v2 13/13] perf/hw_breakpoint: Optimize toggle_bp_slot()
 for CPU-independent task targets
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dD7Wqxrx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Tue, 28 Jun 2022 at 17:45, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
> >
> > We can still see that a majority of the time is spent hashing task pointers:
> >
> >     ...
> >     16.98%  [kernel]       [k] rhashtable_jhash2
> >     ...
> >
> > Doing the bookkeeping in toggle_bp_slots() is currently O(#cpus),
> > calling task_bp_pinned() for each CPU, even if task_bp_pinned() is
> > CPU-independent. The reason for this is to update the per-CPU
> > 'tsk_pinned' histogram.
> >
> > To optimize the CPU-independent case to O(1), keep a separate
> > CPU-independent 'tsk_pinned_all' histogram.
> >
> > The major source of complexity are transitions between "all
> > CPU-independent task breakpoints" and "mixed CPU-independent and
> > CPU-dependent task breakpoints". The code comments list all cases that
> > require handling.
> >
> > After this optimization:
> >
> >  | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
> >  |      Total time: 1.758 [sec]
> >  |
> >  |       34.336621 usecs/op
> >  |     4395.087500 usecs/op/cpu
> >
> >     38.08%  [kernel]       [k] queued_spin_lock_slowpath
> >     10.81%  [kernel]       [k] smp_cfm_core_cond
> >      3.01%  [kernel]       [k] update_sg_lb_stats
> >      2.58%  [kernel]       [k] osq_lock
> >      2.57%  [kernel]       [k] llist_reverse_order
> >      1.45%  [kernel]       [k] find_next_bit
> >      1.21%  [kernel]       [k] flush_tlb_func_common
> >      1.01%  [kernel]       [k] arch_install_hw_breakpoint
> >
> > Showing that the time spent hashing keys has become insignificant.
> >
> > With the given benchmark parameters, that's an improvement of 12%
> > compared with the old O(#cpus) version.
> >
> > And finally, using the less aggressive parameters from the preceding
> > changes, we now observe:
> >
> >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> >  |      Total time: 0.067 [sec]
> >  |
> >  |       35.292187 usecs/op
> >  |     2258.700000 usecs/op/cpu
> >
> > Which is an improvement of 12% compared to without the histogram
> > optimizations (baseline is 40 usecs/op). This is now on par with the
> > theoretical ideal (constraints disabled), and only 12% slower than no
> > breakpoints at all.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> I don't see any bugs. But the code is quite complex. Does it make
> sense to add some asserts to the histogram type? E.g. counters don't
> underflow, weight is not negative (e.g. accidentally added -1 returned
> from task_bp_pinned()). Not sure if it will be enough to catch all
> types of bugs, though.
> Could kunit tests check that histograms are all 0's at the end?
>
> I am not just about the current code (which may be correct), but also
> future modifications to this code.

I'll think of some more options.

bp_slots_histogram_max*() already has asserts (WARN about underflow;
some with KCSAN help).

The main thing I did to raise my own confidence in the code is inject
bugs and see if the KUnit test catches it. If it didn't I extended the
tests. I'll do that some more maybe.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOh9gzzC7sOOOk1q7Ssj2dFxczj1bmufarYS2KupZQthg%40mail.gmail.com.
