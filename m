Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP6D4CLAMGQEM4XIB6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 13EDC57BA97
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:39:45 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id g7-20020a1f2007000000b00374ae0688e1sf1647925vkg.6
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:39:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331583; cv=pass;
        d=google.com; s=arc-20160816;
        b=Af/G1AuT10IQyY/UXFUYovRuzDKf27YOmqn/Evn+ZsbFoL8Zbz4/TgMPFrWn/kd3il
         bvh4MwzdC0mfyNtVqD5Rhb5sCc/WkBinuDzGghCC2LQnASYK9pvcMOLINtei7lpt0+9J
         9BTncPUaEAVIutNBHVCnPRPcYwGwWyPWXlQp7hN+qNN5zhqap8EGvlesHk/sruL2WZ71
         suWAOeR4h6QTclaZnfY6SPlGEARl0yeWP+dETHHbHXn5cKP6jdyz3qpAXlKarJOC13ez
         hDnkmBYz/0afiyvZVFqdMtjr9TQmMqnD6cAAHjP1YmnOPAk9Hr4jnH5znUEVHIJvTRYA
         P0jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4Bxj26aOF6neGhLnHdGDh9DJX9eWRFBUf9NbIKzFPtI=;
        b=JUVqlhlu6TQz167UlaX6CXnMOwnzqLfVpa1zfZrB3hQ9m6LxSZP6AgNYpQqN140oLu
         zmuz8OB9xr3rmfDiPrut1vk0Ozn+kTzjVUSlvN6A9Zy4nEac1WlzQmNQEDzx0As49I28
         Krq5SGmvXuXSB/AAbET3tfxy4SnoojP51Mn3YA7ysDZt8g5T7FcJ5aCyEecvdoCdv239
         ulaSPVgpqD7zbZDX0QlWGiFNTQx8wgFk7x58O8wSoRsQ6ux+vM+CDFUqJBjYDMWit9No
         dnZQbp7J0Rr4pdIoc0W8Ej6z1bEdvKBFFVhGrojaDiKbQunk7Pqh2cOS/uEaBwjpH6J+
         0IWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KDo9ERkE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Bxj26aOF6neGhLnHdGDh9DJX9eWRFBUf9NbIKzFPtI=;
        b=KfD5K1Kc2oHtC64scFv93YGlvbOaGPYM2GUOGptNGgMtE8uZbC9fflcd/QuDQHxyZp
         Tf4cv2aVgx7ycPAlko8Lepw3ejOuIxebynL0qLFMMeNLQjuJNF/48GNVcNQVrtg6Pmxd
         0hRJBeS/2MotcA/lxh0AwkNMPMP3Z9lJnF5yLjlTatKV5uvFT034s0L6K0XB9yHeJ5q+
         foNiSuhByfoFpfcO0yTg13FmjCIjoykjQjePqUXkJhlhCoA94W9nPWVZPm513qEAfPy2
         Aj4fMqYBCzr2dfAo/af0PLjb9uvnNFsUz83dCknNfeaAtc46YRAfFd4a2YqchjpC2a5q
         WsIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Bxj26aOF6neGhLnHdGDh9DJX9eWRFBUf9NbIKzFPtI=;
        b=VlEIPDLlMeRaUn//8mneeG/wwnbqCLUmdeQ0IZ+nfXw/vEUERgv3N8kaj8LlV82zVF
         SBKmHAV/OZJVQj0pNXPVIYceLQhrRrE1WzHQlbBcwVrJk4NTY670jZrTZ6DQNeFilufK
         pf2EClrvPz6C33P6JXl0vZBO4jTbo3AGyZ4Z34p7rD6OqM9lsxCnLHxrm1VR0pDGw95B
         LvPKODEoGP+TpbM+ERsgAupR2SxXuI4yXKAc2j+VFLvPRM06lVhDfp0UYvlEWOyyWSgf
         tGOAR7WyKbePlBYG0GopXY+ikRdN5eBqv/Q4E0azMP93AHdJZNBcnrrzeQ/iQ12o/ynL
         7a2g==
X-Gm-Message-State: AJIora/O2TsQRs3otY24/SDmkAIqDTDvWhUzHPBpfRGi6Ytu5wQwS7yj
	xxuBMTRu1CTeukwuhzwL2uw=
X-Google-Smtp-Source: AGRyM1sfgVXejKTfs1+pzxXjU5pXwC7XLkvXMUtLTcgFD4lHGefUhWKRgyGLQZ0ySoKJIDC7sQz5Dg==
X-Received: by 2002:ab0:4ad3:0:b0:384:243b:c95 with SMTP id t19-20020ab04ad3000000b00384243b0c95mr3558186uae.51.1658331583750;
        Wed, 20 Jul 2022 08:39:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2225:b0:357:655:94fd with SMTP id
 d5-20020a056102222500b00357065594fdls125519vsb.9.-pod-prod-gmail; Wed, 20 Jul
 2022 08:39:43 -0700 (PDT)
X-Received: by 2002:a67:e24f:0:b0:357:61e5:4ac with SMTP id w15-20020a67e24f000000b0035761e504acmr13927802vse.3.1658331583077;
        Wed, 20 Jul 2022 08:39:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331583; cv=none;
        d=google.com; s=arc-20160816;
        b=u4WnxpXjPn2WO+0/QQ5wx4iT9mOB27Gqcof9ux8C+vKEHExRJpVPdf5Osn1/cgstEf
         UeyrmQHGhJ/PpS+6ogCtnhkj0E8ai4uKqxNbZYkrA6VejwoX3FjuXMojkuO+olIplNFN
         pOI8QP4eoU0172Z+ZvHH+lKjF1KQDnKdcCbAbZMZrTknTQM0GLULbvS7HKClcEE1Y+kE
         XBHAGJNoe3iNjWqKaODtpf+e6JAcinBAwGaQSUdZ+IhKWMsF5qFsAiWgRkl9VZlpLUCm
         KAnSmDudQ7lDTJ4PmlSLI8LmJnCotE8rkccL3r1c9iakuSR5NPUSxve619Yj3H9STqsk
         vaCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JRcq3vKjIzJm9TVcaSce4sIDa9ZUrBaFgnnM4S7LNls=;
        b=0kki8pMPKjWsP7qJjrd2c0O1RMk25EsuHucLLhQtAyvI5jD36pvGHPB1IYwYBnhus9
         PG/GpXFomwIZ3+uDhT29BdPRwcq4v6BbFHTw2LesskYvIBBcVRic7Vgk8TWH0wTTVtnB
         tFkX/7oAsuRWzxec6cPzrlGVze2zh/W8kJ2BmgYan44eLYJWOjODwfjakO9Q5cP+Hr6J
         jcIOiId7VDVrzadcbaGjQxIgf5m3WqIks3zeZtxLnt1iYDtDhrwBY4gTkh50ywlG/ijW
         gsIFUY8GmsajzjqI37AXSYdlhgAx2PLDwuPadTma1QiA8++OKhFdE+69MR6aqR/IMTb0
         P1Hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KDo9ERkE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id g15-20020a1f200f000000b0036c18b4c646si833495vkg.2.2022.07.20.08.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-31e560aa854so66011117b3.6
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:39:43 -0700 (PDT)
X-Received: by 2002:a81:5794:0:b0:31d:e7b3:b8a3 with SMTP id
 l142-20020a815794000000b0031de7b3b8a3mr32091574ywb.333.1658331582641; Wed, 20
 Jul 2022 08:39:42 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-5-elver@google.com>
 <CAP-5=fXgi_RUOzSvPZvxNh6A14OY0S_oCHgAD0==nSLXzWqFFQ@mail.gmail.com>
In-Reply-To: <CAP-5=fXgi_RUOzSvPZvxNh6A14OY0S_oCHgAD0==nSLXzWqFFQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 17:39:06 +0200
Message-ID: <CANpmjNOcuacOv7DT4udZwMMuu+7QgaZO7wJ5MReVtC_Vg=ptTQ@mail.gmail.com>
Subject: Re: [PATCH v3 04/14] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Ian Rogers <irogers@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KDo9ERkE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as
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

On Wed, 20 Jul 2022 at 17:29, Ian Rogers <irogers@google.com> wrote:
>
> On Mon, Jul 4, 2022 at 8:06 AM Marco Elver <elver@google.com> wrote:
> >
> > On a machine with 256 CPUs, running the recently added perf breakpoint
> > benchmark results in:
> >
> >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> >  | # Running 'breakpoint/thread' benchmark:
> >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> >  |      Total time: 236.418 [sec]
> >  |
> >  |   123134.794271 usecs/op
> >  |  7880626.833333 usecs/op/cpu
> >
> > The benchmark tests inherited breakpoint perf events across many
> > threads.
> >
> > Looking at a perf profile, we can see that the majority of the time is
> > spent in various hw_breakpoint.c functions, which execute within the
> > 'nr_bp_mutex' critical sections which then results in contention on that
> > mutex as well:
> >
> >     37.27%  [kernel]       [k] osq_lock
> >     34.92%  [kernel]       [k] mutex_spin_on_owner
> >     12.15%  [kernel]       [k] toggle_bp_slot
> >     11.90%  [kernel]       [k] __reserve_bp_slot
> >
> > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > O(#tasks) due to storing all task breakpoints in the same list and
> > iterating through that list looking for a matching task. Clearly, this
> > does not scale to thousands of tasks.
> >
> > Instead, make use of the "rhashtable" variant "rhltable" which stores
> > multiple items with the same key in a list. This results in average
> > runtime complexity of O(1) for task_bp_pinned().
> >
> > With the optimization, the benchmark shows:
> >
> >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> >  | # Running 'breakpoint/thread' benchmark:
> >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> >  |      Total time: 0.208 [sec]
> >  |
> >  |      108.422396 usecs/op
> >  |     6939.033333 usecs/op/cpu
> >
> > On this particular setup that's a speedup of ~1135x.
> >
> > While one option would be to make task_struct a breakpoint list node,
> > this would only further bloat task_struct for infrequently used data.
> > Furthermore, after all optimizations in this series, there's no evidence
> > it would result in better performance: later optimizations make the time
> > spent looking up entries in the hash table negligible (we'll reach the
> > theoretical ideal performance i.e. no constraints).
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > ---
> > v2:
> > * Commit message tweaks.
> > ---
> >  include/linux/perf_event.h    |  3 +-
> >  kernel/events/hw_breakpoint.c | 56 ++++++++++++++++++++++-------------
> >  2 files changed, 37 insertions(+), 22 deletions(-)
> >
> > diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> > index 01231f1d976c..e27360436dc6 100644
> > --- a/include/linux/perf_event.h
> > +++ b/include/linux/perf_event.h
> > @@ -36,6 +36,7 @@ struct perf_guest_info_callbacks {
> >  };
> >
> >  #ifdef CONFIG_HAVE_HW_BREAKPOINT
> > +#include <linux/rhashtable-types.h>
> >  #include <asm/hw_breakpoint.h>
> >  #endif
> >
> > @@ -178,7 +179,7 @@ struct hw_perf_event {
> >                          * creation and event initalization.
> >                          */
> >                         struct arch_hw_breakpoint       info;
> > -                       struct list_head                bp_list;
> > +                       struct rhlist_head              bp_list;
>
> nit: perhaps it would be more intention revealing here to rename this
> to bp_hashtable?

The naming convention for uses of rhlist_head appears to be either
'list' or 'node' (also inside lib/rhashtable.c). I think this makes
sense because internally this struct is used to just append to the
bucket's list.

> Acked-by: Ian Rogers <irogers@google.com>

Thanks!
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOcuacOv7DT4udZwMMuu%2B7QgaZO7wJ5MReVtC_Vg%3DptTQ%40mail.gmail.com.
