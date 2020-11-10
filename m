Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCGTVL6QKGQE6HYEGZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D88C2AD94F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 15:54:01 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id e82sf6266875oia.15
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 06:54:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605020040; cv=pass;
        d=google.com; s=arc-20160816;
        b=PVsni2e7Ma5tY7xWBHQeL1XlJclzLyk8cH16LqgyJqM5j3017ZYL9gMG7RCx6EXIW1
         Fjjv07O+nRxrjAsrARPlvi3NgQG3fKpEPLQjQ9UJWQ2mELXaukIyhCQqA3zG1cYw8xY/
         k6+kOQDj4TFgIy5z0nnR+sAIQiriMtUb+RdSR8mldqM4cK7Fu1gE7sbJrVzXgKK3pnqI
         NqTRTnDsqAvPL3TBdR+S7Jn//WfiRJAkMCvNyMBJKcW0lsFiCi8WpGHmk4zu+KDxRoWt
         3/eY6MI7je8hALmEIMBYCtjNBMlAkk/GAxOGCzp4S+iLadm/8DtUJRkCbMjFLxp98TJd
         w7Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=w8YxzL59keCMT4cK+QprHlUIAYpRgO7JWuxuaml5UZM=;
        b=nJaoEQALzjxm3m9/5CdabfDaOg5NhHxvDlq0hpYMz0JqijXAwiPYi3cX4RcbY4tFet
         funua7YwzXjgy48JuCYSg1ir0MOVOWQVi1u420zCabA9mOVmSRBBjNSoGScDr9YgyrHi
         FbtIBuBMWPrzuhAmR4T2Ms1MqJHuniT9NaQUrJmwf4/URrlh9cnbF4S5DLkwqcyqskBE
         QzQIxTKcg0LGWAmzf3soZhbmyeRyZYsXeQQg0bYcAwjIxZF41u4WugvcSPgCSYKmHR+n
         DkLXjX6/CxnDhmObCj/evdhbpkVQKozmhTibVs+tGMVYEkWz2KvLM0EF08dw+svRNNoj
         DAuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mNP/K9iv";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w8YxzL59keCMT4cK+QprHlUIAYpRgO7JWuxuaml5UZM=;
        b=iNqDVRyZdfeTUbp6Lx2B6lcmjTGgD86d3BVRZFIysNhNJzuJZIacBEjCP/3PsRiUTZ
         wEc9Z4priTqkBTBxwu2+r3x9sQuQ96MMeS1iH51UtD00g2XgioemQT8dqk7793PyGwr7
         lNn1xYEHd5Xu9YuaHHQtLDS1UY4fgEHZz3t6eIpJQSslZOEZqVlCMqWQKbqa5R6QGRki
         exCoiaqWXy4oOyPL5DQlc51g483rpvfl/c/NRrsSPmLHYfnUvGB4DpdR8zEIYsK7FxE1
         Mz3oy+dGjbgXji5b9FOCdh0UZ3mHja1qJwjwZM61NvepTcE8gd6Boq8MOVLGLKTVhc/p
         OoOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w8YxzL59keCMT4cK+QprHlUIAYpRgO7JWuxuaml5UZM=;
        b=VFcGvG9l7TcIw3jaSNXlUj2MI+z+4IfAv/0nrANdE9opuPfGkzmGdYPbewbKYQq2TJ
         zapviZR62Dz4iuC0RtrKeR4Di+93kZPO1a9USFO+3wA8Tq+U4i1wq8M87dtiiQ7QRMdf
         STq9zWXYCtlOyEpP7tD0mIMgzS7OvNGtYAlqexXVc8XKKl7cUm83O8Mur3BNyu3gD0uJ
         NH01cFIuaDi2B1xNCxhshltxY+n0KnFyytj64EOdPi7jk3Y6sDBmG5bc1wDhMOnzGoWp
         2o1U9bV4sjbVcm5yWJ0PYBI9NCNKlgx64+Kb9ltahs5iWIYdminzdUyxzEpuV+NrIyqI
         pg1w==
X-Gm-Message-State: AOAM530YKCRF0NcfPPQNAN/7LfeQQHPvEpaF6ZIFv4vq5433XF6v7cmD
	MGgVkt87Wvlc94h6WCPn+t8=
X-Google-Smtp-Source: ABdhPJymrFWsESOMsXdeOlhU0S9eRH1riVWlQ1vE7ORHbwhCVQHLANqGg8eA7XksNE60G4lK8AkBbQ==
X-Received: by 2002:aca:db05:: with SMTP id s5mr3082660oig.133.1605020040134;
        Tue, 10 Nov 2020 06:54:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6b0f:: with SMTP id g15ls3109140otp.0.gmail; Tue, 10 Nov
 2020 06:53:59 -0800 (PST)
X-Received: by 2002:a05:6830:164a:: with SMTP id h10mr14740849otr.325.1605020039747;
        Tue, 10 Nov 2020 06:53:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605020039; cv=none;
        d=google.com; s=arc-20160816;
        b=TEDynW5vl7P3Cl7ikgn05ctAV/OE/gu2clPbtbNFwCvnoqAODSccb8iliPtQNNjXns
         YNs3kyNqwWkEcjmUysfmsaFAF963VSSIhvhFFom1xgZoQ8fzCVe24uYmnZGAxTGhAWTU
         T67mO8NfmpP+WuTGiYeXPdTZD5pvb4+oi4jwWyDI8YZqrJW9Nur0jH5tws6mgvfE/C0v
         JkYEiLu99ktbx9r6ixKmcL6zKjkwB9Q5dz48BZzJOPaB68FX8TsXUQj0rL3ewWAMBcHJ
         AOUQYl+6tm682VFKQ/g+ACO85h7cA3pn6zJPxKxJ/lDIipqk2tXWI5mMU0IqH4k024ov
         EXgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FbcyUD14O34qORQweJ7OM0zfYmKvTkKcQqefmr2UkfI=;
        b=nmjmZRDaC6yEBDe/Is5tlpQZIZTdDRAcUIzSmcV+imBHu0e4ksqOXwXp35TVYo7gDp
         V9EHgRnG9+Tbvl9qmMif7bJkOUSODfa7pngv56AgHm6tiuYwKZTz/VVfvLVP/ttBPHiW
         iOYwkeInu0CI4h9jnzhDX4UeKslWsxAmXkUO1CFUo77ageSZALnnod3JKhgzyuBWDSLF
         73grT73jy4/pXAkf4owTMsEJPckLZUSxoKMNgnsallhiU5p+LHYQcLUfQVa9eMEgdYGK
         9xM+ox3ehdLCnkW498Cxb3wX5TwBntKMFq7moi0qionzgX0BZ/KoZ9YZWqeNnuA0I1/R
         GLeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mNP/K9iv";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id e22si1229178oti.2.2020.11.10.06.53.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 06:53:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id n11so12756016ota.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 06:53:59 -0800 (PST)
X-Received: by 2002:a9d:f44:: with SMTP id 62mr15154590ott.17.1605020039230;
 Tue, 10 Nov 2020 06:53:59 -0800 (PST)
MIME-Version: 1.0
References: <20201110135320.3309507-1-elver@google.com> <CACT4Y+Y_QarAf_cCNPgRZiSEKty0eSusA1ZMuY61LoGP1RaVtg@mail.gmail.com>
In-Reply-To: <CACT4Y+Y_QarAf_cCNPgRZiSEKty0eSusA1ZMuY61LoGP1RaVtg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Nov 2020 15:53:47 +0100
Message-ID: <CANpmjNNTDznf3hWFw5tD1+vGoN-p1VrR8BrQvSZqtVtUmFPF3A@mail.gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without allocations
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="mNP/K9iv";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Tue, 10 Nov 2020 at 15:25, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Tue, Nov 10, 2020 at 2:53 PM Marco Elver <elver@google.com> wrote:
> > To toggle the allocation gates, we set up a delayed work that calls
> > toggle_allocation_gate(). Here we use wait_event() to await an
> > allocation and subsequently disable the static branch again. However, if
> > the kernel has stopped doing allocations entirely, we'd wait
> > indefinitely, and stall the worker task. This may also result in the
> > appropriate warnings if CONFIG_DETECT_HUNG_TASK=y.
> >
> > Therefore, introduce a 1 second timeout and use wait_event_timeout(). If
> > the timeout is reached, the static branch is disabled and a new delayed
> > work is scheduled to try setting up an allocation at a later time.
> >
> > Note that, this scenario is very unlikely during normal workloads once
> > the kernel has booted and user space tasks are running. It can, however,
> > happen during early boot after KFENCE has been enabled, when e.g.
> > running tests that do not result in any allocations.
> >
> > Link: https://lkml.kernel.org/r/CADYN=9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Qi5NAJiw@mail.gmail.com
> > Reported-by: Anders Roxell <anders.roxell@linaro.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  mm/kfence/core.c | 6 +++++-
> >  1 file changed, 5 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 9358f42a9a9e..933b197b8634 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -592,7 +592,11 @@ static void toggle_allocation_gate(struct work_struct *work)
> >         /* Enable static key, and await allocation to happen. */
> >         atomic_set(&allocation_gate, 0);
> >         static_branch_enable(&kfence_allocation_key);
> > -       wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);
> > +       /*
> > +        * Await an allocation. Timeout after 1 second, in case the kernel stops
> > +        * doing allocations, to avoid stalling this worker task for too long.
> > +        */
> > +       wait_event_timeout(allocation_wait, atomic_read(&allocation_gate) != 0, HZ);
>
> I wonder what happens if we get an allocation right when the timeout fires.
> Consider, another task already went to the slow path and is about to
> wake this task. This task wakes on timeout and subsequently enables
> static branch again. Now we can have 2 tasks on the slow path that
> both will wake this task. How will it be handled? Can it lead to some
> warnings or something?

wake_up() does not require tasks to be in the wait queue, nor is there
any requirement that it's exclusive (it takes the appropriate locks
unlike wake_up_locked()). One of the wake_up() calls will wake the
task, and the other is a noop. So this will work just fine.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNTDznf3hWFw5tD1%2BvGoN-p1VrR8BrQvSZqtVtUmFPF3A%40mail.gmail.com.
