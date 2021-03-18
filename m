Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRF6ZKBAMGQETEDDGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 689C333FC3C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 01:31:01 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id x11sf12074534ilu.14
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 17:31:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616027460; cv=pass;
        d=google.com; s=arc-20160816;
        b=P3+NDSbDrFdjkt+pocINlNxRRv2CMIgN3BKzdmkej1sbXyS6kCqT4/cGGicFA2r61i
         qSsG5tcDSy6hfdfNSfxWjkKpo4OA/CzHBqEE870LhP0qgLosxzcJOLwaXSdZH9Tw1TYL
         vsoJZlKlmiyjsd3Wflg10Fw+vjBO2z4Uy+3kpVr+nOIWOjtlMmJqjXhtf42wnty0ZyV5
         1B4g5cv1fNog7idmLXIMj/VY17OrdylleOFa6E1Md7N0RjGxJKIrhIv9unMZWzhgbWG7
         7+WumJBMoVDfYJtoMq+Ei6SL2+z+HKD8SOcGG0J8gQM/ptcNgdvFJpwMNhSOCbfxTD0T
         B7ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AKh8cxzHAlnVyZwp5rI2OjiwNaj7zptpJf/njo+JTO0=;
        b=wRP8uVaBljMgpEwtVUjGMvnobLpRqrwFP1vH696pwi9/35oiTqcUtuftxMsOQRYXJo
         7dB8tfPAb7uQAT02N5QFT2hOc89wn1gtFLNGHZUwCKJRMTWBwSh5cHk937xAINndizhA
         w82glX37ocoPvnrLaxCgTtoyV5VzGCDNZEXERXrzjAXg0+pgJ4hl7vMOAQFQ5sMPJljV
         jmutshF01BdyuyB5PxYff8wqH4hhUMeDHqnCyH80rhltaQLpKJlq6Ar5BfzYSBhm9ru5
         UdN345gcwLK1Q+mqXbnqqJdL76T1zuSzJ08kS+/YdGP/yTElvePRFgmYHHISXtYidnuN
         G7Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tw1JOhx9;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AKh8cxzHAlnVyZwp5rI2OjiwNaj7zptpJf/njo+JTO0=;
        b=S72xUh6qaBlnM6tI8xkJP2xDJ8j55bU8E3UTUG4GmCMCOhYcMCr05CAIKFa4caGTJJ
         p0zxT9u7+1KXnXyciGEk773+BEHX+/rVP6m/gaKBCNPKRP1NtImpSM55c9dLb+Mmx9F8
         R+4JFD74HGtQsrRWx5Ugq+H9wgbclow1VcXDIx1bStazOIUnyCxb5GEN9Nr9kWnA7iK4
         +D278vJ/25+l5aHPyRzvc5BCAxsOxnMYkJygCkHFBmG/sutXDa0chVw/cyqrqeFCpCM6
         5OciNW34lXTofNo/OAVOJK2O2IYUOJIkfL9J7CFLobV1hG6i6OURaNIy4eb7O0A0uWyS
         jRZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AKh8cxzHAlnVyZwp5rI2OjiwNaj7zptpJf/njo+JTO0=;
        b=Lg88XR9FuysylttPHARsmm21tuFIADQvDaQSr4D2gj09fyUJ3rjCvSBkTq7LlyRq2R
         vFaVObbEtC4cTzuFNtFm45F+6QGn1mK9dcJNXxiBSbaOBe16ODI3Vfvodk4Ahnoqa4bV
         sDgVYhB7j09e3eqOv7hCB6vDgjFaDHCYwIZRb8zCxDs5FAfE3qnVnhmtKoXnlhdHON9i
         sqjWmw39I56TGOE4K6Bxi49oqCIwdGH3HetxiH9s1PJmUmLKyBgB1biY6JflGcUyesag
         eYH4CqrZ+eg6ReJ1hQLUR/p6it3DgR+NsR8BUxtPd9rNWPY5n0nrV+hd65l6TkgeAwrR
         Kgew==
X-Gm-Message-State: AOAM533KW96q49gZIGlj9P+oOgf9YY67UxrmZEhmQ4vUrsvQYXJVeaHK
	9Nwu1aE1+G68nZvfIoWaA/Y=
X-Google-Smtp-Source: ABdhPJwh6nCJcog0phDHcTjMT3HcRQXJOWwLtuiC48SsPe4bbrocyz94Muqoj7ZuYq3TTYdqo6M2qA==
X-Received: by 2002:a5e:c00a:: with SMTP id u10mr8516454iol.165.1616027460193;
        Wed, 17 Mar 2021 17:31:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c8c8:: with SMTP id c8ls70608ilq.8.gmail; Wed, 17 Mar
 2021 17:30:59 -0700 (PDT)
X-Received: by 2002:a92:b011:: with SMTP id x17mr9373746ilh.113.1616027459740;
        Wed, 17 Mar 2021 17:30:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616027459; cv=none;
        d=google.com; s=arc-20160816;
        b=pN4DuCaDhlmW/H439u9f3ocm68FtJTYz2yM1rEcv5FEpAj8KDQyiug7xVNNgwTv93z
         1WWd6aB8bIIRNM1kkJd+PyHFvmgHgImgxDfhPRyRav0OY3a9PidZPL7WUb8IdKvxaHMG
         V13XmPgCqgRznnhJeEGg1jVFKSCFzWwlmt1r5iD7MlJQ2OlZZGiUJFvmgJ8ds1ga+W4Q
         Viu0wFpweiuykjNuMOeDXCUnF/DOIa3Wt/9DSPu5VQYf4gON582DOI8KtNnx+YPZ3q0T
         tiZwuMB8R3XllUl0/WACmL4C6NcwraXOyUMfsWC5obuXSO/f1Rcj//nD2tZECUUUXjC+
         SjhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GkuRWpW9bExkYFxOTvvebzKRarhbJmzTDiFRajMJb68=;
        b=n0ymMkFce3HIjfWebcRITFep28mpQg+wGF+nVU+rMT5bZLQ9MkAzUnGRhfeFImFzfH
         2jtTskZSfV+8Cn0ypW88qt5XI8nckK8JAdQf1hJlEF+tYLhVckAWNjKuUFN9AAbssexV
         dupc4VyKapOSH6JINZNwCygh8/KvVdBvmCfWgLcR+WVuBQ72x8J58qlpqHpd2tzJ+e56
         R8n5/OpM5cuQl/E1Knzp5BJsySP5Pq4Bxku+if2GZk8TT7BX13BaTiEwzi6S/mBjCktd
         Go0rTKERPn4Hs3Za5yynkOrDqNf9wyBkKGWkWBng2Oy4Y5IDIf+YqR7eN5SjPjHVHip3
         mqwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tw1JOhx9;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id v81si22053iod.4.2021.03.17.17.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Mar 2021 17:30:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id kk2-20020a17090b4a02b02900c777aa746fso2200405pjb.3
        for <kasan-dev@googlegroups.com>; Wed, 17 Mar 2021 17:30:59 -0700 (PDT)
X-Received: by 2002:a17:90a:a10c:: with SMTP id s12mr1413387pjp.166.1616027458725;
 Wed, 17 Mar 2021 17:30:58 -0700 (PDT)
MIME-Version: 1.0
References: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Mar 2021 01:30:47 +0100
Message-ID: <CAAeHK+xiNywqQOzB=FUYOBJdSSNXbO4p2SdOvk4WKfhp_jiKGQ@mail.gmail.com>
Subject: Re: [PATCH v2] task_work: kasan: record task_work_add() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Jens Axboe <axboe@kernel.dk>, 
	Oleg Nesterov <oleg@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Tw1JOhx9;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Mar 16, 2021 at 3:44 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Why record task_work_add() call stack?
> Syzbot reports many use-after-free issues for task_work, see [1].
> After see the free stack and the current auxiliary stack, we think
> they are useless, we don't know where register the work, this work
> may be the free call stack, so that we miss the root cause and
> don't solve the use-after-free.
>
> Add task_work_add() call stack into KASAN auxiliary stack in
> order to improve KASAN report. It is useful for programmers
> to solve use-after-free issues.
>
> [1]: https://groups.google.com/g/syzkaller-bugs/search?q=kasan%20use-after-free%20task_work_run
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> Cc: Jens Axboe <axboe@kernel.dk>
> Cc: Oleg Nesterov <oleg@redhat.com>
> ---
>
> v2: Fix kasan_record_aux_stack() calling sequence issue.
>     Thanks for Dmitry's suggestion
>
> ---
>  kernel/task_work.c | 3 +++
>  mm/kasan/kasan.h   | 2 +-
>  2 files changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/task_work.c b/kernel/task_work.c
> index 9cde961875c0..3d4852891fa8 100644
> --- a/kernel/task_work.c
> +++ b/kernel/task_work.c
> @@ -34,6 +34,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
>  {
>         struct callback_head *head;
>
> +       /* record the work call stack in order to print it in KASAN reports */
> +       kasan_record_aux_stack(work);
> +
>         do {
>                 head = READ_ONCE(task->task_works);
>                 if (unlikely(head == &work_exited))
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3436c6bf7c0c..e4629a971a3c 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -146,7 +146,7 @@ struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>  #ifdef CONFIG_KASAN_GENERIC
>         /*
> -        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +        * The auxiliary stack is stored into struct kasan_alloc_meta.
>          * The free stack is stored into struct kasan_free_meta.
>          */
>         depot_stack_handle_t aux_stack[2];
> --

Acked-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxiNywqQOzB%3DFUYOBJdSSNXbO4p2SdOvk4WKfhp_jiKGQ%40mail.gmail.com.
