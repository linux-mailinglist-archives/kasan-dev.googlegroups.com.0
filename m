Return-Path: <kasan-dev+bncBCMIZB7QWENRB7XBXSBAMGQEGFZK2FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8678D33AF80
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 11:03:43 +0100 (CET)
Received: by mail-vs1-xe3e.google.com with SMTP id 64sf4587927vsy.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 03:03:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615802622; cv=pass;
        d=google.com; s=arc-20160816;
        b=huQzUyO5BE2s6+qwufe397dH/W4i0wHDTeWPnAmV1li2dr28otzskOFnEhxs9apCP/
         a4Y7YCi55E0EAxkK2Cp8rMICdrHYAucMSu/8A4N68+5MlaG/X+7OE5xcTUmWZueiPG0p
         nvIIrbdAoFfS2EeNIyUoIQIUchR3LFS9KOMQkZys3GK5We3MK/9bCisy1rm9EqQ4SbNL
         iuvtR3Am1UaMzshv2BZ1BgtsHV4ufeA2cIDZ4Oxu2WQbTICx/qDIxV64Laf9v9weMrb3
         fcTw19o5GInh9YJ9Gp2JgaiGhKQnt8ovs4ur4B1aviypCHfXKzRuGVR5qJRbTxq4eiET
         h+Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0+Q/e4vQ3vI6vJdyvFHAjt4/msE3EQPUjC/0CvDy/nA=;
        b=x5fHUUrAU38zVA9h1KE2/2GCdUij/9RgpqhznMJtGAurEbWq1ltHw89b04RI8dAawM
         5GbI0SL2wHLmCuKyXyA0/gIg8Yg5TVpMHlfP+RF6EA4yYXzr9xswuFam/w7SAqSJfMru
         K29ED6cEW765bYSqoQWMMKhk3CNl8PIGKe8JfqTYS5C8tlQ05jBH7XHU7spxUytQrG52
         dyYZIsDsgXiQpRawX1ZrDLtsYGpURF1oaiL7gCs8rHZNHexj2V3+F11JF0Irh/whQOHV
         VvtvHuk3j72LFcaOAOgNvvHRbl14AJvD1HXYjClminyNpGu/mDbCWMNuw4EWZlb4QC3f
         yR1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aZC06iXV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0+Q/e4vQ3vI6vJdyvFHAjt4/msE3EQPUjC/0CvDy/nA=;
        b=CcehG5c6iIuPmUcNEYlUWVX0RwY4qAnkn1yhKfPjngcmU/s4NGvEPu74FtzE1QYnEp
         /bp2aajgqy87AcwTP+aYFEHA8vCxbVxOpXoFW410U5lrujMgDQYtgLOqtT/zXRwW99Tv
         IeUKwGjGGijGHwJ5TWXjyL2btXHRWn417UTCNQM9dL1fcCzk8gfqLTBS0N8xanKfTYTZ
         Zin2SEjqsYTSMpG69BdbgnwqyeYWbXtBNC2HeafA1c3TSvuanE6C0fLWo5/DBpkcKHkW
         WD6Cap1p9WE+t8aywN2NoaadzO7nbjACrVt8T+K8TUexc9ddq9JqXr+l9D5bMXfbXraT
         HT2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0+Q/e4vQ3vI6vJdyvFHAjt4/msE3EQPUjC/0CvDy/nA=;
        b=jY9CK0w/FvXv+CAe8p6AWmvpg/l5Mwur3X6jR+scEaIciYNcc4VqQywUkWlRlToO3N
         AgzYLsUXNdxTQ2Skov38JuPXRtgrnZ20TcpUkyjQxzh66M8D29bs1CDqHrD1CRWAUjON
         IVc6unQqQlfeBbN9HLMLToPcTy3kVIEm3N2d25l6qVmmB8k9bmQL71OGen2bv80MT+Yz
         hVgsTKvWxe7jyS7N31s9p34ZiUGdVwbXELMrEWKIk/ML8kxEM+ri1OiK3XbNJ9dN4P2G
         ihzsWoeJ1TNVVlM39AGTTd1rLnZZEn0DYDadO0XTsynPgUohE5o4+tGbW57AIc/bPfJC
         kAIw==
X-Gm-Message-State: AOAM531u+zky26CrOiVYCllGY8+9iXbr16/XEkiYVa+3iL7ooTPsRJO0
	YKHFV8ft4I4O9V7+l+JiRDk=
X-Google-Smtp-Source: ABdhPJyrJaqZvhsQmz4rc21QA4qDm5lDADO8yB1d3Vl00RqQ+oZ7d67XzJKW9cNOq3oTaC6EE/3bDg==
X-Received: by 2002:ab0:40c3:: with SMTP id i61mr4172854uad.143.1615802622532;
        Mon, 15 Mar 2021 03:03:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:525:: with SMTP id m5ls1902351vsa.3.gmail; Mon, 15
 Mar 2021 03:03:42 -0700 (PDT)
X-Received: by 2002:a67:f1c8:: with SMTP id v8mr4420195vsm.44.1615802622045;
        Mon, 15 Mar 2021 03:03:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615802622; cv=none;
        d=google.com; s=arc-20160816;
        b=Y2DSV5hylZJBE0ODS7xx1Ty+48xEj0dgm/vhUEr9DgltqTtBRNHwoTcWW2i2j5TXgL
         I3iiar6DKFnFtZQyBIEPZBfcog2insLNAXZuzc1en9NA76rXJgvF/0Xx9j4wkUOqDzqc
         NPOdfqaZuX+hvKYQ3+uzGRSPXyj5oQUTWvjbSsXsutIRZt+OPy0yPNtlAeFxxlvt9c8s
         0EQdchAZHywN2x60Ttv5AfphkUnToXnVSLSou0cTl8RA5dpu7xx0W8gaLomYYj7AY2X3
         /ebuesV04CsR0p/Z0UZo68p9oPj2B5Hs8ZytYqbGcGKJ0RKGpxRhhnuO9NoN6eWgk4R/
         WcSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mMMrIgwms1m+PweB3p+oJVkXrLd9T+PU+71ztQbJ0Ac=;
        b=yEDSutNAA1eUzxIDqMcZjnKwkZWH/Btdv8Tj6Hak813wo2MPc3kzV+EUTAtfwG1iLs
         jGI2qR7FbvYsokDNymt9fSnVVVkIjTixU0ztrSt2Gl2CZfpWGPaY6WEyNnx1evk9vIqU
         HPHEtHQdGI3SvkXdLXprKfkCaLxr0R+TqZ1ScPsO/BVf7QeTDMRHxsZijB2kU6loszRf
         fXV76hCw32Ozak06h7zoDKafpHqdfl/8VzBq1Ao7DDHKlANCIXqQ1EoYMa1eMXjcShKe
         XbqzzzYEv05GoYnfgTZSyas9IHLtAOX8y1lJO1of6TJFXoPcljuKBxf4WmlO19wMuX1x
         BsiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aZC06iXV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id r5si601154vka.3.2021.03.15.03.03.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Mar 2021 03:03:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id f124so30997738qkj.5
        for <kasan-dev@googlegroups.com>; Mon, 15 Mar 2021 03:03:42 -0700 (PDT)
X-Received: by 2002:a37:a7cb:: with SMTP id q194mr523293qke.350.1615802621496;
 Mon, 15 Mar 2021 03:03:41 -0700 (PDT)
MIME-Version: 1.0
References: <20210315015940.11788-1-walter-zh.wu@mediatek.com>
 <CACT4Y+YrFeRQkw+M8rpOF5169LFn9+puL3Dh1Kk1AOoKV-nyrQ@mail.gmail.com> <1615801102.24887.4.camel@mtksdccf07>
In-Reply-To: <1615801102.24887.4.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Mar 2021 11:03:30 +0100
Message-ID: <CACT4Y+YtenynUES2Kb6jSjfw_wT4NMeyX+uG5KdCe3SHhq1qsw@mail.gmail.com>
Subject: Re: [PATCH] task_work: kasan: record task_work_add() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Jens Axboe <axboe@kernel.dk>, 
	Oleg Nesterov <oleg@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aZC06iXV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72e
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

On Mon, Mar 15, 2021 at 10:38 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2021-03-15 at 07:58 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> > On Mon, Mar 15, 2021 at 3:00 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > Why record task_work_add() call stack?
> > > Syzbot reports many use-after-free issues for task_work, see [1].
> > > After see the free stack and the current auxiliary stack, we think
> > > they are useless, we don't know where register the work, this work
> > > may be the free call stack, so that we miss the root cause and
> > > don't solve the use-after-free.
> > >
> > > Add task_work_add() call stack into KASAN auxiliary stack in
> > > order to improve KASAN report. It is useful for programmers
> > > to solve use-after-free issues.
> > >
> > > [1]: https://groups.google.com/g/syzkaller-bugs/search?q=kasan%20use-after-free%20task_work_run
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Andrey Konovalov <andreyknvl@google.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > > Cc: Jens Axboe <axboe@kernel.dk>
> > > Cc: Oleg Nesterov <oleg@redhat.com>
> > > ---
> > >  kernel/task_work.c | 3 +++
> > >  mm/kasan/kasan.h   | 2 +-
> > >  2 files changed, 4 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/kernel/task_work.c b/kernel/task_work.c
> > > index 9cde961875c0..f255294377da 100644
> > > --- a/kernel/task_work.c
> > > +++ b/kernel/task_work.c
> > > @@ -55,6 +55,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
> > >                 break;
> > >         }
> > >
> > > +       /* record the work call stack in order to print it in KASAN reports */
> > > +       kasan_record_aux_stack(work);
> >
> > I think this call should be done _before_ we actually queue the work,
> > because this function may operate on non-current task.
> > Consider, we queue the work, the other task already executes it and
> > triggers use-after-free, now only now we record the stack.
>
> agree, what do you think below change?
>
> --- a/kernel/task_work.c
> +++ b/kernel/task_work.c
> @@ -34,6 +34,9 @@ int task_work_add(struct task_struct *task, struct
> callback_head *work,
>  {
>     struct callback_head *head;
>
> +   /* record the work call stack in order to print it in KASAN reports
> */
> +   kasan_record_aux_stack(work);
> +

This looks good to me.


>     do {
>         head = READ_ONCE(task->task_works);
>         if (unlikely(head == &work_exited))
> @@ -55,9 +58,6 @@ int task_work_add(struct task_struct *task, struct
> callback_head *work,
>         break;
>     }
>
> -   /* record the work call stack in order to print it in KASAN reports
> */
> -   kasan_record_aux_stack(work);
> -
>     return 0;
>  }
>
> > Moreover, I think we can trigger use-after-free here ourselves while
> > recording the aux stack. We queued the work, and the work can cause
> > own free, so it's not necessary live by now.
>
> Sorry, I don't fully know your meaning, do you mean we should add an
> abort when detect use-after-free?

I meant that where we had the kasan_record_aux_stack(work) call in the
first version of the patch, work can be already freed. We must not
access work after queueing it.

> > >         return 0;
> > >  }
> > >
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index 3436c6bf7c0c..d300fe9415bd 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -146,7 +146,7 @@ struct kasan_alloc_meta {
> > >         struct kasan_track alloc_track;
> > >  #ifdef CONFIG_KASAN_GENERIC
> > >         /*
> > > -        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > > +        * Auxiliary stack is stored into struct kasan_alloc_meta.
> > >          * The free stack is stored into struct kasan_free_meta.
> > >          */
> > >         depot_stack_handle_t aux_stack[2];
> > > --
> > > 2.18.0
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1615801102.24887.4.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYtenynUES2Kb6jSjfw_wT4NMeyX%2BuG5KdCe3SHhq1qsw%40mail.gmail.com.
