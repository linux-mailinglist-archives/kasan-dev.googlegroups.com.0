Return-Path: <kasan-dev+bncBDGPTM5BQUDRBPXGXSBAMGQEWHPHKQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C769A33AFA2
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 11:13:19 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id u17sf22682671qvq.23
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 03:13:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615803199; cv=pass;
        d=google.com; s=arc-20160816;
        b=PmIsFqDCpXQLwNAJo/onzUOfkXYLxt3Qih+qVOW/Cc8iAY7mqdlpI34K+JlqkVsjC+
         gbzfsT7A1pkP7PzdODc2NVFmj5uD+KWPzCl/4MyioobSBbgVYSjjS86lVYTuw179L3pq
         fMoXURCLpbRXce8KbskfA/0uRI7SNAs6rZbcfHHWsasBBGtcNVZc4Uq31UZdTX2+E3AK
         lX8Cgmlc/bYB0VjLFbgRiSHPZVx2DkplEa7WpTp563rSlSpnSWYzgT6Qhavqv+Awtdh5
         NmDnLpfmAO4FxK9TXgz1oodwsyPMp9MYp1ONznXwyhj9IOjhjpiS4C1j/l0p7OQIimwF
         l3aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=pDZ4F5gWlqu9AmcIbi7hZXHKIHBX6LEJneCtEOm+AbI=;
        b=NtQZHrFLC/CPBtGFJ/L36gR/YL4UcZzD5TshALXK+MudTJjOuVMEajUD4QyWzRuimA
         C1wOmtZ/xfy/jolRvOAL5yA3HlVt2KjWqPU6aSDmGccKWedrVoWZv1fq/Zgl8AQzSDsE
         I+X/xT5iLUSA7KZ5qEv4uF1fIbduL7RRFvUZNcmm9auhPJqyrTxHvUvHqtVg1yVdQMoS
         y3A7x6uhWcnBx19+4QDwJYMOHTxhQxm4pNSqNddwT4ZKFTAPX9H5Xd/JnZ7PkDdXMlyj
         upge7BFbZx0hm89zD0077BDpwN8uLJbAGCAwbKtu/jZsf3wWldWpGXq1bXpc4a7ZJG0n
         /KBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=XS+ASPMS;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pDZ4F5gWlqu9AmcIbi7hZXHKIHBX6LEJneCtEOm+AbI=;
        b=X/e4GHO9TYjBRfwuJ6AgTrwpe0KYsWTbqERomMEHAtP9yVq4V/Jj6rwr59VGu14Lod
         REMrt5jJLzqMcdxRC5ibG5ri14vp4pZ8EMp0d8DGaRJhYvN3b1TO1X+QuXX5Lq67nGiA
         P5MYU26QzcfuEZg6VqMYwv+fAJarW9zqHWCIiv7svgEl+n1spaxATY/4jwc22NeqyEZx
         e2kfW56LqpGfiPXmEY02Jl19OAAOA6+iKgmRowq4nfWG9JLfTQKkcx5OJjaWEJ2b5bY9
         XzLSukrgooflWf0tRyqEBOW3j3Ye2hgpJRLPexWn0RCjZAeeE7wTL3l9fqJ/l83efyVw
         w0Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pDZ4F5gWlqu9AmcIbi7hZXHKIHBX6LEJneCtEOm+AbI=;
        b=meVJ8Ptsry3I35qWQBO5r5VODxnzIu1YiqYkz8TjsoTatnpWpJAhd3VOcSsX0GpvHJ
         igUVGSMEb30PnGIO9sN388CqKpB38MfN64a+5lT4qrCFGY2IEvlKLKO7zi4KZFM7AsCw
         WtYWefdxfaLF4t2v9UthCApd7NbboHK6rtKUQbxfjR9RFW/s+9Z7Cb/1dwmkqX8eDdC7
         1gEW0oMhmhVbSxwivm6CEBTbxT0MMq/fQa17PfiUJwK/BKQmCE8NNg0AwGG4Rwb4uJMR
         CeYsWwKFrcVcuOA4VZZamRyiiIXd9lwVUW6soFUf0v5P8xY1fds4U3tNMGUmIE5zCRlb
         2T3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+W9qwJEV2v6fc2UpNSRolpypYE+MXe5DqrkvfBj8AacBR8YCg
	Q7/CmmWOaHh5niJyZfUUxR0=
X-Google-Smtp-Source: ABdhPJwTstPiM8IpxEVdHT4rb+N5UH4QDvutpWwxbZc/q1owc7kyoffkJvOnF1rbUtp/417fhumP7A==
X-Received: by 2002:ad4:542b:: with SMTP id g11mr10037970qvt.47.1615803198924;
        Mon, 15 Mar 2021 03:13:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7a82:: with SMTP id v124ls7705427qkc.3.gmail; Mon, 15
 Mar 2021 03:13:18 -0700 (PDT)
X-Received: by 2002:a05:620a:1645:: with SMTP id c5mr23472735qko.63.1615803198515;
        Mon, 15 Mar 2021 03:13:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615803198; cv=none;
        d=google.com; s=arc-20160816;
        b=c9oEyRPTK69qdlkzjm4wKktaBthf1Y7f9m7DqXCZN6z8s3bY3h2eK7Btu+rbD/sN9+
         mGgUAkWDHfXcKQTVjT5gvGgP0P/qJchu1a1f4TczzKg/J4ZwfiFVswHObYsrFc+UMKEk
         gd6/DEmWR3jWtIWVvVpZ1a/O+PVJnBaqWcWDzJoQMw8lF5UA9KqKr1dJO/fqVXOVV1pF
         QouIBWpBhNPVTQtehYqvz5jodj8FesvQgTjR3lsfDLYADQ5wHPNKCbjwm1IIDbW36wWv
         pWW3n+kVNQLYxwTM1Tta6MfHOZnNeiqXs+aYtyOntg4uy3viEd7E1BjaO09m7uaBMkCb
         7A4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=618js/PS6ZPaWu29u7iJ5zsMGtOyFM88Lrk/7gggYzg=;
        b=fC2UyoGAEX2MN/YZ2Q9JQKE9hHDyRS+9m+g8QB9yCwV7MidIMXa3JMdPAnlPy3XYG5
         GXMRPCrfzGsFEQFOtMMK+/ugDQhKsA736aukcjWfORLEk6pd+J9sAZwLq/bT2B/sCDMJ
         wgf/KHNzRNY+H3FAva6ey8KEWQS18KjSjEi6f3vT6nylUMkIq1Fr55DvDRG9fcGzZU9I
         haCFK6OX59Nenf2zfshbuI/f0mbUhq3JqsraRD1uRRjTQDebOlSwWBO1932SbjzHLqws
         wJ6WS/pGCtCI8CCwYV7ELe8EgGDg6WVIwNd3IQsFcFGC19IeSMaRKW05eSFFHPJLC4xA
         gfQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=XS+ASPMS;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id b4si874455qkh.2.2021.03.15.03.13.17
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 03:13:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 14d725c739564bfdbc81dc282ff48273-20210315
X-UUID: 14d725c739564bfdbc81dc282ff48273-20210315
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1803650274; Mon, 15 Mar 2021 18:13:12 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 15 Mar 2021 18:13:09 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 15 Mar 2021 18:13:09 +0800
Message-ID: <1615803189.26681.2.camel@mtksdccf07>
Subject: Re: [PATCH] task_work: kasan: record task_work_add() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Jens Axboe <axboe@kernel.dk>, Oleg Nesterov
	<oleg@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Mon, 15 Mar 2021 18:13:09 +0800
In-Reply-To: <CACT4Y+YtenynUES2Kb6jSjfw_wT4NMeyX+uG5KdCe3SHhq1qsw@mail.gmail.com>
References: <20210315015940.11788-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YrFeRQkw+M8rpOF5169LFn9+puL3Dh1Kk1AOoKV-nyrQ@mail.gmail.com>
	 <1615801102.24887.4.camel@mtksdccf07>
	 <CACT4Y+YtenynUES2Kb6jSjfw_wT4NMeyX+uG5KdCe3SHhq1qsw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 485F11046E134C02B7185E4AE2E19A4AA60643209A878351DC8250614617A2D42000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=XS+ASPMS;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2021-03-15 at 11:03 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> On Mon, Mar 15, 2021 at 10:38 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Mon, 2021-03-15 at 07:58 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> > > On Mon, Mar 15, 2021 at 3:00 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > Why record task_work_add() call stack?
> > > > Syzbot reports many use-after-free issues for task_work, see [1].
> > > > After see the free stack and the current auxiliary stack, we think
> > > > they are useless, we don't know where register the work, this work
> > > > may be the free call stack, so that we miss the root cause and
> > > > don't solve the use-after-free.
> > > >
> > > > Add task_work_add() call stack into KASAN auxiliary stack in
> > > > order to improve KASAN report. It is useful for programmers
> > > > to solve use-after-free issues.
> > > >
> > > > [1]: https://groups.google.com/g/syzkaller-bugs/search?q=kasan%20use-after-free%20task_work_run
> > > >
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Andrey Konovalov <andreyknvl@google.com>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > > > Cc: Jens Axboe <axboe@kernel.dk>
> > > > Cc: Oleg Nesterov <oleg@redhat.com>
> > > > ---
> > > >  kernel/task_work.c | 3 +++
> > > >  mm/kasan/kasan.h   | 2 +-
> > > >  2 files changed, 4 insertions(+), 1 deletion(-)
> > > >
> > > > diff --git a/kernel/task_work.c b/kernel/task_work.c
> > > > index 9cde961875c0..f255294377da 100644
> > > > --- a/kernel/task_work.c
> > > > +++ b/kernel/task_work.c
> > > > @@ -55,6 +55,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
> > > >                 break;
> > > >         }
> > > >
> > > > +       /* record the work call stack in order to print it in KASAN reports */
> > > > +       kasan_record_aux_stack(work);
> > >
> > > I think this call should be done _before_ we actually queue the work,
> > > because this function may operate on non-current task.
> > > Consider, we queue the work, the other task already executes it and
> > > triggers use-after-free, now only now we record the stack.
> >
> > agree, what do you think below change?
> >
> > --- a/kernel/task_work.c
> > +++ b/kernel/task_work.c
> > @@ -34,6 +34,9 @@ int task_work_add(struct task_struct *task, struct
> > callback_head *work,
> >  {
> >     struct callback_head *head;
> >
> > +   /* record the work call stack in order to print it in KASAN reports
> > */
> > +   kasan_record_aux_stack(work);
> > +
> 
> This looks good to me.
> 
> 
> >     do {
> >         head = READ_ONCE(task->task_works);
> >         if (unlikely(head == &work_exited))
> > @@ -55,9 +58,6 @@ int task_work_add(struct task_struct *task, struct
> > callback_head *work,
> >         break;
> >     }
> >
> > -   /* record the work call stack in order to print it in KASAN reports
> > */
> > -   kasan_record_aux_stack(work);
> > -
> >     return 0;
> >  }
> >
> > > Moreover, I think we can trigger use-after-free here ourselves while
> > > recording the aux stack. We queued the work, and the work can cause
> > > own free, so it's not necessary live by now.
> >
> > Sorry, I don't fully know your meaning, do you mean we should add an
> > abort when detect use-after-free?
> 
> I meant that where we had the kasan_record_aux_stack(work) call in the
> first version of the patch, work can be already freed. We must not
> access work after queueing it.
> 

Got it. Now I must treat urgent issue, I will send v2 patch tomorrow.

Thanks for your review.

> > > >         return 0;
> > > >  }
> > > >
> > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > index 3436c6bf7c0c..d300fe9415bd 100644
> > > > --- a/mm/kasan/kasan.h
> > > > +++ b/mm/kasan/kasan.h
> > > > @@ -146,7 +146,7 @@ struct kasan_alloc_meta {
> > > >         struct kasan_track alloc_track;
> > > >  #ifdef CONFIG_KASAN_GENERIC
> > > >         /*
> > > > -        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > > > +        * Auxiliary stack is stored into struct kasan_alloc_meta.
> > > >          * The free stack is stored into struct kasan_free_meta.
> > > >          */
> > > >         depot_stack_handle_t aux_stack[2];
> > > > --
> > > > 2.18.0
> > >
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1615801102.24887.4.camel%40mtksdccf07.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1615803189.26681.2.camel%40mtksdccf07.
