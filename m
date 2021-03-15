Return-Path: <kasan-dev+bncBCMIZB7QWENRBMELXSBAMGQE3TUQMVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5329F33ABDB
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 07:58:58 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id g7sf16082170pll.11
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 23:58:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615791536; cv=pass;
        d=google.com; s=arc-20160816;
        b=YUHJqyPxOFlHR6n/azT7H24aQyZowjav4RH8685cZjeiV3ZwL1IFvjG+WD0fk6N9oP
         WoAAXSE75qrhCWUfiAiUeZW44NmuB9lYZhQCAvzejjRCcARvo0Ocu8EX2fwXtR0pOHYa
         CUvNFB0tUYt4XDvzXO6j89lv5AJIQ/0FIP6RjgFTAoGbCtxFDBCSkLU4F2USTaCz20wg
         srY8cjHFluCl0XjmGfCAMLjUyyb9UAWWDpeCHTw+vJaqG2QRRm55QNrTmVh9GJmW9jm/
         wRYhrgFBI/vsGW0B5wsowMNv1nfusP2rjacUtWKLm2U4Vo0gRcwcVNfo6MhuNDfmwHjE
         2FBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iSvijD7f4kZpIeVfAwe/RpxOaQr3WWxsTWJ4jAxhdbU=;
        b=XBiQhFtktfwltIVm217Wll0R/XFrxIKRXrQkChshNMu/OFpvNbHkzUv33g96TvBRQp
         6qIYB8dQTEooZ/Tyiu716OMPsn1Ll02DjGXTeyEK9KbN5afoFCZlFd1aFa88ayB5sywz
         +rKc4C8SylSVEpSfM0FA64YcB9FDJ28OjszVPpKRvRqKtp0t9kQWbailPpNuYXxUgAym
         +irdnAUf0GqgljaJBzCJpiBMhzKE2QSJoit8h7jKtGGSbL8kmOWqmMDQSzyvOSyka6H6
         eTt5dE629Gei3y3yFaVLQwEv/SqK26lFeLp2T5NsG9doFPKVuZWQezkWUfVyF9QsZWzA
         DzsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QdhmEyhc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iSvijD7f4kZpIeVfAwe/RpxOaQr3WWxsTWJ4jAxhdbU=;
        b=YTvtBWJYLfHUE6vkdNVEiA40XaPujjDg9eZgLIietEMypSKeFxy4oIRuuXQxA828Mk
         InN3AT4IRWF3COPP42vOVr1asDlFJH1B41aUgrSTWbs3bHo8fu99z4QwJCN2MpNYsvPj
         Tf68XPuNFpDpU09qN4fXp7DJpnPSSPSNJTxlArNJPpl7uocUp8hNgXA0L01WYRHYLij+
         XFbvzIMWggJ8L4vgP3DalHoH68ZzxlCRLDyM5OWY1eT31SUDfCDXT2e8/vXWzw6B6bKl
         oCksT9wI26gNGXyeoT2x/TWNfx3uko/EOMRw67nr5nE57m9bvSW4hEaxKwbGJapUTHVx
         j53Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iSvijD7f4kZpIeVfAwe/RpxOaQr3WWxsTWJ4jAxhdbU=;
        b=RGl0IfLnO+SUDOuQAgS16ac0eBkOPezQ/v0WHwP2uF7ZJPv5L6LwcL1HR3iRkihozL
         h3bSOgxoPbo7vBb047cb12ibltiAn1uKa+uYAVqqXjTA6hm7jRIUYHzSkTjwIx8F6Zek
         /iDzQUz8ynkcF1vOwBxTwxWAl3qlu8u+dnvzbNLIgJrQv7cbzfKOsFM9LqUre/rP6zNU
         /fDGApm+OZwL8/X76Ew5M45mF68Re+6PV1q61iBWdJhL2xhpkNRJCDqpo29SYVss9Aa8
         e1VuO0+IDeyya5XTZRIqhKrKCFi9w5YWw/iiU801IYXAVo2HFcgajt0lvZNXxsq9WBnS
         cPoQ==
X-Gm-Message-State: AOAM5337IEQisCBslaqoMGtwZT+HRCu8k/gPMnVcH+ze5WJNP3jIFmir
	x3WqOpz6zr7r0/Mb12xEw5I=
X-Google-Smtp-Source: ABdhPJy2EcnA9CvvUgpnX2+MUs10IYj8XTrJFRcbME6Vjmm1OYBn6Nvp9WoOUXxFlbT95Ex2iyROCA==
X-Received: by 2002:a17:902:dac2:b029:e6:30a6:4c06 with SMTP id q2-20020a170902dac2b02900e630a64c06mr10250048plx.65.1615791536767;
        Sun, 14 Mar 2021 23:58:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da86:: with SMTP id j6ls8262235plx.8.gmail; Sun, 14
 Mar 2021 23:58:56 -0700 (PDT)
X-Received: by 2002:a17:90a:55ca:: with SMTP id o10mr10968161pjm.173.1615791536275;
        Sun, 14 Mar 2021 23:58:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615791536; cv=none;
        d=google.com; s=arc-20160816;
        b=kVQnbN6ZmrFHQEryxRqT6n/cRd3a8m2CgHpwkCVodtgNVcaLgZGriJ5WeC/NrawlRU
         sKH2p3JKesR8HI1V2Qyg3WsR7LPk0BRuzXYrV8+mtiNG08W6oIHOgittd1oV+qPFX8Jz
         X0k+bphyWCVX86L4g5VPabAY0ygTGI05R6+uG2vjZvqFJj5m+FN8wjFEp3xLXAbw3Rln
         p0k8zzSuodI+U33MOhE+qce76HH9+kQIO8kU1tRfqKYWRHmhi7zYMwQVhjgvu+OTWA7B
         G2zZLQmD1bZUwCSYWpexPwZokAn4rUaKAFJEbGHCLfzblp/ws+mW/OoQkCAEzjPCRkm8
         2jJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IU5V4mabE/n2VCRh3kSmfdhuEAACW74e/YNmNcSi3W8=;
        b=GirwX/YP0taPMxsCyQwIDfZbUE0DdNdtW4XurCBQOZyMvVoBy0N5uZmuXc1Tb4Bblk
         KHeivh4m6qQsx2BrK4knaaMQhXndCBDC45fKYdqhdiFAqFZeBdnbo2GG74zpR/ntI00V
         folgCwwq6KavGJy08MKLTwYbcdt4buOR9RAdlctj19qWMejhg2JcYRRKDL7Q0JYyXf/s
         2YYTb2L+UVD3hAxUzChJx9VDOmCyDKtAS5BC+L65VQhcssorrRZUyKxhnijgvTKreSJm
         QZahdVwZkjxUgx/wqcWH+ZScUlRt07MnDUd5pvUaPTznaNA4j5BzTYlQDvKd4v3IikiR
         RNQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QdhmEyhc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id ft8si1235534pjb.0.2021.03.14.23.58.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 14 Mar 2021 23:58:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id 73so8409911qtg.13
        for <kasan-dev@googlegroups.com>; Sun, 14 Mar 2021 23:58:56 -0700 (PDT)
X-Received: by 2002:ac8:7318:: with SMTP id x24mr21525417qto.67.1615791535245;
 Sun, 14 Mar 2021 23:58:55 -0700 (PDT)
MIME-Version: 1.0
References: <20210315015940.11788-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20210315015940.11788-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Mar 2021 07:58:44 +0100
Message-ID: <CACT4Y+YrFeRQkw+M8rpOF5169LFn9+puL3Dh1Kk1AOoKV-nyrQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=QdhmEyhc;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833
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

On Mon, Mar 15, 2021 at 3:00 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
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
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> Cc: Jens Axboe <axboe@kernel.dk>
> Cc: Oleg Nesterov <oleg@redhat.com>
> ---
>  kernel/task_work.c | 3 +++
>  mm/kasan/kasan.h   | 2 +-
>  2 files changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/task_work.c b/kernel/task_work.c
> index 9cde961875c0..f255294377da 100644
> --- a/kernel/task_work.c
> +++ b/kernel/task_work.c
> @@ -55,6 +55,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
>                 break;
>         }
>
> +       /* record the work call stack in order to print it in KASAN reports */
> +       kasan_record_aux_stack(work);

I think this call should be done _before_ we actually queue the work,
because this function may operate on non-current task.
Consider, we queue the work, the other task already executes it and
triggers use-after-free, now only now we record the stack.
Moreover, I think we can trigger use-after-free here ourselves while
recording the aux stack. We queued the work, and the work can cause
own free, so it's not necessary live by now.

>         return 0;
>  }
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3436c6bf7c0c..d300fe9415bd 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -146,7 +146,7 @@ struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>  #ifdef CONFIG_KASAN_GENERIC
>         /*
> -        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +        * Auxiliary stack is stored into struct kasan_alloc_meta.
>          * The free stack is stored into struct kasan_free_meta.
>          */
>         depot_stack_handle_t aux_stack[2];
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYrFeRQkw%2BM8rpOF5169LFn9%2BpuL3Dh1Kk1AOoKV-nyrQ%40mail.gmail.com.
