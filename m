Return-Path: <kasan-dev+bncBCMIZB7QWENRBDFDYGBAMGQEGOCU6II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ED7233CDFB
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 07:34:53 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id g21sf1171330vso.20
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 23:34:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615876492; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDIBhPd7Q5I63/wSpXhUYzJ7U3DPK/M8Sg1BdHZ50hgzeElYW/se4n4JRDMJdDl7O5
         jO/v9n/EH5WH5viID2XtVSElt7fM/Qa6yd2qq1JwZ41nevmJk+aK2RK6EVRF2XpaFXmG
         GUJjwmK6whXX1msePRyOLnwXK3aFU69LmcnpIcdFsyY+8X3tiKmrLieW00Krk3JlWUN+
         jjcTJU6YyU7fU2llVEgXHmxM4sQt9zbkCKM+iRMxfWIZQxJw8bAK1WxiawASegd5PWdV
         OlL4N3tt7yiMvbK1DpePXe5yXJAGSMMRnM5eE+1zMjapUOhLROsE8c7FDAWc9WFO+3AA
         /ZKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LQM5X5Q4CtUCl6EJ9V9tFvisTSaZT5mR4d6svW+QFGA=;
        b=uaWN6x6ErJwuTFMrk2ewg4M2t6ZF2TM4haDX7jKqH2qQkbxtO+ClKWEPOneWek8z6T
         QsVaongpryvF6WMB7NEwNcCBuEn9cws2wQddczSxQm6Zn5GUoJlSlD2S/Hz2EK5LNF8+
         pS9oVW2byeEM5pQ3gS9rtt1sdd2dP7XAsHLrijkDLWgTuajGpHxFWcydcGum4QXnCj4V
         sJ8YjE1hq7TWgMcbDLUxWiwMJTwhesKlu4sp4rhe0uWKh/FpLHr/mvEE67zaEL8E9Ix+
         taGYFk+0rMwofIDLpxmqae6tUI/QabEVRTGPmIYzjOulvKPSCLUtX2FQvpVjC6V1f7Ks
         4Hmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s+uLqyFr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQM5X5Q4CtUCl6EJ9V9tFvisTSaZT5mR4d6svW+QFGA=;
        b=kvfE0MnK7EawbRM4rH4taGgQlAeo11mSrgfUF0ppUAk7FAn/DFaBKugvTiowEDp4+z
         dT5RRfyrfV+tAkWzc4Uxy1s8nyP9li215qkwaYWnm9W4BXaP5jAUp18+OW419F20KUWl
         3fVen5lD4jlDqHt38+8EIuN5iMCfJlCuN0rZCTc0zLPYK3Xdma9zVj3S3yYPnaJpWb7S
         DFK3fZ/MszStOmEz4dFNkPoY4p60yl35w+F4xh3bq+tRJiOT9wZGiqZuk9KZCHkRYm3j
         nJd6LEMAor6pHEX3Tf8j2YVHCqXUBqAguBNdk4Xxz5w9iIAzQ1+Mm2cVclJy01pkIxSy
         B/aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQM5X5Q4CtUCl6EJ9V9tFvisTSaZT5mR4d6svW+QFGA=;
        b=W+qUZSKlroCt/QTaajhUamxncwNPBVlHlZ3sjGJMQZzgHLTfemDpINNblwRnstqEFi
         h0A2QODs386hb+QQtt23RlMOk+zqbZ/eK/X0u3DjxGm4fYw37/LEoY1IH6x4NQ/UYrsp
         LJ8qjwsFy0t14Tiw1s1RrGTgE/w2aYwouyGJmn9aP6SlkJeTs2rpY2z8PwzvBUkWnd4B
         QwWe7ln7qlna9Y6S7o5aWFg7BzOq4Nr3rQfr4LTQtctRe5jphhmF2xuHGiAq+jDoGM1c
         f4vY/DhiNeEhllv6JodAEAfPAANFcTCPVb4R5EiOLj2rWHRO7SDbbAOW9nHoU0TjKRpR
         Cy4g==
X-Gm-Message-State: AOAM533QVHk8O9kU1kHzrwTUU3LA4LMAAhYf4YuxEJM+SEbPDU4ucZ/J
	a/kV2NOQvHcHkgYEWaiJnUE=
X-Google-Smtp-Source: ABdhPJw8nSqm/WVAQiFB/9DICtdoGh3odfq0QNc92VBke0jFfJRbL9SptuiwTEF9bGrFRfpSVDryvg==
X-Received: by 2002:a05:6102:215a:: with SMTP id h26mr16295683vsg.15.1615876492277;
        Mon, 15 Mar 2021 23:34:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5e9d:: with SMTP id y29ls1444468uag.9.gmail; Mon, 15 Mar
 2021 23:34:51 -0700 (PDT)
X-Received: by 2002:ab0:3b01:: with SMTP id n1mr6825194uaw.136.1615876491622;
        Mon, 15 Mar 2021 23:34:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615876491; cv=none;
        d=google.com; s=arc-20160816;
        b=rPI5kDD9ppbi2qqMZU0K0oeoklHBmOqnMM5fA0QqWWUzoIB7jvutDg1snG4asZrvWe
         DbgesmNmUrAWsk5NuPm+LbTc1ahdwHXSNmDSnV29cj3NVNcgNIrp9dCmoG8sZ5NUKu8o
         vduKPI48CWRgR836ahQX17b6XUDg5WTtyEhLNwDiiqPStBQRGo3E9M8MBUC9CcBOhzpK
         IaFmM2J42C2SKHpHxUYFC2C0LHDB9AzZp5kk8AFrDo+xHqE7Ho6oltxR/1mdeLQNeQD3
         NA1b8dln+lXQmW/9/KsXSyFaOdHXl9pUeXd9K4+I9ACnSiyjud1Iob5jSXJuxUsp/gov
         yhiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SByyMFSlLntBAm8fHgqN+CmCCGC2J92yQYTbduz/8F4=;
        b=fDWwEKLNu1k9fBNM0raPPE6mJWFeNFo3QKUt0ykAuVx4e8idqo+/ZX2QhiNa/jVbI3
         jWA5SN7gQCYwhNNfs4NfpZ1CL2zEecbQ0EjvkVOtwOP7pgz3fcAHPX4Pv0Nj0aSyQzSW
         FkFHZBi4b4g6BF1NT5Hg4YigPvA8Kg1rSilIgQ4M2ryFmiLf0oVrSYIDIooPz/HjgZGv
         mxQY1QbfZ47dHIOXPkUvnZ99/r6TZdUbI+GXSTFrbcg3nXcm5nqvRGBSt6dtRheFeFFf
         4fA2mK0tDQn5WTzoK7xBjO2Yr+j2zD2iB5TYY8ppAbOQqw3LaigZzfDcHcbBrbjKPVJ2
         qERg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s+uLqyFr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id d23si912676vsq.1.2021.03.15.23.34.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Mar 2021 23:34:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id o19so3048349qvu.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Mar 2021 23:34:51 -0700 (PDT)
X-Received: by 2002:a0c:8304:: with SMTP id j4mr14226424qva.18.1615876491060;
 Mon, 15 Mar 2021 23:34:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Mar 2021 07:34:39 +0100
Message-ID: <CACT4Y+aMKH24F6DO=iKX0jDmxm4MCuJkA-OTkmgbfDm73LLKhQ@mail.gmail.com>
Subject: Re: [PATCH v2] task_work: kasan: record task_work_add() call stack
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
 header.i=@google.com header.s=20161025 header.b=s+uLqyFr;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

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
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210316024410.19967-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaMKH24F6DO%3DiKX0jDmxm4MCuJkA-OTkmgbfDm73LLKhQ%40mail.gmail.com.
