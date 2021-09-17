Return-Path: <kasan-dev+bncBCMIZB7QWENRBSOWSKFAMGQEIQ4HZTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 74D7040FAC5
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 16:50:50 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id s1-20020a05680810c100b00268d4e0d155sf33993718ois.15
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 07:50:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631890249; cv=pass;
        d=google.com; s=arc-20160816;
        b=mkHKlUGyXXQiJKfTGFg79RvNP4qfiQqqAub52jEQtQFoa8RRCWs+Bf0BpvhscLmWTe
         Jkr4lIpTReYUYPqTMcra4FSYvw51XoRW6GaXRX/MBqu9kZ3pBpcIYxZTlQMaRH53PuFe
         WGELHGlQbaqy3qJT5/0tkVBQZymnN1A562jDHbu9QdnGZstAWEbgr9qtcy80ON7dYBDg
         kDw9BzpXlW0aMbxbo0jDIrvEZayJtFC0Rn8fNHPpGnMSCRnhqUTvuqbuYZhaaWvYTDX4
         2Bbcwiy+EV3Lq8ZiXzCB1GEFQV2GHm40nhBmBBD9Hbzh96gteTTeaYKQUcOp7ZoGFsyA
         yv5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zMA3BWtu+GM36XPowpf656Qf4Tl6ueIxESwwC+fy+HM=;
        b=VtjWc1G1cDeAzp7hrK+cR9N+uQ9NuYVObjoHqfmLBNGKXtyNwrBPDfUsR9FyihMvIX
         OYse96ooujCILeqdJdyvSl9Xj2y6jjacPEjNDkPrEYQFr1ZfhBbBSjq6UZX6dERZOidx
         4Jg4LxWCmMP2PS1L2GnMG6aguWKZkUo07ApKQ6N/QVVJ3F2aECo7XFTClwffs3oQihLQ
         KWpRwINrKE5ZlBB3gI0VRK6zdUANIb9+uu6CdrDKKDayv15gAk5p39A+GqTQ+uOsR226
         7m7pFjk+oi1T5fiKbAwQGT5MXfh2+04uMkLNJTyFYo2jmTyfyFQKCs4IdOLgKDHvUn7o
         BaWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HajIqhom;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zMA3BWtu+GM36XPowpf656Qf4Tl6ueIxESwwC+fy+HM=;
        b=Fx+KPLftlUaktEdZRCh4VOkWA+zvLSnNvLGYHAa69k7A3ncizXzDtyNIQfKSxAqwuf
         sXg/FP6BcCb+rDIX300XbRoualKd7wqM2brm0aEXP5F3Gc0uHbzyxkrvmrRejQgCkL1W
         DvvrI892p5nLY660uqBPN3Y+6QxVzBo/CjgdKHgP3mimyzHrPUmvF6AIKe3aUQzJREaP
         1UPkzqysZMXiLY8C/jREcQiFE32uv4/8WYqrq/8M6plQze8Lz4U69Kuq27U/QBnCJ2XN
         mOfXbUuqFrt//5k6tpg+RPAy/Kq43ziGIQOyh1mvFCY8Dz8DB7g5WuDqt4VBIOzbGl5M
         PuCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zMA3BWtu+GM36XPowpf656Qf4Tl6ueIxESwwC+fy+HM=;
        b=6E8HGR/3jfsB60hwtjvDOobS2Xn7sGHR4A0Mo2dGxN6Zgjyh9N67VPNBlZ7kD6Df9d
         VcXcvzzep3lAOfVPYrAcBWjfWKJ+Ubk0f5jhV4htki3IfZQIQrjESZURCjtyNNrzyILD
         eyS6SG0O/YAclIf8TbVvLVIUe6Y5LkpoN/USmPfqB3ixgsfd5QdrAJaz+JZt249iw8wh
         ZtLYLQNQYh0PRF/Z2ji1ypNtq7a8EDBSAogOoCSP7Bb01Th5Bk6drOhHEEd7MOXn7lVu
         Y1GsxLvS1uYyev9X3Vs5Rh5rTuSJphU5li7SCGEXYTBroypKVF3jUUO/E61+x6W3MO0e
         rNfw==
X-Gm-Message-State: AOAM530T9vdVYfMvizfEAa/KtECoCKOJLVTWWVd18yhW8wQz80r+o0FV
	lHbUGzZJm1QYuAseemrL3T0=
X-Google-Smtp-Source: ABdhPJxIxDIJ/pQBxxef3/jDB//zftyvGyQMSaj17hmfcOkuks/d0pLj2YHkR48KaWYKCReIo1ekaQ==
X-Received: by 2002:a05:6808:1151:: with SMTP id u17mr4273280oiu.175.1631890249426;
        Fri, 17 Sep 2021 07:50:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:141:: with SMTP id 59ls466327otu.8.gmail; Fri, 17 Sep
 2021 07:50:49 -0700 (PDT)
X-Received: by 2002:a9d:720d:: with SMTP id u13mr10002347otj.14.1631890249077;
        Fri, 17 Sep 2021 07:50:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631890249; cv=none;
        d=google.com; s=arc-20160816;
        b=sXn+qOvNmW1R6etgqN2v3D/7qJQoKdClMUv6UBBxATee1swvGLbL466I58KM98xTOQ
         t2LbB+XLGjLuEb8NnspltS9tLtVCVoJRlNPST3QEfjfJZPcp0th8ecVnFNXhKIQfSRRo
         X2A5yD+BSm7/KMQKpq7qVAmXZoART918JNbLfJkZP0XQqlT5IgxnW/+sOyi2gT2aHwby
         2pRtVw666SY3GlqqJFkBKT5lw/HcJTHYGgTUzurbV1zCgHRRVXsvjikGGqxt92NG1EsP
         O569gIWQYQno9Yn1RxSseEshZD2DQoZWZjuJ/LtAsTwz8T719et23wlRjUXarYZf5IW2
         rgoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A+8jh6PTO10F45HFFMFUU3EONxnA5C8W34XTxIGW9XU=;
        b=KOb35vqTl6WesEn+qnC0a5Ipmq6xXWHz21SiLB/EU1oRkbkLFK4gucBXasGmVzhXQZ
         N05OBwtopzCVsGTIVD7uFqXKamx8Hr18FfKgNScrlQry40hWN1BsGhE8OPYb8Ul0MOyf
         ksri6tVaMvei7/q+epRCjQ7S5sPoWm/XhpHtK64yQR2G2XleRmu0OKomDMkjlSqpEw3A
         KZG+Y4SsjIcBuKdOlgyDkMVDsPBfj/q5vP6chfWvLCa81DqM5aRbpm+Dsk7kj8p1nfem
         Ga13Uk/G5MF9rV/tjKq0XgejRvQON4r4V2EI3dgmeEyBwevcpp/EDE2g1FLWAOl74Z1n
         gnDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HajIqhom;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id b1si1049531ooe.0.2021.09.17.07.50.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 07:50:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id c42-20020a05683034aa00b0051f4b99c40cso13230756otu.0
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 07:50:49 -0700 (PDT)
X-Received: by 2002:a05:6830:34b:: with SMTP id h11mr10005271ote.319.1631890248615;
 Fri, 17 Sep 2021 07:50:48 -0700 (PDT)
MIME-Version: 1.0
References: <20210830172627.267989-1-bigeasy@linutronix.de> <20210830172627.267989-5-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-5-bigeasy@linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 16:50:37 +0200
Message-ID: <CACT4Y+aCm60gfP9uyEdb-KKaikGGXkrcY8FXhESnPyO_cWBw4A@mail.gmail.com>
Subject: Re: [PATCH 4/5] kcov: Avoid enable+disable interrupts if !in_task().
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>, 
	Clark Williams <williams@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HajIqhom;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334
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

On Mon, 30 Aug 2021 at 19:26, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> kcov_remote_start() may need to allocate memory in the in_task() case
> (otherwise per-CPU memory has been pre-allocated) and therefore requires
> enabled interrupts.
> The interrupts are enabled before checking if the allocation is required
> so if no allocation is required then the interrupts are needlessly
> enabled and disabled again.
>
> Enable interrupts only if memory allocation is performed.
>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/kcov.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 4f910231d99a2..620dc4ffeb685 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -869,19 +869,19 @@ void kcov_remote_start(u64 handle)
>                 size = CONFIG_KCOV_IRQ_AREA_SIZE;
>                 area = this_cpu_ptr(&kcov_percpu_data)->irq_area;
>         }
> -       spin_unlock_irqrestore(&kcov_remote_lock, flags);
> +       spin_unlock(&kcov_remote_lock);
>
>         /* Can only happen when in_task(). */
>         if (!area) {
> +               local_irqrestore(flags);
>                 area = vmalloc(size * sizeof(unsigned long));
>                 if (!area) {
>                         kcov_put(kcov);
>                         return;
>                 }
> +               local_irq_save(flags);
>         }
>
> -       local_irq_save(flags);
> -
>         /* Reset coverage size. */
>         *(u64 *)area = 0;
>
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaCm60gfP9uyEdb-KKaikGGXkrcY8FXhESnPyO_cWBw4A%40mail.gmail.com.
