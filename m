Return-Path: <kasan-dev+bncBCMIZB7QWENRBGW2SKFAMGQE7AJOJPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B3440FAF6
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 16:58:35 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id c10-20020ab0284a000000b002bc28439694sf7478694uaq.6
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 07:58:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631890714; cv=pass;
        d=google.com; s=arc-20160816;
        b=urAoKXfD6WqMMhdOdW5sUF480W5XEwxEtGF4EJFlMvvQ/d7noy2cvs0HQ3JFur61lP
         l8qJN0JGYg0TXr05JvLdSHN5S/RjubQbIuWZLTjhWXktKR5D6XdJyuAaRC2ts9MX8nL3
         A1LCzmXZRXiY2bxTgB8TVo8LRdNL2BiLNklIqnLWQgVkq7SzgXSjuCT3Ip8vg8k/QOFc
         ltslhAXHQSNVQEAZmQBNTpXo1W0ao3IAFUbnvgQoDVBAtJ4OM3l5Pq0vscXsC5HLU5Ft
         dL21W3ZKeAM5Y6XuMRdg5RtQXtUSybguH1vypsHNqnh5si/wf4ohi1JjOAGpdPaVbtA8
         903w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FhU7RYr/otz/g92ctg1UgGsqpm2hHerxRYGKhUDqcXg=;
        b=Hl/T6AC4KMPB05aKgOArLcULRt6EVukKDYRhutUHl2I2ZZSmH8HQm29yUtl8B49MZp
         xyPYDMJVdtclTK6jLua1157UVDLT/muIsX2epSNcWiQkPm33ak8xDtev7SyGz0FjYk9h
         HsFF2L9b9Z6LXjrfiEOdQWKFOLNII/W0VD59+4K1vz0P/q96PB7Tmz0iyCirxKGpNVYP
         jfTP1B7ZZI1CNBi02TaNatVsYpPf0ObQPPxTzN3p/Ue5ShnF1A4eTex81sWaPrXuxX30
         UjqvqeZT2BqLyV0l3Wi4A9diRs6lxz2MIwgAtnJ+9RKck0IjJ2zn/wIfDDnGu/p0KUZc
         0BoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b1+i3ZY/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FhU7RYr/otz/g92ctg1UgGsqpm2hHerxRYGKhUDqcXg=;
        b=OOlpjV44LqBPUfsGpgi6pVPL15YEi1whFQEXa6JdZlba1HEKDNg7uJWO/nbkA8CCQt
         e34LIq596hFms0qn5O9eNU4SzsChoCpm2Ttys0a4v+4dQ+pFhSmF1Ycz1D1HaKqBMGHX
         f2j30pIOVBoLEKTrBMyUjCYKimrQ3EIv48oHELrpAk5lFJuDusFauYsXz3Z5aP6E+/Ib
         Q9l3AyEl27D5hr3LjLv0IJpz3fGbDQD+5hMXPybTjZK7rhuuHbloLGNJUY2HQ/nIqq3l
         P5VmCROsz7BhRBmFbkWtaMXSb/rubs5XoPLtuTckhXebM4YL/uSZxmuWD2fWv6PNBlKA
         LPmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FhU7RYr/otz/g92ctg1UgGsqpm2hHerxRYGKhUDqcXg=;
        b=6q2zfyrN7Bm+qME/XCMwIbPEZrHT9XmbVzR4nL+4nDHEJg3/r5+xIjS1lPBbg01MzX
         8H/KkWRDTWj7A1KS4EKMM7w/8dek1ZMWsef0zgmVMyBaHr0Cpqh5oeySjkSHt/ZgJoLv
         2R8dOua0pZHJeeVhqSaTIjErnuX5RWCNzkcKGMhB9C9s/jVXpGYa/TRWUJg+hQdos1J9
         BvQ/svxW/bhUgCC1S5S0gA80Pp4IGJ/MjsvgNnjJovu8z6o3SqZxH76fgDDellDn3u+Y
         UUal6okmDoTlYJ4zPHqw0gA5nGk1AM4ezxPvW45JB+hU5t2ZnTlcrONeydYK01i1v3Ld
         5b2g==
X-Gm-Message-State: AOAM530crNd9buk3Se2VmNRHtzZdrCPSfkB5IKK+3a0wFXlg/WGxesFN
	GPUndWbg03Ik07emkrBkxwc=
X-Google-Smtp-Source: ABdhPJzbu0gbcuGH0yVkHtrPIP5tObsJEA1IjPp0kZrABrKaXTvtt5LrLpNXtcU0FeuiYWVTvjcdew==
X-Received: by 2002:a1f:2493:: with SMTP id k141mr6086260vkk.6.1631890714219;
        Fri, 17 Sep 2021 07:58:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3b07:: with SMTP id i7ls416457uah.11.gmail; Fri, 17 Sep
 2021 07:58:33 -0700 (PDT)
X-Received: by 2002:a9f:24c4:: with SMTP id 62mr4838309uar.95.1631890713695;
        Fri, 17 Sep 2021 07:58:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631890713; cv=none;
        d=google.com; s=arc-20160816;
        b=IKuwW+LmYyOadS7mynRQorxHP+0/rUj8owp27i3woX0HkyPlhORy8OMnsPn26ZKqFM
         z+fXUmugTnwv6TP+mCBulBKeTacxHvG9lpKUwPyk7BdzF8ZE5Bd2IvITDMTOhKZkze18
         x6Pes64gW+dgV3rgWY3UFDZkoS0MiqrVIawjWQ3sDYPXuRTJ/mnlOghvCxBt+5PF3cMk
         VNabyCrOuA1xRAX7dHO/g4feE/+dL2eY1WMVaB6kMVfAjMpSeI/7MPIzZ1eOn1nN2gLU
         9XE9m2Gfey2ESToY96+YM9dq0ruwh02Iw+oZmY5y49y/0Sw1nDFFDcj/c9dcCIrbri4K
         WJBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P+JGSMw5LOV21Xn1Nvh/yNqSCnZsmZNBCAdtQCfOwAM=;
        b=sWjICuZbBo/TBkCUMb/73ikhTcjVnLm0VOGkHj2foK9nOg6vsgpG9+mKGuhdhMdL8q
         ktRLDo++swp7rV/iw17og4hKnPCBwJTXYk/NXx/Q6km9N6tAc24xbp7l6RZLBWzXsJXe
         zNLuude9kJ3OvTBaxYZyisSRBoVcCH99KPVwADBi+5u66GX+dHjkZ8uEstpHJP3eITPF
         rOlT7kOd7DA2lW6U+H08ERIgCGPsgdYpxlAcKiON22pujbx4LSg2+ZJKArYO0HOhXBYn
         WXotLY4+f+mhXrvZ1TcNTD+W4/0PtvSAGSsWZiz7/O0e9BobhjsrENLdFBAWxnTFMhRB
         4RqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b1+i3ZY/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id a18si531647vsi.1.2021.09.17.07.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 07:58:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id r26so14324129oij.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 07:58:33 -0700 (PDT)
X-Received: by 2002:aca:f189:: with SMTP id p131mr13961442oih.128.1631890712962;
 Fri, 17 Sep 2021 07:58:32 -0700 (PDT)
MIME-Version: 1.0
References: <20210830172627.267989-1-bigeasy@linutronix.de> <20210830172627.267989-6-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-6-bigeasy@linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 16:58:21 +0200
Message-ID: <CACT4Y+axiW+rAs+8a8E9WRx+rpv67ciKcZT_qEqZ_Hyt-7hLVQ@mail.gmail.com>
Subject: Re: [PATCH 5/5] kcov: Replace local_irq_save() with a local_lock_t.
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>, 
	Clark Williams <williams@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="b1+i3ZY/";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22e
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

/On Mon, 30 Aug 2021 at 19:26, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> The kcov code mixes local_irq_save() and spin_lock() in
> kcov_remote_{start|end}(). This creates a warning on PREEMPT_RT because
> local_irq_save() disables interrupts and spin_lock_t is turned into a
> sleeping lock which can not be acquired in a section with disabled
> interrupts.
>
> The kcov_remote_lock is used to synchronize the access to the hash-list
> kcov_remote_map. The local_irq_save() block protects access to the
> per-CPU data kcov_percpu_data.
>
> There no compelling reason to change the lock type to raw_spin_lock_t to
> make it work with local_irq_save(). Changing it would require to move
> memory allocation (in kcov_remote_add()) and deallocation outside of the
> locked section.
> Adding an unlimited amount of entries to the hashlist will increase the
> IRQ-off time during lookup. It could be argued that this is debug code
> and the latency does not matter. There is however no need to do so and
> it would allow to use this facility in an RT enabled build.
>
> Using a local_lock_t instead of local_irq_save() has the befit of adding
> a protection scope within the source which makes it obvious what is
> protected. On a !PREEMPT_RT && !LOCKDEP build the local_lock_irqsave()
> maps directly to local_irq_save() so there is overhead at runtime.

s/befit/benefit/
s/overhead/no overhead/

but otherwise

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> Replace the local_irq_save() section with a local_lock_t.
>
> Reported-by: Clark Williams <williams@redhat.com>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> ---
>  kernel/kcov.c | 30 +++++++++++++++++-------------
>  1 file changed, 17 insertions(+), 13 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 620dc4ffeb685..36ca640c4f8e7 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -88,6 +88,7 @@ static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
>
>  struct kcov_percpu_data {
>         void                    *irq_area;
> +       local_lock_t            lock;
>
>         unsigned int            saved_mode;
>         unsigned int            saved_size;
> @@ -96,7 +97,9 @@ struct kcov_percpu_data {
>         int                     saved_sequence;
>  };
>
> -static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data);
> +static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
> +       .lock = INIT_LOCAL_LOCK(lock),
> +};
>
>  /* Must be called with kcov_remote_lock locked. */
>  static struct kcov_remote *kcov_remote_find(u64 handle)
> @@ -824,7 +827,7 @@ void kcov_remote_start(u64 handle)
>         if (!in_task() && !in_serving_softirq())
>                 return;
>
> -       local_irq_save(flags);
> +       local_lock_irqsave(&kcov_percpu_data.lock, flags);
>
>         /*
>          * Check that kcov_remote_start() is not called twice in background
> @@ -832,7 +835,7 @@ void kcov_remote_start(u64 handle)
>          */
>         mode = READ_ONCE(t->kcov_mode);
>         if (WARN_ON(in_task() && kcov_mode_enabled(mode))) {
> -               local_irq_restore(flags);
> +               local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 return;
>         }
>         /*
> @@ -841,14 +844,15 @@ void kcov_remote_start(u64 handle)
>          * happened while collecting coverage from a background thread.
>          */
>         if (WARN_ON(in_serving_softirq() && t->kcov_softirq)) {
> -               local_irq_restore(flags);
> +               local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 return;
>         }
>
>         spin_lock(&kcov_remote_lock);
>         remote = kcov_remote_find(handle);
>         if (!remote) {
> -               spin_unlock_irqrestore(&kcov_remote_lock, flags);
> +               spin_unlock(&kcov_remote_lock);
> +               local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 return;
>         }
>         kcov_debug("handle = %llx, context: %s\n", handle,
> @@ -873,13 +877,13 @@ void kcov_remote_start(u64 handle)
>
>         /* Can only happen when in_task(). */
>         if (!area) {
> -               local_irqrestore(flags);
> +               local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 area = vmalloc(size * sizeof(unsigned long));
>                 if (!area) {
>                         kcov_put(kcov);
>                         return;
>                 }
> -               local_irq_save(flags);
> +               local_lock_irqsave(&kcov_percpu_data.lock, flags);
>         }
>
>         /* Reset coverage size. */
> @@ -891,7 +895,7 @@ void kcov_remote_start(u64 handle)
>         }
>         kcov_start(t, kcov, size, area, mode, sequence);
>
> -       local_irq_restore(flags);
> +       local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>
>  }
>  EXPORT_SYMBOL(kcov_remote_start);
> @@ -965,12 +969,12 @@ void kcov_remote_stop(void)
>         if (!in_task() && !in_serving_softirq())
>                 return;
>
> -       local_irq_save(flags);
> +       local_lock_irqsave(&kcov_percpu_data.lock, flags);
>
>         mode = READ_ONCE(t->kcov_mode);
>         barrier();
>         if (!kcov_mode_enabled(mode)) {
> -               local_irq_restore(flags);
> +               local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 return;
>         }
>         /*
> @@ -978,12 +982,12 @@ void kcov_remote_stop(void)
>          * actually found the remote handle and started collecting coverage.
>          */
>         if (in_serving_softirq() && !t->kcov_softirq) {
> -               local_irq_restore(flags);
> +               local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 return;
>         }
>         /* Make sure that kcov_softirq is only set when in softirq. */
>         if (WARN_ON(!in_serving_softirq() && t->kcov_softirq)) {
> -               local_irq_restore(flags);
> +               local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 return;
>         }
>
> @@ -1013,7 +1017,7 @@ void kcov_remote_stop(void)
>                 spin_unlock(&kcov_remote_lock);
>         }
>
> -       local_irq_restore(flags);
> +       local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>
>         /* Get in kcov_remote_start(). */
>         kcov_put(kcov);
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaxiW%2BrAs%2B8a8E9WRx%2Brpv67ciKcZT_qEqZ_Hyt-7hLVQ%40mail.gmail.com.
