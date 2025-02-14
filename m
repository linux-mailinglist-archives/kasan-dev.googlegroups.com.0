Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLV5XS6QMGQEPEGQEAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A976A35BB4
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 11:45:04 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-84cdae60616sf128391539f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 02:45:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739529903; cv=pass;
        d=google.com; s=arc-20240605;
        b=SnGJUZ0o+a4PGr6WMgFQoh3MyMhrxuxHsswFbczmD6kBaqJAlNL4LzmjO4UTarkdg7
         /B1en0bANhfCgVj33kVtDuJOruoQ0L2mlxAqMY5/7SmcJIqb6gmB/BWUYYyt5pxZDmOU
         gNspWHGa35xsmvlHIMXADs5ux0uRBbUUnkoAAIQVzynGDGwFzpEQZ2nn+MoEuSFMawRR
         hWk//TIjGbBPgg2HjDR1ke5QQinIyalF49BQPChzaWndr0KdMbidio3ZCLOAVKwq+zEj
         HqbF9ysfjg6oU6Yz0huFULVkgExNDB23Q9aFw24gf3pzqvCrleCH5Hc17FoBwVcU0/c6
         1ITg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uItUosIaIBhGv631Vv7AWtJmkBC2Ovssb85DETf0xTI=;
        fh=UTWJux+LvG24AuKuvQzuoSoOuynxcfU+cpDJP3WZVQQ=;
        b=Yua1nXvLi3MvXbpqoaZ1Qn7qHnP7q0QhuK3glYFEzbZ57qKy4uh3fT4UEVVLL627pr
         1SVwqTE7yBkV395PHdTwpnr22SHAihkCZkRbchSvHnz+t6jV4q0G6WGJaODpXyyb6uqy
         DV8zZp70BdqFHoq1vj85Ng5y0lT6c9JQay2QFQS5EkbyKsE8sLsYX8jQZrD7JosVqLMI
         gveWrrINjXSaIgjEA9wp39tOk90ztNtttlU0O4zEOduQgW+lXiB7DS1EmTcjVCywAvM0
         G/TTIexYC0DAwuwMdnYzz3UYp3Vs6S1hlI59E1iHITLluX5nWfoy93AsRNucJXDG5OWy
         PyvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WB4vLDNF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739529903; x=1740134703; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uItUosIaIBhGv631Vv7AWtJmkBC2Ovssb85DETf0xTI=;
        b=R0exQ9QjZXIrTa8MNNYUcvlAUPX0lxbaZctyP7BhtpykTzOKwF27UnpGLzOBZ5zQiY
         cgvXUvAe4xI8sTNGzKwjORir5tV/T9xqsGlNHfdMpsh/+4K2XeXDEGk6Cti8SNZjGnj4
         tPbMTumSiDBc64fci0y+BVwp13xhFJA6e0xl22x47WrI4MnhbKAxO6ttKD/c5lRqAIjo
         nDdKlCwSjM8gUCrpp2D0os+AwAmYChIRJ+v8G9ulutjP2U4tawpDCY6dfATX6SjJJAHZ
         wn8GsetDNWAvqHAlEhXdeZoG9TgP7NStCvAQPhRpeo46+5ziSkhLlYzY3kAgvUT7RSU4
         seYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739529903; x=1740134703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uItUosIaIBhGv631Vv7AWtJmkBC2Ovssb85DETf0xTI=;
        b=FLOcspBzSwar2IP5ZsfcU50i/XtBgMESGgYC1X9r5IrIwLyx2mgKUlWb56HJ3y4ht+
         3CsiU1aB3bLX1+5S7Q4QyV0PW2h2KNyI1hEMNKwA+50IMLZ5TIlDlt4x1sQtQH9YfU6u
         bul86rnPZ3mZcQN4fzq8n2+lfMW2HuSoGiLyH3NdmB2HNTyF7o3TZDC1FKNz9XkY5qJe
         6bbRjT7ptQY8JoBzpIoH8zuHSS5XToILOdfqIP9WL81YC9TDuvzTBVyB9zr9agljtTKF
         ST5EenqpAdFVdNkwA71K010LOdNx7n/1uYwKzRUWNVpwLHbcTdbQy/zA7UcPUW0MDXcY
         DRkA==
X-Forwarded-Encrypted: i=2; AJvYcCXV5lA1/3Vm/lpPCMF+0L9Tg5MX5j2Okf8mo3rxkk/4qzgCNlXvdoFgh6m4BAs1lkpcT4x96g==@lfdr.de
X-Gm-Message-State: AOJu0Yyhp2wPSE4c5x9OW/BM727+AIfQEZxDl7RG5Hi1RD3ppJtr1EDf
	mSce7RVcU7akjPKY+l4/uL8xyKRAqkcAjt1J6KLkLGRWDgFC9ZQB
X-Google-Smtp-Source: AGHT+IHqcJ6bcr5dNFdcVe7WBNwvWcAyFHzoz7rIqfY/MZR4W4KATSiQSDV4nvK+idS3sZrSBJ6zJA==
X-Received: by 2002:a05:6e02:178c:b0:3d1:4b97:4f2d with SMTP id e9e14a558f8ab-3d17bdfa33fmr89268595ab.5.1739529902940;
        Fri, 14 Feb 2025 02:45:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE6qk7gZzzJg5nEhp99pycFmxvTKUwZ6ZjSPCwfdg6TAg==
Received: by 2002:a92:2802:0:b0:3cf:e821:65de with SMTP id e9e14a558f8ab-3d18c38d6a4ls6833285ab.2.-pod-prod-03-us;
 Fri, 14 Feb 2025 02:45:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX9fGah+Ri4IatWQ4qOJbixn+6LQdppBEkTI4aQie/VpUJSEMHu9RLNUNDyo1jv2eoxLdW5hnDw4qw=@googlegroups.com
X-Received: by 2002:a05:6602:6016:b0:855:75be:f726 with SMTP id ca18e2360f4ac-85575bef830mr42621539f.13.1739529902071;
        Fri, 14 Feb 2025 02:45:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739529902; cv=none;
        d=google.com; s=arc-20240605;
        b=abAfKF74YTL6NznHQW4EhJb4r2g2UNAMQDuJH3hitEAsP+IpyxDq9LCDOionQK2dyP
         u19erqe5w788gCf8/L9/oFLDosBUAw5C/5vpj/8/wT4WlAPBa5wYLqyNZ3q4jROUOBwa
         3g48taThbyDXmC6hl+xMGoBtTXAfLrdR8hZIcB9GzrJZZcRgEDndLrgnibXTc03+rmEo
         y1xbdHIbJti/c1QNhOo4ESPnMEIzsRjwcdDtaGQ+1Au8qXCOOFZUoXE8AqgWg1SSlxZX
         /IrIihQ8jBsGGetLL/sZkGAGaaweyJlYzZ4Z5odZegY6JBF2xwJVhPRK53AqXes+lCdj
         zE/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V1nKggMID3OWjzPJGLlNPI+kvpL/CDhruykGzB2fMEo=;
        fh=6Qfo2jTx7u5s+52wZKunbJ/Ddy3gQvsHyEgAoyAfIok=;
        b=fqNv9ucTZ17CZ2TEK88bXalLnOzaOIac31gn0WYSdyMklvuo2Z9B+VJPLEmV3UH6ti
         hgQlqDJdqfak5RYbnpGGdJFTm4p1KRd65k3f/VDqb90e79ct5POQmkvFtHahykPHqsHj
         gyKnP/JUmyQ8ACj+tphC/2m8Zo1DIlt7h9UbZVJnhgiSsFy7l83VWlhQnO1FXgTbTBJq
         tpPXOeEmhLGdi9msjKGhdp62tXMFv+yGanoEw+a1+Uuzw6ZY6QnduTWulaV4o411r336
         DuT8cEO60ak758nlYklD17QmC1zn3Ob+Ix3WSvBcXNBbCNLFA5syAz3H/1HYv+Cz6D5O
         Pi8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WB4vLDNF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ed28256f44si142147173.3.2025.02.14.02.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2025 02:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-220c8cf98bbso37078275ad.1
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2025 02:45:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWTPJK4i4h0Emctt9RYUWcW9rYiq7oTdl3Al1wYse9sCU7DOW5jXXHPq0xkJW9Ej/IL2wzYlhrFS0I=@googlegroups.com
X-Gm-Gg: ASbGnctRtWpL/F1YCESX8sOgCXomtc2szhNTdBhaz1cU8o8kg52SfdnpJQ/5ipP7E1A
	U7xKYCoEdGrFtEjf54rQ5m6a4ZF730soe7Rjf8Jh3HqsDBi4SUptRLxXZD6LVw3eZI1wm/HYkFJ
	YhixEx3QXOjG6y4R9p86QrIh498qc=
X-Received: by 2002:a17:902:c408:b0:220:bc9e:fd6 with SMTP id
 d9443c01a7336-220bc9e1783mr191326545ad.44.1739529901147; Fri, 14 Feb 2025
 02:45:01 -0800 (PST)
MIME-Version: 1.0
References: <20250213200228.1993588-1-longman@redhat.com> <20250213200228.1993588-5-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-5-longman@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Feb 2025 11:44:24 +0100
X-Gm-Features: AWEUYZnWkxs8s2ZOaEuYd1RbG1DcAdDz7Uvyq0UrqfOFj1CPk6H-b44AgJXOrfQ
Message-ID: <CANpmjNM-uN81Aje1GE9zgUW-Q=w_2gPQ28giO7N2nmbRM521kA@mail.gmail.com>
Subject: Re: [PATCH v4 4/4] locking/lockdep: Add kasan_check_byte() check in lock_acquire()
To: Waiman Long <longman@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will.deacon@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WB4vLDNF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 13 Feb 2025 at 21:02, Waiman Long <longman@redhat.com> wrote:
>
> KASAN instrumentation of lockdep has been disabled as we don't need
> KASAN to check the validity of lockdep internal data structures and
> incur unnecessary performance overhead. However, the lockdep_map pointer
> passed in externally may not be valid (e.g. use-after-free) and we run
> the risk of using garbage data resulting in false lockdep reports. Add
> kasan_check_byte() call in lock_acquire() for non kernel core data
> object to catch invalid lockdep_map and abort lockdep processing if
> input data isn't valid.
>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Waiman Long <longman@redhat.com>

Reviewed-by: Marco Elver <elver@google.com>

but double-check if the below can be simplified.

> ---
>  kernel/locking/lock_events_list.h |  1 +
>  kernel/locking/lockdep.c          | 14 ++++++++++++++
>  2 files changed, 15 insertions(+)
>
> diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
> index 9ef9850aeebe..bed59b2195c7 100644
> --- a/kernel/locking/lock_events_list.h
> +++ b/kernel/locking/lock_events_list.h
> @@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)  /* # of rt_mutex_handle_deadlock()'s    */
>  LOCK_EVENT(lockdep_acquire)
>  LOCK_EVENT(lockdep_lock)
>  LOCK_EVENT(lockdep_nocheck)
> +LOCK_EVENT(lockdep_kasan_fail)
> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
> index 8436f017c74d..98dd0455d4be 100644
> --- a/kernel/locking/lockdep.c
> +++ b/kernel/locking/lockdep.c
> @@ -57,6 +57,7 @@
>  #include <linux/lockdep.h>
>  #include <linux/context_tracking.h>
>  #include <linux/console.h>
> +#include <linux/kasan.h>
>
>  #include <asm/sections.h>
>
> @@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
>         if (!debug_locks)
>                 return;
>
> +       /*
> +        * As KASAN instrumentation is disabled and lock_acquire() is usually
> +        * the first lockdep call when a task tries to acquire a lock, add
> +        * kasan_check_byte() here to check for use-after-free of non kernel
> +        * core lockdep_map data to avoid referencing garbage data.
> +        */
> +       if (unlikely(IS_ENABLED(CONFIG_KASAN) &&

This is not needed - kasan_check_byte() will always return true if
KASAN is disabled or not compiled in.

> +                    !is_kernel_core_data((unsigned long)lock) &&

Why use !is_kernel_core_data()? Is it to improve performance?

> +                    !kasan_check_byte(lock))) {
> +               lockevent_inc(lockdep_kasan_fail);
> +               return;
> +       }
> +
>         if (unlikely(!lockdep_enabled())) {
>                 /* XXX allow trylock from NMI ?!? */
>                 if (lockdep_nmi() && !trylock) {
> --
> 2.48.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250213200228.1993588-5-longman%40redhat.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM-uN81Aje1GE9zgUW-Q%3Dw_2gPQ28giO7N2nmbRM521kA%40mail.gmail.com.
