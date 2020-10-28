Return-Path: <kasan-dev+bncBCMIZB7QWENRBPU54X6AKGQENFZX2HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 03E5129CF99
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 11:58:08 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id j13sf2414812pgp.11
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 03:58:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603882686; cv=pass;
        d=google.com; s=arc-20160816;
        b=jopm2AH2XGZhuFhRPy9pec8fo0RSf+I/3PwoOnJM+ZuBeuW1pBOxv0ZetEQBdLTIKl
         vOCUIdBMHeoENuPOAGat9WLuB3OjLHiHJhzDUN/19bi/+QCuFE3yq935Yk4XrrvguEHa
         d4D3ak70wHLzd9nU3H0XHrH/bidYrVObwfUvs/UjWUUInuOmzzUbNb11bxPZn7TcKfiM
         k8wN1Ka615RIu9k4vAAb5Dcu2YL2TuaajwICAofiPydwr3wMgAfPgQWBHh6L8lg3IzBf
         /s+XSW3uVSqvLxVq18V7qUDYsL8ZS4R18F7S989hEtOduJD3ZjqOeTNATxD7VUnd6VoH
         JDZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=04QI/q7t/232G/cag14sqDvAxwhAwLNYnGRy8BRTGVE=;
        b=n9bsp7lB5uZdd42C4kYwsL2WVUNKPWaVNrLsauDff97OeC4tElsx96U3BIcFtYOIZK
         9ln6hulmkNoRn4keWLtP4xU2lZzF3XKQbvWxNrypMtWRLpPWZJQUk1acEUqBFlxfUiDI
         7DPgP+X8svJ7iSQ6m4jTt/vCVQK7st2ISTR43Yvkc4rhzoklgC+GLAyngdAx5F16hoZh
         wltOyI/58ADv000pT0x0ppjQh0GP0aOlDmKK/mO1vwpiKq0Z75S0XdRqp2XyKkiyOHYg
         WdQUQTUUzRGHk8WKCatMin2ZjgAmrOtZmHeJFJ/admyNMsaBdtyswNCEbvRzQCNDCaoy
         DRvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cbY/uyv1";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=04QI/q7t/232G/cag14sqDvAxwhAwLNYnGRy8BRTGVE=;
        b=igVBFn9DKlCngEsedfpz3QZ5QwnPhHIdFwEWBo61S16/nVftQDYGk8zrrB1r87qU79
         HSKhzjB8cdIJTjb32OGbZ22ms/dM3QvJfPdHbvyhu3SEXDDQQU7DWL15iqaPDUeeSP8o
         JmuplCs8INilKs/mThx7ZXnqvolMvaRxI7NVsayBEvnZOuFlF158ARUDmSY+BqD0hAAe
         1nqLZfp7/zz3DPruBAQdSf2PxIuD2HwGB/0fkHB3whXbH71F1g7ZSstpffflZRJJOA+2
         PDezRPJZxv5DQdNBmcE7/gctnGQk1lb2UGSTAryJcTdBeJOqxVXVAZQ+sMAkx8fTpTrn
         yEsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=04QI/q7t/232G/cag14sqDvAxwhAwLNYnGRy8BRTGVE=;
        b=h4GcHI/iugDzfM4qzd2CvEMcVTK1EvP1kBkEXNwlcXoOdEjeAn97r9Lea2pDhepaMB
         E4bmK8Fz5wfZbypAwNzBl8jgFDvQ4/RhD1iZRjpANkSa25OhtStXu2RA5nmMB/+RSiCV
         A4QKjE8XNh37T5vJOqYOlETIuGyjl9pwB76wGuFUcIY19cR+ppw4oJWNJjw0tEK8Rm9G
         XdKqNNbcq5hUar7T2EGToj3F7ZUsx7MIW2rzQqy0W6lSJidOqkC7IPQpzLxtabpC1i67
         4228axVFVlwGGb/GzlFQZW2q0sZ295MH82n7Ze+oLq+ZjdyuT8vXB5Jespec2x3/JRSh
         1Fog==
X-Gm-Message-State: AOAM533DL0lOvaVY1tOk3p09xwYlaajCfUn0mVfHHSiwK3KmcUeryPlK
	5Wwyh9LKUSYjgx3a20J/ZdE=
X-Google-Smtp-Source: ABdhPJyD7TM9N/w1ajecNi17BwaGcDjolA8k0MJBB0rgo0e4PIEaV8R9jPCU3R2vzJuQs9qbU1U84w==
X-Received: by 2002:a17:902:c252:b029:d3:d480:9e10 with SMTP id 18-20020a170902c252b02900d3d4809e10mr6621370plg.47.1603882686347;
        Wed, 28 Oct 2020 03:58:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b56:: with SMTP id a22ls1806894pgl.6.gmail; Wed, 28 Oct
 2020 03:58:05 -0700 (PDT)
X-Received: by 2002:a62:75c4:0:b029:163:e95e:f52e with SMTP id q187-20020a6275c40000b0290163e95ef52emr6973850pfc.52.1603882685823;
        Wed, 28 Oct 2020 03:58:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603882685; cv=none;
        d=google.com; s=arc-20160816;
        b=kHisSicuzmo+HLocZ8Zz0lbPeOgjmx7kC5acFt1fG5aLv1OsrSatXkfeSq7cluXKKh
         TwOe9FAFM5Lwwglkkdt+Bli6S8hntquW+Vsd1JalNYG4eq1NtpFP1rizWQYxTEPRlOGM
         O+IMwP7cHmM5UHnd652urnDoD4cCP8t6MLbsoMSGyShzGbRFM+bqMc+Pg9DxMY+my1Lt
         M5NxaIGrSsBTpyIVH5Ih8YtQlOfBGLyyyroe91gtUuBoZQNp9t8v7mDH0TknMijDdx0w
         zPVJVN77qVPUMFJn5enP/kvc/GO6DGUwTIKvZZldJOR9oy9s8LdZfgZK2QYV4/JjGf5D
         GlnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EA88P84wG7kGfxM9G+4L3+CwyjZDcOPZBnLgcdYKwco=;
        b=Lhix9IiSfCsdEQvK70JaEtn09vwd/bVR3izb9x+ADtcp27gkKzJAwi0IPppYLaxK8H
         /2G4GkrIhnL8z7BlWNpdW6IY2R/AgI9lRe9lmMPyqUG/jzipo2w+hYdYA7KqEuEP9JMS
         /GeIxblqvOa8u67XSZ9KAoU3IK+OemFqGtoRhy2qoMQbeh+8g5BEurpRe9+qtK7mw7Gr
         wRduM5K0yylU0MZ6PdKH2v4sJEegw+T4c3MXUpz6lhzvU3ter5kIiN8EPfi9U+0MARpN
         ObbiQQlaDpvkp5BBKMSel3hCRN5dPEQECMx8hrVqhlJ6xdHzE+6ITS6wEvUGUdR204AA
         ar8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cbY/uyv1";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id x6si211687pjn.2.2020.10.28.03.58.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 03:58:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id x20so4056079qkn.1
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 03:58:05 -0700 (PDT)
X-Received: by 2002:a37:a00c:: with SMTP id j12mr799887qke.231.1603882684633;
 Wed, 28 Oct 2020 03:58:04 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <84dc684519c5de460c58b85f0351c4f9ab57e897.1603372719.git.andreyknvl@google.com>
In-Reply-To: <84dc684519c5de460c58b85f0351c4f9ab57e897.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 11:57:53 +0100
Message-ID: <CACT4Y+Zqg475fdxWp_ARvb0APS=zKdLmzRW_0m4ZcoH6rADrzA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 08/21] kasan: remove __kasan_unpoison_stack
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="cbY/uyv1";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> There's no need for __kasan_unpoison_stack() helper, as it's only
> currently used in a single place. Removing it also removes undeed
> arithmetic.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ie5ba549d445292fe629b4a96735e4034957bcc50

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c | 12 +++---------
>  1 file changed, 3 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a3e67d49b893..9008fc6b0810 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -59,18 +59,12 @@ void kasan_disable_current(void)
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
>  #if CONFIG_KASAN_STACK
> -static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
> -{
> -       void *base = task_stack_page(task);
> -       size_t size = sp - base;
> -
> -       kasan_unpoison_memory(base, size);
> -}
> -
>  /* Unpoison the entire stack for a task. */
>  void kasan_unpoison_task_stack(struct task_struct *task)
>  {
> -       __kasan_unpoison_stack(task, task_stack_page(task) + THREAD_SIZE);
> +       void *base = task_stack_page(task);
> +
> +       kasan_unpoison_memory(base, THREAD_SIZE);
>  }
>
>  /* Unpoison the stack for the current task beyond a watermark sp value. */
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZqg475fdxWp_ARvb0APS%3DzKdLmzRW_0m4ZcoH6rADrzA%40mail.gmail.com.
