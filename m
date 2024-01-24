Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQELYWWQMGQE5U2ERQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EFC783AF69
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 18:15:46 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3bbb6fd2ccesf6552798b6e.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 09:15:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706116544; cv=pass;
        d=google.com; s=arc-20160816;
        b=o7TrJ+1scOYO9JYQtKtKR0gEzDATDEvKOlvyw+iGiF6B1XUFy1wDwtyapCXhK/3p0S
         +oBd05qdgZg1bJPk4Tu5sJABtuoiYriVCstLpvnRGKGyxh6UEGzKvSFxCAtrWrqt3mGS
         0blwAzTclGQtkGkrJlcw5YeKPKMT/7WCWVXlEzaG8CjBRpVjmPHfjR5rWtSBzKPoMcSN
         X2Pkd/eyUCLiW0fwBBsZsxEGcDmdPotFCOp3hrL8hhW52ZnwUxKHLPGuhNChqH4omVsN
         DpvUXNmanQJmMpHSS/ykCePc8rNeRHKov8QzXJ68eqlDMKDG8S4mXB0Diljp+HcrYC+h
         1NqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LP+W/DlZfcyAO5D+S6ERhxz5p6M0PXhITFb2Ppf5+xk=;
        fh=EizqXmmqDI5iILr6fRc/86TA2fz6qvbgsnv0wUhGX54=;
        b=0YyhWppw1Csh/eJih2vH+GQUNb7pjxHFId5graT/st9OOnrocVEkxaqTnVg73QGD6N
         436b5k/txJpCeADHmwuET74YxAXq7E38KFdSitpyMAVcZeqtQv/zfaQZLSDb/Sxrivn2
         iLQrmg4K07/FXQ6p0hwyxJe5VS811Sri0QUwJGacAuODmdvYyvWtnHuJ2rlO1jQUltrM
         2bHWDkXmdaIjBpaR4SD7KfZAvYHAieROTHzteL8PpmmdMTp9f1RVueAkiNtrij/v0EUE
         RPyLu7VuSF1HYoAnzrp0fzmpQIdei0GDdE8lbF2GxmMk06aI1tmnY/K4Z4tgFMIjywiw
         89Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jnjaEBGw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706116544; x=1706721344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LP+W/DlZfcyAO5D+S6ERhxz5p6M0PXhITFb2Ppf5+xk=;
        b=AISWtmn1fbpiJMJgPn/ie24xbZA4g7tBtAMTx2zWlX1PCHDVEGHWAGTJcgKZt4k4qj
         lUBzr1N+z8ja7NFP/VFeuFHNYGFajh3RMG81YW/kY2kSflvzou/rXZxPH2Yj+x1Sr1kM
         bG0jt+ARTJibB1B0rKGWZiQZOAEekQXhpid55hq15eUtd4cL6ern2UZlZKsZcogVXXQb
         zVaTzVH5qc07XeNuVJi163DmcEEapZxOlp5aoJZg9JPXiYMelKX0jn0hoC89wdt2U92h
         wByMj2ifGjvBQsPbuNxCTBoV7Qz6Wrgd6Zz8Q1CEKteOiPZTGn8wux8RMUG/sAQPMnt3
         IEvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706116544; x=1706721344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LP+W/DlZfcyAO5D+S6ERhxz5p6M0PXhITFb2Ppf5+xk=;
        b=RA06+vsTD6Gi7hN4WSVKiBiXFUP+8n6paGBUjEtaMBszVryL1bjzEg0TVe++ouda6k
         Nt5g1immptApE99ymCVHZiO3tGFm6LrjlPH0BEhaXkHHA7NqVtuXUH2lRQr3Vy7cUVjQ
         k6ipqrZstzb9hR+4/cMw5dQjd6r7BWVj8bAW8mSYlwSQ5QD+lgIIkyJiQ9z9ma07rYkA
         EaPwxFX6YmHDmMzPexCvrhdIhxkOHssWg0MgaZ2psYghdxPlJ3veKzEeeVwSqHBUuAmR
         m8rAbFZiY4+nJMJRxVB8aChBJXrZF8Hx8968R36Z2iNFT5eXXNBDTnZwNNQQXN8tF8s+
         mh8A==
X-Gm-Message-State: AOJu0YzAY3PEJEgn/BTOTPUoRunCmX84i6JifreB+XF5sCzmfnhY/NHZ
	gIZiw70fYxoneq81YW3AXPD1JvictdUZa9KWn6CvwRfhp8ACfMl7
X-Google-Smtp-Source: AGHT+IFIkZXFLdLP6PBmlzdbujn1rphKTARyY1Enpom1tolj5nNkh8IkOZlbD0o8v/gzaTi42f3lqg==
X-Received: by 2002:a05:6871:5c9:b0:210:bd2d:857c with SMTP id v9-20020a05687105c900b00210bd2d857cmr3914490oan.90.1706116544448;
        Wed, 24 Jan 2024 09:15:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6592:b0:210:a349:1300 with SMTP id
 fp18-20020a056870659200b00210a3491300ls5352826oab.2.-pod-prod-04-us; Wed, 24
 Jan 2024 09:15:43 -0800 (PST)
X-Received: by 2002:a05:6870:4412:b0:203:d7a8:b4ff with SMTP id u18-20020a056870441200b00203d7a8b4ffmr3813701oah.33.1706116543538;
        Wed, 24 Jan 2024 09:15:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706116543; cv=none;
        d=google.com; s=arc-20160816;
        b=DdETDKPbBU782vybr7WtNWUidNwn3afHC2UkWXfCPI8PqfrCNh4UoYTm0r3Q0Ixjuo
         uj8vIAM505RE88m2dbu79Tzek2NRWcbJtVH9xzuB2SMtxTAcri9u4p22/ru599ZeSvih
         PLzWEsyr3gqAfRZbCL/qwReapnMbTKyydvttuXETlTcdeFTqHW+WmspRGxjm6CIGJNjt
         LpSdYwBJujkxgtW2VzEPhMJTx8kPO2jiJXLjO/1IkD97ghgyWUKyeq+xOFvXq8UN9fKN
         3CovhFGe8l/8BNxOmKc/z3tAMPPS8cdxYJwNBWda4wo2HSJelfBw2EQ5IEYNELueSTtt
         zKgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CBltU6iTnXDDudf22oqs+fdl0wSad9suT+55PGOStXc=;
        fh=EizqXmmqDI5iILr6fRc/86TA2fz6qvbgsnv0wUhGX54=;
        b=ST4pVhFSr67rT2lYQU8KzZOuLAn+PENqy7fqyu9r+HX+qjlzLbuTpUIv/RHSSXPB4U
         BAfLgEnoOHGdOPQninXpuffOIJlkLmkH/r8sRGCCYHSAAX12/GMpgXYMM/8v/fwavgXn
         f+HbOjmcZ0jBN2ZNqz7M6dwFQxpiQ+nUU44XnoQVJrN4FnHx2d8Af3zVE877z7OZw271
         Bv8jxGDAdDe3Bqt/8wyERm27gDEsDhJure/jcNZy5gtPkAOBtT4crTnhxGm+djgqAScb
         ocQovS2/yciyw+LSk4FxmIHsdZLSG7qDb85/U+HWy3E3t66qpOJPx5VwgyMOlkEEdS6A
         KtKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jnjaEBGw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92c.google.com (mail-ua1-x92c.google.com. [2607:f8b0:4864:20::92c])
        by gmr-mx.google.com with ESMTPS id d14-20020a05683025ce00b006e0faf7b7b1si232714otu.0.2024.01.24.09.15.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jan 2024 09:15:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) client-ip=2607:f8b0:4864:20::92c;
Received: by mail-ua1-x92c.google.com with SMTP id a1e0cc1a2514c-7d2e1a0337bso1799124241.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Jan 2024 09:15:43 -0800 (PST)
X-Received: by 2002:a05:6122:181c:b0:4bd:5537:c9bd with SMTP id
 ay28-20020a056122181c00b004bd5537c9bdmr1784548vkb.12.1706116542805; Wed, 24
 Jan 2024 09:15:42 -0800 (PST)
MIME-Version: 1.0
References: <20240124164211.1141742-1-glider@google.com>
In-Reply-To: <20240124164211.1141742-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Jan 2024 18:15:04 +0100
Message-ID: <CANpmjNP-9hV_d3zEHhUSpdUYpM1BAFKmTTzWwe5o5ubtwTvQAQ@mail.gmail.com>
Subject: Re: [PATCH] mm: kmsan: remove runtime checks from kmsan_unpoison_memory()
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Nicholas Miehlbradt <nicholas@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jnjaEBGw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as
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

On Wed, 24 Jan 2024 at 17:42, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Similarly to what's been done in commit ff444efbbb9be ("kmsan: allow
> using __msan_instrument_asm_store() inside runtime"), it should be safe
> to call kmsan_unpoison_memory() from within the runtime, as it does not
> allocate memory or take locks. Remove the redundant runtime checks.
>
> This should fix false positives seen with CONFIG_DEBUG_LIST=y when
> the non-instrumented lib/stackdepot.c failed to unpoison the memory
> chunks later checked by the instrumented lib/list_debug.c
>
> Also replace the implementation of kmsan_unpoison_entry_regs() with
> a call to kmsan_unpoison_memory().
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Ilya Leoshkevich <iii@linux.ibm.com>
> Cc: Nicholas Miehlbradt <nicholas@linux.ibm.com>

Tested-by: Marco Elver <elver@google.com>

Nice - this fixes the false positives I've seen in testing the new
stack depot changes.

But I think this version of the patch wasn't compile-tested, see below.

> ---
>  mm/kmsan/hooks.c | 36 +++++++++++++-----------------------
>  1 file changed, 13 insertions(+), 23 deletions(-)
>
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 5d6e2dee5692a..8a990cbf6d670 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -359,6 +359,12 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
>  }
>
>  /* Functions from kmsan-checks.h follow. */
> +
> +/*
> + * To create an origin, kmsan_poison_memory() unwinds the stacks and stores it
> + * into the stack depot. This may cause deadlocks if done from within KMSAN
> + * runtime, therefore we bail out if kmsan_in_runtime().
> + */
>  void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
>  {
>         if (!kmsan_enabled || kmsan_in_runtime())
> @@ -371,47 +377,31 @@ void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
>  }
>  EXPORT_SYMBOL(kmsan_poison_memory);
>
> +/*
> + * Unlike kmsan_poison_memory(), this function can be used from within KMSAN
> + * runtime, because it does not trigger allocations or call instrumented code.
> + */
>  void kmsan_unpoison_memory(const void *address, size_t size)
>  {
>         unsigned long ua_flags;
>
> -       if (!kmsan_enabled || kmsan_in_runtime())
> +       if (!kmsan_enabled)
>                 return;
>
>         ua_flags = user_access_save();
> -       kmsan_enter_runtime();
>         /* The users may want to poison/unpoison random memory. */
>         kmsan_internal_unpoison_memory((void *)address, size,
>                                        KMSAN_POISON_NOCHECK);
> -       kmsan_leave_runtime();
>         user_access_restore(ua_flags);
>  }
>  EXPORT_SYMBOL(kmsan_unpoison_memory);
>
>  /*
> - * Version of kmsan_unpoison_memory() that can be called from within the KMSAN
> - * runtime.
> - *
> - * Non-instrumented IRQ entry functions receive struct pt_regs from assembly
> - * code. Those regs need to be unpoisoned, otherwise using them will result in
> - * false positives.
> - * Using kmsan_unpoison_memory() is not an option in entry code, because the
> - * return value of in_task() is inconsistent - as a result, certain calls to
> - * kmsan_unpoison_memory() are ignored. kmsan_unpoison_entry_regs() ensures that
> - * the registers are unpoisoned even if kmsan_in_runtime() is true in the early
> - * entry code.
> + * Version of kmsan_unpoison_memory() called from IRQ entry functions.
>   */
>  void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
>  {
> -       unsigned long ua_flags;
> -
> -       if (!kmsan_enabled)
> -               return;
> -
> -       ua_flags = user_access_save();
> -       kmsan_internal_unpoison_memory((void *)regs, sizeof(*regs),
> -                                      KMSAN_POISON_NOCHECK);
> -       user_access_restore(ua_flags);
> +       kmsan_unpoison_memory((void *)regs, sizeof(*regs);

missing ')', probably:

+       kmsan_unpoison_memory((void *)regs, sizeof(*regs));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP-9hV_d3zEHhUSpdUYpM1BAFKmTTzWwe5o5ubtwTvQAQ%40mail.gmail.com.
