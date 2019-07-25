Return-Path: <kasan-dev+bncBCMIZB7QWENRB7V54XUQKGQEUW36ONY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F8677486F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 09:49:19 +0200 (CEST)
Received: by mail-yw1-xc3b.google.com with SMTP id l141sf36235845ywc.11
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 00:49:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564040958; cv=pass;
        d=google.com; s=arc-20160816;
        b=KiXCIDTb22BpikeqIDTdDKerwMoa+U7VAMuPeJH+7dSf+zY4h6BvSwsOj2PCbgCC+E
         SsKfiBrBBF+8IL6x0oXTc5pE7oBwN7NXEG87MxoAd351nbbqHN+a5VXuDRjbztdBHVia
         hWRXVKs219EVfRbcGp+2xwusPLXDG0kmZ/98+96GLU/bFV7v1upggWuPRrAHcUQy7mUd
         4qGVhGyiOmqPzPBw/Xn1uZIqhsQjJRnUtWUzNTxkCLlYXbumxWl4e3anYjpSKLjhcfXy
         6Jp+ZOxw013q2b6IAk/rk0rRFv1srFFUJ/etuhWSZynJHDvZCUWn+QVtzok4weiaufUP
         upHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=N1gXRB9plPmcu+ZIV5iKyqukHd4cF6mVNilnOP5CaTY=;
        b=Ua/S71AFidrdOnKTwQrGhBDf4pYgjrw6O0z8rpOsrv3DBYdg8e8Fny3qXWXeoSkmMR
         Eb+X7Sugh5nS+bUz2scyrs0cka0YmJo2lfk+ojjT+zZvERdhy0j1SPD27TWbpay+v1BD
         4/4ZzsDKxV2cQ+pbdUnLPHarh5luN2a0fdouCtSWyyy3Aswgvh7wksKBXuQ0j0hj5R4e
         3oT2kwZt5+kqw+t+gE3R13KAL49X0GLMquyxyTPES/DD2UYUwJR0d1YCNYyT8nwVwGAP
         UvlTbFO+CZk/gLTcEofMb1+HZSfDsrG5xSM9iECKP9rE9z1aCXAeWr4B9EIxeS8ak9cb
         GpPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=me1VA4L7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N1gXRB9plPmcu+ZIV5iKyqukHd4cF6mVNilnOP5CaTY=;
        b=JcdQ8P2N+6UrquzoiiJF/CWERYQE5ZZaeNkxBcNq+CUt1LTZKTKKNhBZ6tH524jBnn
         gfE2JT8ezgHmxUGaowjWRhyw8z4Jp0Q9WoUMgC/ufFPVYkMlFf+1ZPM6VCSpD4PThEjn
         XIg0x1h6IYCD5/jbud2Ju/pNWu9DifG36C4bJvHPodYeqZXETgKmUDVowO+/jypFV8tV
         PuyC9O0o2dfQxWSJAlyJFybwANAmqs0mkl3VCzhiKzQkEG15wmoSjYwcm49H/nyUTKeB
         jYvCTSdvpYMmpa7Ac98chup6676dBLQ467jeD4wKuBvgPpc7Q0iRXYnAvSyWE0Ea7nkS
         gJcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N1gXRB9plPmcu+ZIV5iKyqukHd4cF6mVNilnOP5CaTY=;
        b=hDVhndsW9f362ikjpHMePZl8aXruX53Q4p2MZ4vYUXkJtCoMSLE5C15oWzQp9RVr4T
         ba+zBVJIxlRQxL99Q0+5/Q2bSVtb17dYK7V0pPJKaZtbKgdJg1kQSq6oo903nLknJf9c
         H1KiKR4p5xhFSl8BNIDmxQmBGm7Lg/kuvlIvmDh8+tUH8/PtgVR7snyMDn+etciHIdby
         UH/mcV3p+mN70HeJa8tw/aW6Hr0irMyGuClY4YJi1DfYHk4ZwdiQZr+6Qb/1qMze436w
         bjXduoRQ7EpO8uz3bOwD5En8DUUC9nLVnMAlUlyJCqapxrFrPb0pxnx7UZkKHbZghqde
         RZiQ==
X-Gm-Message-State: APjAAAXx/9ElsiBlENmMze3qaMU49F9pDSmVvSRbXcu2DW7QjQwu66bo
	/NsA9653D2deVOmla3Ar+gM=
X-Google-Smtp-Source: APXvYqwj+3S34eTW3xQgi9qhpm0+FKwzx2/pGsB4VMf9WZC1dgebPvBkn5RM/80ujG5adeOYZsfn5Q==
X-Received: by 2002:a81:2e45:: with SMTP id u66mr51627855ywu.410.1564040958414;
        Thu, 25 Jul 2019 00:49:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:2393:: with SMTP id j141ls6564477ywj.11.gmail; Thu, 25
 Jul 2019 00:49:18 -0700 (PDT)
X-Received: by 2002:a81:f111:: with SMTP id h17mr16594502ywm.36.1564040958105;
        Thu, 25 Jul 2019 00:49:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564040958; cv=none;
        d=google.com; s=arc-20160816;
        b=POt38m/WGgQ5t7lB4e7QUtF4ogqzh7nSSAYX3FXCgJoWQ3+MIGvQvOg6tbCYfN6EeE
         tRzMTo4kQPP4LR+Nkz194hGTX9fK5wdjAuGCq3RseL2LKwitpJbu0hPm1G65kTOJv/Fa
         Rh8Ba6VtxLwoj8z8TkLOo+fK9KUP8caW5wzBjBzm3gwCh7wx6YTfilO8KRB2UmAlCjv5
         lkp2otEOU8Tjavf28rDQg0c4EltWwVly2uGJwN/q7h1bbcS1qXeds7nB/v3ChFxqY9a0
         6BM8UE97Ib8k5ItQtpV5iZjsaRYkZmkYYYSDH2C4l/5KXK8PzBuQKNVf8xhQ2L3zXZqt
         EAdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qp7FSL4EbzUxBEDwMYPtrsBZkkKZuOBCnuu+iYXPJvI=;
        b=p+Y8jkRqaoKaCmogTKCZvzSgGKGcm0j3J4/tJYE/bmjSVjFEqNupVOudgeO3VD83vr
         gsrLVY9ka+2yXZmsI9vo5+FMoCdEPflZSerKhOqdEm+pNryJDl/ffAly4FcUn4pyU7na
         n10w6MbIwPWsZhJ6h45nPMS9lR6tM+DUcUi+IwQRbWrQ6LLVdiQ422CXQpJzFe+cFHVx
         DyAuGqq10iW1JOA1ykWypkX4o9kidLJxN/o4kkJXmOZswxTr6fRw5cVWMFZx4O621CDx
         kF0tqZgwrtr9uXU2l8JmhtuW6c/7ry9p5WTpNJwQfighSL1W+1yth6hcrTE8javLMhl4
         aIGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=me1VA4L7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id f131si1545181ybf.5.2019.07.25.00.49.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 00:49:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id i10so95207264iol.13
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 00:49:18 -0700 (PDT)
X-Received: by 2002:a6b:641a:: with SMTP id t26mr35303516iog.3.1564040957221;
 Thu, 25 Jul 2019 00:49:17 -0700 (PDT)
MIME-Version: 1.0
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-4-dja@axtens.net>
In-Reply-To: <20190725055503.19507-4-dja@axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2019 09:49:06 +0200
Message-ID: <CACT4Y+aOvGqJEE5Mzqxusd2+hyX1OUEAFjJTvVED6ujgsASYrQ@mail.gmail.com>
Subject: Re: [PATCH 3/3] x86/kasan: support KASAN_VMALLOC
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=me1VA4L7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42
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

On Thu, Jul 25, 2019 at 7:55 AM Daniel Axtens <dja@axtens.net> wrote:
>
> In the case where KASAN directly allocates memory to back vmalloc
> space, don't map the early shadow page over it.
>
> Not mapping the early shadow page over the whole shadow space means
> that there are some pgds that are not populated on boot. Allow the
> vmalloc fault handler to also fault in vmalloc shadow as needed.
>
> Signed-off-by: Daniel Axtens <dja@axtens.net>


Would it make things simpler if we pre-populate the top level page
tables for the whole vmalloc region? That would be
(16<<40)/4096/512/512*8 = 131072 bytes?
The check in vmalloc_fault in not really a big burden, so I am not
sure. Just brining as an option.

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  arch/x86/Kconfig            |  1 +
>  arch/x86/mm/fault.c         | 13 +++++++++++++
>  arch/x86/mm/kasan_init_64.c | 10 ++++++++++
>  3 files changed, 24 insertions(+)
>
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 222855cc0158..40562cc3771f 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -134,6 +134,7 @@ config X86
>         select HAVE_ARCH_JUMP_LABEL
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN                  if X86_64
> +       select HAVE_ARCH_KASAN_VMALLOC          if X86_64
>         select HAVE_ARCH_KGDB
>         select HAVE_ARCH_MMAP_RND_BITS          if MMU
>         select HAVE_ARCH_MMAP_RND_COMPAT_BITS   if MMU && COMPAT
> diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
> index 6c46095cd0d9..d722230121c3 100644
> --- a/arch/x86/mm/fault.c
> +++ b/arch/x86/mm/fault.c
> @@ -340,8 +340,21 @@ static noinline int vmalloc_fault(unsigned long address)
>         pte_t *pte;
>
>         /* Make sure we are in vmalloc area: */
> +#ifndef CONFIG_KASAN_VMALLOC
>         if (!(address >= VMALLOC_START && address < VMALLOC_END))
>                 return -1;
> +#else
> +       /*
> +        * Some of the shadow mapping for the vmalloc area lives outside the
> +        * pgds populated by kasan init. They are created dynamically and so
> +        * we may need to fault them in.
> +        *
> +        * You can observe this with test_vmalloc's align_shift_alloc_test
> +        */
> +       if (!((address >= VMALLOC_START && address < VMALLOC_END) ||
> +             (address >= KASAN_SHADOW_START && address < KASAN_SHADOW_END)))
> +               return -1;
> +#endif
>
>         /*
>          * Copy kernel mappings over when needed. This can also
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 296da58f3013..e2fe1c1b805c 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -352,9 +352,19 @@ void __init kasan_init(void)
>         shadow_cpu_entry_end = (void *)round_up(
>                         (unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
>
> +       /*
> +        * If we're in full vmalloc mode, don't back vmalloc space with early
> +        * shadow pages.
> +        */
> +#ifdef CONFIG_KASAN_VMALLOC
> +       kasan_populate_early_shadow(
> +               kasan_mem_to_shadow((void *)VMALLOC_END+1),
> +               shadow_cpu_entry_begin);
> +#else
>         kasan_populate_early_shadow(
>                 kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
>                 shadow_cpu_entry_begin);
> +#endif
>
>         kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
>                               (unsigned long)shadow_cpu_entry_end, 0);
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725055503.19507-4-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaOvGqJEE5Mzqxusd2%2BhyX1OUEAFjJTvVED6ujgsASYrQ%40mail.gmail.com.
