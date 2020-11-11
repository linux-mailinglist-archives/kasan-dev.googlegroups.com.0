Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY7YV76QKGQE62LTXLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 032992AF447
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:59:49 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id v9sf1320568qtw.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:59:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605106788; cv=pass;
        d=google.com; s=arc-20160816;
        b=mZ0W4RqrwZf4EF3tBf6mhq1VpBI+4NZUTM7yWtysEt+ysMrZ+ZNiDVDSixBbmYzZck
         Eiuklox/Z+LJN1FflRp+R0QDisBTgLIjFtOPaiBnCKpl/7E6ciO61sOrR6F4PYai6eEU
         sw+WeQEefULSccPsI/HRrNWFQisFWgNCVnqwFQhMT+Z1mVeeSwZKJvADc1n2GqYHeGgm
         WhzaXBzBo/kO4WFWZSfBgbS2Dx1JL4ULkOFyZVrg4TSZf6CnvCtlei1AR7XjUvCNcJ0z
         3z52nt6OXl/RmxhXFznmo8rf+3ejQSCWrwiStzTM/IduBtSBbLvv/hB1kAQlBz5rOfSP
         0Twg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gsAPWFktrPwATx5WE6V+1CvUcgOtAepZGEW4lZHnfbU=;
        b=kxnyG792ccsJh6BAWNiKGxh+hYaHMt+8e1HD3fg5vM5TyvQVvqXYUzXOnebBbelqTY
         4HSnWvhKrJs68e73AJHpiSZ8GONfUPuXb4WDQ9n479MZWXJef1poD/GM35f3CUQeQkzJ
         MPtYiZtaV+7uLgwG2XjFONgYi8B27Bym6bOvakI9KQ2exzlkV/FaLBM67uDfiOQhakif
         i06MBhsyCnwGFAnMAxYsHt5VeUpTPidugvpvFqZhhbjjhvw0FLZfK6U4e4mLwMobGKDF
         jhojXnGVdPnBObyve30+SlZh8fiATCQ095cf938b4UtpihTXn9OZay85fTwDtDPDsOqc
         iSPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ty273gzZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gsAPWFktrPwATx5WE6V+1CvUcgOtAepZGEW4lZHnfbU=;
        b=MfG7TWUGyN6OCoH1CXf1UeqLdEu7wrRj+8kY0H0EZTmzNoJRl2oGXiV67Goejxsu7K
         MHgLnidApYpE3JlrYeqbh6s5ZckOdRsRVKjS57oWKhmb2T+IK6Ce1T/RYv9M5LKU36GF
         wOvGrldYSoQYImVgjIXMNcANL7d7gn7qhq7gg+dvlAX3Dt2zszaWacthZBlPnaEEQR4Y
         Ehu/ylCo4MrF0auj9mqNRVHRMZVZ8fEW8GyR/eck/jP3MS0IrjQPnjeLratsO46UYTR2
         a6A3/Ree7nv+tR4wjJq60zhr10Qz3WMKvR2BgyovVSz9jDxn1DxqOAjSfqRCIZoLcbMo
         h3pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gsAPWFktrPwATx5WE6V+1CvUcgOtAepZGEW4lZHnfbU=;
        b=j2r9bsLnKsprAlYUppgvcOVJBq08YETleM2OH9FYAuowZPBKdcK8W39AzBCAcDqTkc
         GaBtjD5rCFyXjVHMH/dQVdg47ltWKZD1zBhM0ygAS83TXhXAo0eISDxYL1+AIWOk0+GM
         6AVyYntR3EtMvdpVi/x7YcZ9rnWNYbJJixRjGG/ClLRjbF0ePSmIYJdeQ+sEXmS8MBX5
         XPkvsSut8pwlt94lOJ0yQ6nPzI+2q304S2wAGfJ8ditgmbfJEoaAdmVuSP/0YGB9ymLL
         lVumMpxZoJUJbjYuKaCrxk6We56RVM7npA/b90daLdkC9eQ0DrGiRe62jGmdhVVsawUX
         g1Aw==
X-Gm-Message-State: AOAM5303wWiyKXRQS2MLl2xzJ8s1SwNGW1x3p1L7R15MvkmqY6sm6bDo
	B6Ia6dOWkAJl29UbLGg5y40=
X-Google-Smtp-Source: ABdhPJxjo+GvHPfqaPZOd5q3WymKBL0HS0VlaKncbt+/eLVe4J7rc4wtDtFphD39vYFyXbYyc9omDA==
X-Received: by 2002:ac8:5c94:: with SMTP id r20mr14952294qta.158.1605106788068;
        Wed, 11 Nov 2020 06:59:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7805:: with SMTP id t5ls7748529qkc.9.gmail; Wed, 11 Nov
 2020 06:59:47 -0800 (PST)
X-Received: by 2002:a37:7143:: with SMTP id m64mr21190550qkc.280.1605106787567;
        Wed, 11 Nov 2020 06:59:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605106787; cv=none;
        d=google.com; s=arc-20160816;
        b=AXXkpnnT/rgXVgyQTQBJpjfAfNVQCtergwM4KsHq+N4CptfC8T11R4+19OVBMzY++H
         Xgjn6CHVG8r5in0m/UfbynyIyUtec7JOTUNphgU6HXVpXfRkfJxy8t2Cf6UmfqwBXIwb
         ge35mhcbrl5vQyV9lP5E2ZtZA8KYrh2pMUfWwbqVSA3PbWNiiy/JooTE4Y5NwqoVNTY/
         3Iz7btY8ESrXrqXRrIVTBwjWzFXFBY1bSkaKUvEPLrvk9+U+mSUv4jlgQ9TPweW0tJe1
         rShGD1Rz1LuyUWkPEr/mtk9wvdr65Ajb13q1W9/+1JGUhjfR4dFJSgkkz89XDkbeUJzC
         VPtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/fDcpIY0qGq2TOyxo24BIpfp3mzq21GpKr2EDtPYTac=;
        b=y4sIb7BqDxV56CQ5HJ9P2XJUXF4VSyr73nmkBF8x8YVQ+5c/zeKv3TDnrsEvw6jV2/
         oZzpSVA0YiRQTSieLel5OkhDOd2u5ffm40zOj37Huy4ZdECvWRBHe/byRJUD95DylCUZ
         ajDhsVwW+L0pt/WHTGEvmZUx4j3tgbVTK6vj0MPZ6As2xSPtmxjLQJ+Dx1lFcz4ENcT9
         gB0g+HNGANhOvwVGqCnBRWg2rESdWf0mXa9PV7Emf2oPA/THsMsjU3XarjvdH5FAsnMM
         mcdRCHlAXLC07kMg2YC2usY8jcGTfvB07P6oau2mYzzkSTekY4yALLQGvrqs5EmZcvBl
         56Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ty273gzZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id o23si151106qtm.3.2020.11.11.06.59.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:59:47 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id d28so1859713qka.11
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:59:47 -0800 (PST)
X-Received: by 2002:a05:620a:f95:: with SMTP id b21mr16896205qkn.403.1605106786994;
 Wed, 11 Nov 2020 06:59:46 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <91b3defa17748a61d1432929a80890043ca8dcda.1605046192.git.andreyknvl@google.com>
In-Reply-To: <91b3defa17748a61d1432929a80890043ca8dcda.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:59:34 +0100
Message-ID: <CAG_fn=VhzzFSXE19KJ+0-q1WitAu08scm8s-eXvQWYSqJTub=w@mail.gmail.com>
Subject: Re: [PATCH v9 16/44] kasan, arm64: only use kasan_depth for software modes
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ty273gzZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Hardware tag-based KASAN won't use kasan_depth. Only define and use it
> when one of the software KASAN modes are enabled.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I6109ea96c8df41ef6d75ad71bf22c1c8fa234a9a
> ---
>  arch/arm64/mm/kasan_init.c | 11 ++++++++---
>  include/linux/kasan.h      | 18 +++++++++---------
>  include/linux/sched.h      |  2 +-
>  init/init_task.c           |  2 +-
>  mm/kasan/common.c          |  2 ++
>  mm/kasan/report.c          |  2 ++
>  6 files changed, 23 insertions(+), 14 deletions(-)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index ffeb80d5aa8d..5172799f831f 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -273,17 +273,22 @@ static void __init kasan_init_shadow(void)
>         cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
>  }
>
> +static void __init kasan_init_depth(void)
> +{
> +       init_task.kasan_depth =3D 0;
> +}
> +
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
>
>  static inline void __init kasan_init_shadow(void) { }
>
> +static inline void __init kasan_init_depth(void) { }
> +
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
>  void __init kasan_init(void)
>  {
>         kasan_init_shadow();
> -
> -       /* At this point kasan is fully initialized. Enable error message=
s */
> -       init_task.kasan_depth =3D 0;
> +       kasan_init_depth();
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index f6435b9f889c..979d598e1c30 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -51,6 +51,12 @@ static inline void *kasan_mem_to_shadow(const void *ad=
dr)
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
>
> +/* Enable reporting bugs after kasan_disable_current() */
> +extern void kasan_enable_current(void);
> +
> +/* Disable reporting bugs for current task */
> +extern void kasan_disable_current(void);
> +
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
>  static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> @@ -61,16 +67,13 @@ static inline void kasan_remove_zero_shadow(void *sta=
rt,
>                                         unsigned long size)
>  {}
>
> +static inline void kasan_enable_current(void) {}
> +static inline void kasan_disable_current(void) {}
> +
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
>  #ifdef CONFIG_KASAN
>
> -/* Enable reporting bugs after kasan_disable_current() */
> -extern void kasan_enable_current(void);
> -
> -/* Disable reporting bugs for current task */
> -extern void kasan_disable_current(void);
> -
>  void kasan_unpoison_memory(const void *address, size_t size);
>
>  void kasan_unpoison_task_stack(struct task_struct *task);
> @@ -121,9 +124,6 @@ static inline void kasan_unpoison_memory(const void *=
address, size_t size) {}
>
>  static inline void kasan_unpoison_task_stack(struct task_struct *task) {=
}
>
> -static inline void kasan_enable_current(void) {}
> -static inline void kasan_disable_current(void) {}
> -
>  static inline void kasan_alloc_pages(struct page *page, unsigned int ord=
er) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int orde=
r) {}
>
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 063cd120b459..81b09bd31186 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1197,7 +1197,7 @@ struct task_struct {
>         u64                             timer_slack_ns;
>         u64                             default_timer_slack_ns;
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         unsigned int                    kasan_depth;
>  #endif
>
> diff --git a/init/init_task.c b/init/init_task.c
> index a56f0abb63e9..39703b4ef1f1 100644
> --- a/init/init_task.c
> +++ b/init/init_task.c
> @@ -176,7 +176,7 @@ struct task_struct init_task
>         .numa_group     =3D NULL,
>         .numa_faults    =3D NULL,
>  #endif
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         .kasan_depth    =3D 1,
>  #endif
>  #ifdef CONFIG_KCSAN
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 543e6bf2168f..d0b3ff410b0c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -46,6 +46,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t f=
lags)
>         track->stack =3D kasan_save_stack(flags);
>  }
>
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  void kasan_enable_current(void)
>  {
>         current->kasan_depth++;
> @@ -55,6 +56,7 @@ void kasan_disable_current(void)
>  {
>         current->kasan_depth--;
>  }
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
>  static void __kasan_unpoison_stack(struct task_struct *task, const void =
*sp)
>  {
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b18d193f7f58..af9138ea54ad 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -292,8 +292,10 @@ static void print_shadow_for_address(const void *add=
r)
>
>  static bool report_enabled(void)
>  {
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         if (current->kasan_depth)
>                 return false;
> +#endif
>         if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
>                 return true;
>         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVhzzFSXE19KJ%2B0-q1WitAu08scm8s-eXvQWYSqJTub%3Dw%40mail.=
gmail.com.
