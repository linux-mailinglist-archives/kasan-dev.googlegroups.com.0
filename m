Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA7KSSQQMGQE3NZMTWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B5566CFC34
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 09:06:44 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id z21-20020a9d7a55000000b0069f9c33a46bsf6611130otm.18
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 00:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680160003; cv=pass;
        d=google.com; s=arc-20160816;
        b=0qYObqw2/GEF6uIO10lqI4ox2UxLhAXvVFedmI7mlkVDxLMvE2nPAZdKPK7rHHCRv9
         MYmX9g8ZWhSAw8wrFDcM+B0FcOdRLmYHj9vs6zC9nZlgVRLCxmKqYwmhDeTzGK7EHv4v
         OwSCNQI+6R33nXphzcgNxSCP8oLf1vbXXKM6nFHyFDMjRg5QCxFtr8FpjFWYE/JMAh1M
         /UcA5h6nQo1vbPfi+Zhmjn1rb4EzMRw9hXKc8uW2SVCFWmmT6ng8QZHD1gwwN7/NpcDK
         hoxU8QFeKp245R2mZhqapsvQot7KfS1GUo9NY0fX/PxyRadYOjZsXCZtSHS5i5Kt14nZ
         Hvww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HCFY0b7wP4oRzXk8P6aeYAAJ8eebERJvbVB6MnevYGE=;
        b=Y673BD7StEo6OsOeqoOkFX1y8ZzKuLp/kKTED47ZSegSax4cy5fpbrvy57KsvcXqh+
         +Hgq2Fq8Zod65/1EbAEtfmDrhZMWHLRcED3y8IeP9dPg/k1FnGG3ScOHSMXaoyAKisCn
         VIMAu87f6JHVQkp9cZT4g7mZxwZqx2Or8slvw2sTsjXyd1ekT1H3sng43TWOi7Zwb3Fa
         ZxUPeBHGY7xJkFKLVMSD+6+pNaKkRXjyD7q5VN3ybu/CsxlSUu3Os4l3E+X3Q2ngb3a2
         xfoijiZAK/tCz8xc0/uMcG1wRH92gSKspsrqD/ws3lYXHAYcBFrKlRyW1YkklNZO8WoD
         0j0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tAPDCrL2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680160003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HCFY0b7wP4oRzXk8P6aeYAAJ8eebERJvbVB6MnevYGE=;
        b=L6NWhhmtqJNC14ao3VTOln7zSOx9nhFwcIGd7Mwevxc2Cg0CETy5UPNVwFvtwb7Mqa
         K3HIIET04VeOvfUC1Wh6pGFrEj7RNhdQjwlktfqZa17Vp2u1RA82BX6CEagFsoNMZXaj
         x7SxqIaeR7VhJcUPbD+pxWWrolKg8SD2V37gQHKZWNzBXd7fU8TiGB+sFDmaNAaUd3xq
         kK9zzRQacyn3IbcFl7HFBZvV8xWZRtpIPNmlbUrJZPXKV2VYANzV4zqh3mcGrqnzD+jF
         uPRVPxLhqgNf8AW6CtMcGQg0LU6LMc4fNOGWoXp48yqB43wkiCL9uUiDFuc/AIBEfbWd
         ropg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680160003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HCFY0b7wP4oRzXk8P6aeYAAJ8eebERJvbVB6MnevYGE=;
        b=2RtWCFAgjdOhxcLFQcXA4nU5+8IWkeWWXhmpfczCC3QzBPSXJPYZlRBeakpn+mEG7i
         tcJwh/W6ERDxtCN/8nYm0twld4U1Dzy/j1PFtNo3Q9E/UDJrdORmbitvUCRf4ppfcX+v
         7vF8bk0JdUd3GMTQuRxDixEeOiceyV8uSZh+/KG9eUs+hhEd4uiL1bpSCji4hm/knNjM
         E7qY7MMIrf7qYO1fT6mB6wkyWjBsRMfUhYQ1g98ZZXKigU/kcb2n0QrsX4jQngbzwHvK
         Zb4Q8o3bt6+462DS/r7nbRn0WNPb1LN0UVrzSNbC/7i7hULOhC+hwQs7XcMFNLMbecLm
         xc/w==
X-Gm-Message-State: AO0yUKWGyOAb+m682uMZmsBPxNIXcrqZdIgCrepdKSQwWUk7cejiD3oO
	NthD51aYuycj69glaM9JwPw=
X-Google-Smtp-Source: AK7set/meltQ12Zbkx2Vr+VcZZ21Kk/i0Cezn6/UuS/yKBjCJykVd4pBG5zVRPOuH0FdmQDvS+6J5A==
X-Received: by 2002:a05:6808:659:b0:378:30dc:ae5b with SMTP id z25-20020a056808065900b0037830dcae5bmr6410580oih.5.1680160003205;
        Thu, 30 Mar 2023 00:06:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:631b:b0:69f:7d7b:d8f6 with SMTP id
 cg27-20020a056830631b00b0069f7d7bd8f6ls162427otb.4.-pod-prod-gmail; Thu, 30
 Mar 2023 00:06:42 -0700 (PDT)
X-Received: by 2002:a9d:7242:0:b0:690:f6d8:1f7a with SMTP id a2-20020a9d7242000000b00690f6d81f7amr2120215otk.19.1680160002438;
        Thu, 30 Mar 2023 00:06:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680160002; cv=none;
        d=google.com; s=arc-20160816;
        b=SZTzjaIjhygUxLdPiwGFbJAtHcn2cbXb4aTuvJanBOZqI50Xis5gHJT2S5gT5TSi3t
         cZ/PvIM5LOSwULakkfch+4ztm5zIOhj9MwS9UJS5LlSadCj3gOM2FICE0oVEq0t13I0g
         i6EWU6AMnUF8EVegW7tQJai7JM5cUvpRgCzTX6njoob9jYdagpIcnE74k+IXO1eg+qf6
         ZVoLAcy8pKqoMB5sgB5cUEw1iMC7z9CCzS1GOMTQ9eOp8VkQ6VwVEkR0F4rLzTrPigdU
         4rtg1N+7lU8NGQaP1YXeUrYa0hVFkalNdhe/96/omWoZ/Zthb/HY1bhTXE88Vd4UWilx
         HSlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3Jf77sSPY4oJIgQXlj2P7B6cPGnB5oBp7xZ5q79ACU4=;
        b=omRzDMUtn+4XZ4A/flbmxdFiEJcQslcc+VndRDn6TtTdlD6O/PKtZ4feeSMSscLo5Y
         L+lmx5BcGYNxtgiwZNh041DrJaHGI6MmJgU7MEPtTW1DJPTE9o+YvxcAHsQq9h3BSoCx
         uQSQ6klmPrTpBSQrBZ57SoqWOFg+SPGx0AvZTPQLhcxiOS6dj1GnCxA1VKSicxSy/tV5
         XPMXAw0Aok5EXIz0VvHlsd02kmtBUaF2mu4+QSy7lvFcyecR5JIhiTh3NMSopgu+pEyR
         nFEOQQWMg401mH2u4v1TRlCroRhlLKUnM43W1SQFZDW4rMOxxhE7DBB/rFefG69C4fmP
         Mv0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tAPDCrL2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id cb11-20020a056830618b00b0069f8cf409d9si2821533otb.2.2023.03.30.00.06.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Mar 2023 00:06:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id f188so3864941ybb.3
        for <kasan-dev@googlegroups.com>; Thu, 30 Mar 2023 00:06:42 -0700 (PDT)
X-Received: by 2002:a25:3606:0:b0:b72:1fae:defe with SMTP id
 d6-20020a253606000000b00b721faedefemr5211656yba.25.1680160001845; Thu, 30 Mar
 2023 00:06:41 -0700 (PDT)
MIME-Version: 1.0
References: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
 <d14417c8bc5eea7589e99381203432f15c0f9138.1680114854.git.andreyknvl@google.com>
In-Reply-To: <d14417c8bc5eea7589e99381203432f15c0f9138.1680114854.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Mar 2023 09:06:05 +0200
Message-ID: <CANpmjNNqYN4h7bG6DZtzhevcUjevSy9amoFzp5J1y+CN=xKv_A@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] kasan: suppress recursive reports for HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Will Deacon <will@kernel.org>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Weizhao Ouyang <ouyangweizhao@zeku.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tAPDCrL2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as
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

On Wed, 29 Mar 2023 at 20:38, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> KASAN suppresses reports for bad accesses done by the KASAN reporting
> code. The reporting code might access poisoned memory for reporting
> purposes.
>
> Software KASAN modes do this by suppressing reports during reporting
> via current->kasan_depth, the same way they suppress reports during
> accesses to poisoned slab metadata.
>
> Hardware Tag-Based KASAN does not use current->kasan_depth, and instead
> resets pointer tags for accesses to poisoned memory done by the reporting
> code.
>
> Despite that, a recursive report can still happen:
>
> 1. On hardware with faulty MTE support. This was observed by Weizhao
>    Ouyang on a faulty hardware that caused memory tags to randomly change
>    from time to time.
>
> 2. Theoretically, due to a previous MTE-undetected memory corruption.
>
> A recursive report can happen via:
>
> 1. Accessing a pointer with a non-reset tag in the reporting code, e.g.
>    slab->slab_cache, which is what Weizhao Ouyang observed.
>
> 2. Theoretically, via external non-annotated routines, e.g. stackdepot.
>
> To resolve this issue, resetting tags for all of the pointers in the
> reporting code and all the used external routines would be impractical.
>
> Instead, disable tag checking done by the CPU for the duration of KASAN
> reporting for Hardware Tag-Based KASAN.
>
> Without this fix, Hardware Tag-Based KASAN reporting code might deadlock.
>
> Fixes: 2e903b914797 ("kasan, arm64: implement HW_TAGS runtime")
> Reported-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> Considering that 1. the bug this patch fixes was only observed on faulty
> MTE hardware, and 2. the patch depends on the other patches in this series,
> I don't think it's worth backporting it into stable.

Given the Fixes above, it's likely this may or may not still end up in stable.

> Changes v1->v2:
> - Disable preemption instead of migration.
> - Fix comment typo.
> ---
>  mm/kasan/report.c | 59 ++++++++++++++++++++++++++++++++++++++---------
>  1 file changed, 48 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 89078f912827..892a9dc9d4d3 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -72,10 +72,18 @@ static int __init kasan_set_multi_shot(char *str)
>  __setup("kasan_multi_shot", kasan_set_multi_shot);
>
>  /*
> - * Used to suppress reports within kasan_disable/enable_current() critical
> - * sections, which are used for marking accesses to slab metadata.
> + * This function is used to check whether KASAN reports are suppressed for
> + * software KASAN modes via kasan_disable/enable_current() critical sections.
> + *
> + * This is done to avoid:
> + * 1. False-positive reports when accessing slab metadata,
> + * 2. Deadlocking when poisoned memory is accessed by the reporting code.
> + *
> + * Hardware Tag-Based KASAN instead relies on:
> + * For #1: Resetting tags via kasan_reset_tag().
> + * For #2: Suppression of tag checks via CPU, see report_suppress_start/end().
>   */
> -static bool report_suppressed(void)
> +static bool report_suppressed_sw(void)
>  {
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         if (current->kasan_depth)
> @@ -84,6 +92,30 @@ static bool report_suppressed(void)
>         return false;
>  }
>
> +static void report_suppress_start(void)
> +{
> +#ifdef CONFIG_KASAN_HW_TAGS
> +       /*
> +        * Disable preemption for the duration of printing a KASAN report, as
> +        * hw_suppress_tag_checks_start() disables checks on the current CPU.
> +        */
> +       preempt_disable();
> +       hw_suppress_tag_checks_start();
> +#else
> +       kasan_disable_current();
> +#endif
> +}
> +
> +static void report_suppress_stop(void)
> +{
> +#ifdef CONFIG_KASAN_HW_TAGS
> +       hw_suppress_tag_checks_stop();
> +       preempt_enable();
> +#else
> +       kasan_enable_current();
> +#endif
> +}
> +
>  /*
>   * Used to avoid reporting more than one KASAN bug unless kasan_multi_shot
>   * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
> @@ -174,7 +206,7 @@ static void start_report(unsigned long *flags, bool sync)
>         /* Do not allow LOCKDEP mangling KASAN reports. */
>         lockdep_off();
>         /* Make sure we don't end up in loop. */
> -       kasan_disable_current();
> +       report_suppress_start();
>         spin_lock_irqsave(&report_lock, *flags);
>         pr_err("==================================================================\n");
>  }
> @@ -192,7 +224,7 @@ static void end_report(unsigned long *flags, void *addr)
>                 panic("kasan.fault=panic set ...\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>         lockdep_on();
> -       kasan_enable_current();
> +       report_suppress_stop();
>  }
>
>  static void print_error_description(struct kasan_report_info *info)
> @@ -480,9 +512,13 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>         struct kasan_report_info info;
>
>         /*
> -        * Do not check report_suppressed(), as an invalid-free cannot be
> -        * caused by accessing slab metadata and thus should not be
> -        * suppressed by kasan_disable/enable_current() critical sections.
> +        * Do not check report_suppressed_sw(), as an invalid-free cannot be
> +        * caused by accessing poisoned memory and thus should not be suppressed
> +        * by kasan_disable/enable_current() critical sections.
> +        *
> +        * Note that for Hardware Tag-Based KASAN, kasan_report_invalid_free()
> +        * is triggered by explicit tag checks and not by the ones performed by
> +        * the CPU. Thus, reporting invalid-free is not suppressed as well.
>          */
>         if (unlikely(!report_enabled()))
>                 return;
> @@ -517,7 +553,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>         unsigned long irq_flags;
>         struct kasan_report_info info;
>
> -       if (unlikely(report_suppressed()) || unlikely(!report_enabled())) {
> +       if (unlikely(report_suppressed_sw()) || unlikely(!report_enabled())) {
>                 ret = false;
>                 goto out;
>         }
> @@ -549,8 +585,9 @@ void kasan_report_async(void)
>         unsigned long flags;
>
>         /*
> -        * Do not check report_suppressed(), as kasan_disable/enable_current()
> -        * critical sections do not affect Hardware Tag-Based KASAN.
> +        * Do not check report_suppressed_sw(), as
> +        * kasan_disable/enable_current() critical sections do not affect
> +        * Hardware Tag-Based KASAN.
>          */
>         if (unlikely(!report_enabled()))
>                 return;
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNqYN4h7bG6DZtzhevcUjevSy9amoFzp5J1y%2BCN%3DxKv_A%40mail.gmail.com.
