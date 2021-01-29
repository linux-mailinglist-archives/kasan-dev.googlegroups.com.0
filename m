Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNMR2GAAMGQEIGZALSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id D852B308BA8
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 18:41:10 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id f8sf7651976ybc.18
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 09:41:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611942070; cv=pass;
        d=google.com; s=arc-20160816;
        b=O/1AFJ7W0ssfx22+DLii0rXUSBbH30CCaybvRTjKn3cKatZLzkxggAM2nbCXvuFfyJ
         SmYDRrzsR7uIu4noMuu1SefYMWk54yRjtwEPu7IeJ8gG8gszwdJboGAFfuRWle1A3nhb
         EsL8qBPz/kIs4pNAV0Yy2MGWod0FeVKaZbQJxGUCPtXllEB4Fmtg06ule7Qe92VLZEA9
         PYu7wLrnpmzSdY+m5YbeqePsInkPxVFTdsIfycC4vxBf0onBduuPfuAD4pJUCHUJth4M
         8mOPSOrn6VydAsZt2X0PE7Tt3yjng4sJx/y9I19+nZqSwiIFFdxObs0Mpd33FykGi33K
         u5TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0BmO8pmzFX/luFuIy0Hfxu5eXTaeHcLsonHALowB7T0=;
        b=u/YqUGJXF7hUUn+L9oq1MapxW5znpX2VliQV8Wi6FJ475RfalWs+dQEjBB6hkdigcH
         GU76cF5Il5D7D8yFLLOF7MwyJPydN4c6SClEqui5GQdK4l8mZ7wIPq2z49gTV6f4kx8h
         BxCuAo/VniWzSrMVXiVxQ5VIIHYC1qKL6g0xcUb/O6UUGiAfb4ATxRcMSsEwmXuMGLB6
         E3JNKvJEr+bIHBo4iIaWHEK+NRHDGo1hXy/PMvQ1OYHqWXblzfHsvcLpmrZpKxkm3p0h
         5t70ST05n0VMIYP/yiwaFYE6WH7Eh87y40cC9S6tHEgLMYD/BMR1mG1SqpcOLeq23U0K
         IStQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PHbYJzbO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0BmO8pmzFX/luFuIy0Hfxu5eXTaeHcLsonHALowB7T0=;
        b=IN7BTLFpH87QazQI+ajVkT3cRBb5G1cT9bjlQW+cykcHaOVo6jpXvYOB/tNA91iKUx
         sFRw/IEIgS/MskDOipkW9UIz+SqEvzCKWnewOpXlgtLToN5vnJF3sXqYY8peL/Em3uVT
         wNXFMHW/u8HJ4santnCijqttephZMHhD1RQv34zjDaXR4wXwGVfH2gvPnqncIR777Axf
         en2dX2oi88bEEdvOhdaL3dnq/ErQMKObpyUts0XR4Dfp4DjsIn5m4gvQkvozcuEWL7ia
         7zLXVFrqygLPqcre8PQIxCN+UoNcemMX4lO+O9TokMlSkkMTOisBCHk0FmL84TqYiLTC
         pweA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0BmO8pmzFX/luFuIy0Hfxu5eXTaeHcLsonHALowB7T0=;
        b=Vg2K4FoWqQu09XQhABpcOUEm/UcYy7HyFBWboZwUaWQpPeO3Uofog+mavX+PckblYs
         A5rsSBhaoB9Sl1Xq+1+wsPE5dWt++TpKFdT+4eZqHh2SX1NEzvE7ughcujAAcnspehxL
         KBjO7LVplBCoVXCqMHyHG400Sf+M6Z+sAl3KGA9DJI3ddn0Imc8vS0NQ9VQXESdYG35c
         691rpUjvivRY9Tr/Rg0CjcbenwKebGknUhe9/Q2+HqOqQ9g9C2yNvewkso1KIlb8vZuk
         cDvMHyiXXQSwN12syi+roxo09JHX4DBTJzRF7aIgQCIid1c2JQINr1F//qIycZUbrwwR
         JmCQ==
X-Gm-Message-State: AOAM530t37bo5b2JfsvRhwvDtrd2PAiji7TAD37t5x8KlT0V7WXAgOrc
	TQQoE0q6s2nOaIQ7KlUD164=
X-Google-Smtp-Source: ABdhPJxaXT2fdCUVg5BR2+8YyyDcGHIP+rZxyTH4kGpZLyfJbJm4Gi4Kn07eSxtKAKHbcc/iCIEIbw==
X-Received: by 2002:a25:3bd2:: with SMTP id i201mr7221650yba.246.1611942069902;
        Fri, 29 Jan 2021 09:41:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:828e:: with SMTP id r14ls725672ybk.7.gmail; Fri, 29 Jan
 2021 09:41:09 -0800 (PST)
X-Received: by 2002:a25:2f41:: with SMTP id v62mr7762968ybv.473.1611942069544;
        Fri, 29 Jan 2021 09:41:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611942069; cv=none;
        d=google.com; s=arc-20160816;
        b=HUs/qFW8RBGhxSGk1Wloc79s3o5i8FCGuO3L3dQjE2AWkPGq0RsrnA3UaHvMJoVMaN
         +pBn5OP6NP/kfAYPQdV1BgGtEEXLCTJnD2pIguQx6cZiuKWpLBi8ln8DC2R4fF15fJNY
         mF4s84zlgEnIZKzQGqu9KxixS7g/8NpROm65Xor+IIPLliaQyVXT6CVVIopl0hU3JZRP
         HADGT2SWg/yDwkV8QTSXbjkZ5Aj7mO3T8l4bkf6zwtY1W4MorLg4CPsvrCzdnhxO3aH8
         HNuGiR+XHvh+bTIRGKysoeWH0hGQNzRNCEoM2H/YWgQR5U39O7cRVXlV0PtSAtqaSPOu
         Tpmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z7/2anDq5WllUjyju4vzEFhuV34H44LI/WUUefdFyEk=;
        b=LEHM3LLfUAE0QBVzW7EF4+ZYiNWt6plqn3lRNGEj6qZDm9TZ09qejyg75wlDS/hY+o
         heBnwXBVCCKoT4IhBgeHuLIhn/vkXU+QRRIiLimCl30aitLOiAdc8heEbXW4jKJwj0MK
         PDpwoYe1sFdL/Ac7UGNwrfDtSuuBZ7TRQ/RHRDG7UguuQies4cCTQBfTgX4+PrX3KwWe
         DKdIhERAe7VqH9eVjnlP0ktmlBJeLcx4sWCfnK63qTErMmFg3hGVIUDynAWen9PBxDRw
         RGy/szXSzgxkQZMIZbIf1zzfTtrafoiUBEvP8AXKqTMcsXutkq5UgnZ0BBW+fQ5aRIF0
         +TjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PHbYJzbO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id b16si324163ybq.0.2021.01.29.09.41.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 09:41:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id e9so6755665pjj.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 09:41:09 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr5515927pjb.166.1611942068673;
 Fri, 29 Jan 2021 09:41:08 -0800 (PST)
MIME-Version: 1.0
References: <20210126134603.49759-1-vincenzo.frascino@arm.com> <20210126134603.49759-4-vincenzo.frascino@arm.com>
In-Reply-To: <20210126134603.49759-4-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 18:40:57 +0100
Message-ID: <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PHbYJzbO;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 26, 2021 at 2:46 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> KASAN provides an asynchronous mode of execution.
>
> Add reporting functionality for this mode.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  include/linux/kasan.h |  6 ++++++
>  mm/kasan/report.c     | 13 +++++++++++++
>  2 files changed, 19 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bb862d1f0e15..b6c502dad54d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -360,6 +360,12 @@ static inline void *kasan_reset_tag(const void *addr)
>
>  #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +
> +void kasan_report_async(void);
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
>  #ifdef CONFIG_KASAN_SW_TAGS
>  void __init kasan_init_sw_tags(void);
>  #else
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 87b271206163..69bad9c01aed 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -360,6 +360,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>         end_report(&flags, (unsigned long)object);
>  }
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void kasan_report_async(void)
> +{
> +       unsigned long flags;
> +
> +       start_report(&flags);
> +       pr_err("BUG: KASAN: invalid-access\n");
> +       pr_err("Asynchronous mode enabled: no access details available\n");
> +       dump_stack();
> +       end_report(&flags);

This conflicts with "kasan: use error_report_end tracepoint" that's in mm.

I suggest to call end_report(&flags, 0) here and check addr !=0 in
end_report() before calling trace_error_report_end().

> +}
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>                                 unsigned long ip)
>  {
> --
> 2.30.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy%3DOdg%40mail.gmail.com.
