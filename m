Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRWIVOAAMGQEFF2VAYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id F3B8C3005B3
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:42:15 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id z20sf3552314pgh.18
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:42:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611326534; cv=pass;
        d=google.com; s=arc-20160816;
        b=lw8ptOwRGOYIPf4tag4wjH4pyRfdGimO4CdcPpYnXILs70eYTqibBNScOMtguhOjxg
         6Unzw+CZSN2qaPKt1nJK2tZOXDGXD79QniWa4zUMWCd4mWmwDKinu/tF/LWdmHlj4xRB
         ecshfjCqRof38mLLlMwAl2DgtHGBXiWqrQvtORf1BRhXMzygQEJRxXxhXd493oSZDfwJ
         BYX7gpn/tQs+G+5YECH7WJUd6jm8meNuvXYeIbRARAxNLrfh1PwR90NBuRBxwiFLgf3N
         GKP0p+QH/OqVyeSFG8PLCkKV6iY79MjEoQCWGD3JRtNfHvSVAaiZvosik56tRmYdSH4S
         ePxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tx1YZjoq1ZauImf2HACUTUXcwYoXrIdjndTZvIIKn1w=;
        b=RELHLaekynbwjNHgWS0lh1d1khqCjsh5JWhJGtGcXrO/RdL/U3dYcbwKz7f+AC/osa
         F6UDJ7YBkDyy7Rv0aV6laIGizj7yxsm9BOKtiHp1G1H5E9Ngf0xujvf5/peo3qTqyLbP
         RG7VEooSyJbCZpvjSShB8PsY5f2GWf6QHkeU1232bqO6vDOUNQrsUa3BKQehVyMa9QWq
         0xkw9Ln9PKkZVs03NDOWBp7LgNhZ1XMRDPBKsu8p08yQAITy4BR8NPz5yk7PDohBUu89
         TjH3qwDra1XafS/pfgBjR5hsysfT9yFXVowdC2y2FmwyKwpe5mcmfrvjS1CL3luWdc3x
         Rang==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VswbVDlW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tx1YZjoq1ZauImf2HACUTUXcwYoXrIdjndTZvIIKn1w=;
        b=nldJmW8MhDQinAbbSBoVw+tXXySL1C0U884MZAhCkvctTrKGxtJSFq279vJKxR2jls
         BSfjRCPmONBafNaJuE+umiT+nSpuhVotGSZjOLKmi4znv9kQowHNANJrTvpZKIlfYk7U
         2SbBI+tCtMZ7RRpUnW+rH39sI4iZn7Pc5wkoBRmGrQgWqhz3cUoDLAksq9xt1Q5Ss7hI
         HYTvSlUiPqsriJL755ByCuS50EAW1cAJ0Rsrbw269+FAKnc5rkAOO2b4cl26QCPCJ5HX
         XaAhSmN/QjRGkAQJ81JagIjwUc556NZd/qY0TKk+iqtfliF6Ck3f//cdnknCfKWi92Ye
         bJbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tx1YZjoq1ZauImf2HACUTUXcwYoXrIdjndTZvIIKn1w=;
        b=WLGLeDQAMy9r/3tZC02hrYaKCrt0uBOPj2z1MVlAdSnU8hceSo3i6h0sAoIpwnkqIu
         Y1+5o8CH6pLaTipVMHmrEVrsnHUb7MzzGDdemS+puYAx4ERXZiLMWvx84nkSIFBubfN3
         Xx6f0DixgMSufX0n3O75qBbtLZD/VCPXCp4hYjIBZGxEVR8x0rc3KoiHA/6PmGXsVrZg
         0WDSzKIabvt7SzcgqnSFTmqdq6kZqIS12abQtf523YkKl2aMFj2H0lQXk/b7CeBkzE8D
         cqAgHw2qeDzKQZi4QAddXxALmjJkJ0i+ApSWOcqZvQXuaDBw5kNUrQLGaSz/9ppF2ULQ
         GpLg==
X-Gm-Message-State: AOAM5305dqRUNRWtnmOVNYVEMdFRfvzrSK/blVmcUZUsMEWMkj+c4feE
	xRvn+cZXrV2Cpxbi2LdHX30=
X-Google-Smtp-Source: ABdhPJzX0TSjGK/a4VIKTlz0XWiDmHmj2NNfZuBtI65nIIIATkzYJHGwkJRF443oZ/jp+U8gxj/mTw==
X-Received: by 2002:a63:1b58:: with SMTP id b24mr4992570pgm.38.1611326534713;
        Fri, 22 Jan 2021 06:42:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c1:: with SMTP id e1ls2798958plh.10.gmail; Fri, 22
 Jan 2021 06:42:14 -0800 (PST)
X-Received: by 2002:a17:902:ea94:b029:df:d090:4d9b with SMTP id x20-20020a170902ea94b02900dfd0904d9bmr4812516plb.55.1611326534182;
        Fri, 22 Jan 2021 06:42:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611326534; cv=none;
        d=google.com; s=arc-20160816;
        b=VJP8X579HlrBlXMd8qewYt8bW13/pQYUAQVqzDq+ExNAm6IKmAYoZ7ifURNzrFFiqk
         PtisGopCJ/eBDeSWSSIl/KyqM+0MASkSeGYasbCKjDfmCS8ZHkrbIbgdxqvmzD4SOLT8
         rJDp7c76IPOdDOqwGpwa7T3hUqL83OF6ycTQgn969boS3ipBWMUy9xp6VBRZ7mEg9VRU
         EXq6r2UNfpXmJEOuIldCXyCWGourXJAx+SsoDGCkXhsMVD7hgfNzN0bpz/dIry0wKWtq
         M5G+p1uSFbnt0jRgN8NHyCi4ItwDmZ+oMNf3C0asM/AiHLSP2AQK+6iPkepZCxD6J3WT
         W3JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TDW0uo0U4I8F8s+gzPDSjcYPS9epJOiCg4X2p7A7eF4=;
        b=SGqUnxRAjpWTAZCI/occmMODtH55P4eljfQBGk9OKhxhkt3JOGYuy9V7l73gWJabd+
         rivJzSGdCi2cz5onn1rNM7TOtorQikdQV1na91fQKONrjSatYBlEaGvHc/tf6dlB+lnE
         eGW1AZ0ZQmjRdHWsRSsBjnNBQp8lHR4m7OdymGaaOfL1di+c6nN2aziSo3RddIj/Psvf
         YCVQmzU0T8X7JiZXR96VsipBQxrzI20mPbAUGUpVaZ9RcfKtpIYvS2dLrlfZgqBuMcJ8
         7hPEp3i/2nakaXfIzY4VmlRBcXueX88fx/SR05fxQr+xSLheiv01BoY4HZ46bFZe/DcW
         ouBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VswbVDlW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id jz6si598835pjb.1.2021.01.22.06.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jan 2021 06:42:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id w18so3823003pfu.9
        for <kasan-dev@googlegroups.com>; Fri, 22 Jan 2021 06:42:14 -0800 (PST)
X-Received: by 2002:a63:4644:: with SMTP id v4mr4977707pgk.440.1611326533664;
 Fri, 22 Jan 2021 06:42:13 -0800 (PST)
MIME-Version: 1.0
References: <20210122141125.36166-1-vincenzo.frascino@arm.com> <20210122141125.36166-4-vincenzo.frascino@arm.com>
In-Reply-To: <20210122141125.36166-4-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jan 2021 15:42:02 +0100
Message-ID: <CAAeHK+ydhzfrdrPbjok20rgMEYykpfmjcRASm_bTfhuTVXF_VA@mail.gmail.com>
Subject: Re: [PATCH v7 3/4] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VswbVDlW;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434
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

On Fri, Jan 22, 2021 at 3:11 PM Vincenzo Frascino
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
>  include/linux/kasan.h |  2 ++
>  mm/kasan/report.c     | 13 +++++++++++++
>  2 files changed, 15 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bb862d1f0e15..b0a1d9dfa85c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>
> +void kasan_report_async(void);
> +
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline void *kasan_reset_tag(const void *addr)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 234f35a84f19..1390da06a988 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -358,6 +358,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>         end_report(&flags);
>  }
>
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)

This looks wrong, CONFIG_KASAN_SW_TAGS doesn't use MTE, so this
function isn't needed for that mode.

Let's add an #ifdef CONFIG_KASAN_HW_TAGS section in
include/linux/kasan.h after the HW/SW one with kasan_report(). And
only leave CONFIG_KASAN_HW_TAGS in mm/kasan/report.c too.

> +void kasan_report_async(void)
> +{
> +       unsigned long flags;
> +
> +       start_report(&flags);
> +       pr_err("BUG: KASAN: invalid-access\n");
> +       pr_err("Asynchronous mode enabled: no access details available\n");
> +       dump_stack();
> +       end_report(&flags);
> +}
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BydhzfrdrPbjok20rgMEYykpfmjcRASm_bTfhuTVXF_VA%40mail.gmail.com.
