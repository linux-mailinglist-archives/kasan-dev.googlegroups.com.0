Return-Path: <kasan-dev+bncBC7OBJGL2MHBB356YO2QMGQETA6QWOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id E6127947CB6
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2024 16:19:28 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5d5bb58294esf3733583eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2024 07:19:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722867567; cv=pass;
        d=google.com; s=arc-20160816;
        b=yOmA5CbzPnhLhBy6xPPfZ7yAsjvwTiT1NhyZtmB781hqlAJsZXAwKkBT36FQ1hXBLo
         lWP3lf5/olGE+NIYNYwu4gjRmzn4fsGjtb+nX0RLCZs2hItI6NBiE+rOAXIoP5vIzxon
         WY8jriLqsmMFrMp26YqtE9XXXo2cyQTGpGaFI9Dwk48ql5YkCGd98uk+SYpYYGMUZTyq
         yrph7YXOKiCrpQuoJU6qc1EE3mqrakq+73CrMsCNV/OeAhwDqnGAXQZJFkYvUSe0QHL/
         b4uyEz9TF1Ic+BGBzS7NFHA11rPlbMUhMoQo+T2Lcs4j4PJlHLcaMZ72IZcQouOwjxrM
         UPUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1TGt+ibZZjMiv425Je0oRDeYN25F0maW7xl0jnYtnT4=;
        fh=BopoE3NNU4OeJW6DdAOaZX2wr9TGHS7rAc7QMO3aakw=;
        b=zqlzgtbYzs8woHfWRTFoVuExpsDAZqMQvVgwvDaQmPRo6zqu1GTYrSP7m5RlkJYEfs
         0T/eWKdAt33fg3GiGjehJ3tQpOafKHIHA+PGbZmOXKT6iy2pjhUtwfieeBkqPLZv3CdG
         C14+/0lukaFu0B6gM7aurvnVvA7v9QGmBZxVuihzg/NyCnKKO1+rAj3nmLtDe31Vai1j
         JApZJpaNPynJ9xr5ljncprZTvtqromxO2XGJOzIUGT4fKzqHuGhvahdBpIn+1VX2DZaD
         et7bkKAma16/J7//RZy+979EJoXRZPs4GaRAg2a2YTA297u/Z9pNHhmDV++XhBEzjWRt
         OddQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jX58wOFQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722867567; x=1723472367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1TGt+ibZZjMiv425Je0oRDeYN25F0maW7xl0jnYtnT4=;
        b=fedm3JLTRtR3ukujG+INLKr1W18/iKJWxnQlwrSMJ88zmt03j/VarJKEuGMUsCfsIG
         s6a/SO0LbPtSC1dqliU4aQmTLpCXQvBbY73XkSu7CYE4q4fmG2T/xmHveNtIQIzM83aR
         sx1xool2OI+qSGukbGiwBKSrnwWHklDb3257HFadpdLzkpIFnHhKhGnDv9nsE8zPhb6V
         tV3M6JDTwm0k8X/pShwIa46QZbqX5yucMW0HuC4XOJq6bALjnFmirbRmlq9YXmu5mvdC
         1bhX4+tR9nqtQDc01eOAyyGvOwnE9/NGxaMWQJs/0SSKhBiNbdVDBQQFlJH220emRKMd
         7X6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722867567; x=1723472367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1TGt+ibZZjMiv425Je0oRDeYN25F0maW7xl0jnYtnT4=;
        b=HYh3Dl/tGBeTOMpzHWuw4hhuTxa+sfvHiluH412ihsyzHeZ1ct5+d2i6Mg2+i6Mr1m
         cGGdtmd7WvzWWor9xkjrshuqonGq5sRh2arq3ny/hH6n1XFWf0A7MoVMsZeCd3txEJ7N
         1fX6SBbnaUW8o6tu+a3BXQvbqBo17W/+vNtQl3refpbLaf+G33f8N2L1GAIHrnNbYMDR
         zKButlXN4i8VZN9H3w/cOvE7wn7SiYuEg1eDXZcyoE6DztAPjPzvRazpucaWi0TSMROh
         zVtkkY5r4FNU2TaCPmiC+nNEk0PAAAqmZzHLTagIB9JPl518QSuOMYYjPIg88YrlUMFm
         Rhsw==
X-Forwarded-Encrypted: i=2; AJvYcCUQ5QrcOzsM2WO3aRQ5gEVITcRfhdmFKYCRctgw66k/W7jDVOtZmAz7TJQ+WciOP5pqNkMFGoek6WXd7IZA3c/gXes878J6Kg==
X-Gm-Message-State: AOJu0YwfEUfDRnp3zDPm8Y/Iguv12YnAe4ST7v0QLOzX/Izen8JrxsAL
	jNiWY8R7mkGBG8GqNy3YICIl+QHRphOLnT5kFKqBTQMrockCTfrB
X-Google-Smtp-Source: AGHT+IH2ysfK5WkfT8NSZJHU6cwQaLewGkSskfFBf2JTX6uY9pnFTaT7+JXoEekQhYjL4uslZtlgMw==
X-Received: by 2002:a05:6820:a05:b0:5d6:ab0:b9a6 with SMTP id 006d021491bc7-5d6c821d24emr5508511eaf.4.1722867567279;
        Mon, 05 Aug 2024 07:19:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d4d5:0:b0:5ca:fac6:13e8 with SMTP id 006d021491bc7-5d80155d8cdls1030859eaf.2.-pod-prod-00-us;
 Mon, 05 Aug 2024 07:19:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3d1xkN9psE1Ep/2mkb4as0CO/KQe2hIfoEqIiqXdodmVYjk3YUpl/NHD+logZNuudDXqQS+I4gk4Ri8iHjNm8zyyYhKPhV1J2dg==
X-Received: by 2002:a05:6808:211a:b0:3d9:2baa:9fd3 with SMTP id 5614622812f47-3db559e6d67mr4736558b6e.20.1722867566303;
        Mon, 05 Aug 2024 07:19:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722867566; cv=none;
        d=google.com; s=arc-20160816;
        b=PJbNBGpcMxySOm0S/zquvdF9M0FBQsZGtMKMm6lLA03JgFR7h1P5svN6ZF9X/2tSht
         qJE8Yc5nQfo8lja1+WSGd6este05Nwmq/ZrfJm3SzMyOByPxQjKw3yGJSnM3B0vagfrG
         hGbQc5WgqRSrkno0ID1nbyYEvx19QzAAT2y6s2ZMDfMIvZT3as6o3+wnkcBf0lUHMbHH
         k+c8eu1ZeTBTUWjr56P71V6q7mwT12mE4cdFYd3vd4I/Xo4rWHe5R8FAwaUws3RUaURF
         xD4JLhIxIRs2MjZZqVIwfvpGG86o1btyWgisLVId7X5KuvLbao0Te+Az0iX38liWgxBL
         JYdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4QK3mXKmgaR03PD7D3fidq6cLVoT9CcotLM0Tgs5EgI=;
        fh=59nDUAYJExBcHIkBkRSt51dhNDP0Jt0tw6wM0/01e5E=;
        b=IMnFAHplikguC/YTFrPY7pfidvv76BtZsWnXFAizlWxWJU4lnQ7MORnA2Yi6Irh1Xg
         VXSWM0uCMvffdNKg55WvpNRjf+V/KrGjRTqBrS6Wv4VO1A0ncdOT4ZIFhCLWEXtA4l3a
         MpWwLaRY1thWvzHCq+X4wOxwDnSQ4y+1lJQ0wvUArM2G1s3kQr65Nphv/MqE/3X4dfg/
         GDKwRI21wRGhAf91vB4JQBkigVaDVd8IWzAh0rYfyuiDpv2Mtp8XMojbPOBu4WuCMSPP
         Jck25Lp4GasHG/9P7Tk/H1l7gbGIjPolE21Zdz8wGdfHRa0IGog/ktYM2Aag8ufZg/jC
         GtAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jX58wOFQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x92d.google.com (mail-ua1-x92d.google.com. [2607:f8b0:4864:20::92d])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3db563e9e40si322853b6e.4.2024.08.05.07.19.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Aug 2024 07:19:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as permitted sender) client-ip=2607:f8b0:4864:20::92d;
Received: by mail-ua1-x92d.google.com with SMTP id a1e0cc1a2514c-823227e7572so3479400241.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2024 07:19:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXXUU28G9tZnyNAbleeWtSclgINVO40m6EWRdMTaQyqIqcBn9KuCjqS2YYvkk/A75Mc6RXR2LjpmBKDZUgILpJlWDXb9+IYnwZRw==
X-Received: by 2002:a05:6102:38d3:b0:48c:45e3:16e0 with SMTP id
 ada2fe7eead31-49457ab77eamr8999465137.9.1722867565483; Mon, 05 Aug 2024
 07:19:25 -0700 (PDT)
MIME-Version: 1.0
References: <20240803133608.2124-1-chenqiwu@xiaomi.com> <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
 <20240804034607.GA11291@rlk> <CANpmjNPN7yeD-x_m+nt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA@mail.gmail.com>
 <20240805033534.GA15091@rlk> <CANpmjNPEo=9x1FewrZYNG+YEK_XiX5gx8XNKjD9+bw7XWBV9Xw@mail.gmail.com>
 <20240805140601.GA2811@rlk>
In-Reply-To: <20240805140601.GA2811@rlk>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Aug 2024 16:18:47 +0200
Message-ID: <CANpmjNO94wMDfLpDQqM6XWp7fLjNH=ZSOCqmQ3jQgHQfPaHERg@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
To: chenqiwu <qiwuchen55@gmail.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jX58wOFQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92d as
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

On Mon, 5 Aug 2024 at 16:06, chenqiwu <qiwuchen55@gmail.com> wrote:
>
> On Mon, Aug 05, 2024 at 08:50:57AM +0200, Marco Elver wrote:
> >
> > The "allocated/freed" info is superfluous, as freed objects will have
> > a free stack.
> >
> > Consider a slightly better script vs. just using grep.
> Well, I think using grep is eaiser than a script to find leaks by a
> large number of alloc tracks.

Sure. But a slightly more complex script is a better trade-off vs.
impacting _all_ KFENCE users world-wide with slightly less readable
error reports.

> > /sys/kernel/debug/kfence/objects is of secondary concern and was added
> > primarily as a debugging aid for KFENCE developers. We never thought
> > it could be used to look for leaks, but good you found another use for
> > it. ;-)
> > The priority is to keep regular error reports generated by KFENCE
> > readable. Adding this "allocated/freed" info just makes the line
> > longer and is not useful.
> >
> How about print meta->state directly to get the object state for its
> alloc/free track?
> -       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> +       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago) state %d:\n",
>                        show_alloc ? "allocated" : "freed", track->pid,
> -                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
> +                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
> +                      (unsigned long)interval_nsec, rem_interval_nsec / 1000,
> +                      meta->state);
> > I'm happy with the "(%lu.%06lus ago)" part alone.
> If it's still a not good idea, I will follow your suggestion and resend
> it as v2.

No, that's just making it more ugly for no reason. It's replicating
the state info (just like before) for alloc and free stacks and
generally does not add anything useful.

See, we are writing code that is deployed on millions of machines, and
KFENCE error reports do appear in the wild occasionally. We have to
optimize for the common case.

Your change might be useful for you, which is a relatively unique
usecase. The common use case of KFENCE is to detect memory-safety
errors, and good error reports are a major feature of KFENCE. All
information is already present in the reports (and
/sys/kernel/debug/kfence/objects).

I argue that you are able to write a slightly more complex script that
simply looks for the free stack right after the allocation stack to
determine if an object is live or freed. Maybe doing it in bash won't
work so nicely, but a small Python script can easily do that job. Once
you have that Python script you might even do further processing, sort
things by age, size, etc. etc., and then print whole stack traces.
Just grep can't do that. So if you want something useful, you'd have
to give up on grep sooner or later.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO94wMDfLpDQqM6XWp7fLjNH%3DZSOCqmQ3jQgHQfPaHERg%40mail.gmail.com.
