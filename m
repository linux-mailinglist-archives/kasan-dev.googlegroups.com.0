Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL6ITW2QMGQEAAX2DEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 51DF793F166
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 11:43:13 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1fc5652f7d4sf31883325ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 02:43:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722246192; cv=pass;
        d=google.com; s=arc-20160816;
        b=IZC/8R/bq/irTL5cf/yG+xVJqBPZLql4lGSj+SVWaqbGySJKNuSj9fZNybvxytPD8+
         IBh8Z86xdGdoLK/CWq2CANvMl2jHuUXGRjYUH0pkUOg0xV4S4jZh22Ws5yA4XNnGu5i6
         o/u5AFzn+At/sX7nGn4cxmWXPtSptXlKUPvNJVlJlEJcBfjqdT1xgLZorDclhnnT/+Fx
         9fegpJG0M+wkjYsM2/TNBr2Op7eZyt4dGO2qoNuNN0nVfWixvcuZ0lmu+umkyBNMTxTf
         74DOrs7TjcezChESAY2sl89LS8bdIYPsT0I9ttYGF8nLyiT7i+4K2aHKjl6ypXlsNK3U
         N+Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Cr1ooa1gytjNPrRJgDDCPhRt68EI2J+xaTXYLOvc0EQ=;
        fh=kxBMpz4F2t9Psb9HDuVBAsansrPgD2ruCg9TkCF5Qh0=;
        b=afQq40bu4ZOcFVta5V4OUozK+kHgPA937Hjxvx9FmPbVl5Xeg0moiz6pTAby0Ew5HJ
         GPMjlqNoDm+iBRSPLl5tT2t4v5iwrIO+YgrXGK4TVo3ALJl/dvMro7Ejs2jubmZhJ5JW
         iM4aBdssW2FfyPP3A0r39An3LprBg+6HWb4W7oAQk45dbLxTQQR79P5FzwUyyyb6T2WU
         2+FLAz8BwgQES5rOk+tWIdqYCY2+tjK95AN9R7OSVmBGTY0nOq2qoxPNsEtE931fQw1s
         bLoiGZx+QQGcNyYa7u/jhFfI/2IxydutyvsNdGK2cwC2enaDQaBfGMvTe1SCkZNSLpbU
         T+dA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=j99+9lDP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722246192; x=1722850992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Cr1ooa1gytjNPrRJgDDCPhRt68EI2J+xaTXYLOvc0EQ=;
        b=kcZga8VE5OgR00fJxvJjVwGy+w6YC9oMupHqVPY+TgUlB70zZCj4gD2HUXxsgqPQ6I
         pp4cNl/BrbADg2DmhmO2tyStX/FeanQcAHSC8JElpns4Fj/I3ZkkkMe2Bc2hkO1dfs1U
         /3fncWJbhNy6NHiRaLoP6pRbk5NeiineTMC4g3Vc1yxaVIar+lPa8O6mWXQSvnYOId0D
         lVGfQI20DAcRXYMKM9CKD+W7VmXaB0corG899pctgEfa5B4TCIo65sQSlmkVtlynYwxT
         ZZLPd484Q4KpgJwNkfLBs/WdH2Ipv890w+BF9PLNjrhWrTfKFmDfnx52O7y50zEINHjY
         11Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722246192; x=1722850992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cr1ooa1gytjNPrRJgDDCPhRt68EI2J+xaTXYLOvc0EQ=;
        b=cbFw0kFjiaik4wdFJE1l9vgtVnqC93bI1N+/a4zFnSlHX3ZrA3xC+vsdz/6JXY4jcU
         EDM6klTPGhHnebPoPb5U0mFba9s9j93qrPoifi0WpMfavBqbUyNGzUjEZ6fy2kMZMCHz
         0ow7J1Z+5F1d9KoykoyWbOnL57oInDg/jymhW2UWggjfaO9tgaGJUcAZwvYZ74350GPc
         P7ccyEYbHQdCrzplqBdw8MwUUYklBhfM6ifRZnqXf8BQUSLMRSeJQR7tCHyzu9NVtvkn
         sxKGsH921Qu4ALGA1q4E7Y+QCGkBi8ytfx3SFbUqWD5UGzKBxUJ1VOQUNKS/zEw5t46t
         9AnA==
X-Forwarded-Encrypted: i=2; AJvYcCXEfYha5ACplH3jvsrKWN1CFcbye/Rjr/XpfGgqIIesFXjmz2m0xcqyRUBH5O7ZYKY0t6EbGWscKLCQGy0euSsG9s4QLCrnEg==
X-Gm-Message-State: AOJu0Yw9PBmeRM4WPYzcPs8mSHDodr48UyLuSMasKYwALMtaO1bMwuOk
	ZNR7gaRZ0VCJGkKh96kRDRpsDR+CYBNGLNDXOqaBaMmitsnsWbkU
X-Google-Smtp-Source: AGHT+IEXdBn4y9bMh7DUbXQibv5O41KyvWUyiloHsnpPR7LM53yMkbeNRRg9rlF/ME1ynM8by0IYJw==
X-Received: by 2002:a17:902:cec8:b0:1fb:7435:c2c7 with SMTP id d9443c01a7336-1ff048df0ecmr88715105ad.57.1722246191614;
        Mon, 29 Jul 2024 02:43:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:234d:b0:1f2:eff5:fd69 with SMTP id
 d9443c01a7336-1fed0fa6ea3ls34013945ad.0.-pod-prod-08-us; Mon, 29 Jul 2024
 02:43:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWG65E5o2X7OQzk8vBBXVeQog+Pg3X8Fl9Vl4AmBrOcsx8+0rJuTBJ5H40iLIcdERt2oxFwg26Yae3ivDRXoRhCiqcrpRZ+xcXBPw==
X-Received: by 2002:a17:903:2309:b0:1fd:a0e9:919 with SMTP id d9443c01a7336-1ff048a04d4mr102853665ad.44.1722246190075;
        Mon, 29 Jul 2024 02:43:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722246190; cv=none;
        d=google.com; s=arc-20160816;
        b=BasHZ+nDZn11lEiznKdIiyKN81XB9eVaez4lMzCC9Sm9seNDANZ6eYTgHwKkzqsiCh
         NHm+21dYHP90p2LkVzehqi/uAj3IBd6RlhphZgeIy6dNd4NERRJC8yb+RFMNWypO1ew8
         UwzDHxHQxN+1424DUySJ0FSXe3LupGvBlIZ1ozLbp8aw6g0NHITfx02KiO2UHHlM7cJf
         yOvzbJHSkdp1P0E3/GuDoK9Y7uvoMn9kIy/EwlGm1FzybzRos13uu+oVx8liOv+HEDNx
         I9mr4CGr+v7A0Ae67S/z2I8FqsRsGiedNZ3q2zDgwUj7bcPl5/5ie82bWzgqXDtfdDNj
         SK3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZoJ3ZacNS55oRX7hJpHDUlm+X3SpBJFA/ypVEqbSLQ8=;
        fh=+Ly2h2s6awMsEpMNYL6TtDLYvCCva7ZBsSu2im5rn1g=;
        b=W2e2h9OEJh6MC0GMU55/GNEBioNdZ1CkEiuHBX+x3Y4Mf8LxQe1TGyE66isRO2xkJj
         0C7fWfl6ebIyU/7fy+JyJGJV9g4iYO4emyr1L0SxXNM4yixpWfr/gFN7k+ZnIhjgQRzy
         pyMOIolb3yNTKIjHUs55VTuWxUYVXHptVI/sETH33OZvKQjC6ZoqOx4Jb470czpvRtDl
         4x0vcywfcGmNuZGfZ8GrxjPSjrXIZbxo2r8J1mluQAzhcANzYaeEdsczGHcATLjIyIEK
         CawJ+olZf/zEewvR96pdreagJ3a8Raa0aBQvX8m+vIL+RkJseLvBMF7G6jKrrgvlIgQJ
         NzVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=j99+9lDP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vs1-xe36.google.com (mail-vs1-xe36.google.com. [2607:f8b0:4864:20::e36])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fed7c90492si2930405ad.4.2024.07.29.02.43.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 02:43:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) client-ip=2607:f8b0:4864:20::e36;
Received: by mail-vs1-xe36.google.com with SMTP id ada2fe7eead31-48ffdfae096so100481137.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 02:43:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWT41GIf3V9STD4mx3YCaCdZnZB4j2zkYv0dUSAWytmpLxSRQAKz7rN5q+MRIA5cvAQ7w71m21GrCLmR0UvS5uVtHLiZ+pN5Ng0CA==
X-Received: by 2002:a05:6102:c4e:b0:493:d360:6f58 with SMTP id
 ada2fe7eead31-493fad1515dmr3478038137.20.1722246188837; Mon, 29 Jul 2024
 02:43:08 -0700 (PDT)
MIME-Version: 1.0
References: <20240729022158.92059-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240729022158.92059-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jul 2024 11:42:30 +0200
Message-ID: <CANpmjNP6ouX1hSayoeOHu7On1DYtPtydFbEQtxoTbsnaE9j77w@mail.gmail.com>
Subject: Re: [PATCH] kcov: properly check for softirq context
To: andrey.konovalov@linux.dev
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Alan Stern <stern@rowland.harvard.edu>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Marcello Sylvester Bauer <sylv@sylv.io>, linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org, 
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, stable@vger.kernel.org, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=j99+9lDP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as
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

On Mon, 29 Jul 2024 at 04:22, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> When collecting coverage from softirqs, KCOV uses in_serving_softirq() to
> check whether the code is running in the softirq context. Unfortunately,
> in_serving_softirq() is > 0 even when the code is running in the hardirq
> or NMI context for hardirqs and NMIs that happened during a softirq.
>
> As a result, if a softirq handler contains a remote coverage collection
> section and a hardirq with another remote coverage collection section
> happens during handling the softirq, KCOV incorrectly detects a nested
> softirq coverate collection section and prints a WARNING, as reported
> by syzbot.
>
> This issue was exposed by commit a7f3813e589f ("usb: gadget: dummy_hcd:
> Switch to hrtimer transfer scheduler"), which switched dummy_hcd to using
> hrtimer and made the timer's callback be executed in the hardirq context.
>
> Change the related checks in KCOV to account for this behavior of
> in_serving_softirq() and make KCOV ignore remote coverage collection
> sections in the hardirq and NMI contexts.
>
> This prevents the WARNING printed by syzbot but does not fix the inability
> of KCOV to collect coverage from the __usb_hcd_giveback_urb when dummy_hcd
> is in use (caused by a7f3813e589f); a separate patch is required for that.
>
> Reported-by: syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=2388cdaeb6b10f0c13ac
> Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")
> Cc: stable@vger.kernel.org
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> ---
>  kernel/kcov.c | 15 ++++++++++++---
>  1 file changed, 12 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index f0a69d402066e..274b6b7c718de 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -161,6 +161,15 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
>         kmsan_unpoison_memory(&area->list, sizeof(area->list));
>  }
>
> +/*
> + * Unlike in_serving_softirq(), this function returns false when called during
> + * a hardirq or an NMI that happened in the softirq context.
> + */
> +static inline bool in_softirq_really(void)
> +{
> +       return in_serving_softirq() && !in_hardirq() && !in_nmi();
> +}

Not sure you need this function. Check if just this will give you what you want:

  interrupt_context_level() == 1

I think the below condition could then also just become:

  if (interrupt_context_level() == 1 && t->kcov_softirq)

Although the softirq_count() helper has a special PREEMPT_RT variant,
and interrupt_context_level() doesn't, so it's not immediately obvious
to me if that's also ok on PREEMPT_RT kernels.

Maybe some RT folks can help confirm that using
interrupt_context_level()==1 does what your above function does also
on RT kernels.

>  static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
>  {
>         unsigned int mode;
> @@ -170,7 +179,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>          * so we ignore code executed in interrupts, unless we are in a remote
>          * coverage collection section in a softirq.
>          */
> -       if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
> +       if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
>                 return false;
>         mode = READ_ONCE(t->kcov_mode);
>         /*
> @@ -849,7 +858,7 @@ void kcov_remote_start(u64 handle)
>
>         if (WARN_ON(!kcov_check_handle(handle, true, true, true)))
>                 return;
> -       if (!in_task() && !in_serving_softirq())
> +       if (!in_task() && !in_softirq_really())
>                 return;
>
>         local_lock_irqsave(&kcov_percpu_data.lock, flags);
> @@ -991,7 +1000,7 @@ void kcov_remote_stop(void)
>         int sequence;
>         unsigned long flags;
>
> -       if (!in_task() && !in_serving_softirq())
> +       if (!in_task() && !in_softirq_really())
>                 return;
>
>         local_lock_irqsave(&kcov_percpu_data.lock, flags);
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP6ouX1hSayoeOHu7On1DYtPtydFbEQtxoTbsnaE9j77w%40mail.gmail.com.
