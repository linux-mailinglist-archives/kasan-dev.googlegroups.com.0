Return-Path: <kasan-dev+bncBDW2JDUY5AORBKEW66MAMGQEUAVHPTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 433E45B4E8C
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 13:48:58 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id n6-20020a4a6106000000b0044b2434319esf2883281ooc.3
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 04:48:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662896936; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHzZoD35v0xMXO2FzUb7IZxkElBiK+Fi8ndwP8BdbXwllGCJPmGgpZP0kaRh5YrH7D
         nw9WT/NIy/inSrvju66GQ2I8VRor3ZF3xcVfPymJFtefiGb7mfSoNAzRrr7dZqRBi8aF
         uohJ7KduOkrVLrvzbG1yyNUD165nRw1MXyRUL1RfP9SZE9W2Gw8aPdE4Y1HsRXRB2KIf
         hS23YSIoavVn9GDpe8PbY3i3t0M1ecLLQOxRP+FdOYMuChF3BVkNzEclcNxJve1MPYpo
         XzUwEoQUkldF25g6Uybz8tGdp+e96YTBiCiytMWs8ADGj/XCz3HyxQGSuYDv7/kdr+EE
         4aKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=pGZSNcdafLnJ14iU9D6muz6rx1J2cYBZMVitnOmRqYI=;
        b=vMZuFQ2xG5ZPAzdft3exWgFLGDaFgMFL+6E7VL9hsJnqGivKfcgu2I1gUBWdb5bYbZ
         lP9sNFDTXVbLmSEHuMEQiGESy6bUNxvBiXeW0qL5NGtjJPB7NtJwz/BkMJp8E6YfJ6tr
         g3kapCG5A1tyB5AyOWsWhP1258WX9B7uDyedJFEaJbhE4rB4ARcfnalIyEyHqn+ca1/K
         /rGlPrZRgVXsZxPVOk5rFFyXurQK6P1NaysbsEvptq8gP9W8eH6WC0ZPmQyuAe4lZK3B
         bYt1/cLUyNaBu70C9iuyPNU4WgavY/6P248YWWOcSa8q6qUz/xFB6rxRH4XrygmyQZzb
         Zd/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GQyUfzr0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=pGZSNcdafLnJ14iU9D6muz6rx1J2cYBZMVitnOmRqYI=;
        b=LH7DmYfVD4M/cZdX6rx28Mo+at8PC/7KHfrtaq4vco98ojCzRjNR187gWA0mVLvpke
         Io8kN8Hjy+x8hz0bHnVndRhjq42EHSIhxIYJb1Nx4DrLmUu72cmtNVUY9ItokH2iqn3k
         nrhTW7+kn9gR8DbfeIcOwlS/h2dgbgxm2ASsaumT0v2xOzeNppQlejhwqoxmIkEYuYyC
         Y282PB0G+qt4I0gb98cqtCagJUAS58qJ2QBo+cNj+z60+gcRc0Fzw2+YWloV3Upa2tEw
         sWfTj7kZDJU4hNLZyDInhJH0WpmOHguFRW2Re0SuQ4bdFDhepxbapN7kBJ68HP1Nv1jz
         j3OA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=pGZSNcdafLnJ14iU9D6muz6rx1J2cYBZMVitnOmRqYI=;
        b=EULfUh8upmR9NzqYwGc7p14bX7FotlqAdanM6iJz8Sp5/yyU3m5HfdmiskHVs/kcCr
         BMhrMthuSjhTB7hYFdnDM8GrTuXH8sgY37jkvsdPZd4gukg0uDw0CAPw2uCoD8gtcoCG
         /gz7hL9c49DAQvxo46UAL20LzvkFWMiJgncWRUoCMMVbECDoEffj1h8HwLj74JjmeFe1
         KfZTJat3rMKywz5gQqqPenw0hTPZUTSvIbUAOCKteZx5bX9XbJ8qD+UT6ewU4x2OjCKg
         nsYRXAlc4XX49GA6+dXT0kzd/Ur4eSLKJCCibzh6mbl7Eju57+i8uKO2pZeQRHnXlpkl
         fIOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=pGZSNcdafLnJ14iU9D6muz6rx1J2cYBZMVitnOmRqYI=;
        b=15BxB2cWT9xSPvSTklEULkLv6F/lV72CJRXKxsZdxPh1tJw/w/KWSVgBPTK6raDudL
         ZIawwTq2zcbIgyCwU6GZT4U2fdjePOCg+5ZymEyUsj5UwNtTgFpkcWvfsH5R0lBRGPV9
         GQOQ1nM7Si0E7CkvCVvvC3g0FGqmyN8CLUccDuxxa86GPrmDaraiQb6RQDQlJH2tAtx+
         UhMIR3E8z2B9OV4hGRf0sB25EnPkKRy8s+6R6IpdpUcrWkAnIZVxhQZIciuA3uarwm7h
         Ca1v/Ll4O8IWktzz8Wc9jEAHFfuDYOFV/jSNSz4Q+w5jCOC+/ZlvuRf8oH76qL+dvt8n
         My5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2DcLr0njBlgAm5wRmc3t+BcoUb06Bku1thsIQi7yKrvdIAfTqN
	9drGVZxzomJli/A7UZ64+xU=
X-Google-Smtp-Source: AA6agR5OJh8YQRz8sYC6HGK8jeR1w/BDJ4Ls4Qnrc6zE8HqXm81WgPuXbxTGf8hFAmJIUDB3u3HYGw==
X-Received: by 2002:aca:d846:0:b0:34f:5ec8:5487 with SMTP id p67-20020acad846000000b0034f5ec85487mr3896138oig.192.1662896936623;
        Sun, 11 Sep 2022 04:48:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d8c:0:b0:638:adfe:6a17 with SMTP id x12-20020a9d6d8c000000b00638adfe6a17ls1475214otp.3.-pod-prod-gmail;
 Sun, 11 Sep 2022 04:48:56 -0700 (PDT)
X-Received: by 2002:a05:6830:6505:b0:638:94e4:f0c9 with SMTP id cm5-20020a056830650500b0063894e4f0c9mr8910637otb.270.1662896936084;
        Sun, 11 Sep 2022 04:48:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662896936; cv=none;
        d=google.com; s=arc-20160816;
        b=kFI65N3pPl2GNg752JG7/NNEDmE0cdtpseqP3HkG21cTOCyFKflaU6EOTspji7ud73
         jYe7k1pIvXDcN8L6wse9DpjPm1fmg9ROm2rCCfpsPhWpSZjYdDgNIwobbGynmLxslevn
         NcA0cFczmDOOsl/YMQqRhQ8y3xhm2AHfaWi9HDiVJEWD/z1NRiWsy18sCjOdOg/GyUGv
         7YyXW/w/x02ZkmPXyxYgX+YBhu3tW88486eS5wemVXEm9nraH5I7GbUjjAIJnstGCW9F
         3meuWZZ/iLnZa4Fyqk8inhHn0e3i6GbdXgwduC7sm2I34eV0u1KsjfxHPkdmOf9ZuW2k
         bFQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f3KWsKgAEFkYsTG0akgEuS+HAh1aYxDAn4WpE5Ns8zA=;
        b=0sll9yUJp6JFmymZVpkC4zkJ3iln0KWfu5y1wRk0usfKZv+5D2sH0uCMqibBxYX7sJ
         Nc2mBGM+iiYQNBx+7EOyyy91pIoJOtbCYY+VyouR5hiSd9isdDPrcPjMDkiXaVe54QMM
         jofqz9Aov1Ls/vjulRrHSfTStqVSk1E0QYnMOrUZXEWJs6WpHtNo2l/kWQsNbwJ7tM7j
         a0GPoyb+hMNQa0x+Sc5qUA72tW/UeCqSIIMsUwgb3J2loWLikRyCHlwJxlgn5rBKf+Xd
         jF06u2LboB2yy1lMiU6UzE0FA0ZZlRXdwOUFETRXL/n7AraOoznSxeeDOcySDtPLDlpr
         fBbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GQyUfzr0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id fo13-20020a0568709a0d00b00108c292109esi562063oab.2.2022.09.11.04.48.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 11 Sep 2022 04:48:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id cr9so4394239qtb.13
        for <kasan-dev@googlegroups.com>; Sun, 11 Sep 2022 04:48:56 -0700 (PDT)
X-Received: by 2002:ac8:7d85:0:b0:35b:acfc:f3a1 with SMTP id
 c5-20020ac87d85000000b0035bacfcf3a1mr4031933qtd.106.1662896935625; Sun, 11
 Sep 2022 04:48:55 -0700 (PDT)
MIME-Version: 1.0
References: <fce40f8dbd160972fe01a1ff39d0c426c310e4b7.1662852281.git.andreyknvl@google.com>
In-Reply-To: <fce40f8dbd160972fe01a1ff39d0c426c310e4b7.1662852281.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 11 Sep 2022 13:48:45 +0200
Message-ID: <CA+fCnZfgwjT+Yzxpz-pesqVhitq13Z5aypaXjFodZyCDLr9d6Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: better invalid/double-free report header
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GQyUfzr0;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Sep 11, 2022 at 1:25 AM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Update the report header for invalid- and double-free bugs to contain
> the address being freed:
>
> BUG: KASAN: invalid-free in kfree+0x280/0x2a8
> Free of addr ffff00000beac001 by task kunit_try_catch/99
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Forgot to mention: this goes on top of the "kasan: switch tag-based
modes to stack ring from per-object metadata" series.

> ---
>  mm/kasan/report.c         | 23 ++++++++++++++++-------
>  mm/kasan/report_generic.c |  3 ++-
>  mm/kasan/report_tags.c    |  2 +-
>  3 files changed, 19 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 39e8e5a80b82..df3602062bfd 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -175,17 +175,14 @@ static void end_report(unsigned long *flags, void *addr)
>
>  static void print_error_description(struct kasan_report_info *info)
>  {
> -       if (info->type == KASAN_REPORT_INVALID_FREE) {
> -               pr_err("BUG: KASAN: invalid-free in %pS\n", (void *)info->ip);
> -               return;
> -       }
> +       pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
>
> -       if (info->type == KASAN_REPORT_DOUBLE_FREE) {
> -               pr_err("BUG: KASAN: double-free in %pS\n", (void *)info->ip);
> +       if (info->type != KASAN_REPORT_ACCESS) {
> +               pr_err("Free of addr %px by task %s/%d\n",
> +                       info->access_addr, current->comm, task_pid_nr(current));
>                 return;
>         }
>
> -       pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
>         if (info->access_size)
>                 pr_err("%s of size %zu at addr %px by task %s/%d\n",
>                         info->is_write ? "Write" : "Read", info->access_size,
> @@ -420,6 +417,18 @@ static void complete_report_info(struct kasan_report_info *info)
>         } else
>                 info->cache = info->object = NULL;
>
> +       switch (info->type) {
> +       case KASAN_REPORT_INVALID_FREE:
> +               info->bug_type = "invalid-free";
> +               break;
> +       case KASAN_REPORT_DOUBLE_FREE:
> +               info->bug_type = "double-free";
> +               break;
> +       default:
> +               /* bug_type filled in by kasan_complete_mode_report_info. */
> +               break;
> +       }
> +
>         /* Fill in mode-specific report info fields. */
>         kasan_complete_mode_report_info(info);
>  }
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 087c1d8c8145..043c94b04605 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -132,7 +132,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>         struct kasan_alloc_meta *alloc_meta;
>         struct kasan_free_meta *free_meta;
>
> -       info->bug_type = get_bug_type(info);
> +       if (!info->bug_type)
> +               info->bug_type = get_bug_type(info);
>
>         if (!info->cache || !info->object)
>                 return;
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index d3510424d29b..ecede06ef374 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -37,7 +37,7 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>         bool is_free;
>         bool alloc_found = false, free_found = false;
>
> -       if (!info->cache || !info->object) {
> +       if ((!info->cache || !info->object) && !info->bug_type) {
>                 info->bug_type = get_common_bug_type(info);
>                 return;
>         }
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfgwjT%2BYzxpz-pesqVhitq13Z5aypaXjFodZyCDLr9d6Q%40mail.gmail.com.
