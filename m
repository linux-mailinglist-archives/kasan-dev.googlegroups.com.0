Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRWT7WMAMGQESDT2UQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 49A705B5F12
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 19:18:00 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id e187-20020a6369c4000000b0041c8dfb8447sf4330915pgc.23
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 10:18:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663003078; cv=pass;
        d=google.com; s=arc-20160816;
        b=XgM5pQGSt+oURbhqrgbXF8xvupSBlujRE7D7++lczFUh9TYQPt17xKKi30Q72Vrfkq
         qSRRq6nXwfX2JAXPS4k25oWqDgMpNFGAqB/D+xW4RrD5ERl0otkI3Nyi9TRTzNpWrwVY
         XLeW6tXPBCzo3gM/XveIb9s5qNhy7xUb+jz/axX8w9zoch88L/MpgvISRc9yFDhLg81O
         ofbXKtCGcVcNKIXMPI3R0zjIxgRq8XE7d4qTHUHJjeJasHdEovxnDVqYY4HeTzzwawJk
         HIE/kjU+cSQyx8H6RjEHZEiDuIijvjRar4oeCA0I0sdFar67qm/xx/a1FkBtPl7ugl4a
         Pg3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GQeyAXNKKKhitQzuMJZ6SsmeLXufGTVfYKFG/4I8Cuo=;
        b=vgTJ2I5N4N8N7xjB48s0pX0xOYqU/OukuPLiA5A1JvfkkJVBpnqthryIsVMp9dqHQe
         2Hk7dQfw3aLaU1Bg04t/fAFKAl76YOFdx6JHwoGIIzJnwKAZf+gTWATuE9M2qech/f2M
         vSSRjr8W56R0myCelpGyQERL0f/EggKq0oJ/VEEzIGWf7XbDKLcy9ubYkcKZM7OHOKKa
         Dwd1N4ZTB/T8iEK3E69X41vGtQFsSv3zrqr9q6X4TY9EOajEzSc/2HXnRtNzN3gmwpTE
         qdG0tZvHLGv/9D5gjWvSXcnExsVES0Yu70JqXZJEXH7NOySmwJPzQbJPq7E/cLM7xhav
         Foxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OXLJnC7m;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=GQeyAXNKKKhitQzuMJZ6SsmeLXufGTVfYKFG/4I8Cuo=;
        b=GcBIExMaZ+T0vUddSPEWv1E8tzJ4A7rtFMGvpeKU+qTx8zsAkjVqR0aVg7uVwgO8iL
         5uuxlCOxWHGOlhJRCVBvjdHe4V3YZ31so5rvWhAAlADOZpMOIMP0+SJv7in55nT6teMi
         b5Rw7K1w6KDmR3RV0ArbKWQqa9WVKs71m7CnWeBrWMHhlbhK3i9PoKfwgeTmeqbk9A7o
         QicyavWtchj3iWB1SW2f/OQi2kAm6E8YBGuaV7d2ioMRm9hRtgTG2wxw+QxomV+N8HD7
         YGBZsg0Mz4ETq4C1akv51Q2Jzwk3gQyUE6LDefRAARfVfsAvJHzkks3VcjjR0dbg7PIB
         NRPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=GQeyAXNKKKhitQzuMJZ6SsmeLXufGTVfYKFG/4I8Cuo=;
        b=txi2NNMlSu2ecEZU7IP0Q0Xtu1yF/OkS3zBlz6rF7wVwjoiKeBVOLY9QkjczRbH8IP
         SGES9OEdOuMRjjvGIgxybohAG811nw671gD1kJA4PbFDOALFdRV2NFzVd53kzrgNcWqX
         cN/LS9OvfrNztSIUs8OPrsp4/9IJ0H3CNiJZRpDhGlC6XF9YiVMEoSGCDeKIEMB0zPsv
         dIE29DwN79BeViQOGCniaNRSLUNX38JAAzKaX4Hbl7svmc6b30OMN5z2f4D/rxycZmrx
         a3POPeOuUBaPEuqUSzCSC1zdKYmOHFJCujKYA41gAugaDbGamxqtqSV6vBjOBN+mCH+y
         DLiA==
X-Gm-Message-State: ACgBeo0/euqxtinYi2ePAVQDTrRUjnBb1qLw10RKY1QF33lZVeJbU0vF
	5AXdRZibvSYJCPxXRUnLJnA=
X-Google-Smtp-Source: AA6agR65d7D7oxKuGkAlDNYBevZmt7pnpjbBqKtbiDtLOnrumO48z+bPpKTOCtFlgWai9TzeGgsSUw==
X-Received: by 2002:a05:6a02:20d:b0:430:3886:59e8 with SMTP id bh13-20020a056a02020d00b00430388659e8mr24227363pgb.516.1663003078492;
        Mon, 12 Sep 2022 10:17:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1541:b0:202:d04a:9212 with SMTP id
 y1-20020a17090a154100b00202d04a9212ls2071551pja.3.-pod-canary-gmail; Mon, 12
 Sep 2022 10:17:57 -0700 (PDT)
X-Received: by 2002:a17:902:aa41:b0:16f:85be:f348 with SMTP id c1-20020a170902aa4100b0016f85bef348mr27830499plr.15.1663003077661;
        Mon, 12 Sep 2022 10:17:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663003077; cv=none;
        d=google.com; s=arc-20160816;
        b=f35zDrzffmjzedZeD7O3Ww/qkF+WWWvf+Hw1zvGVI7hTwp5EdO+8FCothOLfMPWxk1
         QfGARz2BWbDs4ODD9l581qS8hbsh6Wk88/+p8gzfa1OGDllftGFOl6Av+lVHefppbZ1S
         cw1xUTyXPSnLvac0HLPVPaZdKLLX4DxcSAjRaf0ZPqpq0hc9CDC4BmXUt1rWscqbWMhO
         vxttMzHIZth6wDFFLqT0axDPMCcEin0Rtyje7B/eYs9jQVQmKjswStrGarOp7QcS+bo1
         54u0Lu/B7cHnQYBr7R3IDj4YJpAKEddFm5YmAil/CNyeyR9WvWJ63w+eX7Lt0l5ZZVbK
         hVnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+KtF588ZPlxi3VVUd2CaBCEItNHS+QL93SWbYzWuiuM=;
        b=x6zAgD7JoQHob4yVOqsVqgxMGmEL4Ob0vpgRDDQzG3xPhV0xVN9RSdKU8BXDDNQX+j
         8ZsmPLieOSeYsVZNJbRaAc+nl3NTDHmfc2bTQOvOa45fiQP9K2JdB2PKKXVe/dIxB4/L
         6Ukt39sHglKsTtpJrsHzFj+rFDz3L71MhLpS4sUS3/Cvyd1rrrdyiNVP1f0CGQ3kckG/
         gVZYnfKzbyK2WieMph9b2aL1DF1Ncdr72ISK5FrW3+zr4QV7L18pgKE56/N+NDOK/HvL
         Y5oUCbuS83a5CY7ruKnJs0+J+BTzp98S0dkEc780IkrET3L7TBI0oMvSHDPl75QbcSIw
         qk0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OXLJnC7m;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id md6-20020a17090b23c600b002008ce1d337si325462pjb.2.2022.09.12.10.17.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Sep 2022 10:17:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-3450990b0aeso109039507b3.12
        for <kasan-dev@googlegroups.com>; Mon, 12 Sep 2022 10:17:57 -0700 (PDT)
X-Received: by 2002:a81:9c2:0:b0:345:4830:1943 with SMTP id
 185-20020a8109c2000000b0034548301943mr23749159ywj.86.1663003077193; Mon, 12
 Sep 2022 10:17:57 -0700 (PDT)
MIME-Version: 1.0
References: <fce40f8dbd160972fe01a1ff39d0c426c310e4b7.1662852281.git.andreyknvl@google.com>
In-Reply-To: <fce40f8dbd160972fe01a1ff39d0c426c310e4b7.1662852281.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Sep 2022 19:17:20 +0200
Message-ID: <CANpmjNMmDyjmYLfqCNdrksbN9BndjerzNTfdKLDQS_7etrNXMA@mail.gmail.com>
Subject: Re: [PATCH] kasan: better invalid/double-free report header
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OXLJnC7m;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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

On Sun, 11 Sept 2022 at 01:25, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Update the report header for invalid- and double-free bugs to contain
> the address being freed:
>
> BUG: KASAN: invalid-free in kfree+0x280/0x2a8
> Free of addr ffff00000beac001 by task kunit_try_catch/99

It wouldn't hurt showing a full before vs. after report here in the
commit message for ease of reviewing.

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMmDyjmYLfqCNdrksbN9BndjerzNTfdKLDQS_7etrNXMA%40mail.gmail.com.
