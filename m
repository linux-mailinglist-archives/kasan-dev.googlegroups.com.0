Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQNGTCGQMGQEB3JG4SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 577DF4633C1
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:04:18 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id s189-20020a252cc6000000b005c1f206d91esf28764885ybs.14
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 04:04:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638273857; cv=pass;
        d=google.com; s=arc-20160816;
        b=tlQG5rDisRaAWu/sRb0VVbGTHy+d0ueiPoLupJEd8RMIcv1mwtJwp4u16SmmhOELTW
         nqwxj8s03nHXfqgoAeVK708iuxwhubwYgfYtjnTIj5tPOPPlG19AvcYjTrlmsM72Jb+j
         wZudioY8H7MXrwpT2RAz9eX2pMNZ13+XRI5ZnZHWk6NFr1GvtLDgV2dmn/lIEpwapUWs
         VQf6nJmeG5M3/nbRHsF0+U/X77ZSq5RZf4Dbp4WMU5FBClOWZMZuv3hQbG5PcdFJJiuC
         UJJem5YeXSEXsIPIlCKNcMF0ECBCpvW2XnwKFt8qIz+qzorTsakpbXHXrcN2mggCCztU
         KzBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Ez9wFeMFag99AuX6GVhqc9HqZs8rY8EzXzz8N/nGVg=;
        b=k9fpa/VHmutCWsP31R2UWZsMFdPO4UVpQCdetThe3iz4WwkGvlK2ZfkCJT7f973pCq
         p6GyLF0qdPjIcU07BrEOVmnk3lgaCm1y98IZexl0S9+XqlgIylHSTl3Wwtr7SXSfp1Pb
         VjZP7ErY5cpldkRUt5DeqKm3PaCYovjsRWZargmRYiY7jMaq55tlmsWidpSkr+3a3ErS
         xw+x0DFG9L+chHitYhVjyWImEQnlE5PHJqTz0dz4xXGpik5r2N+ECC5OLrUh7gYltsW3
         wm47KKSqz0K52j6pmC1TB9FijnS7veTpzrzmAVuoEpfet1fBrDKLuihjDhi7V9tTxnsc
         VWYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PyDcfZpX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=5Ez9wFeMFag99AuX6GVhqc9HqZs8rY8EzXzz8N/nGVg=;
        b=k7NBkeRZRSxvjWMbjjkflGvRajJ8RpAf7p/2UlKqjEQrxDSYhPK0r1eji8GufaKE1Y
         50IWD9jjpmj6hVudaiQZvHTyZQBKZwZdsXfUDtqUo2GsMiUBjtoY1C/qKlClp/zQHqWc
         s6NfFbniso7N37Ukc7D7g3D9Tf8BbiYquE0UcBsnDChInXih/JP7n+Cc3lLE70uZ/njP
         IRUKW7X6k2+LqODyX7rFl8qdfa/qO2paZvjPXtggvr62N5VgwadaTHFeGMvSeoDzQ7YL
         CiQ7ymm4w50c+DOd5RkSVNM0xnciuFMvYnMVvYhdOu1vrAR4xvlFbsJNUGd1JDcSeJ1E
         f8rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5Ez9wFeMFag99AuX6GVhqc9HqZs8rY8EzXzz8N/nGVg=;
        b=wYcdOZgIiWYPRP95w365Ta3/Aj1YgZE6VStFNG4ZG2u7Wqw773r9OcG1x63/Co/yOr
         09rknbagn7XaZ2siPwgBGJWuEYyY9Rq08szz2rzfQdBYQT6CMnY9mPzD0780WaxVa9It
         NzSz3UC9ldIVmPrBNPHfK4Xu06rRUULZdcZhPUh4gpuikQ55y9LtUIlbGPlcpu+arxfj
         fHNZ+HtXeSzT3dMFFGbDOiyW+dpezBKuwPXTW8nw0tc8bHyrt9QDQDf2OrlpuanGv5Wc
         X94mm2xhne2QPAXAVDsiC01ELQeDCRx99bELmnbEAtshqHB/rV8heSJoM6UtlbRhvEO3
         kBaw==
X-Gm-Message-State: AOAM532VLxS795elLeUkrt6M1cReBNymEDE8BeRYRtLBHgNezdIDlTER
	RS4dnCAHn3YVwVpZkVwFd3A=
X-Google-Smtp-Source: ABdhPJw78Kqm5hI7gxB2qlfSBWsZQGcIGxkmv4Wmxv1x0lqT5mL8CwrpFMMD1FPzHdmjabr0Ry90gQ==
X-Received: by 2002:a25:cf46:: with SMTP id f67mr41654741ybg.362.1638273857268;
        Tue, 30 Nov 2021 04:04:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ca0e:: with SMTP id a14ls3221927ybg.0.gmail; Tue, 30 Nov
 2021 04:04:15 -0800 (PST)
X-Received: by 2002:a25:25d2:: with SMTP id l201mr41082906ybl.136.1638273855643;
        Tue, 30 Nov 2021 04:04:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638273855; cv=none;
        d=google.com; s=arc-20160816;
        b=bNTrOdTOvQJeuoWL58v0LGiScWIaKfc+ri6JiST5OSwzKC2YQMcI9hbRecemm0UdEz
         FgC4LqAYxzRvDb9pE9RGHpm0ciEGkF6qNXfZXQExREb8XwWEVycYXobX0VBDOvlWD+iO
         EhrhgDsnsFiCi00hTbvve7o9vGlWT6sPY4mHOgc1mU85aCBozPJ6idzwORdf0Qin3lmj
         zz7EmPJWCUDrgwZjngpZ+0CjH89/M/pl5yMG9fuPz9zzJsCsQRAd/KElQI6Ogzri0KNt
         qDbveWsxUsx/cLrG21tXnL1WfYmcw5td/0he5duDkMUcrvFwn9eNDZn4hVANwVtLd3TN
         B9cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0TDfEMK/KsWzDzMYVf16B8nf+1SscGhMhouVQsRYobA=;
        b=BhO1Rbwgt8USAa8sSPJp7rChgTtRv/7cVNSVwbu+ef8TgPAR0R1ARhDLf+Zkg01gMR
         8uOVSFhDax0aIlO//EVfkD1epzlxgLrVuO0vqv0gWFE9gbQcWR5J6CfQD0c11vAiQoyU
         l7+SQTb+0+n+9LyWgkwvvMmBwekDp1xPmA0tM5NPpnGRLvwB1onJ75TWh3QOCSoiGB/X
         vj2/sp9zdD8kHzSd0AOFAhNoeUjwJO+iTkzWtYP/NbkV6oQUaWbvZhI05S4zOzr9gZFL
         GLGz1Bzc1XV936XjD2IbOdX6L5edPLJYqHk8hA2JgQ41aD1P9uj5ClISFfHi4B8lulJ9
         yHDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PyDcfZpX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id s97si1514575ybi.5.2021.11.30.04.04.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 04:04:15 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id 193so26422993qkh.10
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 04:04:15 -0800 (PST)
X-Received: by 2002:a05:620a:d84:: with SMTP id q4mr37009939qkl.610.1638273855141;
 Tue, 30 Nov 2021 04:04:15 -0800 (PST)
MIME-Version: 1.0
References: <20211130095727.2378739-1-elver@google.com>
In-Reply-To: <20211130095727.2378739-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Nov 2021 13:03:37 +0100
Message-ID: <CAG_fn=X8FhDPKFGM2zrVp=OACDXSxe3J32CDOQ9_jr0sSCBaoA@mail.gmail.com>
Subject: Re: [PATCH] lib/stackdepot: always do filter_irq_stacks() in stack_depot_save()
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Imran Khan <imran.f.khan@oracle.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Chris Wilson <chris@chris-wilson.co.uk>, Jani Nikula <jani.nikula@intel.com>, 
	Mika Kuoppala <mika.kuoppala@linux.intel.com>, dri-devel@lists.freedesktop.org, 
	intel-gfx@lists.freedesktop.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PyDcfZpX;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as
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

On Tue, Nov 30, 2021 at 11:14 AM Marco Elver <elver@google.com> wrote:
>
> The non-interrupt portion of interrupt stack traces before interrupt
> entry is usually arbitrary. Therefore, saving stack traces of interrupts
> (that include entries before interrupt entry) to stack depot leads to
> unbounded stackdepot growth.
>
> As such, use of filter_irq_stacks() is a requirement to ensure
> stackdepot can efficiently deduplicate interrupt stacks.
>
> Looking through all current users of stack_depot_save(), none (except
> KASAN) pass the stack trace through filter_irq_stacks() before passing
> it on to stack_depot_save().
>
> Rather than adding filter_irq_stacks() to all current users of
> stack_depot_save(), it became clear that stack_depot_save() should
> simply do filter_irq_stacks().
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
>  lib/stackdepot.c  | 13 +++++++++++++
>  mm/kasan/common.c |  1 -
>  2 files changed, 13 insertions(+), 1 deletion(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index b437ae79aca1..519c7898c7f2 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -305,6 +305,9 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>   * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false,=
 avoids
>   * any allocations and will fail if no space is left to store the stack =
trace.
>   *
> + * If the stack trace in @entries is from an interrupt, only the portion=
 up to
> + * interrupt entry is saved.
> + *
>   * Context: Any context, but setting @can_alloc to %false is required if
>   *          alloc_pages() cannot be used from the current context. Curre=
ntly
>   *          this is the case from contexts where neither %GFP_ATOMIC nor
> @@ -323,6 +326,16 @@ depot_stack_handle_t __stack_depot_save(unsigned lon=
g *entries,
>         unsigned long flags;
>         u32 hash;
>
> +       /*
> +        * If this stack trace is from an interrupt, including anything b=
efore
> +        * interrupt entry usually leads to unbounded stackdepot growth.
> +        *
> +        * Because use of filter_irq_stacks() is a requirement to ensure
> +        * stackdepot can efficiently deduplicate interrupt stacks, alway=
s
> +        * filter_irq_stacks() to simplify all callers' use of stackdepot=
.
> +        */
> +       nr_entries =3D filter_irq_stacks(entries, nr_entries);
> +
>         if (unlikely(nr_entries =3D=3D 0) || stack_depot_disable)
>                 goto fast_exit;
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8428da2aaf17..efaa836e5132 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -36,7 +36,6 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool=
 can_alloc)
>         unsigned int nr_entries;
>
>         nr_entries =3D stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -       nr_entries =3D filter_irq_stacks(entries, nr_entries);
>         return __stack_depot_save(entries, nr_entries, flags, can_alloc);
>  }
>
> --
> 2.34.0.rc2.393.gf8c9666880-goog
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
kasan-dev/CAG_fn%3DX8FhDPKFGM2zrVp%3DOACDXSxe3J32CDOQ9_jr0sSCBaoA%40mail.gm=
ail.com.
