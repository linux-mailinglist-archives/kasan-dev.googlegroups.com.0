Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIF7ZSVQMGQEPNDCDFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E77680A4CB
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 14:52:34 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1fafa54d079sf3505834fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 05:52:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702043553; cv=pass;
        d=google.com; s=arc-20160816;
        b=sX/pPvqm2kh7sZ7bQSO1QTtmjI5JgzwbNv8gdiqSQr2sW64sdlxl1kT+HrvLuiGnS1
         /txiU8C/VVVU39dNWMP60jgNZ/NjDLledAYvzyxELGgdHD+VJ0Uhkdurrx9pJKOKUUlu
         0SXWDE0Looz62XkIJr0U3QQZteWff//D6C3ok8CWC3t8VGHbRCDQj5PbyaUnkxDoEkV7
         TWPNoMUw1/CXF8fbtIMHkxAmiDD9ejwZI/nMyOKLZRrc6WipBnE1psz3sVD0Au4ydbV/
         YqB1feRqfYzFdrWP0exSIin7vCzLhn9OhaGzji0h4hIz5tAamuWBKkq4vFSru1ipMgrU
         lWrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mDFraD4Yzo5gSQH48M36pRFYBazOu3WrSJoMmJtfh40=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=WcWgFKSSnogc3sa6DGE5DkY23PUrcqhkalmST7Q2AsCIpdw2ACIGD2FpXMvav3hy80
         syxf18qqOo9SToxWApD161N1qn/dPJTV/prt4zOfaTDjRAjZ1i0r5riDEo9qmLaEz1/j
         Cj8tP9glvOd+xwWbwzDahXGMuDz9QTey+zVIVp0SnHSUZ0oWpYNlixm+LVoo8qYjbfWA
         6YA6errINQpsKxz7XmHThClQdjMypAPI5EbkJaWQSgMcoMlVacy0GpolyNGiL4HhGXsG
         /bQti1PPLsxrrFrk+Nni1EZ6LbMAdgzoj/d8vQa7jotEt4le4agDC6hS/Hma5ChWNR6q
         +UWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B7mNRzmQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702043553; x=1702648353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mDFraD4Yzo5gSQH48M36pRFYBazOu3WrSJoMmJtfh40=;
        b=MemGdbz90G2hcfXfQOeEYMhteRqrezHlDwmtDqmTKvGJmwweq8SMNY938Ps9uKF6YU
         G6uOuFYNpETl87sJ7qB0FeDVADz4ZFns86/GMzMw+XszFC20GIMbcKpYPQgZAOorSd5a
         ITjJ06xQHSksvumEzH+qawPxj76HJwbn0oTz6mOyUJ4oikD49GPzMBUDvXyjpxyDkmr+
         qVJzzwI6jem/4Jgmw3c5Uk0euPpcv6fUYPStBq3Vkma2DN/6WDalLS4qKYg74ICNR3tp
         ZjS31yJfbxhBs4wfeeMafKF34penZSBqHhPaymdK71gyZ413092WhqEeMBOh1/ajTdAR
         x4+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702043553; x=1702648353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mDFraD4Yzo5gSQH48M36pRFYBazOu3WrSJoMmJtfh40=;
        b=D4DfZzEZEh62SV1dsImCU6do+1FZsvy4phMgm6QXDE24h5t3kVh3uDw5PHzvg5G5Wm
         Ttn82UC6ku2sBDiVcjWMD+88aja2G8Q7x8cn9/4Q+1GBPA364YkQpoSO8My7cTy7L8u0
         HxoDgepx+A740pdbGcbO7KdgXgk+NZeAHXFVWDA7BHAvVV27Rcckykd4ZnF8EPVwfSc6
         OzUiaUg/5j+C13b9pR77nmTYMST8UD5LXQhbTMuXhtS39yr0+7aFdTbLYWodQcDJAfrU
         oPt9LhrrtF2jPxgCjL22edQGJtnySPX7aAGGqGKQ/MCBF7qR+qJhVfHproIjDHe/PWcq
         3iRA==
X-Gm-Message-State: AOJu0Yw184/zCNll4qE+z9Lbesl50SKtSW9Fj7OUHvXvO5A65PYTFE2G
	h58zLIJFQv8KjBVQRgSKi1A=
X-Google-Smtp-Source: AGHT+IEfKAhEIZkMQDQLZ5b87B1cIvK/Oz1zonEhdkHbYUS4aS5N5qNNxAKzzrQAkXVjvFF1C+nQdA==
X-Received: by 2002:a05:6870:1487:b0:1fa:e0df:600d with SMTP id k7-20020a056870148700b001fae0df600dmr111062oab.9.1702043552861;
        Fri, 08 Dec 2023 05:52:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3a26:b0:1fa:1efd:f65a with SMTP id
 pu38-20020a0568713a2600b001fa1efdf65als2851511oac.1.-pod-prod-06-us; Fri, 08
 Dec 2023 05:52:32 -0800 (PST)
X-Received: by 2002:a05:6871:a015:b0:1fb:37b5:12af with SMTP id vp21-20020a056871a01500b001fb37b512afmr98904oab.17.1702043552133;
        Fri, 08 Dec 2023 05:52:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702043552; cv=none;
        d=google.com; s=arc-20160816;
        b=qUw2KzUJUv3sEJjFDUaWlD3QxecIU2V7DEBFtvlGUpPPl2RDQk3iLz1qKqXZGaLjEu
         1wYnta1matZW6BWLwpUZ/ZGKSIo4JYdslu8LXrCGDBsh2H5bOnpL0g+v+/ekpGdeYTK2
         9IK+jMJMv9fCzA2tPqMlYWOP5yt5ok8FWubT+q94mJbEsZ9uGsHXxsE4UCrl3ug7BZ8O
         9mQrksZDqa5GLBOlvDeAX0jz/RMtbkWkU3AlobaveN/P7XbKqTp6bJgBQhNHrhjPuRsK
         24sYn937pcnJ0cWfvAMNY7i+wPk3cJRORHi/9NJCgHUeGBDbYSeDaoXQUsboIe5j4EGw
         7HMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kxr02EuEVtCzgI9ve8IFgXJLU7RV4njnkPo6roz6Un8=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=B+7JTAk9pqKYs6UdIp4opSGVqOWy/WuMnv/2X7GvLEl9m6nr9jj8RnQubXz68wlctN
         an4rXeNRivgeQlIbkvToa1dz/ODkkjg6y8fTPyZsHBufoEXYF761SxC9yuMa1LPPgwzT
         3BtgVTG/9fTXRd5tvQ0eX/F/AJWrvmTyi27twA/oR4L7SIwYI/BMrZq76L+oQfKY7mgW
         /OtLSJ/bRqW7nYDQVSq+ZpDw4yfvP5i/WiNH22gjC4Cz2UtQIqMltLGHAU/82jZjNPb4
         wFPyIoBNZ0H37KMGcW5ZiqhLskXieYuCGklwoVtDzhhF5Br6XKnBdwA/AkxfJPQvK9pK
         aeLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B7mNRzmQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id m5-20020a632605000000b005b7e6ff6c09si175731pgm.3.2023.12.08.05.52.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 05:52:32 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-67ab19339b4so11605216d6.0
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 05:52:32 -0800 (PST)
X-Received: by 2002:ad4:50c8:0:b0:67a:d049:bd31 with SMTP id
 e8-20020ad450c8000000b0067ad049bd31mr4464764qvq.72.1702043551094; Fri, 08 Dec
 2023 05:52:31 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-15-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-15-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 14:51:51 +0100
Message-ID: <CAG_fn=Vmp70auiTCZCtjhsC_vwnqPLsz_wn12cWd2iU-T5By8g@mail.gmail.com>
Subject: Re: [PATCH v2 14/33] kmsan: Support SLAB_POISON
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=B7mNRzmQ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Avoid false KMSAN negatives with SLUB_DEBUG by allowing
> kmsan_slab_free() to poison the freed memory, and by preventing
> init_object() from unpoisoning new allocations. The usage of
> memset_no_sanitize_memory() does not degrade the generated code
> quality.
>
> There are two alternatives to this approach. First, init_object()
> can be marked with __no_sanitize_memory. This annotation should be used
> with great care, because it drops all instrumentation from the
> function, and any shadow writes will be lost. Even though this is not a
> concern with the current init_object() implementation, this may change
> in the future.
>
> Second, kmsan_poison_memory() calls may be added after memset() calls.
> The downside is that init_object() is called from
> free_debug_processing(), in which case poisoning will erase the
> distinction between simply uninitialized memory and UAF.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  mm/kmsan/hooks.c |  2 +-
>  mm/slub.c        | 10 ++++++----
>  2 files changed, 7 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 7b5814412e9f..7a30274b893c 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -76,7 +76,7 @@ void kmsan_slab_free(struct kmem_cache *s, void *object=
)
>                 return;
>
>         /* RCU slabs could be legally used after free within the RCU peri=
od */
> -       if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
> +       if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
>                 return;
>         /*
>          * If there's a constructor, freed memory must remain in the same=
 state
> diff --git a/mm/slub.c b/mm/slub.c
> index 63d281dfacdb..169e5f645ea8 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1030,7 +1030,8 @@ static void init_object(struct kmem_cache *s, void =
*object, u8 val)
>         unsigned int poison_size =3D s->object_size;
>
>         if (s->flags & SLAB_RED_ZONE) {
> -               memset(p - s->red_left_pad, val, s->red_left_pad);
> +               memset_no_sanitize_memory(p - s->red_left_pad, val,

As I wrote in patch 13/33, let's try to use __memset() here (with a
comment that we want to preserve the previously poisoned memory)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVmp70auiTCZCtjhsC_vwnqPLsz_wn12cWd2iU-T5By8g%40mail.gmai=
l.com.
