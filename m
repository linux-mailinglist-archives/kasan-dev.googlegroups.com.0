Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHG33CVAMGQE6FUU7DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A1237EE36B
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 15:56:30 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1cc3130ba31sf9996205ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 06:56:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700146589; cv=pass;
        d=google.com; s=arc-20160816;
        b=NWmDa+oCUHx2uV8uzMKMr768c2gDUriqgl1hHy+rAnh1OWPoyDgwHyz3VvZkW3I8Nk
         Po+TXL93KgF20/nSp3y0QQfiFOWO/yfpJejRAt0aQxW5BO66Et1TF9K5EjI7o6bOHgS8
         9+ev4pjFGX+DzYXKEoeAEIp+t0lobG5CKHdKXd1GeHivp8DVfNalToBeEjCRQezV9f3h
         XUodCTdcgwlveZUv9rzpik/e4lhTchrnoMK6d1cyF4XccRz390sBt4YGzLHKoGAHY5tr
         sDaZRv3gtDbYVUEFmrZa3GuaRITzxuKVXw11yRv7LUcCn5PmZJVFti2t1nLa7aZZFztG
         035g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0kIVM+/No10jVyKU431YzkFWdU4Ypds+gFYvTn5slkY=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=D6/13GMUfpP4lQZHFQ89hfWXc7VEp3Zsoox5IaAGoZPe7nuD8BruGC8MVTCTl2wHxY
         4R5y+SeyC4nwuV0LBKxPv5jXJNOgdX8ZyJ/nPSP7ycA9pSHEBYy19y6D3EoXhKjdau8R
         2FgAOqfUzyWDQrcIOwueygeSVshDIZsJ+pOuqT75ah+BWIB7ddFPvwkNL0CWM0QI0JTv
         JIk+fTtbRS7VxuZmme9s3YhmrJ88iUO7TifhsUhKV098WI2oLzTnQHXTVeCDqVKDDMUW
         SVn9gfrxy7LXfBmaEXqBFePgtGsBQA3of3aym/Ttfw+ZRXgJHLs1gwbKOubyoKXzevC6
         bNeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iKfsYhdI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700146589; x=1700751389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0kIVM+/No10jVyKU431YzkFWdU4Ypds+gFYvTn5slkY=;
        b=SXkgrJc9+ctQkGlWtWJLIvHSHB97W5bLTI/EjdC+bnBD/vGb7YlQD9mJ2JjToiEZXt
         0HyFgHTYlgr9j7wKhN8F5chFeUiaZTfZfwPetE3bBKumB/5QdXImBtgWMYPnRVBD5ftP
         j/1R5YeyOKRF03udY6x3q0UbTdWCyQ6Cayv7/eA36D6+YsSbT1v/CZaDmrs326ANCupn
         eBVslVzLGdZhTEUOt1c9rV7e9PpQoD5GSgn1AIcO8unIx7pCNqxZxrN/m9XXpal7BU+1
         6WclNap4pO2V8EvVoSkiBnklI7L3Y4zfBgv2UrIVQyvLxSUnPamiYgjQDPguOzy+oENB
         x2Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700146589; x=1700751389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0kIVM+/No10jVyKU431YzkFWdU4Ypds+gFYvTn5slkY=;
        b=FnXAvGx/DOx5pQR/CP/Zr98ebrTeo1ZaJ1bdf6Lf2gDVvoHfDAGLo0je94sTKeUDK0
         lTA7hIpkR5nVp7sAmBMILiZfBUWjfwoqqogjAgyWpVeQ9e91WTWZ3Ol2QxZM1Dkf/FRH
         aW9483ZCoN+prMej6Nac5rWXbxX5/w9uNRAyCQu2lRCIoMYZX9ZLUA3iMTpQ3XeTBP5x
         0mGSCkiw6BL6pG2maSwScZbMcqfCbLEUWpId4ucCxazDMIAkEvwEIziun+rVoV2iVlJF
         zaUiYYX72fkzYvJd1Zo+jOxafqsXvytJt1Pv73GnON6Ca06JsGAcaCo6vZ0VD9AObjLd
         f1OQ==
X-Gm-Message-State: AOJu0YyFBy80fJ901DVZkmPcg0sAkWuSTpG6esNPQqoxUFNpZkcYF3uD
	8lRBzSx2EsZASGNOvTJBBRc=
X-Google-Smtp-Source: AGHT+IEFsHTYZ2lk/quUaTMkO4Tuduzx+BON8zA5T8LQ7JmKoLT8vq64ITyBo6PsKcEq2g3MGlABbg==
X-Received: by 2002:a17:903:2101:b0:1cc:f60:28b2 with SMTP id o1-20020a170903210100b001cc0f6028b2mr8256877ple.6.1700146588594;
        Thu, 16 Nov 2023 06:56:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2285:b0:1c3:f5db:54b8 with SMTP id
 b5-20020a170903228500b001c3f5db54b8ls751811plh.2.-pod-prod-01-us; Thu, 16 Nov
 2023 06:56:27 -0800 (PST)
X-Received: by 2002:a17:902:cecd:b0:1cc:6597:f41e with SMTP id d13-20020a170902cecd00b001cc6597f41emr11655323plg.0.1700146587512;
        Thu, 16 Nov 2023 06:56:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700146587; cv=none;
        d=google.com; s=arc-20160816;
        b=iDrKlH4Bwq/S29S1TUzHQxZ5soejzeKBpe+K0MVGewxGTpsjbyBfcVOSRAmO4J03Vc
         eAPTu1CPmulB7JWY4IMZdh2lquSn2ylasVfBl936p7RZ00lImy3P4fbU6vLo+QP+Pp+j
         wtepiEyAcaGqTNlUN3VhNkhSZIzrYF8m55mgXbtkcSBynqfxE3VyIMFRHylHnrorIXMU
         Q4riRE91Nr8NY8jTX7/rB8RwfAv+cdY+mLd6Ga/mD6ux66bytQcx/ZP5tFtTf7iG46CA
         8VpRJew01k2p4fizOg5hs6MvJEKRlYNJvC/q1zFtSxYov3jlQkuad/tzqZZltoVc8ghd
         yFOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tzM0stGZCClmmzmredmePw1BMrI7dq9aY1ehb48KIQU=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=ufD7R3t4hHN717NG7L1O1FfQ3jbg4ELRia6t4rauzyybLGnF+R/An5u8WEwyJ/6934
         OjUUB4cCTmRveefINRflgGv7IctJtgl6jHpo3lvhaNbG/XnA27X+zwhw3rzAlHhjD2xY
         qLJOVybt1fRNVWnYXKD8viTgMAlpYHGtdn6iOC3CcTnSrUX/cnpnRMu8mp5hBupq7+1w
         dR1gIT/VFHF/L/81PO9yxn8OD0N9NJcPSY9G2jMLE8P2gJ4scSCqRnEskXDiexAcLjGJ
         lN9oi8ChwtMnaw7sj5rfH6YlcvxDWit9ZhDBLM30ar5N9z1vksyqqyWg3KYSVyJVihyF
         LA9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iKfsYhdI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id v1-20020a170902ca8100b001cc4a23c616si627776pld.5.2023.11.16.06.56.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 06:56:27 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-6707401e1edso4718746d6.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 06:56:27 -0800 (PST)
X-Received: by 2002:a0c:bf02:0:b0:675:5925:7e08 with SMTP id
 m2-20020a0cbf02000000b0067559257e08mr8062067qvi.32.1700146586474; Thu, 16 Nov
 2023 06:56:26 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-14-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-14-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 15:55:45 +0100
Message-ID: <CAG_fn=WOfRvDw3r3zcZXWr8aa6MiEuKSa1etQrGVSJP+ic7=mg@mail.gmail.com>
Subject: Re: [PATCH 13/32] kmsan: Support SLAB_POISON
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iKfsYhdI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Avoid false KMSAN negatives with SLUB_DEBUG by allowing
> kmsan_slab_free() to poison the freed memory, and by preventing
> init_object() from unpoisoning new allocations.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  mm/kmsan/hooks.c | 2 +-
>  mm/slub.c        | 3 ++-
>  2 files changed, 3 insertions(+), 2 deletions(-)
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
> index 63d281dfacdb..8d9aa4d7cb7e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1024,7 +1024,8 @@ static __printf(3, 4) void slab_err(struct kmem_cac=
he *s, struct slab *slab,
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>  }
>
> -static void init_object(struct kmem_cache *s, void *object, u8 val)
> +__no_sanitize_memory static void

__no_sanitize_memory should be used with great care, because it drops
all instrumentation from the function, and any shadow writes will be
lost.
Won't it be better to add kmsan_poison() to init_object() if you want
it to stay uninitialized?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWOfRvDw3r3zcZXWr8aa6MiEuKSa1etQrGVSJP%2Bic7%3Dmg%40mail.=
gmail.com.
