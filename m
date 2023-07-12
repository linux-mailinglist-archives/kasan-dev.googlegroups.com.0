Return-Path: <kasan-dev+bncBDW2JDUY5AORB6NGXOSQMGQEZ5RMYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8305F750E58
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 18:23:22 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-345c1f3dcc8sf29099345ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 09:23:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689179001; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ty2wR4Jdoh4haidfGTYrj4GutuODgHSWXI6ypZUUnYQNOyyTbtS4ckqU7wtiNusZ03
         JdYUz57OV9GVmTMN3eJzllO+4OsxDUP64dUKPnqZZgr1tbkLEH4tSHpnX0mny/uMlBCm
         KeVSV3I84fOd1o9QgTSI+7LGZS9+BM17oiAe/Ogw84/tDakzTBsqDfn8gfT6PrfPBJYq
         j57N1U3QUi/Trfz5MqjVKDQNj8CnZv5FZAo1zCjk9nNrOTGtL/8WBg8j2qSSjv24rBEw
         ZAvtgIUwnExOzqutZOu/QTrXl+eQUtrNZYdOEaVHGVqLITKmeUGcN4T22hpfKMXOhIUT
         xfXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Sv1EgYyWB5G2e8bvWIV9SqxNrfN5JWKesvG+x3ruuPg=;
        fh=4I9zulnuaa5TPkCKIOTNIi//wfcaTkqkdQ68aKL3xBE=;
        b=DUrrLbllr8bIVxVupzB8/FmLl0oMBmUalGwM4JOJYobPmhD/JYfthb36EuAswXSBbe
         5na/Riv3kKxivYLTlfaDMeGifEu5whVt4cASnZRFGXlOs65lutPPAnyJldf2cOKatplH
         QgoTpxP1N2/eQXIqsKN0EWF1h7MBKtt/GkY2ZHCsGXk2C0kTNs6q/4C4t+wtcaw6pohw
         9m0hfRE3cs0v3hAdfOe5yZYji0WYvO5sL6vO2896x24KeqAJv4Ru6snOtd0W6/pOOJm5
         EZDe9YUmry53s/rYS879ReBet2GNEaQ0JomR2A68dhQuUFjuXPKrnQ0k4BYNpEhnIiGB
         idFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=VHnuNATv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689179001; x=1691771001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Sv1EgYyWB5G2e8bvWIV9SqxNrfN5JWKesvG+x3ruuPg=;
        b=CAhkGKJ2hxyVeTuM7PHA3dy8b6jLL2jP4C4EpFM1rzStIYu6qq6L0GlsczRKAdgzy3
         Fa1RHJ9wvPw4CviQjZmqn32zd/xw7wQNJ0VUUWxd3iT8Xv0U6cEL6eRF0NAAG6+lThQR
         nt+2oklJtsOnefcY9plPJJ2pLMyV6jB+dDqSKBWSffkqweKPQi1/oe/Kb9i1SIkFe9NX
         qhsv3XLbFwn1oiqJhKycSnwytOQ+rP0LGfy+aG+d5i+1251RKFKKgBT1FrUmxlkSGvG+
         xgy/v8WUksuwMe+6Nkf0kKHiWubgPJ2f1XrHzU68MOKHrYIzPRDHcJXvf9P3S0t+uId5
         t5fQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1689179001; x=1691771001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Sv1EgYyWB5G2e8bvWIV9SqxNrfN5JWKesvG+x3ruuPg=;
        b=eFbbUSsNc5d0Dl0GfEy3ws1psmQOoLdfzFvo9f7levjmZ7H9f7NuUtcRtRS4a+AJM/
         DXMGxiV73vhezcdX6OmV9EDMZqQVvBu2jANpytL0MUoXapLzTagDyFnsoq0zhLkNiVAt
         H5POnW+X/UzTxVHCMc3RvHw3zWu5Z6jHKxnbq3KDhm9m0iBuGhby5kjBRtRoi3MMDItn
         ybFaHaNcbAqheNpYPzf0KJGsNtsrcFNcDXyxlyuXMNXK8H6Bbg1rRT8aqLFUAl1UhIY6
         7V7Kq08L5NEm0w2TfMtx21t3An9a7Wew9Jdsh7I7KmMeXDuK/1zuZMMx6M3Pm4oqjS6z
         akLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689179001; x=1691771001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sv1EgYyWB5G2e8bvWIV9SqxNrfN5JWKesvG+x3ruuPg=;
        b=hrXfl94unNGXGVGaFw8mf36CEP1A0tGzv29pG+95wcW0TDvETJGco2qSZCAh3x9MmL
         mj88cKGd+OuswR9ussXMPn/8+hSGkWsOdNHq38g4p9YifuShBfZtMx1v8U3FVWWPD8K7
         Gdb7He8apPLpzYXLPUUlRQ/pmHAobiQ0nqsjLQahlG1A09TOJtVj545Vv3S2J/b+b3Oa
         hhym0F7YKLSnr4zZ+vXo0g7jk2iuLWHoYJYJ2An3MOekqYcwcbQVq1Yez0n6LPkT77IT
         IMnzFZWe7GR9khPnnjiCfa5GdEtnPLF4+W2PAMabnVm502xWmC++jZy/U7pgD+RkXiYg
         k24A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLY0BhW47mZYnLASAKzMY6IZLbbJGtlUIAVlcF9wlVlOL4cEBjxa
	FdXnNP2IgTRpA7xFeq7f08M=
X-Google-Smtp-Source: APBJJlHFAZ3CwtkTxBp0/l9EdQ/EVYlLA+0PfbZLLeoKkoNyR+j9eP/R8bt3vckoJ/IoFLA10JRq+A==
X-Received: by 2002:a92:cf05:0:b0:345:7d91:a1de with SMTP id c5-20020a92cf05000000b003457d91a1demr18279850ilo.19.1689179001171;
        Wed, 12 Jul 2023 09:23:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1baf:b0:345:993c:d726 with SMTP id
 n15-20020a056e021baf00b00345993cd726ls3392632ili.2.-pod-prod-07-us; Wed, 12
 Jul 2023 09:23:20 -0700 (PDT)
X-Received: by 2002:a05:6e02:78d:b0:346:779a:ff70 with SMTP id q13-20020a056e02078d00b00346779aff70mr4343327ils.28.1689179000466;
        Wed, 12 Jul 2023 09:23:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689179000; cv=none;
        d=google.com; s=arc-20160816;
        b=NIMTAX5SUfzsmWR/UBrUfZB7oEbaIq46Vxv99mmtlMeSCLFm26a+y8gOF3Cx0m/zvy
         6JXcC8graus1kKNdZ/MCKF1fACD20wb0ff1ppSTjykjXLy7C/AJFo/MhnC+UUR8JmQ/u
         x1iBSI9ZQ6bv4o41WHjdziehDP5Uhn1YajLTgY6XMwOLeBgMiYY9aS57U6w/p6+aCp9K
         p9vkCZpts9Lopv3LS0aQEJc7ohJmvyjLHYl+tJ+rc1X39zLbOxLU8gFFX7rmuNLYWaWB
         /bm0zhvKr0qcycX+5G0FkL/aKs7Fy88eH7yYt24KwP3Z3RT4GjKC0q157b2icxHpFx/4
         l3FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/mvKlKHSg/A3EuJ2PFCJvzfOkyyunP0cNJw9XZ1YoG4=;
        fh=4I9zulnuaa5TPkCKIOTNIi//wfcaTkqkdQ68aKL3xBE=;
        b=FCbtKxESqpe1rZeZNtFoeCHhjtmupk4kZwVGvVZGfR5qHUb3Pv+BGb/Z436MvZahUD
         cQHmwgwa9iUwgprVggvpbNebjFCYisEt8dXd6qKW7q4D6ZNUCGmcwT9HS6azW3e+YKWc
         0+l9G03TBRDqeGLBV/mXcgStCbgYqTgMIgZ/Sb3g7ajFeWSZYhiMx4F8dV1LDPpOhLjx
         ddXUC9rTfxpGmNEYJpf4WEcwBujjT865MW/ebqIwl1oOhJI9ruUPh23WKo23QBR81muG
         zo9O0/EZzTB0ThTLfFt7MVibsmf6rIJ5oAqgGJx5e7NWFV+0ewNJ1aegFXmaAmErPuVQ
         cR9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=VHnuNATv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id so4-20020a17090b1f8400b0025bf8494938si194156pjb.2.2023.07.12.09.23.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 09:23:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-262ea2ff59dso3598004a91.0
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 09:23:20 -0700 (PDT)
X-Received: by 2002:a17:90b:400a:b0:263:f5a5:fb98 with SMTP id
 ie10-20020a17090b400a00b00263f5a5fb98mr15776385pjb.28.1689178999981; Wed, 12
 Jul 2023 09:23:19 -0700 (PDT)
MIME-Version: 1.0
References: <20230711134623.12695-3-vbabka@suse.cz>
In-Reply-To: <20230711134623.12695-3-vbabka@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 12 Jul 2023 18:23:09 +0200
Message-ID: <CA+fCnZci9E8Snjuc-rJqSeX+Gn84_AVO5OjQwyFT=vL+pw22HQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm/slub: remove redundant kasan_reset_tag() from
 freelist_ptr calculations
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org, patches@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Matteo Rizzo <matteorizzo@google.com>, 
	Jann Horn <jannh@google.com>, Andrey Konovalov <andreyknvl@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Kees Cook <keescook@chromium.org>, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=VHnuNATv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a
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

On Tue, Jul 11, 2023 at 3:46=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Commit d36a63a943e3 ("kasan, slub: fix more conflicts with
> CONFIG_SLAB_FREELIST_HARDENED") has introduced kasan_reset_tags() to
> freelist_ptr() encoding/decoding when CONFIG_SLAB_FREELIST_HARDENED is
> enabled to resolve issues when passing tagged or untagged pointers
> inconsistently would lead to incorrect calculations.
>
> Later, commit aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing
> metadata") made sure all pointers have tags reset regardless of
> CONFIG_SLAB_FREELIST_HARDENED, because there was no other way to access
> the freepointer metadata safely with hw tag-based KASAN.
>
> Therefore the kasan_reset_tag() usage in freelist_ptr_encode()/decode()
> is now redundant, as all callers use kasan_reset_tag() unconditionally
> when constructing ptr_addr. Remove the redundant calls and simplify the
> code and remove obsolete comments.
>
> Also in freelist_ptr_encode() introduce an 'encoded' variable to make
> the lines shorter and make it similar to the _decode() one.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
> These 2 patches build on top of:
> https://lore.kernel.org/all/20230704135834.3884421-1-matteorizzo@google.c=
om/
>
>  mm/slub.c | 22 ++++++----------------
>  1 file changed, 6 insertions(+), 16 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index f8cc47eff742..07edad305512 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -374,22 +374,14 @@ typedef struct { unsigned long v; } freeptr_t;
>  static inline freeptr_t freelist_ptr_encode(const struct kmem_cache *s,
>                                             void *ptr, unsigned long ptr_=
addr)
>  {
> +       unsigned long encoded;
> +
>  #ifdef CONFIG_SLAB_FREELIST_HARDENED
> -       /*
> -        * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tag=
ged.
> -        * Normally, this doesn't cause any issues, as both set_freepoint=
er()
> -        * and get_freepointer() are called with a pointer with the same =
tag.
> -        * However, there are some issues with CONFIG_SLUB_DEBUG code. Fo=
r
> -        * example, when __free_slub() iterates over objects in a cache, =
it
> -        * passes untagged pointers to check_object(). check_object() in =
turns
> -        * calls get_freepointer() with an untagged pointer, which causes=
 the
> -        * freepointer to be restored incorrectly.
> -        */
> -       return (freeptr_t){.v =3D (unsigned long)ptr ^ s->random ^
> -                       swab((unsigned long)kasan_reset_tag((void *)ptr_a=
ddr))};
> +       encoded =3D (unsigned long)ptr ^ s->random ^ swab(ptr_addr);
>  #else
> -       return (freeptr_t){.v =3D (unsigned long)ptr};
> +       encoded =3D (unsigned long)ptr;
>  #endif
> +       return (freeptr_t){.v =3D encoded};
>  }
>
>  static inline void *freelist_ptr_decode(const struct kmem_cache *s,
> @@ -398,9 +390,7 @@ static inline void *freelist_ptr_decode(const struct =
kmem_cache *s,
>         void *decoded;
>
>  #ifdef CONFIG_SLAB_FREELIST_HARDENED
> -       /* See the comment in freelist_ptr_encode */
> -       decoded =3D (void *)(ptr.v ^ s->random ^
> -               swab((unsigned long)kasan_reset_tag((void *)ptr_addr)));
> +       decoded =3D (void *)(ptr.v ^ s->random ^ swab(ptr_addr));
>  #else
>         decoded =3D (void *)ptr.v;
>  #endif
> --
> 2.41.0

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZci9E8Snjuc-rJqSeX%2BGn84_AVO5OjQwyFT%3DvL%2Bpw22HQ%40mai=
l.gmail.com.
