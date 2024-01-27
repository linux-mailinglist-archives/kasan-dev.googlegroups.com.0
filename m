Return-Path: <kasan-dev+bncBDW2JDUY5AORBA6D2GWQMGQEXOVCA6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 28EF383E91E
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Jan 2024 02:51:01 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5102ed61056sf71397e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 17:51:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706320260; cv=pass;
        d=google.com; s=arc-20160816;
        b=TcJ1HoLho3AwJnFXMalubtuR9hcz6gImdXjPJ+rC2I4JmN6Y2y1afQZW8C1p0ttOIF
         5ytq20owyvNneB5uXrWTdhtJwJb4FywxYPqGW7hfZ0LCRIlDMTWgDSwt9yp87D9kxTO5
         ocg+xGWfO2UlGOLNCNyois6y7Z+FBpnzGRIAyAsgHPnneRPrA4XHZgxJ9A8sA0GLSGJM
         pqJE9o61zAKELg98+k1PV6VUKyzXxAcwCZs41D4RDKyPSn+57n7qZ5pnflQUeNlqso3A
         moq3UCm7boRMbpx6BOwXlIeSAJEkOwuNHPJVnMlZh/axvdarZ7VEHeQ4uh8H34KEHvwf
         GKOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LRveRUHixfgTot1A6Arc1kaKBNbco1ANlzpWC6liAvs=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=MRf+/RG/yBO/ur07bGqlJc1dGw+G3cdzfTPup8i/gGJGknj2w1csx7Y1D++pFSu2MZ
         /BRYOQrCNqnPz8/WP5P4Ab8echiAlS8eM+rOGJnBtAHZ8gh7sEwQS53BbKxFSBvfUAio
         evtAsY5xd4W9FhI87Ll2OyyBj+Sf1dRU2WfK/zhTd6rlfdAJL82Pdk3HfRN6hH14L1/J
         d7vOCv9LHHXxGAfYRSijmnzhh99tHhody1uNOA3s8+f4oKT88bh8YFO/zuu6aOC7Z+GZ
         ls5TlxOm9YDfO1O8X/0QDqArujNus698SEvemw6pf0aC27M3Jak1pQwGd+XZZq9FMN3Q
         aA5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YfoikFJs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706320260; x=1706925060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LRveRUHixfgTot1A6Arc1kaKBNbco1ANlzpWC6liAvs=;
        b=C4HigLzOcjQWRIJ8i2PV1KW+9dInhYrDbR/VoXcBZOxmR1CBmR/ZxeFaUZHX2Tx9Hz
         2eyGd5c3rKlDPi+Wm4zBw/pR07MPeeDU6AN+kuB99sBcgfQABCPw1ITsMnHjvu+vZXY8
         4z5cRmd7uoo3p6SGncr8o2QyPUVgcM2DZXXhyjNmaOLKb3yHWPGVM0DLbZlHC3IA+bl4
         NChcS1MMxhMikQWvu39S4doJwhhNXoMPqokZ6Mh1HFD8+aDmniu/uE+2q60c9YB/MB41
         3kRjcZX9s50TcspmJYzu1FJGZG8gp1AnMMQh5a0JyVhFRu082QvyIsttJpueBOyt1aUn
         r7xQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706320260; x=1706925060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LRveRUHixfgTot1A6Arc1kaKBNbco1ANlzpWC6liAvs=;
        b=iq7QHLBxpNSLuNKg7Pc/g7mqHi8fR8kYeIsLrbKnchgaJhHCparO2YynDhDNXbnBP8
         s11CggZMtF8iAuei6jGZPPd6akVyjFuWqxAtu5mhMkg2rygeTntNG/jPElZKgZirli6D
         ocbM4o7tOiy6iLLdKtyksIUwMfd2n39j4tvkGGNZjQCLg16fTLloY4UV2ilTRiG+Ic7s
         ftrYtIMm8c5WXZhgOjIUOwsFLxpKxhvWPArN0D39RSAlHGkU4oqM4yVcoZA9Yff2U1Fh
         OM/MkGzQyENCMJUwCHZWUKZ54Fvpn3jOARP3koPmpfD80G+rqgn/XmblJ9m2KUIRqKnp
         TjmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706320260; x=1706925060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LRveRUHixfgTot1A6Arc1kaKBNbco1ANlzpWC6liAvs=;
        b=FlJi7L77CrZmv23FJymagY+6rv2XSIaIg0aVFsPXVOfQIhfovDkAINJm7UQqg4XIDE
         akIiFr05/WEmGiqf+5DcjhiP2fGJNZ/D1cUCRX4Mv2ZlVTMyk3urTxNsyi9vgnTlaB+c
         fUeMUIGuo7pM9eGEHG6Qtjht9gHG+FAZD4+2dzFNaY5amjTQlj7mrduUZ7G6IzQevboL
         zvr866SQNk1Ho7kHFFw6N8LX4Osw5CgyPJymTRTKeL81cDqbhGR+kqLSMrIIPYeSYSY3
         1fu1WTeYiKX802VOl/ogSdChQm89S8IGyytdNa8wP4V+GLwG12HuUfelDcxrs/m4l4V/
         uJuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxDwCScrwOipcEbxs/0FLttBb/0wQadYWufGkYlCYcoIjm6d8Ia
	+A97r6/CiNOWw4858VTrPSwztE5fCnXbCAhs8kilKl326vrwa/A0
X-Google-Smtp-Source: AGHT+IG9pIFPzUaF5KMtUg596uRrqUxGcgfSVkba16mYqPHrVbH99+HhsoAINYjSCFVG2MozMJTZCA==
X-Received: by 2002:a19:4f4f:0:b0:510:253f:32dc with SMTP id a15-20020a194f4f000000b00510253f32dcmr377250lfk.32.1706320259603;
        Fri, 26 Jan 2024 17:50:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ef:0:b0:510:12fc:838f with SMTP id v15-20020ac258ef000000b0051012fc838fls236872lfo.1.-pod-prod-04-eu;
 Fri, 26 Jan 2024 17:50:58 -0800 (PST)
X-Received: by 2002:a19:2d59:0:b0:510:28ec:2a82 with SMTP id t25-20020a192d59000000b0051028ec2a82mr361262lft.44.1706320257632;
        Fri, 26 Jan 2024 17:50:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706320257; cv=none;
        d=google.com; s=arc-20160816;
        b=R9jLjO/yBu1OvqD8IWr8f7QwskuSDdHYbH0JIZ4meBZNjwK1qS3F49vbKnfOecUQ6q
         szEITXsovAiYANPkuUBv/pXzjZHFTWSNyCRPREg5s9YuWAeSljWHNyj9UPoE16Q/5urU
         1irgsGBXSmbBFVe4GvBq8cUnvC6Z9Nk6unvjXKXeghlxEn5zwvXbwtE9JWtXnyLrBhiw
         cGukpgJkUZDsAEJ8WqWtPG+hdPrW2R13/Z1OU0JgYQ8xFlQZ74/osI16ev4eYmp9zd1D
         RbNdybXTidVYs7In13nWyANmDKr6OjXScHZO8KuNc9qGkBNDnBRJRy3cDxs/bB3CB293
         zD6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j3KL7omzR2YR5H0m3wzbipCveRvJiJv/pASMUWh3gAY=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=hHzsu34wi+EufIv3KT5768ZcRAIhhAvjO4BBx2HwUoJuIrnN/rvxEiaxrxE4NmXXDu
         c9yoUcKWqWr9gEYzAJ4HsUmFhUq5tCzWJiCN4vs7+TREM+YUcazhkltVUhBC7brafryt
         C8d/ffTEIgiRuXsWALPEEcEk3DyMXr84ZKDymGiXTJnpf7wpcI9/0OXajJwMuVIWxMqv
         zeloW2oKWRxJ3oBvgo6U/mBL2Jv6L8heWq6JWlxQGLjtdhpjwvJuU8msdddyxJ1vXN5O
         7mZlF5s4ZgpTVntAMKtNccOVvWZEXQplig+0uXRIp88FkGCd/JzovW75QGX/wm163aOq
         Z24Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YfoikFJs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id be34-20020a056512252200b005100f83603fsi87075lfb.2.2024.01.26.17.50.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jan 2024 17:50:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-33924df7245so1305059f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Jan 2024 17:50:57 -0800 (PST)
X-Received: by 2002:adf:e34e:0:b0:337:a81a:a92 with SMTP id
 n14-20020adfe34e000000b00337a81a0a92mr381731wrj.16.1706320256834; Fri, 26 Jan
 2024 17:50:56 -0800 (PST)
MIME-Version: 1.0
References: <20240125094815.2041933-1-elver@google.com> <CA+fCnZfzpPvg3UXKfxhe8n-tT2Pqhfysy_HdrMb6MxaEtnJ2BQ@mail.gmail.com>
 <ZbO8yD_ofPQ1Z2NT@elver.google.com>
In-Reply-To: <ZbO8yD_ofPQ1Z2NT@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 27 Jan 2024 02:50:46 +0100
Message-ID: <CA+fCnZeD_UpKw+hMUY3rkTAkPqYvhFe85HP8LSZOHrv1DyQ-Ug@mail.gmail.com>
Subject: Re: [PATCH 1/2] stackdepot: use variable size records for
 non-evictable entries
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YfoikFJs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Fri, Jan 26, 2024 at 3:08=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, Jan 25, 2024 at 11:35PM +0100, Andrey Konovalov wrote:
> [...]
> > I wonder if we should separate the stat counters for
> > evictable/non-evictable cases. For non-evictable, we could count the
> > amount of consumed memory.
> [...]
> >
> > We can also now drop the special case for DEPOT_POOLS_CAP for KMSAN.
> >
> > Otherwise, looks good to me.
> >
> > Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > Thank you for cleaning this up!
>
> Thanks - probably will add this change for v2:
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 1b0d948a053c..8f3b2c84ec2d 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -44,17 +44,7 @@
>  #define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_A=
LIGN)
>  #define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
>                                STACK_DEPOT_EXTRA_BITS)
> -#if IS_ENABLED(CONFIG_KMSAN) && CONFIG_STACKDEPOT_MAX_FRAMES >=3D 32
> -/*
> - * KMSAN is frequently used in fuzzing scenarios and thus saves a lot of=
 stack
> - * traces. As KMSAN does not support evicting stack traces from the stac=
k
> - * depot, the stack depot capacity might be reached quickly with large s=
tack
> - * records. Adjust the maximum number of stack depot pools for this case=
.
> - */
> -#define DEPOT_POOLS_CAP (8192 * (CONFIG_STACKDEPOT_MAX_FRAMES / 16))
> -#else
>  #define DEPOT_POOLS_CAP 8192
> -#endif
>  #define DEPOT_MAX_POOLS \
>         (((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
>          (1LL << (DEPOT_POOL_INDEX_BITS)) : DEPOT_POOLS_CAP)
> @@ -128,18 +118,22 @@ static DEFINE_RAW_SPINLOCK(pool_lock);
>
>  /* Statistics counters for debugfs. */
>  enum depot_counter_id {
> -       DEPOT_COUNTER_ALLOCS,
> -       DEPOT_COUNTER_FREES,
> -       DEPOT_COUNTER_INUSE,
> +       DEPOT_COUNTER_REFD_ALLOCS,
> +       DEPOT_COUNTER_REFD_FREES,
> +       DEPOT_COUNTER_REFD_INUSE,
>         DEPOT_COUNTER_FREELIST_SIZE,
> +       DEPOT_COUNTER_PERSIST_COUNT,
> +       DEPOT_COUNTER_PERSIST_BYTES,
>         DEPOT_COUNTER_COUNT,
>  };
>  static long counters[DEPOT_COUNTER_COUNT];
>  static const char *const counter_names[] =3D {
> -       [DEPOT_COUNTER_ALLOCS]          =3D "allocations",
> -       [DEPOT_COUNTER_FREES]           =3D "frees",
> -       [DEPOT_COUNTER_INUSE]           =3D "in_use",
> +       [DEPOT_COUNTER_REFD_ALLOCS]     =3D "refcounted_allocations",
> +       [DEPOT_COUNTER_REFD_FREES]      =3D "refcounted_frees",
> +       [DEPOT_COUNTER_REFD_INUSE]      =3D "refcounted_in_use",
>         [DEPOT_COUNTER_FREELIST_SIZE]   =3D "freelist_size",
> +       [DEPOT_COUNTER_PERSIST_COUNT]   =3D "persistent_count",
> +       [DEPOT_COUNTER_PERSIST_BYTES]   =3D "persistent_bytes",
>  };
>  static_assert(ARRAY_SIZE(counter_names) =3D=3D DEPOT_COUNTER_COUNT);
>
> @@ -388,7 +382,7 @@ static struct stack_record *depot_pop_free_pool(void =
**prealloc, size_t size)
>         return stack;
>  }
>
> -/* Try to find next free usable entry. */
> +/* Try to find next free usable entry from the freelist. */
>  static struct stack_record *depot_pop_free(void)
>  {
>         struct stack_record *stack;
> @@ -466,9 +460,13 @@ depot_alloc_stack(unsigned long *entries, int nr_ent=
ries, u32 hash, depot_flags_
>
>         if (flags & STACK_DEPOT_FLAG_GET) {
>                 refcount_set(&stack->count, 1);
> +               counters[DEPOT_COUNTER_REFD_ALLOCS]++;
> +               counters[DEPOT_COUNTER_REFD_INUSE]++;
>         } else {
>                 /* Warn on attempts to switch to refcounting this entry. =
*/
>                 refcount_set(&stack->count, REFCOUNT_SATURATED);
> +               counters[DEPOT_COUNTER_PERSIST_COUNT]++;
> +               counters[DEPOT_COUNTER_PERSIST_BYTES] +=3D record_size;
>         }
>
>         /*
> @@ -477,8 +475,6 @@ depot_alloc_stack(unsigned long *entries, int nr_entr=
ies, u32 hash, depot_flags_
>          */
>         kmsan_unpoison_memory(stack, record_size);
>
> -       counters[DEPOT_COUNTER_ALLOCS]++;
> -       counters[DEPOT_COUNTER_INUSE]++;
>         return stack;
>  }
>
> @@ -546,8 +542,8 @@ static void depot_free_stack(struct stack_record *sta=
ck)
>         list_add_tail(&stack->free_list, &free_stacks);
>
>         counters[DEPOT_COUNTER_FREELIST_SIZE]++;
> -       counters[DEPOT_COUNTER_FREES]++;
> -       counters[DEPOT_COUNTER_INUSE]--;
> +       counters[DEPOT_COUNTER_REFD_FREES]++;
> +       counters[DEPOT_COUNTER_REFD_INUSE]--;
>
>         printk_deferred_exit();
>         raw_spin_unlock_irqrestore(&pool_lock, flags);

Looks good to me, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeD_UpKw%2BhMUY3rkTAkPqYvhFe85HP8LSZOHrv1DyQ-Ug%40mail.gm=
ail.com.
