Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVEXR6UQMGQEJUC526Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EF2D7BD77A
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 11:45:58 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1dcf6a4378bsf5794990fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 02:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696844757; cv=pass;
        d=google.com; s=arc-20160816;
        b=GqzYLbeeZXCxUsJ2eK3FNrv5Ug9VYfCCHFoc7Pb56RTD4LLGclcuBpv2xwl3f9r4zR
         O5XDIMyFixskEOhIqgjI3BKtgtr/4pReIqNMh0EzbULLZ4aam1kJ0b6WRO0Ct1sy6Ch4
         oFEmGEvMIPoh05Z1KBp/01zYCRKuqdhqvxjWLSiQzwA3tV6u6I9J6p2NWxWzrl6+Ly9w
         ztJckiDBkE77M+YE9wUY/vK737o5JpsDOfZwnZ/xgAsP+iwR9BLh20y7On1tqJHEmJ4O
         y64kLVE422ut+K5taQkvmTuhgtf8lqzMObo3e+6mmM5MRHF5il/qLu+1UVReiAoZLgZd
         zm8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sXsrk/ZMGTkXzOPhbDHE+hvKmX7HcgUVYNe4ZTqj+zw=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=XmlEgpZ2jouUHApksQcF7VkxxrmwTU+FzI3CPw6lDx+lEQbtzyTG9G1g37enhQTW+Q
         bzFdEORoioM7KFcjhQDQ59xYmOdyjCDH2cZgYGdgy4GXfOKzT/hRhDXLJxL9oOjyMZby
         N5hWXRMbCgOs3GGrEfjFKiDOyRwcokhvSonKAU+gUvm6fTdrJhIG3WV+FZeMmBacxk1v
         +w2LU0oFgtPdQBUhNA9rrTeu8z+TQsY3Xl1eUQfPCjSMR+eeetjp9TzLy6Hovwok+m1F
         IRMGZwAwlTg2HWxGw13jUiN4K7vyp4SJ1M/KBHfCXBVX6vwkVD6hgZN6Lkwp1O6847U7
         Tlng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FCmEKiP6;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696844757; x=1697449557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sXsrk/ZMGTkXzOPhbDHE+hvKmX7HcgUVYNe4ZTqj+zw=;
        b=GrBWmG6hu6wMtcDoivedB0lfchzwRKkEGX7/o8UW2zzEWKr3jHsSX3gKvI32F51lMT
         QqRjF95INWmVp5vkhLiT6EhHSUh5pC6MesFztz85KB9OsNNF+VsWFJmaj25//DEAl+VD
         KRdTD2xL7Rc86w2fCF7JWzema/NMAho/zBbL7+6rb/EhEp3YB9hr8lOq5cNHJUybUZRC
         dcErct3nL9crs8X+WoxHSg8yq5u2hCSLlGYjk8UH76Str44eNOVyXX4CpaKr/lPfj89N
         KHQfFhUjNrhs9r/8NVOH7l2pZf3unPDxWjJj+PwscJl2D+rGwZLCpwtcobnFARlrjKhi
         JqjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696844757; x=1697449557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sXsrk/ZMGTkXzOPhbDHE+hvKmX7HcgUVYNe4ZTqj+zw=;
        b=DmR8yqSiARgYbHDoeuOydaoMfXjiM5ErRqQiyRPIdWEXNyE4yL54dx2JQitsrbjEeR
         LlFhK0ZGoQNtJiKs5/6GhN4uxbjGu5TJncnHVwpKnfoKJKVW7K2dRAHVDGijKHiHajq+
         6K5BMJaDCu362FBk+gjNE4xTUtKwNuygBaZANUNKHiiTNPglOJcaLOGw/Sf9ItBfs0gx
         fzbsai9yV2eZ8V9WLtTR/f/QYTHkO+tlVaM9zidW6CyV26cFkNGWHoh8S+f/5ahO7Cmx
         /g2u1j33ZV5k2U6LskJgUfJyd2Vwv5b+9BCCMsLobdUbDNS1kau+ETFOJaRlrRZPgMhF
         wibw==
X-Gm-Message-State: AOJu0Yy1F2RbWS9cl5Y4WBqBDcq5dPr+JfDBmHUcUj5B9J2ADIbkkavi
	GLLE+qrOFYPdNJb8O3bywzg=
X-Google-Smtp-Source: AGHT+IFoSrqZW8dNzdB23bzhRzM/mbL918YhTLdXUoDG/6fXS4vCjaPrnKl8MzreVx4WQss1e1jT/Q==
X-Received: by 2002:a05:6870:7024:b0:1d0:dbdd:2792 with SMTP id u36-20020a056870702400b001d0dbdd2792mr15332642oae.39.1696844756952;
        Mon, 09 Oct 2023 02:45:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:209:b0:1d6:cbc7:fb4c with SMTP id
 t9-20020a056871020900b001d6cbc7fb4cls6031922oad.1.-pod-prod-06-us; Mon, 09
 Oct 2023 02:45:56 -0700 (PDT)
X-Received: by 2002:a05:6870:910c:b0:1d5:aab3:ecd3 with SMTP id o12-20020a056870910c00b001d5aab3ecd3mr15093056oae.6.1696844756373;
        Mon, 09 Oct 2023 02:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696844756; cv=none;
        d=google.com; s=arc-20160816;
        b=rap1xFgtoR0svls7huHIowKibEbC/vcEuyGVDSl+Tu+/I1dL7g9A/lVdl2P2FVosnd
         bs6UsmwEcacZyqtTqZ7fe+Z9EfbfcqLlTJBQDShImwAzk6N5cGSSDmJXRQP+BOxVROBH
         QwmGiRo/oSW4m953y3cnLFtTcYsUFhFwwAozirdKssOyZNYdL/vEubwZSLGkphwIbnET
         clNGdJmybPwU9kS/oJ4pAPMOognrHfGoSzr0eBKNLDPcxq++U68gj0q7v6J5ce1YU+9z
         kSzgD7WYWAC/dKhTBxyeKMzorz3bM21YfqbkTWB2lB9fCptso9DYTi0eEeVWpmkvBqnp
         BpBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Y350VwO6015lGO7ERBdBbOV3S2AzDXdRMs/XXWO/P3w=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=WGLcKDzpqBavYs6jOHKMQFckOSY77zRpxxqa3t0+Mor7l7hH3r0Hsz5Ujne56cX9gf
         IAg7wOJQ7b+TRGFomENS6lrrCIOri8T2YsDs3qpJCvdlmdSGm/gW1XWCAdRHFAIa0d2O
         BOD1YrS5PhFGJaMlk0qqznaJiXJ4uRvJ1uaKn7aAjcXj+mvZa2N83naAfFLA0aqGDcgn
         Sa63i8mb/blZOEWzUgEu/JPpyXFSc7F76V+k7w95JRMdIQQdsn9lc9T2xb5tjElGINVZ
         EdP8EHivyjUHpyfADsvtpl9fVZWnN7tS3DwGVsENV9/Qvgh4bfWNC2A9kAaiZwwUjmqi
         NhrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FCmEKiP6;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id ti23-20020a056871891700b001d6741a71e5si658226oab.4.2023.10.09.02.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 02:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-65afd8af8bbso29098206d6.3
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 02:45:56 -0700 (PDT)
X-Received: by 2002:a05:6214:3d0d:b0:651:69d7:3d6a with SMTP id
 ol13-20020a0562143d0d00b0065169d73d6amr16569724qvb.15.1696844755772; Mon, 09
 Oct 2023 02:45:55 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <5c5eca8a53ea53352794de57c87440ec509c9bbc.1694625260.git.andreyknvl@google.com>
In-Reply-To: <5c5eca8a53ea53352794de57c87440ec509c9bbc.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 11:45:19 +0200
Message-ID: <CAG_fn=VBAN+JPtqRRacd69DOK9rZ-RMpzn+QDJTsZgQ68sOS=Q@mail.gmail.com>
Subject: Re: [PATCH v2 11/19] lib/stackdepot: use read/write lock
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FCmEKiP6;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
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

On Wed, Sep 13, 2023 at 7:16=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Currently, stack depot uses the following locking scheme:
>
> 1. Lock-free accesses when looking up a stack record, which allows to
>    have multiple users to look up records in parallel;
> 2. Spinlock for protecting the stack depot pools and the hash table
>    when adding a new record.
>
> For implementing the eviction of stack traces from stack depot, the
> lock-free approach is not going to work anymore, as we will need to be
> able to also remove records from the hash table.
>
> Convert the spinlock into a read/write lock, and drop the atomic accesses=
,
> as they are no longer required.
>
> Looking up stack traces is now protected by the read lock and adding new
> records - by the write lock. One of the following patches will add a new
> function for evicting stack records, which will be protected by the write
> lock as well.
>
> With this change, multiple users can still look up records in parallel.
>
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Alexander Potapenko <glider@google.com>
(but see the comment below)

>  static struct stack_record *depot_fetch_stack(depot_stack_handle_t handl=
e)
>  {
>         union handle_parts parts =3D { .handle =3D handle };
> -       /*
> -        * READ_ONCE pairs with potential concurrent write in
> -        * depot_init_pool.
> -        */
> -       int pools_num_cached =3D READ_ONCE(pools_num);
>         void *pool;
>         size_t offset =3D parts.offset << DEPOT_STACK_ALIGN;
>         struct stack_record *stack;
>
> -       if (parts.pool_index > pools_num_cached) {
> +       lockdep_assert_held(&pool_rwlock);

Shouldn't it be lockdep_assert_held_read()?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVBAN%2BJPtqRRacd69DOK9rZ-RMpzn%2BQDJTsZgQ68sOS%3DQ%40mai=
l.gmail.com.
