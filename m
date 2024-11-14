Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBYPY264QMGQEJWU2B3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BA829C8BE6
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 14:34:27 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2fb58d1da8esf4120881fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 05:34:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731591267; cv=pass;
        d=google.com; s=arc-20240605;
        b=IiSiVTH03og83dTPHn6PHR7L1maLcUPQILqlxhHdqet2q8J8BYjZwlr29hW3Zwf6CD
         cyOMM6ZOYYHEpt1LA4pmG5aH2vNCQLTjSwmNaBPj/W8CpsBmhrnileaEVpOuGZIhFm3x
         Mx0v+ilI6qduu/FT/DduafNX6CZ0sLf8QzRVZaLR8Xo5LpjQBG6wF22XszEKNy5JswJl
         EN3uynRU5NcQHwXk7S/FrV1frsWIe5wkneHXiXb41W5aKWl86qJ5LpRqLssdaI7xKToL
         lFX7+jQVnSJ9pCYFBpClV8qhX4qbievj3B3scZhqS7EPj51AFVzePLBe/0Fu9HOMpshT
         3QUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=5uifKh3Ziurt6J4vVZSqwtf+Yzq6i1DIOK/XJ0xeWTM=;
        fh=oH7jlfGYFsqqZXMf6cbrs6aAxPK6bnv1CULKwxbqYsM=;
        b=jjYrtkVUEHMuUzeZtsY7jqqd11eh7QYFGjQaidN2NXESsR5/TJ8QuXq9K/RhteG8Pl
         7x8g8jcceRAB3xUffyODlkCOJlM7ID/jz8/P3g6gpKZDn1XWDuBqRtQbNccU6NO/fqwV
         2nWkSmFrY1BmMSnFtFUQppXNmnd9rHEoLXv7L/hHOaXGvbn2nPQj+3bzEWo+L17Sk2tA
         juZpCP6j7uWZab2C+FecP9mYwNOJP7eXijcqQWN0hbABpRnxtjZkqb1lXyhGq6nLvPVs
         2KnmiB4nmYzXlSJspCDg+bXWydkj29oaKqQxlcJa5OvHPdZWrP8qYBp4vac4Rmx1yRpr
         15jA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ifRNJ6dn;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731591267; x=1732196067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5uifKh3Ziurt6J4vVZSqwtf+Yzq6i1DIOK/XJ0xeWTM=;
        b=r8Jm1m/HDJbnK3qoUGhXxOQedO3H3K3WS8iSgCHww4VPIldVI8CB0oIi58bxQIxzRk
         BflFCzZxyJFGpdWXnfe2pckRBuoNpy0h5/QLr94wcr/PAFzgHSQXidxA0Zkw6WvX5cJH
         Dq4rrFppqPAEsGVtv0dkgeacooM3vSuNq5CHyIvhi20dHIpHI7kEJZ3n15gp7HWEAr8+
         0lZNf/dYIuzlCVUBJcNm3e66EsJzdr5E8wlkkd5XKuFj6oA6q2ukxepM1hetdb6BJbrq
         Kgd3N/1wU89Mm1EkjE+GY3mTGuWWwaSWpDQVuGgtFXqwwU1wF88yo6LcZ7vyWgOPEi8y
         IG8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731591267; x=1732196067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5uifKh3Ziurt6J4vVZSqwtf+Yzq6i1DIOK/XJ0xeWTM=;
        b=DsMpHxtB0+c03QkVi8AETW1MeLf8AME+SUKutvo2UqcENBzwqimG8ySOi+3bM2Q0Ef
         FKA3zRvUcvf3OypVecqWpWpcNbbNeQiEtBKpkZ0szrBKy/5lnida0tOprwtbxO1U6Z3o
         na5a/hzRZi9x8W/rrfbJx6M9LytC6fKAS5u7C0TK4AZcVFtfRNQcBmGk5NfT/yHLJw1/
         WOwcESQtSW3nR8pHAr0giRjAktEfQNSP8/kmS6f+MRW0FeKHmW3jDfpiTUT7bKdgTLCD
         MhLUpdqW7XeNTEJObeuLw3sNbvwU5Q4/CEn6yYWpyn8ZGp4QKV2ma1V5Wbo510agPgBh
         PQyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731591267; x=1732196067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5uifKh3Ziurt6J4vVZSqwtf+Yzq6i1DIOK/XJ0xeWTM=;
        b=c1cenFO7qbWqF+asNB0AFT223786WZ5A6g7+ocHUljxqMPbL/jWXZpAeL5oZf4Qfs/
         JJoD2n7kg6ba6AmxZf2hT0fjddTSQGiPkbCgJuwPjAqEggCyWXY86hNRuTZsuNFqfRUZ
         zGSVkjlZeapJf1u6fo6X4sxRziFRTrVshDb9S6WOKjQp6puk+yK51L0fZZ6q4STtBHYq
         c2O3yMxeZxszFqcA+DHRm87F3APg2BEFv8HGDEZnXSTPXbfa1mI9zTQNGi9lkopQ4Ba8
         bfiK1fc1pPwhQk70lHilLVvIUFd9lvvdyDAZ/KOFkBnLxvwK0KWAJklz/LYw0stOZiXd
         GSxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUK/BpJz5KtKgMPrQ8UQZhHgwLHuMPdW93L8CRKU2BuijF4w7PB1/YHyd2gDF23PmrMtxuFXA==@lfdr.de
X-Gm-Message-State: AOJu0YyrjeG/vwVTaZeTe91hXGoFgCtvoXOrSC0TZpK7cT11Wic/W3Xl
	OABHkrDSwXZmhVNrMgo7ho7Ut60SFchumpfnb5A/KEgKX1uET3vK
X-Google-Smtp-Source: AGHT+IFk70PwTlVkdswSTzVHtHYIk4Fj+sZTuKTyLQgkRR2n9kcD+wHgfn8OJCGLbn3+OfXRVsL2Rg==
X-Received: by 2002:a2e:b8d5:0:b0:2fb:6057:e67e with SMTP id 38308e7fff4ca-2ff590640ebmr13009451fa.32.1731591266121;
        Thu, 14 Nov 2024 05:34:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4818:b0:430:5356:aca3 with SMTP id
 5b1f17b1804b1-432d993860els3148435e9.0.-pod-prod-06-eu; Thu, 14 Nov 2024
 05:34:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX61sz5IycWrdfg/MyZcg7sc8LLBu6MOI/0mPCz37fmnxChcB9MOLaMzsFzdX3a+Ei12z6Dx5+5bNk=@googlegroups.com
X-Received: by 2002:a05:600c:a02:b0:42b:af5a:109 with SMTP id 5b1f17b1804b1-432da7cbb26mr18735235e9.24.1731591263832;
        Thu, 14 Nov 2024 05:34:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731591263; cv=none;
        d=google.com; s=arc-20240605;
        b=EHlXGcEfRRA7kDd/P91xIl6ZUcHejolfgoqaixHVf5JjWATQ1HgwxRBhV36mQqjhCt
         8pq0oEcxeeHBRnbdcBG8LLK4K3KwsAdtdc8cr0ANI/4phkgD3I6k91JS2yrBn1GVsxKD
         u07qm1F4AzfPUGq3gGPrT+qDRb5egnRKPnUwMaxZD/ddteQq8IlhzzyJCyR97ay4C+XF
         QzBLcu4UVU4BwUEchCbrgZ5Woy3F+nmwaPYl8tLCZhWcl2U7ymY471B6tHslk4HMahTO
         QLtOph837tfM2E0+bXHFcZISNrJUjexn0bWMn6EdLlw9ylqbLBAvJg/vV6F27CTECnSA
         /V2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1gPQZzQK8GNelw3AYb5yhBmVDG1cjmV9z/F+0TDBmsA=;
        fh=4/j46SlPkKDz+d0rJ2bVbMaOqbJJ98O58n/cqla79Ng=;
        b=PLxzOWMatr1e+N2UziqcmQYyhIsMk6D9rt6G/2kqXIl/n1S+MpONktwqFhcYe2fwzD
         hITqrOfBp6LY+0v/RGoGkzW4ihh0wzeXY0Mg2EZtuVC2oYs6H/xEeszo/KvSdG8H98vl
         aJFY+pCT7tp8B+3vzufRkZ25l0Uw1NK9766R62bp4U1plpliBoCij0DMBnXmgIlkSmC5
         iTHxAiiuPafEbMsl7Px459Sh/3Nukaj+BIXVEwblsiUCYbd03VxaDVAI/8eUT34V1Oh1
         K1nGacnif6qJXJBLKlvXg+II9EPf/3iIRkZdnfJfv0pKz+utkUfxvCR4dy8CUajLGZ+W
         ZKWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ifRNJ6dn;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432d48a6cfbsi3670345e9.1.2024.11.14.05.34.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2024 05:34:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-2fb3da341c9so5622971fa.2
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2024 05:34:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWtzaa94yAW/cB316ZuhQBjXmccbzpKE84yPhfaffVaWi+R5ewDWBBBuup4yOVbn+/ddy+EnTEW2s8=@googlegroups.com
X-Received: by 2002:a2e:bd0f:0:b0:2ff:552c:290b with SMTP id
 38308e7fff4ca-2ff5901af4cmr10159161fa.10.1731591262685; Thu, 14 Nov 2024
 05:34:22 -0800 (PST)
MIME-Version: 1.0
References: <20241016154152.1376492-1-feng.tang@intel.com> <20241016154152.1376492-3-feng.tang@intel.com>
In-Reply-To: <20241016154152.1376492-3-feng.tang@intel.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Thu, 14 Nov 2024 22:34:10 +0900
Message-ID: <CAB=+i9QUC+zscxC6AuK9qUaD-Y9VmAv2-Ovqt8JRJJARWxZ-EQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] mm/slub: Improve redzone check and zeroing for krealloc()
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Danilo Krummrich <dakr@kernel.org>, Narasimhan.V@amd.com, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ifRNJ6dn;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::22c
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 17, 2024 at 12:42=E2=80=AFAM Feng Tang <feng.tang@intel.com> wr=
ote:
>
> For current krealloc(), one problem is its caller doesn't pass the old
> request size, say the object is 64 bytes kmalloc one, but caller may
> only requested 48 bytes. Then when krealloc() shrinks or grows in the
> same object, or allocate a new bigger object, it lacks this 'original
> size' information to do accurate data preserving or zeroing (when
> __GFP_ZERO is set).
>
> Thus with slub debug redzone and object tracking enabled, parts of the
> object after krealloc() might contain redzone data instead of zeroes,
> which is violating the __GFP_ZERO guarantees. Good thing is in this
> case, kmalloc caches do have this 'orig_size' feature. So solve the
> problem by utilize 'org_size' to do accurate data zeroing and preserving.
>
> [Thanks to syzbot and V, Narasimhan for discovering kfence and big
>  kmalloc related issues in early patch version]
>
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slub.c | 84 +++++++++++++++++++++++++++++++++++++++----------------
>  1 file changed, 60 insertions(+), 24 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 1d348899f7a3..958f7af79fad 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4718,34 +4718,66 @@ static __always_inline __realloc_size(2) void *
>  __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>  {
>         void *ret;
> -       size_t ks;
> -
> -       /* Check for double-free before calling ksize. */
> -       if (likely(!ZERO_OR_NULL_PTR(p))) {
> -               if (!kasan_check_byte(p))
> -                       return NULL;
> -               ks =3D ksize(p);
> -       } else
> -               ks =3D 0;
> -
> -       /* If the object still fits, repoison it precisely. */
> -       if (ks >=3D new_size) {
> -               /* Zero out spare memory. */
> -               if (want_init_on_alloc(flags)) {
> -                       kasan_disable_current();
> +       size_t ks =3D 0;
> +       int orig_size =3D 0;
> +       struct kmem_cache *s =3D NULL;
> +
> +       /* Check for double-free. */
> +       if (unlikely(ZERO_OR_NULL_PTR(p)))
> +               goto alloc_new;

nit: I think kasan_check_bytes() is the function that checks for double-fre=
e?

Otherwise looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> +       if (!kasan_check_byte(p))
> +               return NULL;
> +
> +       if (is_kfence_address(p)) {
> +               ks =3D orig_size =3D kfence_ksize(p);
> +       } else {
> +               struct folio *folio;
> +
> +               folio =3D virt_to_folio(p);
> +               if (unlikely(!folio_test_slab(folio))) {
> +                       /* Big kmalloc object */
> +                       WARN_ON(folio_size(folio) <=3D KMALLOC_MAX_CACHE_=
SIZE);
> +                       WARN_ON(p !=3D folio_address(folio));
> +                       ks =3D folio_size(folio);
> +               } else {
> +                       s =3D folio_slab(folio)->slab_cache;
> +                       orig_size =3D get_orig_size(s, (void *)p);
> +                       ks =3D s->object_size;
> +               }
> +       }
> +
> +       /* If the old object doesn't fit, allocate a bigger one */
> +       if (new_size > ks)
> +               goto alloc_new;
> +
> +       /* Zero out spare memory. */
> +       if (want_init_on_alloc(flags)) {
> +               kasan_disable_current();
> +               if (orig_size && orig_size < new_size)
> +                       memset((void *)p + orig_size, 0, new_size - orig_=
size);
> +               else
>                         memset((void *)p + new_size, 0, ks - new_size);
> -                       kasan_enable_current();
> -               }
> +               kasan_enable_current();
> +       }
>
> -               p =3D kasan_krealloc((void *)p, new_size, flags);
> -               return (void *)p;
> +       /* Setup kmalloc redzone when needed */
> +       if (s && slub_debug_orig_size(s)) {
> +               set_orig_size(s, (void *)p, new_size);
> +               if (s->flags & SLAB_RED_ZONE && new_size < ks)
> +                       memset_no_sanitize_memory((void *)p + new_size,
> +                                               SLUB_RED_ACTIVE, ks - new=
_size);
>         }
> +       p =3D kasan_krealloc((void *)p, new_size, flags);
> +       return (void *)p;
> +
> +alloc_new:
>         ret =3D kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO=
_NODE, _RET_IP_);
>         if (ret && p) {
>                 /* Disable KASAN checks as the object's redzone is access=
ed. */
>                 kasan_disable_current();
> -               memcpy(ret, kasan_reset_tag(p), ks);
> +               memcpy(ret, kasan_reset_tag(p), orig_size ?: ks);
>                 kasan_enable_current();
>         }
>
> @@ -4766,16 +4798,20 @@ __do_krealloc(const void *p, size_t new_size, gfp=
_t flags)
>   * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possib=
le that
>   * __GFP_ZERO is not fully honored by this API.
>   *
> - * This is the case, since krealloc() only knows about the bucket size o=
f an
> - * allocation (but not the exact size it was allocated with) and hence
> - * implements the following semantics for shrinking and growing buffers =
with
> - * __GFP_ZERO.
> + * When slub_debug_orig_size() is off, krealloc() only knows about the b=
ucket
> + * size of an allocation (but not the exact size it was allocated with) =
and
> + * hence implements the following semantics for shrinking and growing bu=
ffers
> + * with __GFP_ZERO.
>   *
>   *         new             bucket
>   * 0       size             size
>   * |--------|----------------|
>   * |  keep  |      zero      |
>   *
> + * Otherwise, the original allocation size 'orig_size' could be used to
> + * precisely clear the requested size, and the new size will also be sto=
red
> + * as the new 'orig_size'.
> + *
>   * In any case, the contents of the object pointed to are preserved up t=
o the
>   * lesser of the new and old sizes.
>   *
> --
> 2.27.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AB%3D%2Bi9QUC%2BzscxC6AuK9qUaD-Y9VmAv2-Ovqt8JRJJARWxZ-EQ%40mail.gmail.com.
