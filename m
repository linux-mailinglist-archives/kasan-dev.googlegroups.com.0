Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIPGRDEAMGQENIUX2EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F0F6C1BA95
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 16:30:43 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-78f28554393sf1558956d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 08:30:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761751842; cv=pass;
        d=google.com; s=arc-20240605;
        b=EABjzoFYcnl4I5gK9kdWN1zhrtbGavDUEhnqHNt1lzP2VS8WoVPSbp6/YW7rGWbDYQ
         3QakRAHxtNDtAfGjjHFQyUOeEdVOOPJhb1AhvsxhYT5PYdBuQIdN1aYXbYGINBDqUuSC
         EVgtz9mqcIdJ20oi5mdb8BFTjCohAmuTeFaGderE7+YVDr2+I7Rs8FW2EUozxXwF5/6U
         z2yx9CEVukwDUwAKpYMlQL1WKSBfLjmcgn+7qhI0TnQ2idGewXgOjqYxVGAkMoQRrnM1
         Z61ho6jRPwYxLXZdZq34W0xnSKOx37SUSZ01FHot6bWou9RnfqBb6yzx5Jmc7W8016zw
         LU2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QN0ekgh0YZbocY1BtlNVfIR0QwzBsstRRtMDh7HCPdY=;
        fh=ONuAA578UGlh1XWIqOHWjITLg9pgKdubMKrqgeQHqBQ=;
        b=cmwtduHHV1eSsvjofvTBX5nekkcnvuzZH97z3oxeyDXAnCLPBhgvYX5s4RySoAW9Xl
         CWKm32r41AI+7ZgRduFqKsloIMihYP5wb/aHe1lzzjscdpJr66KlkFYcC/9O6uAElO9i
         HkleemTDbxYkAVEtZVuOBD+K3LoiirG0p4YiTKhzfn+Q83O5Znzp1kdcBbbdfJO1P/79
         Mkl3C6AhuectQeapUZUepCePQls/qIoVQR+rTdaXb9XVmKXs/NFBvlxxC2ZzC7v7cdYk
         R2QTjZLGlM13IfoqjGemSVBtIpOAWhxgCGDSfKVG1/TDR8wDqHcuCJFkaN44OH/C/X+E
         CtzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=r5hLlsX1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761751842; x=1762356642; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QN0ekgh0YZbocY1BtlNVfIR0QwzBsstRRtMDh7HCPdY=;
        b=KE4uqamm26IjDuC7IZE3AcPPOttSMg0JrS+0gzbO7s9v9mJFqfE/BZQP0YgfwjsaRi
         FZ2JgRVriHGKFeyWnaNxsZD+lIKbRNr7YXuYpW7Nta55YmKVv//a6UOsZKmO6PyLLZOO
         HDV9Q2ejzvTwzd4w+poOkzcqo8LBlgdpbQjxUukpMngiuikBz9guNgyMeGkZPp3ixcMo
         ccTrLYSWbro1FmdGHmjvI4lg0FX0ZJwlluyqpK7r7eRRrAPh64PKXhBgOHYoJVjvF5SP
         /WlVQsyoGpP23Ds2RCrl97Dz/INwyvG9KlDhxa4Ei7oiT9f9dkH5nPF+ObYLvt4LWwat
         DWJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761751842; x=1762356642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QN0ekgh0YZbocY1BtlNVfIR0QwzBsstRRtMDh7HCPdY=;
        b=e5WArUFv9Doq0sV3KlQAM6hEbkO+JBh1CMJrvJ42xLvOh7T6OsRFxsoAeRL0ip6ZyS
         DyavF9n6RcYkvPjTiXObrYAbfmdC9SNpR0OI8PUfIZbiFsH2cGnBhnj2LVCePkwYkGbc
         C/ThFFHZD3CsxQUveie9XMArPhBM+ImZlAllxr3NZu+5b2z+fQnXXmcBJQnhKtyRBK3E
         72PeLosnA+0jg2EcBamQbmX9OexjdU3vXmVN+nZs2AQxASI5vYi5mOYdCJqUu+dLMO5J
         x7dsaeIC5MwwBY7YQ+WbUiEJA14t8l26NHFJRjZDqIUCxTPi207hvITqTiuC7bM2WPOM
         qlWw==
X-Forwarded-Encrypted: i=2; AJvYcCXo8vJNVwMlUYpVGBMohQOcyGZPvxHB/Lcen9wS6fUKHll2MpkZi+aL4GTu+xt1WflSz0gbDg==@lfdr.de
X-Gm-Message-State: AOJu0Yy5FLWWJTOvjCWM459BOZICwtxrFDR7BwJv0XDczZ09fZcWXCMX
	3Xm5H2OGnP6pqMVe1JCTLQRCnXZxMtB6/vGZDibflRij1W4WGolmBa5+
X-Google-Smtp-Source: AGHT+IFUVKsfx4ifI9KuMbcIBgf39uNdV497ssOWVZGmiihaURfo28SPSSY5DOmez63RX2Wledf11g==
X-Received: by 2002:a05:6214:262b:b0:87c:226f:f5c7 with SMTP id 6a1803df08f44-88009be7d5amr42682216d6.38.1761751841896;
        Wed, 29 Oct 2025 08:30:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YoiX9slBg/Zmh1hmDH3g+DSWNwwVH7FWMFzWbe2D6BNw=="
Received: by 2002:a05:6214:f2b:b0:819:df42:aa30 with SMTP id
 6a1803df08f44-87f9f9b67bfls10251606d6.2.-pod-prod-07-us; Wed, 29 Oct 2025
 08:30:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUgBgxK6zKPZPbH6GFK3cvmJEKt7QFDA3kQpsaL2X9n9nsZV5DzFX/lIBkvhs2efhw9bVptFSHK5Y=@googlegroups.com
X-Received: by 2002:a05:6214:5287:b0:87c:2548:bfbb with SMTP id 6a1803df08f44-88009b283b5mr44611786d6.16.1761751840028;
        Wed, 29 Oct 2025 08:30:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761751840; cv=none;
        d=google.com; s=arc-20240605;
        b=C1jktm4ILCwJE21Z5fjYLrAcBclRtDvBVitomzkhb8uenCTdGTcSNe/OV96RATO4PS
         LN/bFujrLDPm9qy4fupArPwehOIxDzkhn8bQfe2b1DzWu/MU/qOY79sPw2u+MQBYSwK1
         qG01y3b3Qr6vjG+YfdFTNzVkKof3u/pgcwdTcRTyqVpYj8pEcw2gzzlcQdeDkkpIO/Ec
         u8yYcIOChJGHUiho3O/OkHfyoRv3BA0u1m4BnMm1qez8FpgaLPXuLvUZjGcP3S9EM1gb
         TyZIxOArruBSgeaaEuiitOOegEs1wXCuHwu9EEWZhO8EdH3/rbAaI4hGBfbZ1JnrnyA2
         FCdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a/Chhgm7KMivLaP7UfXKsNLQx2xR5ZnzWFQSYqKYSi8=;
        fh=efbJtJbiKAZRi2RQyD+AoL8AEtSMlqRMt35CTI4yBXk=;
        b=DYkEnIO+N4qqtwGNTNzkmDBGi3KI50/4JYM9UrpcQogo32iPcZOoxB3x6MA60f85tZ
         DwWwFlIk1zOea184Els/SUl/vKBg7GUVmYkBQdvVCgQP4bsQ9QVHg1tYsiW0U0V5Z6rF
         RCSv+5M1kPFNdYQrfdBkyA2VwR7T+5I72tAgiW7UwXsEUyzFDNy47Q5oR1EKsCjmpyD0
         fY2BJng4P6SpoM0gsigGJAObEUzz4XUZ9/G+EBdwnW3H9IBUmR2w4kizczWpQYfLuDHM
         Juta0GKhB7mN1FtyOjeK4ktxm293fSlg0oS6jXWwTOH8h4JPxsZph77HPqf0G/iBGx+u
         Hs0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=r5hLlsX1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87fc6639688si8193356d6.3.2025.10.29.08.30.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Oct 2025 08:30:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-2947d345949so65098065ad.3
        for <kasan-dev@googlegroups.com>; Wed, 29 Oct 2025 08:30:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX3vYQtNfZqeuGLnkCsuvIs+TjG7By7E5VxmBpSHhoGCmUtezRw3fAT1jfB6L2JavfRO5aiyl5GaQ8=@googlegroups.com
X-Gm-Gg: ASbGncuU84aDebW//YHRd1FWvX0R5SaSMM+57T97xm6YC5pSUCm2RMwIKQWHHqqZTIQ
	j/PF5Et80z1oYRi4MSj4zqWHK6SoQ285iAIaRD+A6GQqPa/nrhF0itvh3GYLCgDm5UbYMYy65YM
	ua9ihhU24nGWECpWQDPS+oNv36ccvkLcyCaFaVem0U9BFzie1qdI704Jb15RELfpjcjHN4FawOd
	HJ8glO7E+sDDCRNq8FxRjmtL9BWFq26FNbtrPvpuXmkxM5lDlCmRrLdUSY6YWrKCWF186WKo6/r
	crZRaG8dzUuNI5057dzzIiF3Xg==
X-Received: by 2002:a17:902:d4ce:b0:28c:2db3:b9ab with SMTP id
 d9443c01a7336-294dee25ef7mr46936785ad.26.1761751838802; Wed, 29 Oct 2025
 08:30:38 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-1-6ffa2c9941c0@suse.cz> <CANpmjNM06dVYKrraAb-XfF02u8+Jnh-rA5rhCEws4XLqVxdfWg@mail.gmail.com>
 <0f630d2a-3057-49f7-a505-f16866e1ed08@suse.cz>
In-Reply-To: <0f630d2a-3057-49f7-a505-f16866e1ed08@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 Oct 2025 16:30:01 +0100
X-Gm-Features: AWmQ_bkcozjdjluUvttU4Roh8Mm8XDdSh0qCy1zW1YFReOaqG1YdYoXpHqK6R8Y
Message-ID: <CANpmjNOtocYUyX4HEB9GELeDVb1LbgESea98+UH5LCuYVoZbCw@mail.gmail.com>
Subject: Re: [PATCH RFC 01/19] slab: move kfence_alloc() out of internal bulk alloc
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=r5hLlsX1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as
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

On Wed, 29 Oct 2025 at 15:38, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 10/23/25 17:20, Marco Elver wrote:
> > On Thu, 23 Oct 2025 at 15:53, Vlastimil Babka <vbabka@suse.cz> wrote:
> >>
> >> SLUB's internal bulk allocation __kmem_cache_alloc_bulk() can currently
> >> allocate some objects from KFENCE, i.e. when refilling a sheaf. It works
> >> but it's conceptually the wrong layer, as KFENCE allocations should only
> >> happen when objects are actually handed out from slab to its users.
> >>
> >> Currently for sheaf-enabled caches, slab_alloc_node() can return KFENCE
> >> object via kfence_alloc(), but also via alloc_from_pcs() when a sheaf
> >> was refilled with KFENCE objects. Continuing like this would also
> >> complicate the upcoming sheaf refill changes.
> >>
> >> Thus remove KFENCE allocation from __kmem_cache_alloc_bulk() and move it
> >> to the places that return slab objects to users. slab_alloc_node() is
> >> already covered (see above). Add kfence_alloc() to
> >> kmem_cache_alloc_from_sheaf() to handle KFENCE allocations from
> >> prefilled sheafs, with a comment that the caller should not expect the
> >> sheaf size to decrease after every allocation because of this
> >> possibility.
> >>
> >> For kmem_cache_alloc_bulk() implement a different strategy to handle
> >> KFENCE upfront and rely on internal batched operations afterwards.
> >> Assume there will be at most once KFENCE allocation per bulk allocation
> >> and then assign its index in the array of objects randomly.
> >>
> >> Cc: Alexander Potapenko <glider@google.com>
> >> Cc: Marco Elver <elver@google.com>
> >> Cc: Dmitry Vyukov <dvyukov@google.com>
> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >> ---
> >> @@ -7457,6 +7458,20 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
> >>         if (unlikely(!s))
> >>                 return 0;
> >>
> >> +       /*
> >> +        * to make things simpler, only assume at most once kfence allocated
> >> +        * object per bulk allocation and choose its index randomly
> >> +        */
>
> Here's a comment...
>
> >> +       kfence_obj = kfence_alloc(s, s->object_size, flags);
> >> +
> >> +       if (unlikely(kfence_obj)) {
> >> +               if (unlikely(size == 1)) {
> >> +                       p[0] = kfence_obj;
> >> +                       goto out;
> >> +               }
> >> +               size--;
> >> +       }
> >> +
> >>         if (s->cpu_sheaves)
> >>                 i = alloc_from_pcs_bulk(s, size, p);
> >>
> >> @@ -7468,10 +7483,23 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
> >>                 if (unlikely(__kmem_cache_alloc_bulk(s, flags, size - i, p + i) == 0)) {
> >>                         if (i > 0)
> >>                                 __kmem_cache_free_bulk(s, i, p);
> >> +                       if (kfence_obj)
> >> +                               __kfence_free(kfence_obj);
> >>                         return 0;
> >>                 }
> >>         }
> >>
> >> +       if (unlikely(kfence_obj)) {
> >
> > Might be nice to briefly write a comment here in code as well instead
> > of having to dig through the commit logs.
>
> ... is the one above enough? The commit log doesn't have much more on this
> aspect. Or what would you add?

Good enough - thanks.

> > The tests still pass? (CONFIG_KFENCE_KUNIT_TEST=y)
>
> They do.

Great.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOtocYUyX4HEB9GELeDVb1LbgESea98%2BUH5LCuYVoZbCw%40mail.gmail.com.
