Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ5AW3CQMGQEOW25I4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 39DCAB35A45
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 12:46:01 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-70d9eb2e970sf108740206d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 03:46:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756205160; cv=pass;
        d=google.com; s=arc-20240605;
        b=EfhXmArdY8Vkyx/mzqvElZQrDCICkPriUoS0GJvLNMdSzZNz0/9//SuuJgzx+bWiOw
         AVj3i+M82RUrydWjxnc71PAv8zuchQDPG9N8R3m4NAf0GlVYvjKVnrAQnn0soZPlJA7B
         CjREie40UMYRGpl5ZpTtxgBt88BEkJPAvURW2gm6uZP0h2XD73DU88kfI7GwavuxvxXn
         AVz6iloHZzGVIK3hsmhPv8zf7mASOhF1p/S0A+quv9lJtDHajYfLnWBKRkrtncvuNIDA
         yIAR2a7TBvyeG9VC8aEr3k0aVTdHHxST/MXGXE4GgPmmb21xYCVaWEXtM7vbAASWo4U6
         l6Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zMCUFSzV94IH3c8GHvo20zOyDk+L8+TzISjATY+QDC4=;
        fh=DIKjmSjZUoR/ZcZhMfndTjg6rR/LzyFeUOLlN6lMZ0g=;
        b=V82mNi2c/1cCp7QVJYr39HitPeyD5ekzsUSPCNuOGMM5GYV9At0xROtEJM+YtoEXmT
         U20dXX+GeBmoNGe7+KFUnRYVkpYrp5hM+fmlbqwPse+L0Vq3NOzalxMv9a0leThCIahJ
         Ha1mzJNLN3Cfl3SPMC+IGG1C5ZbGkAEkvk+RrYYtUIGUN7qVJqpynOGiNmcWMFX/gT6U
         OWaI0PcOCuF97Fo3+BXwa9LCEgLOIkKbUC9bHb24V7OX+3FgR4aEU5FPn0mT26RJLqEM
         1Uo00abUEtUdTYLRwjPgrZvkXZjGIpW2KJFs5aaRDILdWSbmZKyxoImE/P7MOOHFo3O/
         El5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cg++MqE2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756205160; x=1756809960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zMCUFSzV94IH3c8GHvo20zOyDk+L8+TzISjATY+QDC4=;
        b=j3gHASGUav0Fq3E8TwpQXx4xgVjNNjCp3vR2TZtS+FxSLj/Qy4jQkxD9iQ4AESKOwW
         XRlEm1nzB0s/dieaMgtwFRji+8MCeCN8yFmLVvGIypEMoY/jQDkuoRoaJPoPY47zznZT
         RJboz+KO/l9vvCJepJhRQPPHfT5iuvZXuNmwqvD9clA/opCQhzygK4SXWzKV25OJhhHN
         o7LMLPnW8+hZM7yhSM55YcrxrU0fDhLWk1CMvJrApcRZPvioGAO8eYEY+TnTMklI4udF
         WpF7AcFMxgaSbgpSIW4fpZoI6Q+LnVgbW2XTQ1uqEZQ/4HosJf19lbWnsfE5YDpKQnQc
         EtDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756205160; x=1756809960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zMCUFSzV94IH3c8GHvo20zOyDk+L8+TzISjATY+QDC4=;
        b=f9ATgL9KWDHdod0s9A8AVcSB5X7/SVj3ZbsM92gFYMYxOYMbQ9ISqx4rOsm2hzO9P0
         RoaLL0Q/4BYx60R/6JaFETPhG8pgni2EIpx03y8Z3vb89NU/eTXdpOgXtTifsNHg1UHz
         ISaQOOix1vEu3um2MtDGbnoXETmk3EJHAMPkyIHltcCuHnWXu3pHzpKSyW04vLyjKUyw
         g8Fvod0CXjo+9veTB8KI9MD5f4FHlD1+DLZm1Ktw0aaMo4mfEGcp2aFl9gvsWYNJHTas
         tVoyh7JBl4xqfimvKGx/C2b2z41MNUCLOyWdWIVcxT0SufIkw/wHPEhqZWaoO/4qR9sh
         OJfA==
X-Forwarded-Encrypted: i=2; AJvYcCWGXzy3leRaXSF40tR1LMc4+DrMcgridCC3K2O2J5D5dXPOuJbgYqSnRlsph91WoXQWskvnfw==@lfdr.de
X-Gm-Message-State: AOJu0YxeRWwya6xT8ouFN8h6QGL6WE5OumXR6zns3R0S9h3bIlDDvzX3
	O4iBd21FN39OfR1qR4ysCg2e4/hmXlbH0rZo1MzB4qKRbkFO+yrdkwcN
X-Google-Smtp-Source: AGHT+IGq+l6B0eqOIT8aApds8NRyr/55cMngJeOKm9FJwr1wPKfXcVH5Uo2t/iLyiWjh2oPQW6tmCA==
X-Received: by 2002:ad4:5dc2:0:b0:70d:cb02:9989 with SMTP id 6a1803df08f44-70dcb029c2dmr33461426d6.3.1756205159882;
        Tue, 26 Aug 2025 03:45:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdSzNanG8HvM5324aRYGBpHuU3ePuKzxxxppzyNz0vLQw==
Received: by 2002:a05:6214:2aa1:b0:70d:d6d2:7edc with SMTP id
 6a1803df08f44-70dd6d28010ls3945856d6.0.-pod-prod-06-us; Tue, 26 Aug 2025
 03:45:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXRJsI6PMS/GJlNgWHIH1pHfamDZvNql7W2pb4UTIzJMKvi6/I/KT/Y458hPWKX4/CANoFtv6rr628=@googlegroups.com
X-Received: by 2002:a05:6214:318b:b0:70d:ac0a:47aa with SMTP id 6a1803df08f44-70dac0a48a9mr127588876d6.55.1756205158907;
        Tue, 26 Aug 2025 03:45:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756205158; cv=none;
        d=google.com; s=arc-20240605;
        b=XzHp/MqjsX3jaEBC+FcPqh7kD5zg2g/32syudTpMD4j7IKHHtnN2NW5hk/CDtfmgAP
         xgq5XXLOyTs7uXVXObC49LfI9GOryqe8ScEVdvjYtOybq5VQj372OGnJZFIzoxRpni6W
         U8J+dYZq6VAA2C+p1nAH6gxUqQsibmw5vJFrKKbVFXBjGSuJunSM7ciJue/CJQfaLg2t
         /Jx+mH+jDPn6lmbzrYcZ0oNSELe+AsPJWUEE8cLf4YzTldmSHidiydC+JEDethhwJ6Fl
         8IzIv0lA3mGTaqCsPqNN73Hz4bMAeWcPX41iC+rlvtsDFZpqnGFCS8Oj4aa4/8CkVpF6
         +pVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZGOLh5cQuaV0+vt4hcjFj06C3bqSM1fNgF6Sjp1p1nM=;
        fh=CwmjCF+ATJoIquZEO4shJLgqcEsuvPLSKUvzlOEcYuA=;
        b=ZMqM1aXiSTBaIb+J/3lfqM3oU6y4tuwX3cLNJ3Kb0ucMARLNSaxvUVU8VbdQrHeQpg
         BoS2X9e4Hv7yZYQphJj2qwY12k6JzdrkJ74Aybw+4oK7N2Zcdy16jsg7rGARkGZXnu4g
         vsuQhIBYx8kyYCpsulNtU1u6/dh93hX+hYtzPVAhne7Hszwjr5xHEKhIOXpHK4+eJzd4
         NWW0B5+sKSoRjC4sts9Cf5OM3+R0Lj1yIsrmiRLiytcT7sCKh6Dhr+HhLPx9APlfG5e3
         J0KHENUufJg6NkLShjt6bkwAS72rom9YqRGqEGP/PZgFV/Zmqn7mMAxHwrh+sNQ/cP0r
         MvZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cg++MqE2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70da705cdb9si3672086d6.0.2025.08.26.03.45.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 03:45:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-2445827be70so53749965ad.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 03:45:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJvDZadHCDI7h0wJ+caU1J5nTmXfTyYf8MXLHABZfUxLQazKNuad6bN6Ylih4s6/CmLn00L1I6P+g=@googlegroups.com
X-Gm-Gg: ASbGncuwNUYKEcHdUBCslq09FEl21Ab+2AGF5D+X+xTEq4yKyue/JrT1Anw91wQX9LZ
	yPdrFU4Bhad1s0YTVNnm6d2l3ingopJ1UPI6QhyuWMvornRyo2LwSkTk8dOwhUrUcVeHeSGkzWh
	CjesC3Wx5lpye3uX6+Fy6ahvNd7Yn362O3zjo9QQCmR4B/sa8qAwYS7NEbGvPrlqrEzTuOYU+0Z
	iHY/MbU3Umw9NsTO05Cpmep+Fk=
X-Received: by 2002:a17:902:dad1:b0:240:8262:1a46 with SMTP id
 d9443c01a7336-2462ee54512mr199229855ad.25.1756205157527; Tue, 26 Aug 2025
 03:45:57 -0700 (PDT)
MIME-Version: 1.0
References: <20250825154505.1558444-1-elver@google.com> <aKyT2UKmlznvN2jv@hyeyoo>
In-Reply-To: <aKyT2UKmlznvN2jv@hyeyoo>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Aug 2025 12:45:19 +0200
X-Gm-Features: Ac12FXxpah0HkZevruBg4QeHMNDjWXsh7--6Kjx5Kp37atP55Mt7D7-5zFmt0B8
Message-ID: <CANpmjNPUsbkyg5VvzUSYqVvaScXpqdfsb_oq2PuKV6VbkZLqFA@mail.gmail.com>
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
To: Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, David Hildenbrand <david@redhat.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Florent Revest <revest@google.com>, GONG Ruiqi <gongruiqi@huaweicloud.com>, 
	Jann Horn <jannh@google.com>, Kees Cook <kees@kernel.org>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Matteo Rizzo <matteorizzo@google.com>, 
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, linux-hardening@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cg++MqE2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as
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

On Mon, 25 Aug 2025 at 18:49, Harry Yoo <harry.yoo@oracle.com> wrote:
[...]
> > This mechanism allows the compiler to pass a token ID derived from the
> > allocation's type to the allocator. The compiler performs best-effort
> > type inference, and recognizes idioms such as kmalloc(sizeof(T), ...).
> > Unlike RANDOM_KMALLOC_CACHES, this mode deterministically assigns a slab
> > cache to an allocation of type T, regardless of allocation site.
>
> I don't think either TYPED_KMALLOC_CACHES or RANDOM_KMALLOC_CACHES is
> strictly superior to the other (or am I wrong?).

TYPED_KMALLOC_CACHES provides stronger guarantees on how objects are
isolated; in particular, isolating (most) pointer-containing objects
from plain data objects means that it's a lot harder to gain control
of a pointer from an ordinary buffer overflow in a plain data object.

This particular proposed scheme is the result of conclusions I
gathered from various security researchers (and also reconfirmed by
e.g. [2]), and the conclusion being that many successful exploits gain
a write primitive through a vulnerable plain data allocation. That
write primitive can then be used to overwrite pointers in adjacent
objects.

In addition, I have been told by some of those security researches
(citation needed), that RANDOM_KMALLOC_CACHES actually makes some
exploits easier, because there is less "noise" in each individual slab
cache, yet a given allocation is predictably assigned to a slab cache
by its callsite (via _RET_IP_ + boot-time seed). RANDOM_KMALLOC_CACHES
does not separate pointer-containing and non-pointer-containing
objects, and therefore it's likely that a vulnerable object is still
co-located with a pointer-containing object that can be overwritten.

That being said, none of these mitigation are perfect. But on systems
that cannot afford to enable KASAN (or rather, KASAN_HW_TAGS) in
production, it's a lot better than nothing.

[2] https://blog.dfsec.com/ios/2025/05/30/blasting-past-ios-18

> Would it be reasonable
> to do some run-time randomization for TYPED_KMALLOC_CACHES too?
> (i.e., randomize index within top/bottom half based on allocation site and
> random seed)

It's unclear to me if that would strengthen or weaken the mitigation.
Irrespective of the top/bottom split, one of the key properties to
retain is that allocations of type T are predictably assigned a slab
cache. This means that even if a pointer-containing object of type T
is vulnerable, yet the pointer within T is useless for exploitation,
the difficulty of getting to a sensitive object S is still increased
by the fact that S is unlikely to be co-located. If we were to
introduce more randomness, we increase the probability that S will be
co-located with T, which is counter-intuitive to me.

> > Clang's default token ID calculation is described as [1]:
> >
> >    TypeHashPointerSplit: This mode assigns a token ID based on the hash
> >    of the allocated type's name, where the top half ID-space is reserved
> >    for types that contain pointers and the bottom half for types that do
> >    not contain pointers.
> >
> > Separating pointer-containing objects from pointerless objects and data
> > allocations can help mitigate certain classes of memory corruption
> > exploits [2]: attackers who gains a buffer overflow on a primitive
> > buffer cannot use it to directly corrupt pointers or other critical
> > metadata in an object residing in a different, isolated heap region.
> >
> > It is important to note that heap isolation strategies offer a
> > best-effort approach, and do not provide a 100% security guarantee,
> > albeit achievable at relatively low performance cost. Note that this
> > also does not prevent cross-cache attacks, and SLAB_VIRTUAL [3] should
> > be used as a complementary mitigation.
>
> Not relevant to this patch, but just wondering if there are
> any plans for SLAB_VIRTUAL?

The relevant folks are Cc'd, so hopefully they are aware.

[...]
> > Additionally, when I compile my kernel with -Rpass=alloc-token, which
> > provides diagnostics where (after dead-code elimination) type inference
> > failed, I see 966 allocation sites where the compiler failed to identify
> > a type. Some initial review confirms these are mostly variable sized
> > buffers, but also include structs with trailing flexible length arrays
> > (the latter could be recognized by the compiler by teaching it to look
> > more deeply into complex expressions such as those generated by
> > struct_size).
>
> When the compiler fails to identify a type, does it go to top half or
> bottom half, or perhaps it doesn't matter?

It picks fallback of 0 by default, so that'd be the bottom half, which
would be the pointer-less bucket. That also matches what I'm seeing,
where the majority of these objects are variably sized plain buffers.
The fallback itself is configurable, so it'd also be possible to pick
a dedicated slab cache for the "unknown type" allocations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPUsbkyg5VvzUSYqVvaScXpqdfsb_oq2PuKV6VbkZLqFA%40mail.gmail.com.
