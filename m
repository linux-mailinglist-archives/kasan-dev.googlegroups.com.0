Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB3UBUO2QMGQEH6T2TKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E9FF940F59
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 12:31:12 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2ef62acc9ffsf37581551fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 03:31:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722335471; cv=pass;
        d=google.com; s=arc-20160816;
        b=YQa6wlEdumB1LphNX3yDhC1RKayGFq9izwZw25piYyfgeQS+ILEi/WQ9nyGq2YU+wG
         +GPR47Lk8Dm0iFQ+zjFsSxviz+4I6WbpEyKIWHkvcrUZB6xlEZfaGEv03Y1LFrIPKb95
         jlfUbDPjaAWcZn0ttcTmez7v2uffxNrX18dGmwyJAletZxQnwGSY1DulI/EGaqjxGTZL
         kIw6A7RITjijmPtYhsViTW/YShRpoTFzqp4qBUcjQkPo4Nx1H/wjJha5FqGmsPzsRg/l
         khCxZdxq3FHN1nmzDth4b5/aKrwzzx0rOgGdZ2afcPccpU04NFKjP/emP/1HN9guFjWX
         exuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Z31SteBZDD9atPHfrnnbY7fGFoxxVhu94O3y8u2MZY=;
        fh=JD4bjLFFU4wEJprwGCkdmkCeIvGZ8WPUkYVHqUrwHak=;
        b=JPQQ8tSza9eQW9voiLUDnT+xo/WtDN0bWIy1Xirg0bCtktGt6sOTrjkBXgQzg7xKIg
         jWuAWv3xgpvpW8S8YphyRktvIZFJgTM52ifJxziVB0wPR4BP8mQmoQReFmrJFWZoRZE7
         xHo7B0vBBRkNNkxTraiJ3UV5escX9bVvEvLhmORR9qSZ1h4SKOhsNXpAY5A0cCTKYXfA
         10C93/PpG3Qxhd3f+1EO14rk3i2AHDZ8PGfg9Bm9sHowomIMyQPeImOdYYH7rAzfn1eu
         sNMfXytST97lZn6/Zm1SaMjaUDLcaEw8NreWU45/Hf4ILgUTMngjTZ0IjMvtub75xDZo
         01VQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uHTVlQm+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722335471; x=1722940271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Z31SteBZDD9atPHfrnnbY7fGFoxxVhu94O3y8u2MZY=;
        b=RO+G3UCFwcIIhGoG6H4Z2NQXxshrOIne5l7LdD9PnshGytytd3P8YUnXyFJ+Rt92jA
         rbF91z1BGXSxsovrprv16TCzz5eBAqUPygV6zoMzksWylCfqmnamBetjzV7nCpnUFTZo
         /tqybLncWi1ElIsuC8/t0NODFJSGC2oota+fMX3ZeQ2Yc3hMqpo4RBkPmJ+c9DtqbuA1
         MAZADdL3hGkpPtHmeYUM2ud/7a61n23X6+ZolV4VFvFcRMsAaQ+o2XqS4+upAihvj2B/
         meRCKVMlQgLgYphb87hy7s4YyAVsForIvKG8//ryt74Z+KcI7+wTWC7W0nh4VU0QH41Y
         Oksw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722335471; x=1722940271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5Z31SteBZDD9atPHfrnnbY7fGFoxxVhu94O3y8u2MZY=;
        b=N7wiJYYMYr8gziWCLBfqGLeXT3TGOG9xpHWufGPOOqS53yVAcNPViGvU15QV0DrXSl
         yf+36lzOVvoX/RLpnHcMaf7wBM/rRBoojegI3bqRvmvu9j0H0ZhzNkmSQ2Xm4Z87VyyL
         QsEwYE5aAAsNcS9FMc6/mPAqFScyzuGM05hTw++JIgcFbjTVos2RFNgteW85uBSG8wCr
         kHQGjvyipcWy/Fk27wLLjqJLtG8ijcyr9uwgCeRd9gbojBTRPnfTS0uXjkvzDhepQGgL
         KL/bYfkUCzBuMZprcJAA/xOrGIJGVXHxzxzdbsabexiXkf0m4Jl5elIE1p9SRVkTmh7Z
         eBJw==
X-Forwarded-Encrypted: i=2; AJvYcCW9GREn+8Hcoa7IrRiZHSIFLsr3xiDks7m0qjLfNuHzw5a+iXYVJ13CHwqpdhJgXBO0kz7+jkcvchq0FuegWkNdtBYxzG8pRg==
X-Gm-Message-State: AOJu0YxW3zPy5ipy0FQ8cnxWASvJG1iaDyhXwCZqK0j/QV2tjxvvYUaQ
	VueUr8B3DdF4wbOd9TRk8DBFsiFpKD8VBMUIB6RYEA6Qk8vxkXZZ
X-Google-Smtp-Source: AGHT+IHDmrT+qbAVCdupLF/Y9Lz1qfHVQW/frXNNyH3v5Cz8ctbzZk06XjRT5fo4AwjE26HNFui90A==
X-Received: by 2002:a2e:9b57:0:b0:2f0:29e4:dc52 with SMTP id 38308e7fff4ca-2f12ee2ce09mr70906221fa.27.1722335470715;
        Tue, 30 Jul 2024 03:31:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b12:b0:2ef:2eec:5052 with SMTP id
 38308e7fff4ca-2f03aa5d7b1ls22219231fa.1.-pod-prod-03-eu; Tue, 30 Jul 2024
 03:31:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVf7f9mr23hxSIT/qceGIIHm7ifdmq4ivkaNHBi93W1TxxvvsCpX5KAelTwFlys3+sa4CPChuBpX5A9wmQ7iv9jMeHWovqA1FiyZw==
X-Received: by 2002:ac2:5501:0:b0:52e:f950:31f3 with SMTP id 2adb3069b0e04-5309b280a2amr7276602e87.35.1722335468473;
        Tue, 30 Jul 2024 03:31:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722335468; cv=none;
        d=google.com; s=arc-20160816;
        b=G8wEgK6cso0mXTynYg8ow71LhF9/kESWUt0R2+TajOnTFZkH6zSlAOtSNIX9bEqRO+
         3nYEKXe8h7Hot58RXXwcODQCA2/ZS7fABHzBj700+8+v29BcYeaR2+kWxmuOgIcjVvhA
         Psih4UC64GAc2XBbY8+IlOT+SoJckT18uPv/DpbtnEZvgXVp+VDck9Ab2/DmJ6Vst6lu
         O3kvg5Kvdkn1iXiIsVPOZz4ro+gO34r+xQRwtNdE+1mk421tLZZSZLlcyrY428Oqj8K1
         GJfyh9+pmrThJvhNEz0DIlU756MCzDFoDUVFzgLB0oKS8EVPjTNahz+nWcBFGkLRB8Lk
         MaiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uchJL9SjgJGVthCYhjfEyhLXgYgaYchmaG7P26alVxE=;
        fh=gI7IgjUc713ZejINQRUIoLD3rm5qtfaN72d2Y+4C2Wc=;
        b=iFtQYFgLvNo9vNXn7yFBvO5mcOfwL3v4pyjO1D5+j36wsBINz4C7zDQhogVLYNNiSQ
         C8DLQEyaa41p4EdafvUXMmkzymacrRlhlELmw5IqdvfRMHFkoiTmrGvv2LwYSQGycBV7
         89StDpyoHmXS3IqDR0OzKGqMugchctorRLrgeauj91a5q1yOkFLZv2zsDi6uTZwNcyK7
         y/HLtaao2hYmdEaSdYkIuUD9UOxZy1BA+NWI4R+wa5YCKj/ECfDwNLpNhBbm/E/wJ6ws
         5Xvm3yPXw2qeUlIV2EMF8Fbs5Uh6YNP7yah8bqgtHKVKcjTD05Jows45ZUzzWPJEycK9
         4lBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uHTVlQm+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5b4961b3d15si25788a12.0.2024.07.30.03.31.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 03:31:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso12547a12.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 03:31:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWbPyFBbuLI7izY7IY3AJhlkrlQAexZaQ20NyvkbKPtZTJ9WqkqFW91UVzCGpv5IJRrqpmiSEyTYe3aO72ciiLn/t20HRBfE8QgMg==
X-Received: by 2002:a05:6402:268c:b0:58b:93:b624 with SMTP id
 4fb4d7f45d1cf-5b486ff3d5emr46614a12.1.1722335467220; Tue, 30 Jul 2024
 03:31:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
 <20240725-kasan-tsbrcu-v3-1-51c92f8f1101@google.com> <CA+fCnZe-x+JOUN1P-H-i0_3ys+XgpZBKU_zi06XBRfmN+OzO+w@mail.gmail.com>
In-Reply-To: <CA+fCnZe-x+JOUN1P-H-i0_3ys+XgpZBKU_zi06XBRfmN+OzO+w@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Jul 2024 12:30:30 +0200
Message-ID: <CAG48ez2Ne7ZR1K2959s=wP2-t-V2LxCmg6_OJ+Tu58OvwV42ZA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uHTVlQm+;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Fri, Jul 26, 2024 at 2:43=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> On Thu, Jul 25, 2024 at 5:32=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> > Currently, when KASAN is combined with init-on-free behavior, the
> > initialization happens before KASAN's "invalid free" checks.
[...]
> > So add a new KASAN hook that allows KASAN to pre-validate a
> > kmem_cache_free() operation before SLUB actually starts modifying the
> > object or its metadata.
> >
> > Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> >  include/linux/kasan.h | 16 ++++++++++++++++
> >  mm/kasan/common.c     | 51 +++++++++++++++++++++++++++++++++++++++----=
--------
> >  mm/slub.c             |  7 +++++++
> >  3 files changed, 62 insertions(+), 12 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 70d6a8f6e25d..ebd93c843e78 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -175,6 +175,16 @@ static __always_inline void * __must_check kasan_i=
nit_slab_obj(
> >         return (void *)object;
> >  }
> >
> > +bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
> > +                       unsigned long ip);
> > +static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
> > +                                               void *object)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_slab_pre_free(s, object, _RET_IP_);
> > +       return false;
> > +}
>
> Please add a documentation comment for this new hook; something like
> what we have for kasan_mempool_poison_pages() and some of the others.
> (I've been meaning to add them for all of them, but still didn't get
> around to that.)

Ack, done in v4.

> > +static inline bool poison_slab_object(struct kmem_cache *cache, void *=
object,
> > +                                     unsigned long ip, bool init)
> > +{
> > +       void *tagged_object =3D object;
> > +       enum free_validation_result valid =3D check_slab_free(cache, ob=
ject, ip);
>
> I believe we don't need check_slab_free() here, as it was already done
> in kasan_slab_pre_free()? Checking just kasan_arch_is_ready() and
> is_kfence_address() should save a bit on performance impact.
>
> Though if we remove check_slab_free() from here, we do need to add it
> to __kasan_mempool_poison_object().

Ack, changed in v4.

> > +
> > +       if (valid =3D=3D KASAN_FREE_IS_IGNORED)
> > +               return false;
> > +       if (valid =3D=3D KASAN_FREE_IS_INVALID)
> > +               return true;
> > +
> > +       object =3D kasan_reset_tag(object);
> > +
> > +       /* RCU slabs could be legally used after free within the RCU pe=
riod. */
> > +       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> > +               return false;
>
> I vaguely recall there was some reason why this check was done before
> the kasan_byte_accessible() check, but I might be wrong. Could you try
> booting the kernel with only this patch applied to see if anything
> breaks?

I tried booting it to a graphical environment and running the kunit
tests, nothing immediately broke from what I can tell...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez2Ne7ZR1K2959s%3DwP2-t-V2LxCmg6_OJ%2BTu58OvwV42ZA%40mail.gm=
ail.com.
