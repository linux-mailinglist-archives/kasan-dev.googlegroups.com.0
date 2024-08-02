Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBCOFWK2QMGQEMYDABSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CAAA2945A84
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 11:10:35 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-52f02833519sf9290751e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 02:10:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722589835; cv=pass;
        d=google.com; s=arc-20160816;
        b=VoEWNOicvc7X31Qqkj3l/tOdR5YRfgVDzg2amNXztJTARsMQhmPiknU8wxrtusLmJc
         PPWpXAM+NbtaTllmIIC+BCGeCJfNdl4MWs/bUbqxIoOj1MfLQi1+Zf2kL6mZjPuih/eM
         aNm5eK5VJkUqIUWc1WIL/ro22Y+tt/WC1RABDx+wwBt8QfEChuWsBZ6VttHX1Pmx9ZhV
         l14OZNx5tO8wv4xAdZrk8wQ/LtZocKWStC7a83vs+msS1npUlZ5JVMSLirY34e04eJd8
         QqwXU/b1yIbpK6p4Ccb/EZRyUuKjGXAqfNhM/CfQ9vzwQxcDEn6sT0rMaar/z5PWlmkI
         QWrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A3gXJlssIdw6gmZ6rz+0nKazn7PRcLeqyxa5OGzaKe8=;
        fh=3wfHkotscWTd82LmiuBoDlM6LqTpsc4bNjtBZ0BTciQ=;
        b=gi18xd9AqtiLPsSe0y59HYqOU2v7kENQ5oiNRz9Wy5JWu3lJAMVmNiYdTdshEJiMWM
         OIUDpxMPPNDaplVLyc3DKKfeqJ7EINI8ZLUX/5HwcLubO+vyVpEtU1F4j1tO6WTVSfja
         tZcC9iVmaO8HSkz2jUKJ6izrzPuQwIu1CRhw/eSUammpF3hbIB6P4lQTfyszT9Zws/zR
         s3jD4GkMGp8JrROTlWtoFXVVYuFO6MSerR8aYqryvPL1ldpv6bRV3CvOUFN+0X/I97GV
         pqJE2Z4MG6tn3bUaTfA6FuWYapqyWzCBzpME0T0POaIdR5SDFu0wHCHz4nfoh3I1AUvg
         T9pw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oQFRRXuz;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722589835; x=1723194635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A3gXJlssIdw6gmZ6rz+0nKazn7PRcLeqyxa5OGzaKe8=;
        b=ooUIqVLZtdbNMqAS1j+yvavqIDu/ngVI8lr2iwDK6FFfYdeOgwESLPbihzzatJ5pPq
         mUNU5spgLuPw033mSDuOBA0sjyZ3RYshRt57AhC8FfBIT/FwYkSoHwynudZweRId6/Sb
         qNqO46cvjfnvczag8af3djcGRlrXGVz7aCkBZJKL3eTIcFw3DkrEtxW+Q3wIYP2HcXuw
         UKuqmQBLBU8syR7qyH9fcflmNd4v6+fHudr40ITer0toYo6gnm51WDS6nRGZwmRTEDb1
         78V35v7nTmFT/rBUuMuzYZhwPK0K3Tkj1nW9XX4STIkqteOSD27S7Wt/B+lRYecTXUbU
         F0UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722589835; x=1723194635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A3gXJlssIdw6gmZ6rz+0nKazn7PRcLeqyxa5OGzaKe8=;
        b=KtwDbO3NRFSNgcnjWmxvxu7Z4cz6lhdV3YYViLDakaaa/N8dK6KsOi0uQ0TQG9APDB
         TbPlOESR+lStTrn+esRyxqM0k8jLLEPLYtnSc1Ylw1Lm5ce47rE+dq5hK296Z1cpO1ey
         SRvIIkU94RTShBKuS2hT3bO0G7Yg4peUhr61iSTvEeZ/6LWTDtDn/6eJ6fRipQIcNas+
         sB3OTLcBAES98PX2hEjDrPR4tkJx3ASGgEs9puoQgN0RWPEHJChkf/V+Ho9InciDhjMJ
         lcyqE+NqjXpUC241jy5STEWh9AOatyeSD9U5bj/63G+PujR735OWrzOgZacf1/8SQPTZ
         OHBg==
X-Forwarded-Encrypted: i=2; AJvYcCVZkkMLiMp4efYa62/k0yZIDo9GgtUezWnfWg8z5Je0vwvTaO65C0RLAwzJWakLapi1BZPNMmaSuQUuJbsxvNHcmk6gZYd2Yg==
X-Gm-Message-State: AOJu0Ywl6Jj/NlrXCYXnyyXUr9tM2G4Nml5L3qNaR73faad6DHS3NQ/4
	KQL+5BZBXxCVExO2LFt9A6a3FdmxIoX0P0LzL2PTisb/O7iKPZ14
X-Google-Smtp-Source: AGHT+IHj7gHQz4xrgP+J1J06r8Fpg5UDXhS1L3l+Q6ed4JOFuNZD0Y3gjELaPZ7y8GUVrr3rBmmC9A==
X-Received: by 2002:a05:6512:3f1f:b0:52e:f9f1:c139 with SMTP id 2adb3069b0e04-530bb4d6d72mr1805002e87.58.1722589834101;
        Fri, 02 Aug 2024 02:10:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3088:b0:52f:4ab:7f4b with SMTP id
 2adb3069b0e04-52fd3f4f350ls4366641e87.0.-pod-prod-03-eu; Fri, 02 Aug 2024
 02:10:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXrvqXK/wzNC0Iujzdq8qKkdCZ3G4vc9H7AsorbftA03x/bYrkPpt0VHl0rvrwHhE44lmPjgXD61Bo818iuOAPJJQ56GQqO7mkBVA==
X-Received: by 2002:a05:6512:15a0:b0:52c:b479:902d with SMTP id 2adb3069b0e04-530bb392926mr1722970e87.4.1722589831825;
        Fri, 02 Aug 2024 02:10:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722589831; cv=none;
        d=google.com; s=arc-20160816;
        b=AmAGvz3MARcJYHmc5TyMi/kZzfJL6394SRW4pymujjYKhMYAqaseQ0fS9n6Qm30dtm
         +mI2o1/4fFt5eWdC6JxBw+P/0iwF7GICaP/RuTvSCpwDqv9potHMrBXJaSvIG6xuyvOU
         ZE+d5H7Z+IAs4cfcbHsGAeKFh6NreIgSV0hbE5y/f/PDkgpHzMR6wcrMxjk3CMTCPfoM
         8KwRCk3FrBFIX6p6gyyZwJMrT2rp7RUiZpni01hOGq4v6dkAnyEXTZjQVTSeES4xLI/8
         hd3AVTACZp8mNFufqDgQ5CTxv3fizIOLZPU8W2xEOirZ7AVj5NzDI08lhih/2JaJL8W8
         /V9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BdfVeEEYqxRlg+wsbTTfgEpqIH6PLQRg/ETvJe3ixN4=;
        fh=8i1Usgo7V6IfmtrodXlNIb7TjRxQvxSOJxmUKl6XP58=;
        b=VS5HEtloR9HsUGyqRjO11zwQxkMRjZJggcNt1+p+LJEcEglG9xZwxn6G/P5dxpNcAl
         4iWMfEmmlCALQ556AgulW+aCDhiICvWb3IdM1JG9MnKdVOsipy5vFI6wQV8XqheyY62e
         lHtLUMIitXgyTmm9253NfZ1vDV69NRetkc5LX0r04a4TpjlM6zHrGCVsd7YnY1bLj7sj
         n9mV0xOCCS/lD5hIYzBXHBO28z5oKGlIg8jHuvMhni+U4zkbZku/fDfUVDfS0p3lX4l/
         7IsJoLJ8PzjCf0rkKvrxOwldJJeF5ahyg0xTYmZaQEVPh3PXR+op1EOHU4PbVL0bEe5b
         zzbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oQFRRXuz;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530bba2732bsi60110e87.8.2024.08.02.02.10.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 02:10:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-5a28b61b880so48095a12.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 02:10:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUd7nclpDtV8Eg86zCh8ItwYoGUMlrgEmPY4zcIJYCscW0xtm6Hp9yXn2l99s6mLlra1Lvexb/LB9i41NeelvBEyuaSUxomVcZgfw==
X-Received: by 2002:a05:6402:1747:b0:5b8:ccae:a8b8 with SMTP id
 4fb4d7f45d1cf-5b8ccaeab1bmr32772a12.3.1722589830338; Fri, 02 Aug 2024
 02:10:30 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com> <CA+fCnZeq8JGSkFwGitwSc3DbeuoXnoyvC7RgWh6XSG1CoWH=Zg@mail.gmail.com>
In-Reply-To: <CA+fCnZeq8JGSkFwGitwSc3DbeuoXnoyvC7RgWh6XSG1CoWH=Zg@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Aug 2024 11:09:52 +0200
Message-ID: <CAG48ez1guHcQaZtGoap7MG1sac5F3PmMA7XKUH03pEaibvaFJw@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
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
 header.i=@google.com header.s=20230601 header.b=oQFRRXuz;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as
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

On Thu, Aug 1, 2024 at 2:23=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
> On Tue, Jul 30, 2024 at 1:06=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> > Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_=
RCU
> > slabs because use-after-free is allowed within the RCU grace period by
> > design.
> >
> > Add a SLUB debugging feature which RCU-delays every individual
> > kmem_cache_free() before either actually freeing the object or handing =
it
> > off to KASAN, and change KASAN to poison freed objects as normal when t=
his
> > option is enabled.
> >
> > For now I've configured Kconfig.debug to default-enable this feature in=
 the
> > KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_T=
AGS
> > mode because I'm not sure if it might have unwanted performance degrada=
tion
> > effects there.
> >
> > Note that this is mostly useful with KASAN in the quarantine-based GENE=
RIC
> > mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> > ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> > those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> > (A possible future extension of this work would be to also let SLUB cal=
l
> > the ->ctor() on every allocation instead of only when the slab page is
> > allocated; then tag-based modes would be able to assign new tags on eve=
ry
> > reallocation.)
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
>
> Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> But see a comment below.
>
> > ---
> >  include/linux/kasan.h | 11 +++++---
> >  mm/Kconfig.debug      | 30 ++++++++++++++++++++
> >  mm/kasan/common.c     | 11 ++++----
> >  mm/kasan/kasan_test.c | 46 +++++++++++++++++++++++++++++++
> >  mm/slab_common.c      | 12 ++++++++
> >  mm/slub.c             | 76 +++++++++++++++++++++++++++++++++++++++++++=
++------
> >  6 files changed, 169 insertions(+), 17 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 34cb7a25aacb..0b952e11c7a0 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -194,28 +194,30 @@ static __always_inline bool kasan_slab_pre_free(s=
truct kmem_cache *s,
> >  {
> >         if (kasan_enabled())
> >                 return __kasan_slab_pre_free(s, object, _RET_IP_);
> >         return false;
> >  }
> >
> > -bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
> > +bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init,
> > +                      bool after_rcu_delay);
>
> What do you think about renaming this argument to poison_rcu? I think
> it makes the intention more clear from the KASAN's point of view.

Hm - my thinking here was that the hook is an API between SLUB and
KASAN, and so the hook definition should reflect the API contract that
both SLUB and KASAN have to know - and in my head, this contract is
that the parameter says whether SLUB guarantees that an RCU delay has
happened after kmem_cache_free() was called.
In my mind, SLUB tells KASAN what is going on and gives KASAN a chance
to take ownership of the object, but doesn't instruct KASAN to do
anything specific.

And "poison" is ambiguous - in SLUB, "poison" normally refers to
overwriting object contents with a poison value, which currently
wouldn't be allowed here due to constructor slabs.

I guess another way to describe the meaning of the argument with its
current value would be something like "even though the object is an
object with RCU lifetime, the object is guaranteed to no longer be in
use". But I think the simplest way to describe the argument as
currently defined is "an RCU grace period has passed since
kmem_cache_free() was called" (which I guess I'll add to the
kasan_slab_free doc comment if we keep the current naming).

I guess I could also change the API to pass something different - like
a flag meaning "the object is guaranteed to no longer be in use".
There is already code in slab_free_hook() that computes this
expression, so we could easily pass that to KASAN and then avoid doing
the same logic in KASAN again... I think that would be the most
elegant approach?

> >  /**
> >   * kasan_slab_free - Possibly handle slab object freeing.
> >   * @object: Object to free.
>
> @poison_rcu - Whether to skip poisoning for SLAB_TYPESAFE_BY_RCU caches.
>
> And also update the reworded comment from the previous patch:
>
> This function poisons a slab object and saves a free stack trace for
> it, except for SLAB_TYPESAFE_BY_RCU caches when @poison_rcu is false.

I think that's a KASAN implementation detail, so I would prefer not
putting that in this header.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez1guHcQaZtGoap7MG1sac5F3PmMA7XKUH03pEaibvaFJw%40mail.gmail.=
com.
