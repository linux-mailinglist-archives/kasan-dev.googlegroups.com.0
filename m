Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBFVNT3CAMGQEPFGNBFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id EA83AB13E3B
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:15 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3a503f28b09sf11204f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716375; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fwt4JPshaHpHhM7PYhLvOx5eEzbOYhucBV0AiypzlSUcQYe4C5dFCoFDMqSgIAcQBX
         mMGLsKtwdDF7EN42hJDw8tgqcjF+9UOIwWHTJcSLs2cattmi0UvvScCFfRqE6IfXGXOY
         OmuA0m7sDcQnZn0JaOlnekyWAD1LmQT90c5xtB8ad/Ngt+M7U58RtOMRXj6f3XbGRJPo
         54y394gGNJ5xDAdnuX7jFcMDfVRbirNvaGS5d/j5iXbMF5nNaWq5znNF53NmducaqFGA
         v6sLJyPx55P+dZRzQahpKtwbCdvjbun0SQh5RsQhU6ekqmnVRofT2XS3VP0+gxI1ST+U
         63YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e9aQSz6OLFu41vwxdp8RsDhfHszJDq06CyXIxC2wFCw=;
        fh=N2p6pnaSa/reD/zLIbaPShqOm+GsoP9PqBdSnzXO8Xc=;
        b=PfVKjgAw1w8Lsfkc+FkcdyLbSIASDkrDmW86MBHqDQa6GieforB2F4qRR7o2eGQt/n
         qQeWa8z5+RLdzhXXrM1hgrgxSL4qNDcuq+FpUaRsV1MK4VWAsGKdPZJAcwnvWoVr2amQ
         TT1kCBctMhJs+B2t1b0LL9e0G9+KaDsxQ12AWu7qnGzAlhSpEACbIFy3tpV1OvxYG/H3
         10Xz83HnCvJbXV4b1ECgxVYqT3tzAZ3dYTEd512XTAbrqhFv84x38okGSD3Pc4b07cgW
         3i0lEdDgkzy46mMTsu3WUTkStvmxtifBn/DWrD1atUTWDx/Gie2CKXJOZ6YKd6pwVfZe
         XbGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YZFCBVDk;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716375; x=1754321175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=e9aQSz6OLFu41vwxdp8RsDhfHszJDq06CyXIxC2wFCw=;
        b=QymzTNmxGYFFKy5Voh3SLMQ1DqYCeZH9pA9sf1IbRR6C06bm6kWDPgQ39efaBzSiZQ
         xXMRAKZao7hKqpA/MDJLBS65deiDY2T3KpysJleqftLm3mREyksexh1oo71gZlkKsC75
         4Zu+niPI8lbW9aXnTJygtDniMAxtl+Y5Z0fCHhSgWIDln/3QQzMLpzrA3kc8/wVhSW2F
         ikSC+bYBM3Wb9DeVvp8kbEI07yavOzIf7+MtMwj1cHFGDDlOIwKj49NtFt1+GK7gszi+
         byD56ZWZ5ItvpCTHHSln5FCmgLE87JKbg2tHb3e5+2zH3Eirm8eoBO+16MxghvhwXif8
         F4Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716375; x=1754321175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=e9aQSz6OLFu41vwxdp8RsDhfHszJDq06CyXIxC2wFCw=;
        b=pBsv9Mwid7SG2LdGQmGCuwtEs8xMcDFaA4JWNN0/hHZRvRXXy+D1HElMWCRc85wMVu
         8j6qIQWnLUPPRFRZYIR5qS6osGGbyA8zq3KOQforUreqAFzaUjiVQT5EPfmfX3rDK0vg
         z6NhbNc9U7Gw36GuXA5cuoD4gFwoFggzuUEtDgo85YFOAKYeW97VuN92EvfjpqSSh5IP
         9D0b3TMCtZiQJkUpceSloOACH4QmrYraboAX3W6GV/yKKfiax518kaHANpQRWR6tx8Iq
         Rp1Xqg0vv6xOM4FbNqDGlnSqdlf8dxl2r0GxYjJJG21tI1bweDEibyt+YYq5WRJ+xAyu
         A4Mg==
X-Forwarded-Encrypted: i=2; AJvYcCXskGuR9crryKy3ufTdacUsQnOUwbgEcXfcAZisaZylB1IodJRlTN/yHdbr/RPD39gbdrecRw==@lfdr.de
X-Gm-Message-State: AOJu0YyETZ4J0D6UcYaJMnbOjEuFmrDup1mYGADpDTiUIZUfsnVJlfl/
	A+MoC4fWe9AgmWIalQoiX5bWzZiOM8h3CYtINZIjkFg+M0S5I8LtG+3K
X-Google-Smtp-Source: AGHT+IFzD1LnL1CZK/yMdtUuFeSl9x//WEgx8aNima0iGZ3L3MwRdcNVfNsjYvR/KSv9/mlawLyUDQ==
X-Received: by 2002:a05:6000:2f88:b0:3b7:8ba2:9818 with SMTP id ffacd0b85a97d-3b78ba29c7fmr1572662f8f.22.1753716375363;
        Mon, 28 Jul 2025 08:26:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeQQRflj2T9t5coQ/zSTT0lk8CKrg3Bsm9CmlSX9WBIZQ==
Received: by 2002:a5d:5f07:0:b0:3b7:88cf:e1bd with SMTP id ffacd0b85a97d-3b788cfe555ls295140f8f.0.-pod-prod-00-eu;
 Mon, 28 Jul 2025 08:26:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxo63CGniUL1Rbnm9+W8dfzKGP+N4jr/Ash+KW+kt1ieZg5n88FEezd+/umLN9dTczcDIiXo9fzM8=@googlegroups.com
X-Received: by 2002:a05:6000:3104:b0:3b7:828a:47df with SMTP id ffacd0b85a97d-3b78e3dd9a6mr5894f8f.4.1753716372506;
        Mon, 28 Jul 2025 08:26:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716372; cv=none;
        d=google.com; s=arc-20240605;
        b=NbwVMD4iAu9s9sHFwEZBM5wxaGYcClXWxu50OqzXQgGJf5NGIw+lDuYZkr/HAMC6xN
         qBHQ4e/ruEpXOW/CJQ+5B9wH5P5WaDp/DhKpChvk/IFzkYGrhR5Z64F7U1Inhq6eOJA4
         ormeCcvRyfEQYlGosE34c/GUDKx0VGMxavJQYqayoyeItvTLL2g138izz1Z4d0fmE3LK
         IX/hNllAQIRkwpSfx+kpDUQDtTz9IN8O0BEViYMbEcHc04rXJkcB1GTbopM2h97cZ+Y3
         3+JP6czNSZNDMedJ7k9VjxYULK2IySB2rgQ+WehPzEX4q+2Ltxse/tLtp1kkvSpB4VVk
         K9cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZqOC4wRRGhe0Mg49hUc2tJcMbQEAuNNfAJDotAhUq+A=;
        fh=zq1b/XfUu7fGAaLXlV9CaHtFIpmwDD5Ox0xUiLoMbTE=;
        b=ZhcK2hRgxM+Lz05xjhVpbNKt3H0Gyhlmr19utZg6uPuidCHOWyKPR932MhUO6PocLY
         FaMkfrdMVL95TTUQHk2bREI8LTBDa1b97cxRBMvlYcrejCMiD/A879ADvDso1bhI8lq9
         3IA9HcEJhn5bSUvUHLzrLmAwy3Cu8XEDSByW1Is/+GD7cBzDwXqlrG5fVLmKIx4sJdQV
         y4OZmFeC2g1MuSac4jF5uAMWChuPKN0UajSDWqDe/6cAJnxm5Yl2uIAYrjhjofAiSHqr
         nsz67utFydh0AeKjMd+yxOqDonni8F/4CxY+ui/ryb4KH90x3OJXlyYY6GzXk2ScKHjK
         czbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YZFCBVDk;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b7845511besi121912f8f.8.2025.07.28.08.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-6154c7b3ee7so9682a12.0
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVzhWd9P8HOc24v/AeCjg0iZ9Du+FyWC2CT1QHzRWwe9ov8N6THuHGI2RujQuTm0zE66aXhPHoSip8=@googlegroups.com
X-Gm-Gg: ASbGncslbXAPc3IF19YTrGWKfGjtXxriGgft9vkMiR2DSlpnDm3elSIq7Kkzn4/O3gL
	+oHWi+UwMQzm+v6DUBzVRt1RRfTW9KXpMF7hb322I95sH0QHonpX7DIs4K6LUPcxT9s8exJM33T
	VE5RybKhMVjtErQvkj2WB4dft4mWXHTJWWfKV0Yd1xtDnVL0iAEsA/kZ9nyug1rUiI903b7vHjL
	FXtdkJRzPWTC1q5z3+9MDN4OH8Wnmlu7Fk1yZflXlSs
X-Received: by 2002:a05:6402:1a39:b0:615:2899:a4e5 with SMTP id
 4fb4d7f45d1cf-6152899a78emr101033a12.5.1753716371615; Mon, 28 Jul 2025
 08:26:11 -0700 (PDT)
MIME-Version: 1.0
References: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com> <CA+fCnZcyh52CqY+XDMMjc6f5KQoaji=7KiFM-6+2NidjfyNVGQ@mail.gmail.com>
In-Reply-To: <CA+fCnZcyh52CqY+XDMMjc6f5KQoaji=7KiFM-6+2NidjfyNVGQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jul 2025 17:25:35 +0200
X-Gm-Features: Ac12FXzgMg6AU9sijci9qK5lKdc5wEfC84NjWQbqd2yCO609j_hdZiglhUudTRA
Message-ID: <CAG48ez3Z+7pBPTShMrxZObkShCR9rE0euE76i9ciQNKy5bhyPw@mail.gmail.com>
Subject: Re: [PATCH] kasan: skip quarantine if object is still accessible
 under RCU
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YZFCBVDk;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as
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

On Sun, Jul 27, 2025 at 12:06=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
> On Wed, Jul 23, 2025 at 4:59=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> >
> > Currently, enabling KASAN masks bugs where a lockless lookup path gets =
a
> > pointer to a SLAB_TYPESAFE_BY_RCU object that might concurrently be
> > recycled and is insufficiently careful about handling recycled objects:
> > KASAN puts freed objects in SLAB_TYPESAFE_BY_RCU slabs onto its quarant=
ine
> > queues, even when it can't actually detect UAF in these objects, and th=
e
> > quarantine prevents fast recycling.
> >
> > When I introduced CONFIG_SLUB_RCU_DEBUG, my intention was that enabling
> > CONFIG_SLUB_RCU_DEBUG should cause KASAN to mark such objects as freed
> > after an RCU grace period and put them on the quarantine, while disabli=
ng
> > CONFIG_SLUB_RCU_DEBUG should allow such objects to be reused immediatel=
y;
> > but that hasn't actually been working.
> >
> > I discovered such a UAF bug involving SLAB_TYPESAFE_BY_RCU yesterday; I
> > could only trigger this bug in a KASAN build by disabling
> > CONFIG_SLUB_RCU_DEBUG and applying this patch.
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> >  mm/kasan/common.c | 25 ++++++++++++++++++-------
> >  1 file changed, 18 insertions(+), 7 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index ed4873e18c75..9142964ab9c9 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -230,16 +230,12 @@ static bool check_slab_allocation(struct kmem_cac=
he *cache, void *object,
> >  }
> >
> >  static inline void poison_slab_object(struct kmem_cache *cache, void *=
object,
> > -                                     bool init, bool still_accessible)
> > +                                     bool init)
> >  {
> >         void *tagged_object =3D object;
> >
> >         object =3D kasan_reset_tag(object);
> >
> > -       /* RCU slabs could be legally used after free within the RCU pe=
riod. */
> > -       if (unlikely(still_accessible))
> > -               return;
> > -
> >         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE=
_SIZE),
> >                         KASAN_SLAB_FREE, init);
> >
> > @@ -261,7 +257,22 @@ bool __kasan_slab_free(struct kmem_cache *cache, v=
oid *object, bool init,
> >         if (!kasan_arch_is_ready() || is_kfence_address(object))
> >                 return false;
> >
> > -       poison_slab_object(cache, object, init, still_accessible);
> > +       /*
> > +        * If this point is reached with an object that must still be
> > +        * accessible under RCU, we can't poison it; in that case, also=
 skip the
> > +        * quarantine. This should mostly only happen when CONFIG_SLUB_=
RCU_DEBUG
> > +        * has been disabled manually.
> > +        *
> > +        * Putting the object on the quarantine wouldn't help catch UAF=
s (since
> > +        * we can't poison it here), and it would mask bugs caused by
> > +        * SLAB_TYPESAFE_BY_RCU users not being careful enough about ob=
ject
> > +        * reuse; so overall, putting the object into the quarantine he=
re would
> > +        * be counterproductive.
> > +        */
> > +       if (still_accessible)
> > +               return false;
> > +
> > +       poison_slab_object(cache, object, init);
> >
> >         /*
> >          * If the object is put into quarantine, do not let slab put th=
e object
> > @@ -519,7 +530,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip)
> >         if (check_slab_allocation(slab->slab_cache, ptr, ip))
> >                 return false;
> >
> > -       poison_slab_object(slab->slab_cache, ptr, false, false);
> > +       poison_slab_object(slab->slab_cache, ptr, false);
> >         return true;
> >  }
> >
> >
> > ---
> > base-commit: 89be9a83ccf1f88522317ce02f854f30d6115c41
> > change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24
> >
> > --
> > Jann Horn <jannh@google.com>
> >
>
> Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

> Would it be hard to add KUnit test to check that KASAN detects such issue=
s?

Sent a separate patch with a kunit test.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez3Z%2B7pBPTShMrxZObkShCR9rE0euE76i9ciQNKy5bhyPw%40mail.gmail.com.
