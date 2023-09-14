Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB5G7RWUAMGQEFA5FIAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id DA91C7A0F1B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 22:41:25 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4011fa32e99sf10676895e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 13:41:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694724085; cv=pass;
        d=google.com; s=arc-20160816;
        b=rIsQj6mVnnzeCH5dOwY6yujPou+LxaJi8t+sNlzbo+7W/EgN+IKkzSUzIR7XXzCjOn
         kn5nZnZcuznVCr4RG3PDzC5m1li5wqMdXChyXdpI4wedAD74e/NbPR/PnvJIjQ+7R31y
         ptAxWxenbgtVDOI1T8xEV4COdMv5zGJltYf93wFV8Y7x45nyf5y55Mscf7Mukcsgsx6d
         PwKmdMUZdo2fiXUrxHQq6OoNwdNpSRLshxn9cHbQpkDdx+aAjJx0NVhsaU2OEnWa2B0A
         N85Kol2KbTFYynbYBP8BVA71UB0N6316xHaDeOQhmFPvYgadq4g+kJXsDvPpD9GLVjET
         9L2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JHgTi04ggp6ioL1ORPOo3AU0Vq+SLtF7mnvZ5uAyJ/A=;
        fh=/WFzTKm7Ez8TDfilJ4ZgX7DpfPmgE6PfEuhudsznIwk=;
        b=cJDnY0KGriwLytDc+ktLuneYuQaXh4MYI7PzLwXP4W3rVw4/IbV+J9wFwNgfTP2mB/
         mEDUfhFPPZ2i9ccPMCyX0TwqUYVFpTBQl+EHuY4UWHOunXXX42DF71y5rDvNK36u2ONL
         OCAWVpZOJl36e7q5cYsfUPnHpbdjQOa2qpUA8O9n8CuM5goryixvu1V3ITJo8ErkugJe
         OXc2XDwV4skH4XHf91qVTVw4toK2h6inSpIdrKLAU74Jj46OVv19lQ24ginwI6HmunXM
         3w5z9U2/mo/bDWUFK8A5ig52u6VlSh+T99kBl/cqoFO/uBVBuYRABnikgtNRsYDfv3N8
         dmGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2LSeQtRp;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694724085; x=1695328885; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JHgTi04ggp6ioL1ORPOo3AU0Vq+SLtF7mnvZ5uAyJ/A=;
        b=qsSTW0zMOYyvHzHdTH7pxHOxOmv3dT71J/n4JBGp2WegLxKAaDey+C+pNLKkuny2ZC
         DT/IqkyC758GYHSlEWKDpK+Xkmanvtuq8B54Q6+kPAIUy8+UCdQhZhgFR0/7yPevFHyt
         ti869b6pfK2TUOFOEMS1wh7sIALN0zYgIlHx7yi2hJpR1b/MKz4IcO7j1bVnKm4HT7nU
         yja35ONECupmCpMe/0IWzvPG00uSfv/32fORv8ea53ZMgsSK7TLQYpcBu8NFSdOLVrm8
         Y3r+Fpzs8xPa61oJ6374rbFdjV1faHIG0v+1QXNY0KWoMXTfM2PtilYNzANf3azAqZcM
         zHYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694724085; x=1695328885;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JHgTi04ggp6ioL1ORPOo3AU0Vq+SLtF7mnvZ5uAyJ/A=;
        b=aeaLQ6xNLXDGw3+RVJZGxIRwxgceyqAkXCOPOBIS8k3clrRb5a83i06MV7mjkAQU2l
         k44BcI+t/UsOyB22x+N058YEq9o35/YCHl1u2M4uKhf6l/8EFLjlv1mOyCinBgqsR6Cf
         e3JB+6yFvdZlddzvB9hvs074KggkHAuXAjHuPukLohLJIyrvwjkNAPCe4XN2gFhpQ7eE
         EIyvwLep4QIAxTT43hgXpF+BwDtyggZKxFmIFu48u4yNmsthCBk1sFr5Of/KDKWRuwUX
         k36x1EJ17iwlHQt9J2Fp+YOaf77uR+6VVUMIhr8xJLjgzdqtvAGWAniIj9eCJV7G8kbu
         D6Ig==
X-Gm-Message-State: AOJu0YxIjJu+ZlVrTWqtIxpTW8E2E49jh0CQ/TT+xibrTgvX+LBlE7ei
	l3z5AgrF+y2DuR2pZ6RUJXg=
X-Google-Smtp-Source: AGHT+IHAPHRy4/5kmxUVXN1UPHURlVlmTgy57KpAFwfRFlF/xlrelHnATwLw8QzCuUyM0P+5FhGCWw==
X-Received: by 2002:a7b:cd06:0:b0:402:ee67:45d1 with SMTP id f6-20020a7bcd06000000b00402ee6745d1mr5380469wmj.36.1694724084540;
        Thu, 14 Sep 2023 13:41:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6025:b0:3fe:e525:caee with SMTP id
 az37-20020a05600c602500b003fee525caeels545620wmb.0.-pod-prod-04-eu; Thu, 14
 Sep 2023 13:41:23 -0700 (PDT)
X-Received: by 2002:a05:600c:2197:b0:401:aa8f:7570 with SMTP id e23-20020a05600c219700b00401aa8f7570mr5945414wme.1.1694724082891;
        Thu, 14 Sep 2023 13:41:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694724082; cv=none;
        d=google.com; s=arc-20160816;
        b=DDXSm8u9TnQLmSE1MQaOBabFg7/SYU94fULSVVCON5/jncLSwXD9S940uNRNfmKYOQ
         zsUtSOfssypT6jf9Iu7ynom+AmkwvGFrWubZS9l4o7qJWHs+38mIDbZa6Eh2zhThBR7D
         mLLPwYPnsA5e4MOE0YXt9vQzLf4iiD+PqLp8XslB49U1WwhyxhlhAfMs7K0HQ6DKB3np
         mmRG25/cTPuNc42fUdCZxoOIZ6G7exguE5v3eecO7Zv5G22siXwne8CteLrUXLTUST0X
         O9Askp8OIdzuilcfmmo/ucDiz+5NYYCsvJVKq+KVABsPoEuuhNa9Psc5x1xV6KEFTAxS
         6Ndg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fAwsTmQ+ELNb0oAFR4fBQd1wUmizG7i6iQSI6zVD64o=;
        fh=/WFzTKm7Ez8TDfilJ4ZgX7DpfPmgE6PfEuhudsznIwk=;
        b=gVvOrvg0WAXY6psCOPyXlQ7YceEQgixyHpfV9uReCsGPul/bcfO6uAnc7/AgJ+cSbQ
         1I6sj5Bbm5K1SQwalVMs020vigWoKr3IUbfKM8WgnQP2LvUR7rhHclT+CFrWEtL9shk8
         7Zlc87iKUCv+nqJUlUTiJYkATwcG6NB8J24QjFPBsXWiQ5ckwC21TRraVymRO0GhrKxA
         gLsTI/weIZNaOBmZo9j3lE5MFWqb0KhM4PkqGV8OwVRfhKFTmGdk3Bs8aK+L8JEAkDDQ
         IUny3bgnH3mrXXJQ3ZYBX+q7+bZ1/fsRjVeFzZYsgAB9tCy3tLdXG8SUSDrjYlAlXOSj
         sEAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2LSeQtRp;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id a22-20020a05600c349600b0040475077d8fsi158211wmq.0.2023.09.14.13.41.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Sep 2023 13:41:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-4005f0a6c2bso5175e9.1
        for <kasan-dev@googlegroups.com>; Thu, 14 Sep 2023 13:41:22 -0700 (PDT)
X-Received: by 2002:a05:600c:1e05:b0:3fe:dd72:13ae with SMTP id
 ay5-20020a05600c1e0500b003fedd7213aemr45137wmb.0.1694724082359; Thu, 14 Sep
 2023 13:41:22 -0700 (PDT)
MIME-Version: 1.0
References: <20230914080833.50026-1-haibo.li@mediatek.com> <20230914112915.81f55863c0450195b4ed604a@linux-foundation.org>
 <CA+fCnZemM-jJxX+=2W162NJkUC6aZXNJiVLa-=ia=L3CmE8ZTQ@mail.gmail.com>
In-Reply-To: <CA+fCnZemM-jJxX+=2W162NJkUC6aZXNJiVLa-=ia=L3CmE8ZTQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Sep 2023 22:40:43 +0200
Message-ID: <CAG48ez0aenPmr=d35UGa4_BiCwYU1-JHhD_2ygThvjOEXEM7bQ@mail.gmail.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Haibo Li <haibo.li@mediatek.com>, 
	linux-kernel@vger.kernel.org, xiaoming.yu@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2LSeQtRp;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Sep 14, 2023 at 10:35=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
> On Thu, Sep 14, 2023 at 8:29=E2=80=AFPM Andrew Morton <akpm@linux-foundat=
ion.org> wrote:
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -304,8 +304,17 @@ static __always_inline bool addr_has_metadata(co=
nst void *addr)
> > >  #ifdef __HAVE_ARCH_SHADOW_MAP
> > >       return (kasan_mem_to_shadow((void *)addr) !=3D NULL);
> > >  #else
> > > -     return (kasan_reset_tag(addr) >=3D
> > > -             kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> > > +     u8 *shadow, shadow_val;
> > > +
> > > +     if (kasan_reset_tag(addr) <
> > > +             kasan_shadow_to_mem((void *)KASAN_SHADOW_START))
> > > +             return false;
> > > +     /* use read with nofault to check whether the shadow is accessi=
ble */
> > > +     shadow =3D kasan_mem_to_shadow((void *)addr);
> > > +     __get_kernel_nofault(&shadow_val, shadow, u8, fault);
> > > +     return true;
> > > +fault:
> > > +     return false;
> > >  #endif
> > >  }
> >
> > Are we able to identify a Fixes: target for this?
> > 9d7b7dd946924de43021f57a8bee122ff0744d93 ("kasan: split out
> > print_report from __kasan_report") altered the code but I expect the
> > bug was present before that commit.
> >
> > Seems this bug has been there for over a year.  Can you suggest why it
> > has been discovered after such a lengthy time?
>
> Accessing unmapped memory with KASAN always led to a crash when
> checking shadow memory. This was reported/discussed before. To improve
> crash reporting for this case, Jann added kasan_non_canonical_hook and
> Mark integrated it into arm64. But AFAIU, for some reason, it stopped
> working.
>
> Instead of this patch, we need to figure out why
> kasan_non_canonical_hook stopped working and fix it.
>
> This approach taken by this patch won't work for shadow checks added
> by compiler instrumentation. It only covers explicitly checked
> accesses, such as via memcpy, etc.

FWIW, AFAICS kasan_non_canonical_hook() currently only does anything
under CONFIG_KASAN_INLINE; I think the idea when I added that was that
it assumes that when KASAN checks an access in out-of-line
instrumentation or a slowpath, it will do the required checks to avoid
this kind of fault?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0aenPmr%3Dd35UGa4_BiCwYU1-JHhD_2ygThvjOEXEM7bQ%40mail.gmai=
l.com.
