Return-Path: <kasan-dev+bncBDW2JDUY5AORB564RWUAMGQETJDU34A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 041987A0F0D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 22:35:05 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1b728bfb372sf2057968fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 13:35:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694723703; cv=pass;
        d=google.com; s=arc-20160816;
        b=vjd2/0s7r8TbokvSpxxD9tsiiiF+BBTgVN1Z7+yhJ4O1fQE6N6NRTTWnzMyrdMhr/W
         +m3RhaYjgM3NOm8gc8MDEtx4X6WFZAl5mqpxkvuCKUwGwyZI+rY+Nj9BWoCKp8rh1mHJ
         K4hAYJuI2+8ak6vyRvXGhJ3wJJwNxeL71Vq37dhnyXf3rlSTrDUNEdEgZdwfjnWa8KfM
         38z24hCj3aUO0nw0e031XUuaB1NM8iqs9DesNACUCFaKphxhZ+quv6MwL6V9KArILGKf
         K8TUrRHTvbE6lqGbZWg5CN/TZu33VSE2HCU4nIuIaHgw6wJ114mdN7WGKcF2ggPLqjFh
         mhbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=aSlTB6Hpl3b9vlHZaqvmpkvvylfMf0ZFShKDJXZQ4tg=;
        fh=Vkmxc6xe7+fxH/mp1IrK5CmTxXTZyKUFmn1ygh470K8=;
        b=zCBwIYickZ9ThhS/IB7sXoLndTmfWkw+BzJHRw7E3N6/VBACy80TdiIibWEOFw/T3Y
         ulF56WGZIIBa1IZb1Ew3V1I+Ixf/o/t1vS4M3zFZ7DAvFV9Ybwc0MRKty/OUhT88oF68
         K8LUWFvbziNqgkAlSKpGs6K3c2CFnKj1yGj9dWxJJ6wA4bXuZHnxSIg927v2GpZXFToO
         +ok4hJgIkXRiFe5mNNNM6ZxcwzngT0wqhzqpec5CZ7y9b5nfb2zyKHm1/8dt4VsWX6TX
         su++jwbq6FQbHKVTjqQ/5ncZ33gQqztX4nqZChO0jDRBB+z6MtDC4Ln3VJOTrkNC6+ic
         2tyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=HxtD9gjT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694723703; x=1695328503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aSlTB6Hpl3b9vlHZaqvmpkvvylfMf0ZFShKDJXZQ4tg=;
        b=odtIW+eaJkU1zpYJPTwN32FKcbZ8G1O3WyGkbuxM3ChR3BV+lbO//V9vgcsp1pE7KO
         XlNRe1XqTeU56ynPE//+PMpPfOWZST6YdUrHlqDfYJ8/yol2DRE2Wc6fEd32W3nz9oT8
         r3oI6nNT5NYuWljaztmz2QmcKSKgD0x3ncVAYRAJAwGZ97tFJizbXmQfm5aIqM3ZyBrr
         O9qoNWjWbKjlJcJKu9tYt9lCNk5LkUCprwINkHYaghq6/dhl4HstesWTvAE576tAO41I
         qNuTydFXeAEi9/CUNWw4hvE3msqA+z5nC+K/ma+tzaP3ccDmt+Cegb2v2JIAUgeGDRrM
         Z0Gg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694723703; x=1695328503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aSlTB6Hpl3b9vlHZaqvmpkvvylfMf0ZFShKDJXZQ4tg=;
        b=AzfOXk/Hl8EEld4aHpXg9fN7xQ4bCBfb6Nwd2nUIUsn5bxPeWGUcqfbuhBKNKNdng/
         xz4x37h6W82Az7mIDjQ9BxKogbEoSXgV45zBD70NyWFSx88t/inwxpHfBfMxZmayn8yD
         h2jjhmD0H16JRZpa/TgacfiAdcFbAVT95qk3vvCWDgXIG1gO/q5B4ODsvCeZ9JiMzE+u
         hpg9BrZtyhQSwbpP1xM0TvVDvY97SxiobCfAHHfh+r7yvYiZojqWICd8GkKyYrC9czlk
         clNXCwWaY+jpXgpRaL10Dm6K8biZ33Skv2CdYkdvrGz6gedZsLUMFFeG7ILgDXETZyAe
         rY6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694723703; x=1695328503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aSlTB6Hpl3b9vlHZaqvmpkvvylfMf0ZFShKDJXZQ4tg=;
        b=A0s5/Xq6BgLTpCscYrnJvs1o3hgao1wvZnuhHHrUn7OFwKk2bO3L4nXUIQqWkDvOcY
         3XLL89lPdJ06YylFVYmaebP+XPpT6/wb0/+CD8k+iEI3T/qWYtRhw986P6OBXbS+1+2z
         zoNcSATIKfzz8iX6CbLCUYqcWeau7mzMVbdGiPtEfNOWOgn0GLsb3hKE1KpPR28qW/7Q
         s/vM0lvl7RF5xRvKLUJnvJncjCPmmNngitRhhWKgCox5M2D9+8b+4b/6dEIur6YNZKsP
         fX+jz9AWoavXJ39fcT13UxOQdKVdTzvH+R1nBhwLkEJoWVxiORRXiEI0+HG4SYZ+tBjB
         5T/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwGqBfJA1oQsk+gon6cqniC/ds5mmSueOeMtVWCQLfWrErev+B4
	Z61EechevAA30T10VDlXw/o=
X-Google-Smtp-Source: AGHT+IGoWfjluAG6onHAuGc0OkPjtzWMGDHjFVMFclmYp3zIL2X/VoBjYbyWVEI8s235NJIwiP7G4g==
X-Received: by 2002:a05:6871:29d:b0:1d5:5d44:7404 with SMTP id i29-20020a056871029d00b001d55d447404mr7252839oae.43.1694723703624;
        Thu, 14 Sep 2023 13:35:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9691:b0:1b3:d7b6:9f4c with SMTP id
 o17-20020a056870969100b001b3d7b69f4cls13912oaq.2.-pod-prod-01-us; Thu, 14 Sep
 2023 13:35:02 -0700 (PDT)
X-Received: by 2002:a05:6358:4299:b0:13a:c28f:3cd7 with SMTP id s25-20020a056358429900b0013ac28f3cd7mr7804820rwc.14.1694723702696;
        Thu, 14 Sep 2023 13:35:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694723702; cv=none;
        d=google.com; s=arc-20160816;
        b=xfugiSaqDnuUAtmY20G6Km359bQviwIi8zv9H0zZd8L0yAZzyFyDbxerWNWpDFCq8B
         j+/Dl3PpEqunmb68Vt/NerB+58LvqK8cJHgnfdrcI4wWJ4FkqfUzsPr3SUPf/X4v0zrT
         wCF39Q/NVvjEVUszNHoD85VUGcTHoTUB+KS20rT5s/IV8DhtnShYhbjBv1sIFEqjIenz
         mjVY20AG1Zat3RV8ZySmfI1bJ38wQZ0kc/E7pi9yGjWg7oOyy0JPRw8l6PBuBcqLAnzq
         ql6buXvA1wf2t0oV81VAEHaCl4OFUZwZF09LHeRWUOWiKXvfTbGMHTVQN1FWffj94spC
         Sigg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RUZ4tKWNQQW/M0sqK1AFluw87RumzXnsJH+qNtjEDz0=;
        fh=Vkmxc6xe7+fxH/mp1IrK5CmTxXTZyKUFmn1ygh470K8=;
        b=zqGpDfVX/nbeBG2cwlwNmUxpAw3U+4YKQVt0+DZogTKV06+TM7xC3Xdi5+UPAQCwDt
         +A24vZdy0yeIGHJA5e3HUrFRNa8SBNK+yiJfsCtWCXYAaOT+y17ptm5JTTfC/aMLWM+9
         SlM8y1YE2hpz9/r6k3+YY/jMWw/4B2Brr6kNrlF+kHBcJ7777RfEs55z4+9nuy2UdAGb
         i/1KX+TL7ckjyMcxCZhU7SOchgxPX/aTBE0I1UnpTSEI+c9z5cRwcnDWrGWN3eB6h7bf
         Ge8rGXisMozsC800/iwvOWV3uJfeAK73TGE4jGBxl2NUfXMd91UldQkqS/mY42kvXoTK
         yroA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=HxtD9gjT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id r4-20020a632b04000000b0056bcd716015si287208pgr.3.2023.09.14.13.35.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Sep 2023 13:35:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1bc0d39b52cso11919135ad.2
        for <kasan-dev@googlegroups.com>; Thu, 14 Sep 2023 13:35:02 -0700 (PDT)
X-Received: by 2002:a17:902:c949:b0:1c3:ea60:73e2 with SMTP id
 i9-20020a170902c94900b001c3ea6073e2mr7674254pla.27.1694723702114; Thu, 14 Sep
 2023 13:35:02 -0700 (PDT)
MIME-Version: 1.0
References: <20230914080833.50026-1-haibo.li@mediatek.com> <20230914112915.81f55863c0450195b4ed604a@linux-foundation.org>
In-Reply-To: <20230914112915.81f55863c0450195b4ed604a@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Sep 2023 22:34:51 +0200
Message-ID: <CA+fCnZemM-jJxX+=2W162NJkUC6aZXNJiVLa-=ia=L3CmE8ZTQ@mail.gmail.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Haibo Li <haibo.li@mediatek.com>, linux-kernel@vger.kernel.org, 
	xiaoming.yu@mediatek.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=HxtD9gjT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631
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

On Thu, Sep 14, 2023 at 8:29=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -304,8 +304,17 @@ static __always_inline bool addr_has_metadata(cons=
t void *addr)
> >  #ifdef __HAVE_ARCH_SHADOW_MAP
> >       return (kasan_mem_to_shadow((void *)addr) !=3D NULL);
> >  #else
> > -     return (kasan_reset_tag(addr) >=3D
> > -             kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> > +     u8 *shadow, shadow_val;
> > +
> > +     if (kasan_reset_tag(addr) <
> > +             kasan_shadow_to_mem((void *)KASAN_SHADOW_START))
> > +             return false;
> > +     /* use read with nofault to check whether the shadow is accessibl=
e */
> > +     shadow =3D kasan_mem_to_shadow((void *)addr);
> > +     __get_kernel_nofault(&shadow_val, shadow, u8, fault);
> > +     return true;
> > +fault:
> > +     return false;
> >  #endif
> >  }
>
> Are we able to identify a Fixes: target for this?
> 9d7b7dd946924de43021f57a8bee122ff0744d93 ("kasan: split out
> print_report from __kasan_report") altered the code but I expect the
> bug was present before that commit.
>
> Seems this bug has been there for over a year.  Can you suggest why it
> has been discovered after such a lengthy time?

Accessing unmapped memory with KASAN always led to a crash when
checking shadow memory. This was reported/discussed before. To improve
crash reporting for this case, Jann added kasan_non_canonical_hook and
Mark integrated it into arm64. But AFAIU, for some reason, it stopped
working.

Instead of this patch, we need to figure out why
kasan_non_canonical_hook stopped working and fix it.

This approach taken by this patch won't work for shadow checks added
by compiler instrumentation. It only covers explicitly checked
accesses, such as via memcpy, etc.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZemM-jJxX%2B%3D2W162NJkUC6aZXNJiVLa-%3Dia%3DL3CmE8ZTQ%40m=
ail.gmail.com.
