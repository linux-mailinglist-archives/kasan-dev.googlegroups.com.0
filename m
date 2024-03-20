Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBUC5WXQMGQED43M3VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D3737881838
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 21:03:19 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-69649f1894dsf4128266d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 13:03:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710964999; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIG3jeJ7V029y5Eqe0nPjdGpqoyZ4Jwla32dhvM8FIX15FJzMzm21bxL+Nvi+hdkor
         cGLnP0m5cG5angUQcxaoRsQYgtpCCQTZ+8Vuh5OvatQcrda17vcYx+6P4A4GSKRNOkME
         qQCf7uILc0Ib8vk6PwlxAna13ZjJsMrfGL6ynOitO41D4AUZ8Pi7lxBB9yBKSsLN/4T3
         68bnUq9c2RBsNZBJHQyfD2l8NEWzJx3wyhgiznTalEDIuYTIZdw79jYk5TDJqMy+mo6T
         eaAn3J9mZdbokuaP8qK2cMrF2fYFI4CbgmIri8OEqXC1SO3E71NM/u0ts8j+rPYLEsb/
         8ftg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o5GFVWTF6qxABOhdZUMBuBolLuPSzj2abxuYhwi1shE=;
        fh=7b/RxVIemRnKVKZTcDcPNrO5DhF2ax7n9phfvndc/bQ=;
        b=cPHSKefWzdfb05J0Uz6teWv2kpUxudSwD74knasaZXNa88TthGXVertlh3Fc+PpCtk
         sZajkt3KDyu5kyTLo4Hg6wVFxSrSwIFtAcN/qd5VEnMffqSaFuTYVjQGucX/R/u1+R4B
         D4IekpONmWoLqPuALa7V86JVAZ5TXWO+OOB1gmGh982aj7lkgzFTDhQn/sJRdl77yvYW
         u2eddzLmCjHshnp37bSDyNfG0mxicoFA0Y5S0BP5QVy4hlUGlG386mSnHp703+6ZlQSX
         hCZ3zrhfAZAdwvWz0SGDVP1MG3+8Q3K4xI5h3SvRO1C82Gz6kba5l1oTkpcu+FwjIcns
         6dDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m1meN6HV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710964999; x=1711569799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o5GFVWTF6qxABOhdZUMBuBolLuPSzj2abxuYhwi1shE=;
        b=BkS+p89NPmDQ57MHlhzzlFmwDYYSEQxFa01yJUtGTZrMBwDK/mrtWBBX4VYRQ7vLV7
         XoEdmsf7gV0i5SG2/kHm49DbYQv+g/+9yTZoPZakCvRvVrtpvHgPAXCxGfmw2H9wqidI
         ImWmFOhkgHRS+uZlnKi7yHkEtZsBUZy0pSz/VgZs2n0yZlc+Jg0aWNEFRYkiWAwqGHbB
         POBaQsHrGnNjU2Fx7VVjURssF7JZpopATZyQXACVFaQBRL+Zb8OI1N7qAytriNOj7xmF
         fSkuY9yHl59q8Pznsba+zU3beq5cgcURQQgMloWGX6VVR1xP1sBq4HOzxEp0qUZS5n/E
         2+wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710964999; x=1711569799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o5GFVWTF6qxABOhdZUMBuBolLuPSzj2abxuYhwi1shE=;
        b=E235rUW9/o8kRjCcGh5WHISQFMxIVN6pROsCNypn041J9TubbEus50Uo6LMpVq4s2g
         0ZTW6rs4/PUrJ/hOGhXl1FPayFM6ciZBfsRiPpfspfqNzv+VYXmc2euycwQ7+CXKTW1I
         t0IwxJUBTaurjPCwd1WaWt+Ec42Ug4rocYQmQhvI66od6l86mN9Yd6gMSP/NxBp/buL6
         NmfaO9FHshUcUTiqYZa4z5He0Z4I+0oKUTpwKFBSy7wfw7xw3KSH9y5XpdH5sS5ohE4D
         SvXi7on0BvQzIARDBbZPjwQbL8bg2kDOVI0tOcmuKzm+5SMTDNaj+rmYFpx2cvSZnmRk
         yufw==
X-Forwarded-Encrypted: i=2; AJvYcCUBiKfj7gKK/vGwyPoy1fbLmJuFoiJeyeD7VC9nqeZpLjtbGdPvWZuyMLTFEwafdaGyMHDuo/iqyYgt6LqK3BTMEIWpLdnMdQ==
X-Gm-Message-State: AOJu0YwkN5yYjM9DWKrFOvazusNcZXwLSB82X8DR4PtHtAlrPQKEE+N2
	RpxhKfycN0Ue6f4Yvz01yDvp87tJTOaNSWLIJO1Fide8C1hrbhvj
X-Google-Smtp-Source: AGHT+IHfRlA5EuzFoFn5RuGEXozEyC9CA0Me81xJBldK29Aud+twSjbhpasuol2gq42+U94NUNuxXg==
X-Received: by 2002:a05:6214:509b:b0:696:116c:f00 with SMTP id kk27-20020a056214509b00b00696116c0f00mr8444196qvb.59.1710964998521;
        Wed, 20 Mar 2024 13:03:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2684:b0:690:c6df:5de9 with SMTP id
 gm4-20020a056214268400b00690c6df5de9ls577093qvb.0.-pod-prod-08-us; Wed, 20
 Mar 2024 13:03:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUKmrAivt2Nt9XTab+JhtPyBZtIoKkouV5KAiCBvs+GR9kgH3SS52I00TSxPRcEwVwPw8j60utNmJIx4p8RizJ8UYVET9OumXsgQg==
X-Received: by 2002:a05:620a:211a:b0:789:e842:a04e with SMTP id l26-20020a05620a211a00b00789e842a04emr7292562qkl.39.1710964997900;
        Wed, 20 Mar 2024 13:03:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710964997; cv=none;
        d=google.com; s=arc-20160816;
        b=iyCgq1saGPmGRCD2wn7xZ8R/uPFAQwbrW4FgC1Zn4DCoNnPLfUEwtrhLTojGETh5kw
         NDoZ2fH0LyLYDTSSlINUTR9urqrSjPFW2G1e6ZrPoEHO5nKyC0R+RwsPAaRTU6o8UhwW
         xfS0RyA/1Bb5zTyH6jeBLucR5FIEOGr37aRLdEuFIOwra8oPI3a/uU5Mf+TWjnp9BEKf
         ljLn3rWxGNFNppmTlNwWcv8yC1PYhgHfqGnfrNwdwtpxdVtF49OK7CGixv/590vtBKF+
         D9Wyn4gWHTpiM9lXOhh3cxRgghebwRBWMAPs0akh9yBRc9FKpWPEESwHVlVVc08Gaa/1
         ea8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YkjIh7R8ArNWNqbrZmcumDc49q8HuLT8tVgxi9MGtH4=;
        fh=F4GTuKfycPlVnYbIQncHjWZEjuaXIECSy8VRtfINF3E=;
        b=g7frR75BChpjhQbt4x8ueO3cIJcDZzpOPll6A18qXVdVVnLvAvGpGZoCqMzv0j5Bjr
         iCzwK91jjAlWwBqqBa42kUaDUZuvdo9t6J0r7yG0EjXa6PAmEhhkBw8behiAXjzTmx4I
         r+QuM33KnH7+1BI03tNE901a7zb4hKO+1TsTJ3Z+tWpW878/VVQYfCl7PpMLpcWUfUTP
         C617x96kjKsV482BZOVajyOAOTS0Wrq6UNlNNBlC02dGoF4RVeO3G6t6nR+vkdmL1a7f
         fs0wbJbZbbetap8bQXURuSbKvHQkuRoBIygR/tQf7atu4pDL3Cq5ptrp/VEI7f/EVBAX
         mRQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m1meN6HV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id b8-20020a05620a118800b00789d9871717si1037722qkk.5.2024.03.20.13.03.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 13:03:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6962a97752eso2042356d6.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 13:03:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWjxqMSRdjVFzJpH7zy5wpH201hmRLIjhhzlDYMALTEREYYkcY/sO54SDV1ADBhygNIq1/aNdxe3RmgoR1tgvc633Rcf4ftt10tvQ==
X-Received: by 2002:ad4:444d:0:b0:68e:fb17:e14b with SMTP id
 l13-20020ad4444d000000b0068efb17e14bmr7409618qvt.1.1710964997369; Wed, 20 Mar
 2024 13:03:17 -0700 (PDT)
MIME-Version: 1.0
References: <20240320101851.2589698-1-glider@google.com> <CAHk-=whepBP2i6KrkSMdV98vs2PSpRcWS+zg0e8cNZKq0WUDnw@mail.gmail.com>
In-Reply-To: <CAHk-=whepBP2i6KrkSMdV98vs2PSpRcWS+zg0e8cNZKq0WUDnw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Mar 2024 21:02:35 +0100
Message-ID: <CAG_fn=WfZxp6Xm-8PN2nQfdeyRscLCvhp=0WU1dQC0Gvy2yMkA@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] mm: kmsan: implement kmsan_memmove()
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=m1meN6HV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
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

On Wed, Mar 20, 2024 at 5:05=E2=80=AFPM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Wed, 20 Mar 2024 at 03:18, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > Provide a hook that can be used by custom memcpy implementations to tel=
l
> > KMSAN that the metadata needs to be copied. Without that, false positiv=
e
> > reports are possible in the cases where KMSAN fails to intercept memory
> > initialization.
>
> Thanks, the series looks fine to me now with the updated 3/3.
>
> I assume it will go through Andrew's -mm tree?
>
>                Linus

Yes, I think this makes the most sense.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWfZxp6Xm-8PN2nQfdeyRscLCvhp%3D0WU1dQC0Gvy2yMkA%40mail.gm=
ail.com.
