Return-Path: <kasan-dev+bncBDW2JDUY5AORBGGN3CTQMGQESXRK7BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B44D791D66
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:48:58 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-34e1bf8c73dsf10273865ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:48:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853337; cv=pass;
        d=google.com; s=arc-20160816;
        b=bOVHZYCBXHomofa6LUT48HGeWkSCDQlaHF4+JZOIx4PL9Mze8DZVVukYtgQ3v61yt9
         mYOTbhL+6wQmbt6qM9lsTAkJbsyFpIP2Z7cK38CmCCSuo9EO1UD41PfNtAin+qkBiYOn
         APg9/dQlhfOYsjLNgM5tDK/eJV3pY99i1nJZGPTK9vMBw6IwmuxoMxNtBuj/yMDen2qu
         HbShdWaif0Y9vi0wQX+cnYpKtiZ2SjomC3Fz/KqpFqMKEB3j7loKSlRvAszSFa+68E6t
         tRfTluIu0Mz882rURBKdb6sQzi78o07DNpCSEVc1oPmhoIYvb3+So7vl+r6gLHQPztWM
         9tuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=iLzJSj+jcMwkYWjziu501DGOgWw3lpREs0UrNcj5fjg=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=VGBL1p9gCl4ksoxIo0ZLSC1NWR3y5URGKIg1JQU5nIwbceKhHxqu5Py+aVG41GUt8F
         7StEV5jz+6q3DmTgCGgKK+KRu1YTZXPBZwiaZxbeN5HUdsP5A/YK6DA/w/5xjTT0Pb66
         u8qZlQ2nHnHpo5IznPHZ/jONyNf1Lxu0n1hSKxq6tfW4VBSqoDSXfiTFNwE2Eeum11DJ
         QW2KoI1Nm6pGL1+xqUlmIT8cguzcPh/eICbXpF5bUDdzqK3kTqjbd9dgxeFDXoObtHiQ
         GhVrN2PAARezLRxHVdQlKjumLgyJSgXaktPTfXfhlbDKldniRk4iEsI3oWVgk9Sb0Ztr
         i4dQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=CMCZ0qg3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853337; x=1694458137; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iLzJSj+jcMwkYWjziu501DGOgWw3lpREs0UrNcj5fjg=;
        b=hIri6J+f9XkTgpkl8aZZy+NZG6E6R4RFnQu2ojo7AS5qoViH542f2LP/z2Jl768N0V
         O9Y1geqAxSg85VfwQ6GEZfHFAQPcirbAWitKB+sY2P1qHVW0TGqwmlavxcXLIKmMhc7n
         hnMuZN1I1G62x9gOmidbFovQfkLLrv2Ye2Pz9a0UVyKDT1ms9J3wEKL3bNWa+9kk5hdT
         9k9bhS15qwz5cwmeE6tesX5WcjPNGLjhiZ2UdGyF76B8vJ+CvS0gGfRE+OUbjbNy7DG5
         z8OdRhMPQXN33hUlLKTuwe2SLYWrfzgK8aG5A8lj/YsRse4jc0W6j8rKT+P1BHOVmASw
         W9YQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693853337; x=1694458137; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iLzJSj+jcMwkYWjziu501DGOgWw3lpREs0UrNcj5fjg=;
        b=Qg/No1ivUgMJfdGb3vPGtyoxqR0aG8AqtLhrQN6okwFS5CE0BCX9R4jAF4n0e40l7q
         89ltsP1O4ezXLUf3E7QTgFbQwu1QBsQmmjMw6UkNITSOb9xEiqR5ZqkyBAqsJWZ4epFp
         ytsxT20bCDcXxQL39NmgCXJMueg0Y9vrL0tkP6cybvGAZ0DvkhbaFFhH/VoHmh4oFOYq
         MefCe1JzglRWJsHfSYO/MdiTa7WBbjg7EuPXkcX+j6NyN1/wKJwFkrKRAceUzHbTAWtV
         Bj45KFkEautgjHXLxcMs3eTJUg7lmfx/PMlm5GAguqWYRqmzErbONp0bQvHy8ahHaGbX
         i1Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853337; x=1694458137;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iLzJSj+jcMwkYWjziu501DGOgWw3lpREs0UrNcj5fjg=;
        b=OLpy9GHz9C7d3jWASxPzxNQukYMXoVsE1+9yzOVfCAbGwa2D6UoohX0874kcv7Gos9
         pZwDuaRKOGa77o+sgoBUi9NHltE8s7uz/s08flTID+/9kusyOSYCiNg/q/yIrO+l5lwB
         0jKGNuLLrzDvSs1yKz+9wo1ej1gs1iG2G776Bywx7YsnEvK4Wit3Lo1hsZFrxsJUciNG
         ziiq6mfNkz1TgLlNAnM2wblOzB3wh+DQCw+2VF6pNRkm53MW+J9w+w9P4bsC2th+XRip
         PpbJOwJI7KsUxpySRounkU48OBM/vHdEZpk6kcYdRf7veDsw+OW6gZiUldLZy7//4Nx2
         7DsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx3p7rHcbXQ7e6HnVrekxtjq0tq3GgUFJJPXsdznkjAO1/lwTox
	phPjiHLLV+NAzUufCVgEgTc=
X-Google-Smtp-Source: AGHT+IHGVE+N7/e5H4/lpd0xMdmtCFwywPn6Q3UxSIZxgGSTDi7ly6tdd052arHDnL3nXOyLmFpRPg==
X-Received: by 2002:a92:cb0e:0:b0:34c:e6e6:80d5 with SMTP id s14-20020a92cb0e000000b0034ce6e680d5mr13741997ilo.26.1693853336951;
        Mon, 04 Sep 2023 11:48:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7610:0:b0:33c:3817:7a58 with SMTP id r16-20020a927610000000b0033c38177a58ls1800465ilc.0.-pod-prod-07-us;
 Mon, 04 Sep 2023 11:48:56 -0700 (PDT)
X-Received: by 2002:a05:6e02:1071:b0:349:8fb5:87c4 with SMTP id q17-20020a056e02107100b003498fb587c4mr10600947ilj.14.1693853336377;
        Mon, 04 Sep 2023 11:48:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853336; cv=none;
        d=google.com; s=arc-20160816;
        b=OVtuIehYTOp3CJVGgFDGiv7OJ7bipqX3jhtbvL0nVPUi5zBxseKDUHneg2mRUEUVgV
         kPtGl7cSpfq17GohxgHtovFHj8xejbOEhSfKC8qAuBrEYc2aCxZ8dMV+xCTB4semFpph
         J5+QCViGEgGC/4qpdevy5nlYJ2VQwlNBA6l4CNrVdRJNFKFaIgWYnmAb1gDugAcFj9d5
         lzKrIenIVWDpfCt/lYBWsPLuVWKxpw/WOAZ0OMIYbZ3wxIp0w0F0IMk63R1jwtrMv3hA
         1E+hA+kX7RcPqdxW0T57MsAlHVPcsFnmU/+mPcL14HjzCokXhLVdifxIxZeeg0x4txj6
         Zk7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kHkLed3ShSa5G4ls8XODIWF8XE/UOVeInJKV4+j5nGY=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=iSbyolYMs/XoCHlQLhoGe2L92O50zAQyVMrPRk3/+fVqwqaRLfUViatZt+8cWBU/CS
         L6BxDLI7ycZa8h4fUjEK4zj+qUxdj5cWfagHa8KY4DKhNqG7MQgDS2YMX6gFEnXueDwD
         UDVQdnsDxxdr8cT74O1rvfkHc8lq5rOG7IqCsg+HIOh0eHrFhrpEnMzQJfDryITGpytA
         LO/QwSIRASppm3Usa/0lYqI9uPOUCYkJ7KWHFk/vUart1gV/M6PLg1RZdFEtA2TyAP5R
         orMjqfhl/9zN7XBi/6f0pMfXcWRFtwigzr7sHd7DVK1Ua02KcBc+TeNSEAsY3iyBf+PW
         vgkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=CMCZ0qg3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id ay22-20020a056638411600b00430afd12ee6si1429940jab.2.2023.09.04.11.48.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:48:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-271c700efb2so785469a91.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:48:56 -0700 (PDT)
X-Received: by 2002:a17:90a:f00b:b0:26f:d6f4:9646 with SMTP id
 bt11-20020a17090af00b00b0026fd6f49646mr7159222pjb.40.1693853335614; Mon, 04
 Sep 2023 11:48:55 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <f7ab7ad4013669f25808bb0e39b3613b98189063.1693328501.git.andreyknvl@google.com>
 <ZO8OACjoGtRuy1Rm@elver.google.com>
In-Reply-To: <ZO8OACjoGtRuy1Rm@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 4 Sep 2023 20:48:44 +0200
Message-ID: <CA+fCnZcAuipLKDiNY6LJAs6ODaOG9i6goVLQSdbALrzUDsnv5w@mail.gmail.com>
Subject: Re: [PATCH 15/15] kasan: use stack_depot_evict for tag-based modes
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=CMCZ0qg3;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033
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

On Wed, Aug 30, 2023 at 11:38=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -96,7 +96,7 @@ static void save_stack_info(struct kmem_cache *cache,=
 void *object,
> >                       gfp_t gfp_flags, bool is_free)
> >  {
> >       unsigned long flags;
> > -     depot_stack_handle_t stack;
> > +     depot_stack_handle_t stack, old_stack;
> >       u64 pos;
> >       struct kasan_stack_ring_entry *entry;
> >       void *old_ptr;
> > @@ -120,6 +120,8 @@ static void save_stack_info(struct kmem_cache *cach=
e, void *object,
> >       if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
> >               goto next; /* Busy slot. */
> >
> > +     old_stack =3D READ_ONCE(entry->stack);
>
> Why READ_ONCE? Is it possible that there is a concurrent writer once the
> slot has been "locked" with STACK_RING_BUSY_PTR?
>
> If there is no concurrency, it would be clearer to leave it unmarked and
> add a comment to that effect. (I also think a comment would be good to
> say what the WRITE_ONCE below pair with, because at this point I've
> forgotten.)

Hm, I actually suspect we don't need these READ/WRITE_ONCE to entry
fields at all. This seems to be a leftover from the initial series
when I didn't yet have the rwlock. The rwlock prevents the entries
from being read (in kasan_complete_mode_report_info) while being
written and the try_cmpxchg prevents the same entry from being
rewritten (in the unlikely case of wrapping during writing).

Marco, do you think we can drop these READ/WRITE_ONCE?

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcAuipLKDiNY6LJAs6ODaOG9i6goVLQSdbALrzUDsnv5w%40mail.gmai=
l.com.
