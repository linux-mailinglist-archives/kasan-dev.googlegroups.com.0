Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB2FLWK2QMGQEJ4FF4IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 665FD9459B9
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 10:16:42 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-42803f47807sf2670405e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 01:16:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722586602; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZC6gQA/7LXLCIkAnguatpq5EXSfFZFR7ArWyynGvN+9aV7d5yE5wr6l+7+4OegHFru
         m0dwGGlvh3qOyFMuSKZs/QNrOff3qvzoNKW/j9XabOQhnx0IrA+SwHL/46B8NqTSCpub
         neJENLaVlPw/QRtmReh5bdfTzdlFRSvqNJ0r/kNk6F3Ts/cI28LsSHpGqqIhQ09xDenO
         IgS9zKuA8UOIEVdzJ2H5xdkVEMiyJKVrYx81glbx6F/x+v0v9XzEvdBljZwlpcFTLZEW
         U/AnuBToIOAJp0fh57ZAJe8TKrozVMOMBrU+v5MdRX40T8VDAuKOwi4ijvNQOMt30M3m
         nw+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eZ9zKVMAbbOSUvXKvot/YRWr0K869ACI6Mx9af+Dm4g=;
        fh=Dn5uM/PbT7OLzFwu9zYv8ofXn62hQffx+DyJhn7FLXo=;
        b=g6qkpmx1hmaCuDYdKawyN06nZCIxrIHvbD1BNP/rdVqLjmabHMfMqQ4GszhGEwoByB
         fx446POuhzs1seQ74VI+wF+ZH/SPXNjVniVee5zRQCeqIjPnonXkAX1gO8nytQpOvy/w
         cZX7qiovN9ZU1HGZllXIkiqNZN4eiOrVQxDtlRc3Tn26h7Mov+Tgab84FPHHdDg6EQcm
         PbiiK+rIRI3UIMKDUYVUvJCjM7syFMUoWBFC6/IFHlbKCLhdGF0gh/PZYJL8SM5UpDyv
         zRjhO7PIezEGhn98DW2dAL+KFVC1L+DBytmFvW0U/RF7FRVtv6wo8vz0Nx+IsDXi1UA2
         xfZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qr0XVcA+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722586602; x=1723191402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eZ9zKVMAbbOSUvXKvot/YRWr0K869ACI6Mx9af+Dm4g=;
        b=vNDMWm7SPNUUlOzOQyONO4qVEwDQr4zr5ScONEdJLak9TmBFgpOnD7bCauUVXEA5N9
         7Xn6SBvoo01p/snISQ1LvhxKe+n0vwj+pwCGkn0HyhIS2W0xxeniZv8vePactlMy/clx
         VVNG2a5lL0e1WcVaGTvD9syowbzHvkAz4r/TQBVhLrQb0rwbbiU2zQyaPMHU9J2fomSJ
         TEZov0Wa7TQfOnL5y+U1F2a4xbar2VjSFRdWmkCpk/338hKcZVhF6x5/jiF0krr8s5g7
         T1ZITtA1cAH88pN++PYuygZyv5g15XmDGJQrobol5otI5yAEUCo96LwGDnGc+QM/cBg5
         08CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722586602; x=1723191402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eZ9zKVMAbbOSUvXKvot/YRWr0K869ACI6Mx9af+Dm4g=;
        b=ApaV78eQtUZTGaAi4tK7s62y3voyRwljsO0tmFfPYT+7wMHFyWHcPMmvE+1X+R+p9m
         ityp2TecP0qPw5QusD2jLR47GItvjsEGqeZdn9Mrkr2gbEzHe9zUbUGF+/JwPJh6Lzxn
         yeLnFvttt2wTCAC2wB3gguuS0LnGgj3L+H6VVytmuna7+XmKrqinjqjLWdp+X5zKp6n8
         TuTpSfPJMABvpq44ODJ/YFhvuMAxXZxRBB2qcd8ANzBnYEs173rQtDgZDejYBBR/WdE7
         Q9NikJUgLl89GGBDJLbJi9Fhcg4ZXYZJe+Uzeq7obl7nCKG2CjBgmLigxFSd7gtxccPf
         mnrg==
X-Forwarded-Encrypted: i=2; AJvYcCX5r0ir+blX/rlrKIettkcxUkBPTx0icvamvTqC4lPo8qm4YQwL0HHxzO7XOauDAqntdjzs0euAtKUbI8sXmkdpEsPmvHzfkw==
X-Gm-Message-State: AOJu0YwoS3LJ91ecg6hnOMLsUUeguHIOTZqcUmjv8syJ4c0qE8kCDZ/S
	DksBPZDQ3VrPPtHg/MjUgXE+fd8DSFZr2Xg/eHXO/f/IQf9mcQgD
X-Google-Smtp-Source: AGHT+IFBLx00LbvOrFLGr8GvX/8oq/7LCqS088xYMqyQc335sMf3rEbDqCAbI/Dj+vAnboSUbOLJ2A==
X-Received: by 2002:a05:600c:1e1a:b0:424:898b:522b with SMTP id 5b1f17b1804b1-428ec103508mr99985e9.1.1722586601041;
        Fri, 02 Aug 2024 01:16:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1041:b0:35f:1b09:66d4 with SMTP id
 ffacd0b85a97d-36b31978220ls3652675f8f.0.-pod-prod-05-eu; Fri, 02 Aug 2024
 01:16:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVurelWoblSOhxlsDftzJMDAHCezfFqwOh3VukTb538aYgxIeiJSROPPmSOw5cmsd3NkpoP+hGOctWYnZV7SGOAjuU7qZSfPxzRhA==
X-Received: by 2002:adf:e389:0:b0:367:9d4e:8861 with SMTP id ffacd0b85a97d-36bbc1c7d09mr1868804f8f.57.1722586598991;
        Fri, 02 Aug 2024 01:16:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722586598; cv=none;
        d=google.com; s=arc-20160816;
        b=fdOI3XsHOMbyuwpK57YhwUOAMGWDgwfUOrPCFmCEho2WehMARtU6ilh8DzRVjF4cWN
         sRClVzg6f2EAseMwPQ5sQHz7Y3cWwojmA+WiHUWaqs/oWtDj2CKGgS0z6jFlIMqpcyBw
         wyE8x2Qf4ZFyHLL9UFPqyuP4ZZCEwBr9DQJXCBWBimSXR0JJBAery1BrPGJlXOdSQrs9
         W9gUp989FtJ6Zoe1WgTHO1RZkWu2Izyp5oqlgzaD3lE8L9cMv58cot1+EwKtzeGO/6mH
         62fOVjJV1n9ZwGBI6+OGwII+0zHGbN5TjD3EC/pciLTzouwB2KHc49pBJzlj5uPqZZeg
         3YMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dPqWS3uBC8uRjVmox5tLMIJZ6S7fBW9xV6DFvr9D4DE=;
        fh=t5/vktQGEfZ2e/myGjoX0gbMjGTwlOF9fCtMhHIiceI=;
        b=rejQt7x/tSXkU3HzRAI/qMOtvqhZLPv6JwOtNCEpy1A1IoiUycDU0btWzdXWggoKpW
         VndOXmQtE7UuFqqUTF75MqfLcBCaF13ri26bsROkDI9EkxGevGEQw0ExJlBXtHbch9Ej
         GA/gxwew3it7lErlO5P8La5gmXO2nfxEz9Shxb9Hqrrzyo3KsA2bMxuB+eZM7bNklIZd
         HWrw6ORPcMOk7BpftPGRYMAjnshLskcZToewvo902bP+82RivftjceQJnZWeT3WAYv5n
         Cf9yxYxxNBlV0iQk9nHOOxFOdaNRxvdTsszLaFi7ESGUbQa7Bp+3bTwEmyD7CiDtl1Pw
         d7DA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qr0XVcA+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-428240a989bsi4742325e9.0.2024.08.02.01.16.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 01:16:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso48502a12.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 01:16:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLdoRzaqB+w829GOQiQER/Pli+18pzrw08/vrSALs2CgGK1Zocj52SVz9tYpTQqtmBgi1WJKSvHrmxe3rrL9eddhuqxrptWp5svA==
X-Received: by 2002:a05:6402:5206:b0:58b:90c6:c59e with SMTP id
 4fb4d7f45d1cf-5b8713605e3mr87660a12.7.1722586597734; Fri, 02 Aug 2024
 01:16:37 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com> <ZqyThs-o85nqueaF@elver.google.com>
In-Reply-To: <ZqyThs-o85nqueaF@elver.google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Aug 2024 10:16:01 +0200
Message-ID: <CAG48ez0-DYzYP4pWgJF-bT4EbQcNmt08F-7zM+twa0bjjVRFLQ@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Qr0XVcA+;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as
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

On Fri, Aug 2, 2024 at 10:06=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> On Tue, Jul 30, 2024 at 01:06PM +0200, Jann Horn wrote:
> [...]
> > +#ifdef CONFIG_SLUB_RCU_DEBUG
> > +     if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
> > +             struct rcu_delayed_free *delayed_free;
> > +
> > +             delayed_free =3D kmalloc(sizeof(*delayed_free), GFP_NOWAI=
T);
>
> This may well be allocated by KFENCE.
>
> [...]
> > +#ifdef CONFIG_SLUB_RCU_DEBUG
> > +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> > +{
> > +     struct rcu_delayed_free *delayed_free =3D
> > +                     container_of(rcu_head, struct rcu_delayed_free, h=
ead);
> > +     void *object =3D delayed_free->object;
> > +     struct slab *slab =3D virt_to_slab(object);
> > +     struct kmem_cache *s;
> > +
> > +     if (WARN_ON(is_kfence_address(rcu_head)))
> > +             return;
>
> syzbot found this warning to trigger (because see above comment):
> https://lore.kernel.org/all/00000000000052aa15061eaeb1fd@google.com/
>
> Should this have been `is_kfence_address(object)`?

Whoops, indeed... thanks, will fix in v6.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0-DYzYP4pWgJF-bT4EbQcNmt08F-7zM%2Btwa0bjjVRFLQ%40mail.gmai=
l.com.
