Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF5DR6UQMGQEMFN2UNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id B46807BD82E
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 12:10:32 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1e59fe8319bsf3863409fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 03:10:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696846231; cv=pass;
        d=google.com; s=arc-20160816;
        b=eGWY6N6rmtTbK1eUKvLTI262/+HMFsA7Gd5W8nO2tkQN+QwWKFZ9nKzrGMnJIvfbmm
         ZehQ5R0UFcustlhmygbtG7puSo8hs0NWmx9N4jo+rhlmOVNSl/CCeP2qhg6koaoCz8jS
         WKPFKi3Pbhc7p9FR/fadkc5v9Q9fsbHmYLOW5GZdAIpHXmgmplbFozupNWiWlBfAllm3
         +XgmNHKpqh7ZlGcL5PYleIXOZPJZ+QPw6CFh1uwjHPBiOhnO4plqNgQF6aSZml8BVdMe
         N5GfMJFlHJ7ALrAOcgDL5UyHJ8ekKDEPFpoh6DTW29yXFeuWNTIo6VVHfvPEwfcDbrzw
         CsOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nzJcC9cqS42jEGajbj2vkpiZUWco3KEPWk7GkVUICdc=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=CPsNgy/FLRmsaAutjnfimsqWYmZX09k1E/pEZHMm0SjgJvNE/2SIaQI9oodfmUIagV
         g/1A5dBCCdMG7MoT8InYuppTuZyJWv2pZgYcNUiV7vrwel4xoSF80F1k65aFkgz4Ub3e
         eKNxVd4Pq7N3kLGc4MidK23ZEL2IEoSzlm5iTb2rG2+TeaHzKQJqyyaR6FsBwgz75vPP
         wenmM10xg0HaO0XDskgd0joGQVsMjA2zUOnWg1jWmferHYFnfbolTQGUgEh9K8wRzKe4
         crCSnk984N/bmnvxatu96eI9freNYJRY6i2BMYC9dYcLyekXKYu1GhkJKIBcbLrEKXUr
         z06A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VYsddNPX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696846231; x=1697451031; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nzJcC9cqS42jEGajbj2vkpiZUWco3KEPWk7GkVUICdc=;
        b=E58imGl20FmbtrVDAjXDXIlfWxovD0xFMyPbqPG/a/cS/ga6cyGUYmLtYs4Fml7fJt
         2p6DsiqC2N4cT75ycbgSO6k5w7BedEiRBquEyCVuCUkbEQLmehmO4pAQYhizDnbM4zUw
         MNZXfOLnCly/M6n9OxImZMT9gPUxrPP64+XbI85rstxYf3uB9CZvkjBv9D2NrNlJWfSk
         6XU9QF9T3y0qHwXtReYn+UD+0Cfv0ABq9aUiDD28eCUyApR3JqB2ad7ULi2B9p/ldMie
         tdn5vyeio6XRkat0H246YvjVDtQJhZry3JozPsYpI5gcsyKlwTvAju90d2FyXcZjGBSr
         vE2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696846231; x=1697451031;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nzJcC9cqS42jEGajbj2vkpiZUWco3KEPWk7GkVUICdc=;
        b=X30HkThboG5+6yCooF39bjENn+72bConrtP7prCIgjqZGre1R1Pd1ZhLJBTmv9oGWF
         UcfnD8GYsTWxW0xuuFBRtltzyFkDJdBWcVbX9T4T3EMwqOL9YshEx5Zf98wg/lhdDK8D
         /Ko7/tNv2Hs2CwUmhiVIDbyZXAj9pXwJ07n/Vcg3LFu01j74aFhX9xzk6HwFk0XJpUZ/
         SiPgYoAwa/PbxomxiF2/T1vO4Tjh8dVp1qj0ZXqOxKBaJjYs9mLlspHaBOJi9FvbmXJa
         W8GYHNVpqRp0UZqCNB9rGXCSijFXGkcyuWTD2TNm3mEiC3GG28K512MPN3sYcCJ6npS2
         YfrQ==
X-Gm-Message-State: AOJu0Yy7kL+xaUC8O26IR7tTshUdWnok8IPFZ62EVBhTtgBkbJ6yy9fQ
	Ey1fWYGEeAjsYbAA7KurWA0=
X-Google-Smtp-Source: AGHT+IHOkbSEFtuSJ/Ul7eZVtMIiElPpJhAhOwFneh1IRaJpfg/e/YkTWcxvQWn8jXcPZXs899pm+w==
X-Received: by 2002:a05:6870:1683:b0:1d5:b2ba:bc90 with SMTP id j3-20020a056870168300b001d5b2babc90mr15834216oae.59.1696846231275;
        Mon, 09 Oct 2023 03:10:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8e85:0:b0:63f:c010:6927 with SMTP id x5-20020a0c8e85000000b0063fc0106927ls2930193qvb.1.-pod-prod-03-us;
 Mon, 09 Oct 2023 03:10:30 -0700 (PDT)
X-Received: by 2002:a05:6102:a2d:b0:452:8574:4545 with SMTP id 13-20020a0561020a2d00b0045285744545mr9699869vsb.5.1696846230588;
        Mon, 09 Oct 2023 03:10:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696846230; cv=none;
        d=google.com; s=arc-20160816;
        b=HEp368TCPtHYalF7mdWIg42HbB+0GgZo5e6cGwaS7p5ZniJfiTMR0YCoszPUCasBw4
         63pNiCNPSLkydi9MXiyuAniBBcvt0J8aV7xKxeN/9AWAPwU6sJ8dVPuWfKxcVk5KYGF5
         hbUnmlr3vng7sMWYW2+wSIJ2k3l5o48nTAZPuIjFtgS7aTnoP0H9lc8OZa7xwGVfMpks
         WrFFPCtbQwN/YfNZYhSJd/UJArnBHWBPPn8UweoY149xi+XgQvGWD/z3sznpxRjPH7aL
         kEqw0uWOo4zzzGLmnCiZIAN0ajdiQk+t5hS5BikQ2a/eyG6Z8RQMYtzavZ66W4d28UQ1
         JeBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pKAlUAosFjrafJFjKgxhfBSe7ZC79o6SyWOfRs4IFUY=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=T3SC42NfjlfmetLWMRChnXPzMDfw75jxBnk2WU4Y6tjb2S91BDKB8qWBwN+zqdkbq1
         pSD0ErOf28siiMd2jgb7gfj1V6oK01FLtDRWCJODIqkBTbPp3MT9qPmB/fxMw/g9ok0o
         7B4lBw2VUAQwXsfsfSBxqhCXgfKiTIzGomoWB9IFXg8R8rfZkccgZ61RYVbtOxL0ki6Q
         Q6GgjB98cyTaAyoJHzefvflQF2PcVU/k5D3GoFSdfyJ9544d4JSYVluELMnXU0iBFJL0
         GzN8k1xi6s3gRkPtgf+OlleXaqmkkqRzn2cNXFNEICOvFGgl2jriDqbj5TWCYql2En9w
         gMJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VYsddNPX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id d17-20020a056102149100b0045258d13d6esi1660643vsv.2.2023.10.09.03.10.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 03:10:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-65b0c9fb673so22956796d6.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 03:10:30 -0700 (PDT)
X-Received: by 2002:a05:6214:301b:b0:65b:1594:264e with SMTP id
 ke27-20020a056214301b00b0065b1594264emr15604865qvb.51.1696846230114; Mon, 09
 Oct 2023 03:10:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl@google.com>
In-Reply-To: <2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 12:09:54 +0200
Message-ID: <CAG_fn=XnH_z70wPtX=jRtKsb+Kxu5hosnZbnNC=mw6juSm7idA@mail.gmail.com>
Subject: Re: [PATCH v2 14/19] lib/stackdepot, kasan: add flags to
 __stack_depot_save and rename
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VYsddNPX;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
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

On Wed, Sep 13, 2023 at 7:17=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Change the bool can_alloc argument of __stack_depot_save to a
> u32 argument that accepts a set of flags.
>
> The following patch will add another flag to stack_depot_save_flags
> besides the existing STACK_DEPOT_FLAG_CAN_ALLOC.
>
> Also rename the function to stack_depot_save_flags, as __stack_depot_save
> is a cryptic name,
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
(assuming you'll address Marco's comment)

...

>  void kasan_record_aux_stack_noalloc(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr, false);
> +       return __kasan_record_aux_stack(addr, 0);

Maybe make the intent to not allocate more explicit by declaring some
STACK_DEPOT_FLAG_CAN_NOT_ALLOC =3D 0?
(Leaving this up to you)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXnH_z70wPtX%3DjRtKsb%2BKxu5hosnZbnNC%3Dmw6juSm7idA%40mai=
l.gmail.com.
