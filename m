Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI7IXOTQMGQEV6XZ3DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E72A78D3B7
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 09:47:49 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-64a0166deb5sf65625476d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 00:47:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693381668; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYl9adVU5R8jbq0QggC2upvIc0QutEG1pGmSWJ9ScsoEAcmLVHqYw8SA9AqFCiw7FC
         zMs89Av/aqwI/DwXzt9Z1lMZt5t8d/7IdubAW0tKLamgDd8LE/ALqxClt02mZm4mKxRJ
         dzJQY5lS4vsY/MaZa8WYM7mO4wepkOZ1tVsoEG18pYMqTfFy/MS8ZhPIlvzoPjM1tJor
         yGMffxjDgitMGW5i/HxtZF63RDC6O/DLEtC5YB9/RnoLkEp9ohephdhE9JEYR0E640WQ
         nHOSl/CstzAqAlMeMcBW7IxCLp5hDNdVgEuHr7FQmj5OFMwD66oP9xHf9e5i/FVCkF4x
         +s6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bWmKAaI07b4tI0ni0+fv5B7EKx9cBzoDXIA5lK0eDkE=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=u/wl4V66+/aVB+x6YNjGPeCv4btWovnIVTJ2fMUhKrYEdHuw40kZJVVcwrheOnIM9Z
         ACCDVaUVWdpr1AMwEIzXloFm3yaxJbkKGlhVzUPLqCaoi3Nqmjs6YQ0b6aUihPgJvYvi
         SuBK8igkIJLSk5qKb5Tg4o/0/xJYJk4hp6ZYhWoVFoyJg+DWct+HYJZoRLZQLfNVEIDI
         zKjB2yA7yAqjlx504BxVLJQaAZA+FcNXI0TUAIA0VBNQ5p/8jZhiljiUF9KLTj5EMqSs
         OleCXFKygzHZTrhf1g66EV15w7xXhA8X/yBxAtlKjGSJeVY68jqbdbmPFAJIgs0guO4s
         RI3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QJG3TZ8u;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693381668; x=1693986468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bWmKAaI07b4tI0ni0+fv5B7EKx9cBzoDXIA5lK0eDkE=;
        b=Sn/M7cJNO+vnRHKZhyFE8Cp79DPVH6PZUbhfh/ZP4TEByo0HAgOBsETLnLUPmpR3ul
         x32kQaewIejpiwes8b2qFgHn2QXBJJTHtK+yfuHMK0CLvRNRCNkDzwMjPonOx0X9bfbh
         dt7WezGMkdw1oaaPgpAtA3GcBB4gNHsoHET0M71h9TSVlDVHnXn+Mol7sLcoCRuvuyG5
         IAwq6Z7eh8jITfwEac0fKjYCa3exdDLrvRyHFbvojv5AfLkicY6fjYJK1S+qa/wRlrhp
         2aNU4zh3HJ1KudM5LarSFjRdwG61qmD6/hph9+8NrzcWo2i7DTECSF4Y9pHGZG0Oa5OP
         fTtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693381668; x=1693986468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bWmKAaI07b4tI0ni0+fv5B7EKx9cBzoDXIA5lK0eDkE=;
        b=DYIB1RzhlPs0Wj7XkD6xtfIHYHCz1AYqJWglNJylPS/oAk31XzWVVkEJwphd/IL3Dd
         Yq6E47Hm4RmkEHO7r1kisvZMmU0ZqAlW6MM6JE+tQVsr0+wEHa2z02YTOVNbIDUO9fCc
         zUCUwNAy5+TrGfgKePsWWYM71LeDU4PtTeQiTn4xdcToZXUErP5+SszIAp4DjbWq5rey
         /E5OmkSCTjYiTU3AUF088HngCOC9cZB5fMrRjUloNGbyxywteeeHMD3KTK540ct3bVtc
         nvMSiDxf5Pgk06ijD7wcgJAtlvXOQng4ou57BEt+9y3bAtveuGid6iZVq+vtKNmOlr0R
         omtQ==
X-Gm-Message-State: AOJu0Yze4elCZXCqAazVCWqOkSSrQsnQk5NnnYOc1v5P5b2o/UjPMAG6
	GhkYC9UBciIcSOwDmkiC5sU=
X-Google-Smtp-Source: AGHT+IHdxQvmGS/OYCO1plBDtVXd1rqBB6AlZQmdXONtf8Ek7HB0aKr7+VSGIgtLUUbPjqLsK66zFA==
X-Received: by 2002:a05:6214:4a83:b0:64f:7a11:b06c with SMTP id pi3-20020a0562144a8300b0064f7a11b06cmr1598392qvb.43.1693381668086;
        Wed, 30 Aug 2023 00:47:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f1d1:0:b0:646:e041:1e83 with SMTP id u17-20020a0cf1d1000000b00646e0411e83ls2205046qvl.1.-pod-prod-02-us;
 Wed, 30 Aug 2023 00:47:47 -0700 (PDT)
X-Received: by 2002:a67:fd72:0:b0:44e:bc13:b761 with SMTP id h18-20020a67fd72000000b0044ebc13b761mr1508043vsa.14.1693381667381;
        Wed, 30 Aug 2023 00:47:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693381667; cv=none;
        d=google.com; s=arc-20160816;
        b=uAaYOFABK7d5nlVZPIFI1DlAM/qwKZXDwM7f/42wIdHpc6A0YzmANiherDRhdjMtlh
         UQPb1s/x7SeNtz8/8Bk91iP6VY0/wSIh88ISlNFLHBDRuHhw2mRdGp/0pwr39y3m6E4I
         MCDtdIS9wk9vRqW7vBg5dBTJAyWmbN+e7/Z3b/kiRBM+U8vXcf+Ay/Nv/dhcV+lKg1fs
         NFCBM9b1w0uawEcHWZMW1BmtiIP5xsvz1FPuf1jnyzD8qj+aJq8oR0a9kfudEzgwhp8p
         5Oo5htHETxDtWr9d/zbPKnhyATKCHXd/olZAbQcJJxx/6BmN4bE4zDH+01Yt1reT5e8e
         Vuow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HTiXECgoGfzw84lh/WoSfah+6f5iJwFeqm4gOKFlKhM=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=dVcl2d/u0gO/GXbnwcfJEk8oyOzQQsi2KYvcdGkQtv971mHp40G+MphH9o8vv8RMec
         yiyOoR3i64/o+u07Hb8b+rLQNBxZKb9w4yOBPMvgDQmahmLo236gC3iko+wcVwRVLeEb
         dKrNM4IZ9Qfi4Rb5z8r/gRuATedi1kzttFP8Cbf+TdeCm1tOSPLBmPkBS/tzbSE7V4sM
         nsMRgX1/TJlwuDQJm+jcr3n9/0mCQ3e2GqCDHeVdA9UR/gheyRNX0AyfkEUPIXzfp/8E
         1NQSpunWSBDc3eEk+G0G6KQUnhSngbRqlujQm+VQnwVU6bPGxTWqogEs95jN7K+8p3kP
         AnDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QJG3TZ8u;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id t5-20020ab06885000000b007a5003d1b38si529926uar.1.2023.08.30.00.47.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 00:47:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id ca18e2360f4ac-7927f24140eso172793439f.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 00:47:47 -0700 (PDT)
X-Received: by 2002:a05:6602:214f:b0:787:4f3c:730d with SMTP id
 y15-20020a056602214f00b007874f3c730dmr1662268ioy.18.1693381666723; Wed, 30
 Aug 2023 00:47:46 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <757ff72866010146fafda3049cb3749611cd7dd3.1693328501.git.andreyknvl@google.com>
In-Reply-To: <757ff72866010146fafda3049cb3749611cd7dd3.1693328501.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Aug 2023 09:47:10 +0200
Message-ID: <CAG_fn=XJ-fZTJPqrjcu2PVNzBvg8309M+jT4h_iGraYNN4APmA@mail.gmail.com>
Subject: Re: [PATCH 04/15] stackdepot: add depot_fetch_stack helper
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=QJG3TZ8u;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as
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

On Tue, Aug 29, 2023 at 7:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add a helper depot_fetch_stack function that fetches the pointer to
> a stack record.
>
> With this change, all static depot_* functions now operate on stack pools
> and the exported stack_depot_* functions operate on the hash table.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

(one nit below)


> +static struct stack_record *depot_fetch_stack(depot_stack_handle_t handl=
e)
> +{
> +       union handle_parts parts =3D { .handle =3D handle };
> +       /*
> +        * READ_ONCE pairs with potential concurrent write in
> +        * depot_alloc_stack.
Nit: please change to "depot_alloc_stack()" for consistency with the
rest of the comments.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXJ-fZTJPqrjcu2PVNzBvg8309M%2BjT4h_iGraYNN4APmA%40mail.gm=
ail.com.
