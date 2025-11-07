Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7HJW7EAMGQEP5MVECI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BE77C40205
	for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 14:32:46 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-88233d526basf6122326d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 05:32:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762522365; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nvaw32Ryaun72JPPLzaVjNkqK2KEVzVP849DwF09EXmDhAij56b295KVM/UZVLgywk
         rSz1xXyHhFu5zZCHDUD/mp6E7qrk/9OyGOML2xOIq4saYSbNC80gpjm0BKw+BSlYPDfY
         V5f5jeO7HQiNR3Vxj9xAO7tVE1X0yVjpbEXZTmJ20i5lSWrhseq3aTVjJz6BEuWbaYiw
         YTAe2mbZNQmZrPNIRcVjJyL+TgYIflSjoDs0aZe5bcPHPlgpAaPVXbIAE70k35qVEBcs
         6ahZjQACObd+6inHG3nHzz6AQ30TMwzUDqQnT0zlIUcOXlzl3ncJ8h3fyKUx5tAurKGM
         TZGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lWawbqkQ3hEW6+bO5EhiT6EmnDQxguP2GIYOo9bn3F8=;
        fh=z1tBUJt/e5CVs0S/DlCf5WMsOiX9ClSaMR394qFSIPc=;
        b=HNRm4CDf46G8QmCwihk2WSQuYUUCfbKl0UR+Y7dluoKdaG34nb80g7ZSRT1Q4EueBs
         OVhFfx8Sj6x22TP5xubinq7kc6ndMTKkO4klx4EB+aNOtCx25c8FCFYlBdHW2O3XPWQ3
         6v59pCTxEnJTYt8AMbUvF8ADP33EFcl6ndlB9UY+9excQpyiTZ2wcKED+m1VhTFoGuyK
         NoqjMqltweNu+J2gUkFJ8DzlDBtAFGl9iY0U1gqnpVHm6CVTLS6PGNZc2CdUkf5Ncuhn
         NMc6ajCvUbwawrNnwRHTEAigkAoOD90mukL3j+RgSnrBKUcoKil2ZpzIUPgsE2ExkY3P
         4Odg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tHl3OML8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762522365; x=1763127165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lWawbqkQ3hEW6+bO5EhiT6EmnDQxguP2GIYOo9bn3F8=;
        b=Dcvj7YqSS5FneyFHzdX3OS5voeLCJq/Ip9JxUW7GxEW0W29BOUe7EAC8CN8U2MODTu
         arhb5CuRpLilStFvWILgEZPHcjDbLno8tYkXIc7s2NzAS4SrfMitXBpFjTtDoQ6IYBNM
         ffngkmAMUckZTvfBCnFXIlNNLxke8YXAM9xCjwQEZ5Vn8GUt/vbIh3hcrLAAveebKOEn
         OK6pBcKJq0OMjVjQI56EIFGjvwb6L6gjro/RGnI0TK6JVeDpvnAW1YMakHfZxizt/JCt
         LrXBTYVjjd/8+OA/X4/O+HcAhZks0mozHCJ+PXgvD6+AOgR4YDhkUepZkav1XS2cSBfo
         vGWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762522365; x=1763127165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lWawbqkQ3hEW6+bO5EhiT6EmnDQxguP2GIYOo9bn3F8=;
        b=Vc3h5MyWtucoZP4UUqiA6xTFgH2+YXdKwKaKeVezBXWP+MepTgTDRFizTseS3E5yqo
         6qIY3SIAYfvbp8RMs5VSEE0XB0VOuTBvOMf8LeYL7c5kRf3jCAJsjN49RiUFwH9HniGJ
         CJuHkm6wh3596prXXzvuWoWJ8ddrSq5NsgkFNKPDIPCVjHOhWCU/5cGdw6h2zYc7tbj5
         nfeEJanp/GPMY+JXGSvGlQq1jVYNg3v9VPhRJu5vhhCKXVGBfjHW9+X9tQEfzUITpXxq
         GRaAA8S13MzDdhF+PIa6CdDu+4fKYPuYrlZg6yA6jod80m0uGdqU6SdXj+YvUmWkSYfc
         forg==
X-Forwarded-Encrypted: i=2; AJvYcCUKv1K+LFB5LyjBCjhtbR8b4U/cq428UlGPkKPl9mzs3XhqyKiI6DcLIwsKKx4bBv9/JFxSWw==@lfdr.de
X-Gm-Message-State: AOJu0YxX/KMQLlB7s+eVpEwHI1/h7sUXbduF/ssXOICCfCf/wVN+1iSY
	Ebo+oOh33FVUUdOSKfVjffd7vyw8zWvgx4ZOpIe68YL4DiJpJGr7k327
X-Google-Smtp-Source: AGHT+IFhW/QBhOViPJkN9GnAJPhgDJYXqNjPLekUj4GVOTfs+wG6gQPWzyHaNH2CJfjE06+xpPDUDQ==
X-Received: by 2002:a05:6214:1cc7:b0:880:298b:3a6d with SMTP id 6a1803df08f44-8817673fbddmr39488156d6.35.1762522364500;
        Fri, 07 Nov 2025 05:32:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z9CGei0m+7JFPnxhwAmRuRb8Z0Zn/NuFcQCfby5o/t1A=="
Received: by 2002:a05:6214:301e:b0:87c:1e10:ae60 with SMTP id
 6a1803df08f44-88082dee744ls25000256d6.0.-pod-prod-06-us; Fri, 07 Nov 2025
 05:32:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXAzpAlkuhqsjDyU06LTHu9udiE+oNGj/RoamwiSA4FKhq+63XOTDNU5EPvZl4oOBnyuUryCpOO/nY=@googlegroups.com
X-Received: by 2002:a05:6214:20a8:b0:87c:1f80:7609 with SMTP id 6a1803df08f44-881767400famr38574816d6.34.1762522363739;
        Fri, 07 Nov 2025 05:32:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762522363; cv=none;
        d=google.com; s=arc-20240605;
        b=BRnr84B9tUxQdY76PLG0eFUetx332h8eSWCpLErbOg8no/8VdJH9XH8FSrEOR+szUY
         YvVV9uVgmWKNsTzDwH27zdMBI5ZqpTxWUKPZR48eA0rDoPY6+n9c2y6dJc+/ypDVpKL1
         UbO7cBHDFqnJIAgXNa+D+ecHIzz82qkkHg9Hw1183IlNUaXg+2hpEa+7ckIkGFqKwuH2
         HLLdyEW9e4PSgI+HymjkaoY6/1beCEC2H8MA2J9JHecz+amslH3CDCwKVvhQFVvCyGQY
         cD3ITgeECzlSUQRhxYauCEyP+btO3DhhVZnsZNd5DfZKuBuRZ07xFtU2pyJFK7HxYBFD
         dYlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DYGsUdW8QJxBbEDi2Itt5Jzut6orTX2cfcUNRJS1Mww=;
        fh=fbcmzMZqvuAvrsQg0DQlHpOOCvribQ5dt5At+SsjoAM=;
        b=iebEw0EDTdf/ieIzovZ+6rLAbUGIc8OXjyUpGFDYd1UykEz3okn+QrWAl5o6Qp58Pi
         BAaInXNgib8UghtPn0TaGMNWkPuRFpIHZAwaWyVqFh+5D6e8tG9PpViIGZ+zC/NkT55I
         DTMd1lhhRa4+MLFTWiiIF5koWe2A6wHyl/ROwMJgs+NOSb2JyMiF00tmIPSqvvoyEMam
         SZzM3/11eaeH69SL8PJ5BcEJEQ79VRrqONbn71iPJetTIbmeb0lzCw4EE/n+7TgTrtqe
         wLMlYV6Q2nWvsOee23xCgcXQRXE5w7EZT/AdQxYwPe2xaJvE5GkVRswWyNUgfKBcQhX8
         eFPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tHl3OML8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88082a110a0si3772226d6.4.2025.11.07.05.32.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Nov 2025 05:32:43 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-87c13813464so9372676d6.1
        for <kasan-dev@googlegroups.com>; Fri, 07 Nov 2025 05:32:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUx9U15XfEpz7NMTAKewew9BFj5gxPVR93SEAraqu8bykck2wlNjtsFkw1XMrzghz/wFlOusSWc0IE=@googlegroups.com
X-Gm-Gg: ASbGncvXqqYIgBiwA79dZBwC1KjnqJ2JNchEbUIZ1j36OgIOXRx93WMkkBPafPdsQvu
	0r7otAqo4QDcFqMGcEGSj+u6G6iQZeCOlch0U7cxu8KGTqm9bhsy7M9bqBlIjYE4HyoyKorUVq5
	TA/lOkS3/Pej1+gdgrZTUij1mI/vqyxK5+/+XyLjXYpihpsfCqoWXWHkQjQ7/ZxGzzZwAeJysYy
	M8uCoHMnt0rGJkj3P7Cl8gi342eEkGwWqYYbRrUJOl7MLzTQlUniuoY4oChhjFJDDBxNAjSjcWJ
	+bP8ODTrFuBEsgc=
X-Received: by 2002:a05:6214:dc1:b0:87f:fecf:17b2 with SMTP id
 6a1803df08f44-8817678f534mr37024656d6.64.1762522362918; Fri, 07 Nov 2025
 05:32:42 -0800 (PST)
MIME-Version: 1.0
References: <20251106160845.1334274-2-aleksei.nikiforov@linux.ibm.com>
 <20251106160845.1334274-6-aleksei.nikiforov@linux.ibm.com>
 <CAG_fn=WufanV2DAVusDvGviWqc6woNja-H6WAL5LNgAzeo_uKg@mail.gmail.com> <20251107104926.17578C07-hca@linux.ibm.com>
In-Reply-To: <20251107104926.17578C07-hca@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Nov 2025 14:32:06 +0100
X-Gm-Features: AWmQ_blqrF6qkYIlKEriMvS8QB3DM2vAveh3NdlyDLE92dPFiq1osVICbBllaDE
Message-ID: <CAG_fn=W5TxaPswQzRYO=bJzv6oGNt=_9WVf2nSstsPGd5a5mNw@mail.gmail.com>
Subject: Re: [PATCH 2/2] s390/fpu: Fix kmsan in fpu_vstl function
To: Heiko Carstens <hca@linux.ibm.com>
Cc: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-s390@vger.kernel.org, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>, 
	Juergen Christ <jchrist@linux.ibm.com>, Ilya Leoshkevich <iii@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tHl3OML8;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Nov 7, 2025 at 11:49=E2=80=AFAM Heiko Carstens <hca@linux.ibm.com> =
wrote:
>
> On Fri, Nov 07, 2025 at 11:26:50AM +0100, Alexander Potapenko wrote:
> > On Thu, Nov 6, 2025 at 5:09=E2=80=AFPM Aleksei Nikiforov
> > <aleksei.nikiforov@linux.ibm.com> wrote:
> > > @@ -409,6 +410,7 @@ static __always_inline void fpu_vstl(u8 v1, u32 i=
ndex, const void *vxr)
> > >                 : [vxr] "=3DR" (*(u8 *)vxr)
> > >                 : [index] "d" (index), [v1] "I" (v1)
> > >                 : "memory", "1");
> > > +       instrument_write_after(vxr, size);
> > >  }
> >
> > Wouldn't it be easier to just call kmsan_unpoison_memory() here directl=
y?
>
> I guess that's your call. Looks like we have already a couple of
> kmsan_unpoison_memory() behind inline assemblies.
>
> So I guess we should either continue using kmsan_unpoison_memory()
> directly, or convert all of them to such a new helper. Both works of
> course. What do you prefer?

Upon reflection, I think adding instrument_write_after() is not the best id=
ea.
For tools like KASAN and KCSAN, every write has the same semantics,
and the instrumentation just notifies the tool that the write
occurred.
For KMSAN, however, writes may affect metadata differently, requiring
us to either poison or unpoison the destination.
In certain special cases, like instrument_get_user() or
instrument_copy_from_user() the semantics are always fixed, but this
is not true for arbitrary writes.

We could make the new annotation's name more verbose, but it will just
become a synonym of kmsan_unpoison_memory().
So I suggest sticking with kmsan_unpoison_memory() for now.


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DW5TxaPswQzRYO%3DbJzv6oGNt%3D_9WVf2nSstsPGd5a5mNw%40mail.gmail.com.
