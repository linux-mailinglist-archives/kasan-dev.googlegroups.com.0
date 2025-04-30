Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDMIY7AAMGQEUMCQ55A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id DF490AA4321
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 08:32:46 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-476623ba226sf122566941cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 23:32:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745994766; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hu7S5rqUL5RPK47JIY5g5hIN2NxkTFdAzwzJyRP1h9JF6pu6hHh1D2Yh7HFvIIC2Hv
         GhD/nGdCJAVcxlUPdiWbSVrCixcO84ONISFr4M6LeOOJ8I8sx2E68z4Ns15b1bCfhgIi
         Ny1cV58XqZqAPqV5Xu5j2R0gxRi1cbyQdpiCL6Tj/NsEj0XWuvUX2uL88ExoK/e82gXh
         3FIGglVntltNtM36SjPPYxaTZ6dedsFDBMNOnC4RHhNOFs0cTBYXt7nmRoT4Y2rJYDXy
         nNJ+6Q99rIi1semnbWmA75ZKx9oxxC8VQkys+/p1gpFkg+n18Uv2T7uigPLIVOcvbcVr
         b22Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tv/b8Vh6CBTUbHsDDkhEJn607xaDcdocXCzHQ6fmMXk=;
        fh=J/ojcG7DBYtYAxY1el6+uKYsT6GogIOw+n2zDTNsMik=;
        b=DH1bhhxLk0MNDjEeO/NbP5OPZKeYf3fMiQq1XG6ZOITQy1WjQJ2TauijkQaSs/YD7f
         6x3XnJtKmAzvfR5zZ+GM7VtXNr7uzAS77gbNBr1oPlRBxK23AjcwxmJD/AjG8rTPGCvM
         9UdvBPQYJB82F9Rw5IN7R85dZ9h0m9ibu+IWZ2Wb4hv1LAYKd/1iM810N2BewVgBrFaP
         8J6ybzljxsPZjDxSGnnlps9csKgmFmtkkzh0affKIxNPZMOIrATa6kBEyMSfCCwcOZ8q
         w9rE22cU9aMvGw9gthTYLfuf3RT6LytJnOPaZ1ztTE1TeXnEpz2o1Ejm+rD6KFmOQg5D
         Gunw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XrsnE5GV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745994766; x=1746599566; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tv/b8Vh6CBTUbHsDDkhEJn607xaDcdocXCzHQ6fmMXk=;
        b=hnjUvM9ahQo+E11kAqcSo+1NtUfsRC9L9fmY2Cf0Ztd6LdYd6W8DXst4VPLwKVUO8a
         Ffq1vUUHojAM9i9Z87hXUmb1mg7z/lDyMYldGmqmOYGVPjGISNHBF54hd/Cc4bAB8c9O
         mE7NyAOQi2gzvryewrYwJmAO42u8pMnN2U3l9YDZiaNrtLlZiQ3GiqOflbsSmOOe8bls
         4wMjgC8RydPTK2W932WCt8Ma4PfWw1BjqgbRkc3BKveefFwa7/70LIq7vIs+JrzOvVNo
         baYA1SZ0jJ5LyaMZgg/ArP87Lfm/tN/PS+CYrAj0vecpbLsFmQm9hDQ5rhazoq93h/p7
         /7hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745994766; x=1746599566;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tv/b8Vh6CBTUbHsDDkhEJn607xaDcdocXCzHQ6fmMXk=;
        b=OqPtqHcZLSr/Cx8ilgbPTOA4BC0ZpCjKiQD5UMEbMXebtx61hfny6KaI0bsoDjXcP1
         l1jAOUXbjdb7JERFqHvSw0vzJdwG10UipSd/YRDnUwm3L30sgmH6gAwFIMRsGFdjS4HO
         BRJmRDBqOi28AJ9GKx43hqPWOeR2yBqljkS4zJww8o7YiA2cIvixh/u0nKkWNc6zm6k9
         IwTIU/nGcoQiRMKou5Kjqr2yjxb75IzWFj0mw0mb050lejmTnV7SB+2vxhdIEOQt2wkp
         m7JZXNkc4RbmNyqc5jdhcl/sKf+qTMzrpgHvqeRFlliHUa/fJZdy4lyDG5YMDjcwN/KI
         HWfQ==
X-Forwarded-Encrypted: i=2; AJvYcCWnP5mTeeU7cQ+I+lbZQJYOMw1hNYuCx5p4TlPbw4h2l3iAXlMSqB6WlkcBEC3oZ6bQabY+Vw==@lfdr.de
X-Gm-Message-State: AOJu0YzA63MTwI6dRDVn0aQVGWyxDwdyOi+jUuZnx1MvJ9DGQHVxgIwC
	wWMqlpmgLOuMiEUeD5/DV1nPSQQttlAlYDg/N5tSDAyi6zaFpWwB
X-Google-Smtp-Source: AGHT+IHZxQicHA/rWunPJIOfNhjo5SW6slrv1+muiyEGEKQH9aLevzbB+PHI0HwwRuYRPozp0dyfkQ==
X-Received: by 2002:a05:622a:1e19:b0:477:6f1e:f477 with SMTP id d75a77b69052e-489c3c8d67dmr40488151cf.19.1745994765547;
        Tue, 29 Apr 2025 23:32:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHyR6QGMWeNrijm2YUp2q6vlk2Pm1aykb3yzBIUokqP8A==
Received: by 2002:ac8:45ca:0:b0:476:91a5:c821 with SMTP id d75a77b69052e-47e5e3f7ed8ls51479751cf.2.-pod-prod-03-us;
 Tue, 29 Apr 2025 23:32:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUO9dipVbXyxCXVTwnkrVtw7C/JmDNzcBrmHqB/CTpLoSV51/By/+YTaQoDOOPaEnZ3ydHR4dE79D8=@googlegroups.com
X-Received: by 2002:a05:620a:2547:b0:7c0:a70e:b934 with SMTP id af79cd13be357-7cac73fc3a9mr257321685a.7.1745994764636;
        Tue, 29 Apr 2025 23:32:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745994764; cv=none;
        d=google.com; s=arc-20240605;
        b=iCe9NbuiUX5rZ1W15EUGmNBFLJkWE26E06PPy+6BdlV/2XCeix1EXvvTmPAMt8sbYC
         YNliY9WQ77SzdADIPH/ZeVaeSoYyATheAh4MSOckxiuLzACbtQ4I9lGozo0T60/MUFzS
         hE1I5Thx63KVoxO7GC+mC+7XdA+3+Dj1B9HFzUN74bxOkoBwZGGtQ26KNRjGSrDtBuMW
         Lpz8ZDJI1FNzoVKx2tlREGFttyZ+GjgxH7380gtrelJwo22OLdPlix5GryFPmK4tuuXB
         UBEFDOjDIg357Fi0KIcfJP6SYom56Q48grvvDgLQlsQvAKmXDQA9TQT4YPKtRkGzGw8/
         wIEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UAbc6YX2BEbygBjJalZAbMTq7w51TuvD5bWRRi5P2r0=;
        fh=jXTP+bLdrANm/Z4u6XtS/aUSSLJLa6xMXyroRscz4h0=;
        b=L7YonRPS5ue5VSpY905XPRoaQncx7hfZdslho9Jx0KxTIUQX5yC851euMZx63gp1tS
         oNSfRLUtw4G9ALp3FKNll/zyAAKLTkZS7VmVFDaydsd8ELCYq9xic6Da5uVdhXws8YrW
         gB2RBaS6jQu4pUHoyN6fPH1DFB1dx6oSm5b4xJxyUm2/NkH8+KrvdETObEl15HbVzvwX
         FodZaMD2tBxRtXUGR1YqSlz3JswhX5tQzHAgHPFG8DBp6xqqsjjlOxBly8KQTrSqJ5PO
         fmOr6jBJI1hVvFflYUlEYpPA/nxW9qsaFvOiW3oYtnI7x0KC97cR8PGrlr99c26hiadr
         eNIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XrsnE5GV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c96d002e96si30110585a.6.2025.04.29.23.32.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Apr 2025 23:32:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-6ecfc7ed0c1so65387246d6.3
        for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 23:32:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVWuNRMNRv3oZ7fN/S0tBLzmJ8aRorYmvTbfBPb/IZQSb2C8DKEH0fGrWd/3oJbafuJe1uE5wrdPAY=@googlegroups.com
X-Gm-Gg: ASbGncsxIADzoe7VZbJnq4ekR7m+ZUlY61rQKF6mJMHmmQ/9TXUVkbkEqjzOG9a4cGa
	+DBaVu47jyPWSZ3arEJx566MGU/Myeqs2S5YR8lSH8wC9jXY3OZsRkGJ5cqkgai3AVN8Or2uI6O
	T6hWW/KVJ7NEhH8uzVFxpJXcpreXXJE3AmMFiMnOoDjXf29KJ7wMg=
X-Received: by 2002:a05:6214:20cd:b0:6d8:a8e1:b57b with SMTP id
 6a1803df08f44-6f4fcf54668mr42054026d6.36.1745994764028; Tue, 29 Apr 2025
 23:32:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-6-glider@google.com>
 <aBGJQF8aMfWmz7RI@hu-jiangenj-sha.qualcomm.com>
In-Reply-To: <aBGJQF8aMfWmz7RI@hu-jiangenj-sha.qualcomm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Apr 2025 08:32:07 +0200
X-Gm-Features: ATxdqUHu1qKH5gcCfA7KsbnTw7kQoM95BYm5aAyVkI445VxwmoYxXFvDOEOIBGM
Message-ID: <CAG_fn=X2wBJAhvwMHesQMH9kpnZFjqRL5RLNBvFT7j9ZC0+GCA@mail.gmail.com>
Subject: Re: [PATCH 5/7] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
To: Joey Jiao <quic_jiangenj@quicinc.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XrsnE5GV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
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

On Wed, Apr 30, 2025 at 4:22=E2=80=AFAM Joey Jiao <quic_jiangenj@quicinc.co=
m> wrote:
>
> On Wed, Apr 16, 2025 at 10:54:43AM +0200, Alexander Potapenko wrote:
> > ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
> > in the presence of CONFIG_KCOV_ENABLE_GUARDS.
> >
> > The buffer shared with the userspace is divided in two parts, one holdi=
ng
> > a bitmap, and the other one being the trace. The single parameter of
> > ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
> > bitmap.
> >
> > Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
> > pointer to a unique guard variable. Upon the first call of each hook,
> > the guard variable is initialized with a unique integer, which is used =
to
> > map those hooks to bits in the bitmap. In the new coverage collection m=
ode,
> > the kernel first checks whether the bit corresponding to a particular h=
ook
> > is set, and then, if it is not, the PC is written into the trace buffer=
,
> > and the bit is set.
> >
> > Note: when CONFIG_KCOV_ENABLE_GUARDS is disabled, ioctl(KCOV_UNIQUE_ENA=
BLE)
> > returns -ENOTSUPP, which is consistent with the existing kcov code.
> >
> > Also update the documentation.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >  Documentation/dev-tools/kcov.rst |  43 +++++++++++
> >  include/linux/kcov-state.h       |   8 ++
> >  include/linux/kcov.h             |   2 +
> >  include/uapi/linux/kcov.h        |   1 +
> >  kernel/kcov.c                    | 129 +++++++++++++++++++++++++++----
> >  5 files changed, 170 insertions(+), 13 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools=
/kcov.rst
> > index 6611434e2dd24..271260642d1a6 100644
> > --- a/Documentation/dev-tools/kcov.rst
> > +++ b/Documentation/dev-tools/kcov.rst
> > @@ -137,6 +137,49 @@ mmaps coverage buffer, and then forks child proces=
ses in a loop. The child
> >  processes only need to enable coverage (it gets disabled automatically=
 when
> >  a thread exits).
> >
> > +Unique coverage collection
> > +---------------------------
> > +
> > +Instead of collecting raw PCs, KCOV can deduplicate them on the fly.
> > +This mode is enabled by the ``KCOV_UNIQUE_ENABLE`` ioctl (only availab=
le if
> > +``CONFIG_KCOV_ENABLE_GUARDS`` is on).
> > +
> > +.. code-block:: c
> > +
> > +     /* Same includes and defines as above. */
> > +     #define KCOV_UNIQUE_ENABLE              _IOW('c', 103, unsigned l=
ong)
> in kcov.h it was defined was _IOR, but _IOW here,

Yeah, Marco spotted this on another patch, I'll fix kcov.h.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DX2wBJAhvwMHesQMH9kpnZFjqRL5RLNBvFT7j9ZC0%2BGCA%40mail.gmail.com.
