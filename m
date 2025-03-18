Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7EG4W7AMGQEYCOHZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EE6DA6707A
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 10:57:18 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2ff8c5d185asf9531379a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 02:57:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742291836; cv=pass;
        d=google.com; s=arc-20240605;
        b=lfuOUCoCwKmuBiC523ZIiP7WlKlME2UCu+CAgmFglrcUIU9rdtu3jnkeqFiDl9YN55
         Sdg49aOe1BJFxgcbPEq5EhMXG9vrtHy8blS3wzwxIl85Y9Tode8OZz6ShGMaZxjmSFWs
         O/oAodGTiQmmPkrBxPM6K8SqmshjKYQpM1mhWMNeJhUGAk3+dCU4QRsCFTUojhDXt3AE
         yX0HQIsEhIDc+jBQ8DbhX7QqjfflDOStN76rj87YHWT8qykSMQnS6saBbY0cX514RCQj
         zh1L6pCRxzTlMmTjk2RAbaMJEb7eFd6NQ0aHaZPnUl2yTGZ3K6KyA+WAqusmdGfdTqYv
         SlUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i3xexnADhOZ/Y4YaTphXtzmtYm6s6fsgyTUPWhlsfL4=;
        fh=CJFC/rWrt1d1yA+pEhdqCqszWeV/rBbLS5feyaI2Mtk=;
        b=i0J3oG9t7n7w3iGc9fz9S02kcV8jS7gQVJdCB9sfZ6itqZcX8IKRWiEVkapTAtz3/c
         wuW6tqXtDPdUe7FhNXTu06jyaHvXRtNRj2+Rs4VVIfoFZL1PBnvewgfWUFJpf95bltb+
         dF3j760KTSKhhjX5YaIrDY8E00z2ep6mu0U5Zfw430MAu3lR+WicFAq8pPZkqGiq9wMi
         YTDf8vGvReS3jlAvwaM2SSQg7PcaYK/83EFk+709Nguc0ZgJ36DlEkjF+Fig7KkG5yI6
         sr65voCSBXe/9SyHJKKwxJdUiFVO+8JHnkp640pgXHhsfZ0L1uJk7nuVgMLeKuO0R2ao
         tdAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ierOdSkc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742291836; x=1742896636; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i3xexnADhOZ/Y4YaTphXtzmtYm6s6fsgyTUPWhlsfL4=;
        b=F35BSN6nGi/cvmSyQX0rBUqj+EF4JeYks3mfi/FvMuQqdmfberZj7XDGMKHK7XhR6B
         A+rokFoOT9pkpcx3kcUDHVAvHY/1/9uLsMbA2I8HR08fPq0WnmfAWkvpDx3Gc8pd+pmX
         KsTENDht/SThteifVBftn1SUsjYOYb5sQGhDCjwwrRk+gVArNlDx8WO0X/yggAp+1mAf
         8JEzVSEjGeDxzIzwbSRppCfK02f14g6mqL1DCfNl3homjaMabRt+4Gl895fbRnWbxErb
         JtayP77bN0mqhQ32cyuG58L+8yRSjEMT8cPg6Kes1Cnfu6unNXbEe2ozePKGaJT7WGvH
         fcIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742291836; x=1742896636;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=i3xexnADhOZ/Y4YaTphXtzmtYm6s6fsgyTUPWhlsfL4=;
        b=b9EbkUqtfGqY38ftXTCqBdH0BbheEy59x3Qo+K6MDdsQfhnTYmNJotn+vwCz6QFNLk
         tbC2HEqmAsLb4H2uShH7bGxVd80F+g4i4T1nCFVMIpuCzWmcMEkwV97hzoyRIq+sYqoC
         OHyIA0o6h28Zc8BajOgMkNm22Daurhk4a5m8X1ZEtwk0cHMhRQUklnRWZlhRlGcOFoHx
         9/46DnhWk2Y5sC5U8BJ9fPovCBH6luno2xLJyRb4IM2WLRZi5+OGxU5LSFcaJHkmQY0U
         3KREr9ZbzdYs57TfaxzKaVayIlCjQldovMUgPpxZJZ9L5oJEWg7z5qAXGTrVui+JzWSu
         F3pA==
X-Forwarded-Encrypted: i=2; AJvYcCWzxxVbrRBORaql1a39ZXxtu5KUorBv+aIMP46nGS6eWDyrg29GKbcupz9MTsjRcUkFdMgoUA==@lfdr.de
X-Gm-Message-State: AOJu0YwMgRcYQkmiCl61FAH6U93MNUP+thCIaPQ8jn/QLNtQc3Ud84AH
	0WmbYSCq3rfdmoKYHHw6toX/cPJOm45LsNHar/Y7ZibqvxVcEBT1
X-Google-Smtp-Source: AGHT+IFSlvnFUqrg25GiK/Q+F9kLBBIhjQltqhzcqnoXkNqPrsrQnsrXXPKreQNQnwF97rE5nlkdag==
X-Received: by 2002:a17:90b:2748:b0:2ff:6ac2:c5a5 with SMTP id 98e67ed59e1d1-301a5b7ddfbmr2456103a91.26.1742291836568;
        Tue, 18 Mar 2025 02:57:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJuWTi9i+atmMO5tGOtm+6IIECxliAehw/iGkuL7LrObg==
Received: by 2002:a17:90a:154e:b0:2e7:8a36:a9b7 with SMTP id
 98e67ed59e1d1-301531d9795ls3024804a91.1.-pod-prod-03-us; Tue, 18 Mar 2025
 02:57:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/Saan/kA1Nae8KF6DSI17qY92Fs5+z8xs86l7E5pE9fjUs86yrffB78hH+WR154ul/F8OGhBF0eU=@googlegroups.com
X-Received: by 2002:a17:90b:2ec8:b0:2ee:d024:e4fc with SMTP id 98e67ed59e1d1-301a5b94925mr3022277a91.33.1742291835336;
        Tue, 18 Mar 2025 02:57:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742291835; cv=none;
        d=google.com; s=arc-20240605;
        b=aO3ArIpYv8GKi7bJC0Psr6nSPvA74bLEg4Vju3zfsY19NvD+8U/Dz3fbw7cO38zMCG
         cQwcyBrYF2G2bcMpLn5/7pZ/Pr5c8F4nINRY8tNcB7DopjsuDiChagcMpt3SKFpu5XT8
         NdeIvRr/EAOJ5IRDAhyD3cFSuVZOdEL93SqqQ5aQ9E5JcBITIxelHtVrychhnvUorhXK
         jMmJVGv8WUWmBr+9g67wmHadGMyLvTg7Nte+GZuMP9RNTRhoHKZqlAIdJk3kpOJ6Zfyv
         /x8JrQK8porcTGuH+fFvlvkd4UuKGuFOwAdC4KsluKrPAYFcYEKENiGscAmhDsTqxgCk
         UhdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Y6vLzjufl+mwLMPqfqy0R5Y6cwgxKn2lZd/fQNHN43A=;
        fh=RHythD7UW5EreySkvf8QUb9z7zHWAzUgAH1lTVAKx8I=;
        b=WOl1TE70SwQy1eOBXBixPTmiLMyp/ebNZXzIXCwzVRUp9ojLXnMf64IcEQW9MXfI8d
         9ZocWjHzEOt1Ad27Stv3jhZAV5YSsM1+/J0Eak92FYGh+1NCJ6zZmLKLhATZNzPtgb8F
         h4TQ/UBTKqqy7ZMWkWJyutc/ca00hZyzHy53S0IYiuLHvS/8cIqQ9ZYJEqN7h7k3RS01
         JsBQdnp3iEACxR8SnxSD0WZOU1m5YBMPdmxBJ37VNMXDJ6MsogUfBeBuQZpVkgVJ0wkr
         iYE1adczdk0c/bTI7cOKx94Qltw/YJfPMBXXn2CfcBxAzkipfCNO+BZehx2QQrjqbxmV
         h3eA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ierOdSkc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30153b0a429si798253a91.2.2025.03.18.02.57.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Mar 2025 02:57:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-6e8fb83e137so44843726d6.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Mar 2025 02:57:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVwevyC3D25YuFpkD2NsSumsRN18fahOv23wJ3htmVFjDeMjNkt+3bagmDKOxIgTWV2X+/lzh1yh4w=@googlegroups.com
X-Gm-Gg: ASbGncvixAuCIs5lLxZKlU2v9/Fnkdw27YqzhCwYqrV9GR2aSVh4Bxz+tRTOQ5hk8cn
	2Mx6arg1nR2191V8nq4zioSfafy+eksjwXQbscp4R6L0U0E6m9/nuutGEVoZzbCl54e34j2IKLY
	YnsmGDRozJbOFFqsrGLSry0NAyXNkwVn/IIJSMDTCK5tnZjRd4zagZ4A8=
X-Received: by 2002:ad4:5e88:0:b0:6e6:61a5:aa54 with SMTP id
 6a1803df08f44-6eb1b957c5cmr37408396d6.44.1742291834750; Tue, 18 Mar 2025
 02:57:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250318015926.1629748-1-harry.yoo@oracle.com>
In-Reply-To: <20250318015926.1629748-1-harry.yoo@oracle.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Mar 2025 10:56:37 +0100
X-Gm-Features: AQ5f1JrFxFNE5b9N5gKecOSz_7mX00YrYbmIQQ1sFdm83WaYQV5DvfZijArv4Mk
Message-ID: <CAG_fn=W0Vcv7imazajmWzQQVNNb-6kKQQuX+3zGch9QvBnNitg@mail.gmail.com>
Subject: Re: [PATCH mm-unstable] mm/kasan: use SLAB_NO_MERGE flag instead of
 an empty constructor
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ierOdSkc;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
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

On Tue, Mar 18, 2025 at 2:59=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> wr=
ote:
>
> Use SLAB_NO_MERGE flag to prevent merging instead of providing an
> empty constructor. Using an empty constructor in this manner is an abuse
> of slab interface.

This code predated the existence of SLAB_NO_MERGE. Thanks for fixing this!

>
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>

Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DW0Vcv7imazajmWzQQVNNb-6kKQQuX%2B3zGch9QvBnNitg%40mail.gmail.com.
