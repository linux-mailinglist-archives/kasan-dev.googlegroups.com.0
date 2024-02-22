Return-Path: <kasan-dev+bncBCG5FM426MMRBK5W3SXAMGQE4BLRVPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id AEC5585F520
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 11:00:14 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-5dc1548ac56sf5852752a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 02:00:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708596012; cv=pass;
        d=google.com; s=arc-20160816;
        b=HHxISbVCJ6ypeeZShshFkFAvFHgqUlKDViCnabhAt1uhuYyUT7ysrjenYz7tSi1Wrk
         GdKryoHbTmH+qVb2oH8fEE9U9qjfVoLAqMIo5Y6UO/BUxrN2Bzg70kLe8sOoXw2+uIpB
         nNDy8L6MhPdCaKl1PJ5rIUSROVmLbNqdVag1YnknmLkv6KSzcatRiopkuNiVzbSpsUpi
         RbBBB+9PVPDCUAx5MStacQ4fT5xmrzEyGCWUoT4bVYH9rGsKBAgaO7FYLOXDLt8AQ5KM
         yUXnQ7Dn+O5qE8qGIOkfVsreTsJJbABU97KzeEowr2WZboRocEWMdLtrUrJPU7UAC6WI
         1czA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6RueqEn0Dvp5//UGI6p9XWRzmJrS7simZqKT9P+Lqo4=;
        fh=9WrP5dijPgYEWNu0HnK18AQilv6g1PIri/PLcCyK0yw=;
        b=KRzCLJTIoBDJtcpIb6dLgC9c/bBH3cP1CbWbL765Py2iqfMYHAP1SPJnHpH8KMG+QZ
         JDsexV/mTqJTb/XDcTzaZp/hKFwPZpqwtmjBRN0Seh6ThP2+vKNaCLzp+k5nLrClPfQV
         s7QWlzpNumMWmZ206bdE6LNlp+zAoHqi4hOjNTcBaLLIfzhRIDvK1ZWS3Ab5XX1ZqmXo
         GoLviilhflOefuj1uWAH7y+XJIJQmPWni9p7HBXAwsfVB+nXXmZeRgmnVAOd1LMHaXXc
         vO9X+eW87wIS/P2Bxz799ChLfSrgzdKVF91QIo42/awmiLlWa2iH+/+RIu692oLDg3zo
         sP0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=phQ7WKGu;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708596012; x=1709200812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6RueqEn0Dvp5//UGI6p9XWRzmJrS7simZqKT9P+Lqo4=;
        b=S+H/Jua3A/SEPU4k2lcsf5u7+yKO9kswU/LGUIJt9KaNuvFNCXT+puRrXvt4+4lujS
         gbaKgQ4eR0d6GeFVo3q1E9ajcPE165Mvd8ikuD6lTByJ2ICmYLvKftZvt2pDRCYPukqu
         VQpSUQCvOyhEsFR/g2ulZTDJlvKglG+no5j69yaEP2WPiMLJAG71liG1dat/lOSI0hDr
         g5ULCsrDcUCkwmGqGSSWWpbG45vvbZPkfjGBoJBbUc5fEp9CtIwmvRKm5HhMYZbYQpuX
         ibwx2sagq8l1Z4R9RupCMdIDqDMcvW6jMCxWntpkJnT2oqFRyRIkLGALYNysSXNXXW+A
         gDfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708596012; x=1709200812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6RueqEn0Dvp5//UGI6p9XWRzmJrS7simZqKT9P+Lqo4=;
        b=EUjwegfZe4B8mR4ebKKv8IK1obgQELmclbk56ccgSIJg9uf1QPBo7A7hyQeNYSQlzM
         VcdiCX6GyJ3gwSVmel9afAGzcHm3vmsj7yBhfkArORXiIzyZxNguCKMZc2xcnHOjr1Mv
         s6eD0lQnbgLksSILGj5yDZoJO0yhH8tcZ5nw9/77dpbQ+OyDtpvznfAeGtzd6jdulkHd
         GWNFSMvSQpZAUcnixrLzzyFEp8eMrfNoqVZTaNPCZmbt1KRtCT+MX+XW7ghp9i29VTyx
         6Ke32k6ai8Qs8nCKGgX5azEdpKjYihqe9yCM+aZy9fj6Gf6h+1SGD4hgTlUzQzn+oUvC
         Y40w==
X-Forwarded-Encrypted: i=2; AJvYcCUWVIsMS3YQI6g1qGomEOaSa0h8/THz1BTD+Vxq0DlR2dZDKOeeHJkRljFclET4Q3laUMUlt6bE4obKjLMoZtYp/DAiV8zbxA==
X-Gm-Message-State: AOJu0YzSUBKvZKO/WAKmJSCesZ1jsKV+WCMIVloRrgZb5/8VFi/Z9oKu
	h7siIAn9DktskeVF6AwDHag9uYXfuHau9bbqK14Dt0kH+DvVwk/I
X-Google-Smtp-Source: AGHT+IHjGj0EQUmLjwg5DacWDtGN1SjI+Npf7Ukwvy4BFlCRLyRwiQXItSSjST9gjXEo9zhDPoVj6Q==
X-Received: by 2002:a05:6a20:94c8:b0:1a0:57ae:8e86 with SMTP id ht8-20020a056a2094c800b001a057ae8e86mr22635991pzb.56.1708596012043;
        Thu, 22 Feb 2024 02:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2682:b0:297:6fe:6d01 with SMTP id
 pl2-20020a17090b268200b0029706fe6d01ls2781479pjb.2.-pod-prod-07-us; Thu, 22
 Feb 2024 02:00:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVE6Q3npPTTtMN+6McX4uNdJBf/bV2Is31jwDiq4u9Whxg65v5dbsQUUR6mhQ6Sm4/GgGGlE7dfW0g7npqR2ckuisTNUmKWGrGGgw==
X-Received: by 2002:a05:6a21:1014:b0:1a0:c427:9c4b with SMTP id nk20-20020a056a21101400b001a0c4279c4bmr4484389pzb.19.1708596010590;
        Thu, 22 Feb 2024 02:00:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708596010; cv=none;
        d=google.com; s=arc-20160816;
        b=DjWctx+TMikV6IO6h9aGRLfSn4BbhGX1vUa0wX5KiYQVd484dCQ1aCVxdirnapU18W
         VlL/m5xjfQrYrv2rfJeZIEEnR9NnsNS2tJ2gNhA27hgeBf2B0TLKYxEiM7tu6CuybtJf
         JMwiBues7Mkj2HTDtOvRPYksRoCtv0bt0tlcbcYkqQlFCzk5c+/op8yfSeaoJQdjcpeP
         BNNWTq86UkTcCltivU0X0DJ0MgDLHkzF+6Bs1hhPE6n30nzwsSXiVo/U7yMunegm1XlW
         T36BXFkPYObDd9Vs5kMeTdB/v1gS3ok4eNd9qjEuesmICHbIVOU97qZma/I1hiHzsFN/
         2W+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xY3a5A8TczyzS4EQy7YnxSv2e9KYZLcka7tIrv2ih1k=;
        fh=ci3Tz8GGSoYiQ1r/RO6IDzQ3OTPPpLOZd9t5vk/P9NQ=;
        b=JIjuT3aYtZonCoDbP7+vALOW0z5DrZu9ta3hVBXVe8OZvml9spU34c1mqGLd8nlAiU
         u9ZD21+b1tu6NVxWFfLPj+DH1Zx9H5Jtq4kHuUjNs1cnw1LR5XnqU8sWYPPPsHFPIRBg
         bXSN0p3gmRnYL3/lxz/VT6qZBCtjrxvSQO4r8fd0uwjvNbycNTSqkiO9KzXqMmhjh2Qw
         Zr6ntphJ7s/Rsm4mqUcSshUEeRGY7S+tjd/Q7qalX1BlBjo4VAOCoHvmnOMeCoqjUezJ
         VK8esfq1zK5LuyKiw5cxg/AkGkqlXjNIW/c7w6vOFZ3a5p16eG+v5d99FVuyB78ZoAKI
         llFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=phQ7WKGu;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2b.google.com (mail-vs1-xe2b.google.com. [2607:f8b0:4864:20::e2b])
        by gmr-mx.google.com with ESMTPS id s3-20020a170902c64300b001db3eb95007si735001pls.5.2024.02.22.02.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Feb 2024 02:00:10 -0800 (PST)
Received-SPF: pass (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) client-ip=2607:f8b0:4864:20::e2b;
Received: by mail-vs1-xe2b.google.com with SMTP id ada2fe7eead31-47079f43a37so685829137.1
        for <kasan-dev@googlegroups.com>; Thu, 22 Feb 2024 02:00:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWXFSOoquRLQYL33SNfqj+6BqzEMfZcM6KDahxrFTGbC8abpVYYTM5BEFpM1hA7VGeXsJdiJXTd2PqeZfHcntR5lyHH1lABoknWxQ==
X-Received: by 2002:a05:6102:1626:b0:470:4a6e:4a4e with SMTP id
 cu38-20020a056102162600b004704a6e4a4emr14352031vsb.29.1708596009136; Thu, 22
 Feb 2024 02:00:09 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-25-surenb@google.com>
In-Reply-To: <20240221194052.927623-25-surenb@google.com>
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Feb 2024 10:59:57 +0100
Message-ID: <CAH5fLgiyouEuDGkbm3fB6WTOxAnTiDx=z6ADx7HN3BTMAO851g@mail.gmail.com>
Subject: Re: [PATCH v4 24/36] rust: Add a rust helper for krealloc()
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Miguel Ojeda <ojeda@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=phQ7WKGu;       spf=pass
 (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::e2b
 as permitted sender) smtp.mailfrom=aliceryhl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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

On Wed, Feb 21, 2024 at 8:41=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> Memory allocation profiling is turning krealloc() into a nontrivial
> macro - so for now, we need a helper for it.
>
> Until we have proper support on the rust side for memory allocation
> profiling this does mean that all Rust allocations will be accounted to
> the helper.
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Cc: Miguel Ojeda <ojeda@kernel.org>
> Cc: Alex Gaynor <alex.gaynor@gmail.com>
> Cc: Wedson Almeida Filho <wedsonaf@gmail.com>
> Cc: Boqun Feng <boqun.feng@gmail.com>
> Cc: Gary Guo <gary@garyguo.net>
> Cc: "Bj=C3=B6rn Roy Baron" <bjorn3_gh@protonmail.com>
> Cc: Benno Lossin <benno.lossin@proton.me>
> Cc: Andreas Hindborg <a.hindborg@samsung.com>
> Cc: Alice Ryhl <aliceryhl@google.com>
> Cc: rust-for-linux@vger.kernel.org
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Currently, the Rust build doesn't work throughout the entire series
since there are some commits where krealloc is missing before you
introduce the helper. If you introduce the helper first before
krealloc stops being an exported function, then the Rust build should
work throughout the entire series. (Having both the helper and the
exported function at the same time is not a problem.)

With the patch reordered:

Reviewed-by: Alice Ryhl <aliceryhl@google.com>

Alice

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAH5fLgiyouEuDGkbm3fB6WTOxAnTiDx%3Dz6ADx7HN3BTMAO851g%40mail.gmai=
l.com.
