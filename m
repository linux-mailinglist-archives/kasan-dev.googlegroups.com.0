Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFGG4XCQMGQEF3NGTTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DF6DB437C1
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 12:00:05 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-7722ef6c864sf871391b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 03:00:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756979989; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lf2BNPjx4tt1/ghzjh194i8zhd7tTfgAQCQNpFnhb3XrF7EjMowDZAC9atzsVp9i/d
         7otxF0DZYdrmITZvZepgH2OMTifK8noD7cFlPkUgXK/aXRIt9yXvbva3hLZDoAS1sDvB
         Vp0rDM6Y8GTsdzpuKQs3ODoEaMDTH+CfUZk8YTvchKBWFx0WkINVAitnnOa9K0TuoHSm
         T/WCDJVQa7dU0auzctKJmUjTyexOnFhsKbQBUsuNdVz40WWLoZ1jqfk9Se3KNvT6PRzN
         Hyp7uXA0xjVIhEQ8u9Fh20vjkkQ9x5qbphaMcpKpMMXKd2IogpTy4FFUeLK+KZFU0/l9
         iCzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qW4UaiOFRGEWq5TRdwdp8WEif5J9nNIGAZt3FNPYpWw=;
        fh=BoLf1cRZiUq7BZgd9DXcNm5gSaaUqXnEkWl7Xif28h4=;
        b=Os0FKBPiwL380ZYN3SxTWPPgue6NVfdD6vPRYNuTvtPMp0a45D1qnbGC0FKhKGl6pg
         ehGsAid24L3vFP8OSIVAeMagrNO/n/luL6H6GG8+SwRHOFZP7JSeGWHp6Pyy9hDTjhfO
         6ScJat8GlvexE6uaWbZOGOOk6xX7N+2IJjzrK6zZuxFjEfqFRecQfLrS5o+IlQ3ZR6Fn
         9ORaY/PmHBqCgjfpU4t6ppDEwvhfjY2p8BM7i6lVAq5iRNBTlq1cin2PWG5Lds7kCAg7
         IJ5oU613i7LhRpDGwjbqPcIV1nliGpmh7C5PqTTb2uTZ2SAeyyoTfhIHeXiEF/pqebss
         NI+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rgceiZk1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756979989; x=1757584789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qW4UaiOFRGEWq5TRdwdp8WEif5J9nNIGAZt3FNPYpWw=;
        b=jDmwmAPadM8gGSLTUKDnu3Iu/7Nt1gFRvyuZk6h3+l1A5JfPTroLPhzie+DegnoKRx
         UCQr+UTFqTbRgYT8IiraCcgfy61ta0ZAA+BhYVTZvn4fhpuEnT5xf+f0/TCltdPwgN5b
         WWfEVr75gQCiDFy+XrN2Ai1PoAoIS8L5MXV1qwGFHNMD5Df+7InExGNVCHGEhAf33zYg
         m89Yhc1Bnfg/7I07T8orhb38XzvDxkHRvDBjkqshtixKnfqEcC1pHIltKVV+hBLCCSyv
         Euw5iHfXdf8iyoF3opOw7Xzd/LbGWcu/Hr5bAEx25v8qLWI/roH7qWZGEnwK7Yn3uNIJ
         Pu8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756979989; x=1757584789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qW4UaiOFRGEWq5TRdwdp8WEif5J9nNIGAZt3FNPYpWw=;
        b=OXCQrEph/rEW4Czw7raig4zCy2LidaJznxTt7wxRE3Y+VLRcKQFZvFoDg6Zqu6YfXS
         KF0ZaLyuIdsWaxg/Y1Ek+t2K+mvMe4PhDATrtgot3Fl9546Z2V7dmvYVIlgFdTiwPgfK
         WQokIsVuxBMbQqMSxK0BiHnbqqNzcnnI7vziA6mxRz9nJkOg91pN5mXtBIX/Vjf98+Xb
         Tr+gZOM1oiU29BsnwndVcLN/cnX+NK228hWF6HDCE6ZQx2K18BXUpGVXDIBccT+62gwx
         FSKk708jXMPREubJd0jkwxt78dPKMX2/NMw+Hqn6i9qDR5YeUUHb9vUCzBT43ZpBNkk/
         ke4Q==
X-Forwarded-Encrypted: i=2; AJvYcCXryviUQIxt6Faqz7UjE12GNmiwLDNBpMwkCs+3w5o+I0O8mKTZzLcEQ3ysU3R4otOQrQOt2Q==@lfdr.de
X-Gm-Message-State: AOJu0YwCwWl/lMx9wwLmO4f1drVb/bbtV8c4R6NkEKVPuudbAHsJ7or6
	xjMNnqVu5ZfVa24jwwv2ANxJWlThdtljVCQ/reivJiavGNhgn0zuXNl4
X-Google-Smtp-Source: AGHT+IFO/JDctkqBuCxM/MCL6uhBmRiUAak/FIBOpnPBImhHx4kySvNklrly9CL2aS3Tyh6S/WHUAA==
X-Received: by 2002:a05:6a00:b96:b0:770:4d54:6234 with SMTP id d2e1a72fcca58-7723e1f4471mr19864388b3a.3.1756979989179;
        Thu, 04 Sep 2025 02:59:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfRTeKuZiYIf5DVztI1kSa1cEUOOeu0mX4m6mLWgAyrDQ==
Received: by 2002:a05:6a00:1746:b0:771:5b5c:59f3 with SMTP id
 d2e1a72fcca58-77262282699ls4188146b3a.0.-pod-prod-04-us; Thu, 04 Sep 2025
 02:59:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPEStIgbQHajvxPGQf44ZAUE1VI0nptgnckQpRmn+WFGtnVxjH53L3xbyDeclc02O0e6qYlX62Yo0=@googlegroups.com
X-Received: by 2002:a05:6a21:38c:b0:246:1e3:1f75 with SMTP id adf61e73a8af0-24601e32507mr11316943637.6.1756979987880;
        Thu, 04 Sep 2025 02:59:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756979987; cv=none;
        d=google.com; s=arc-20240605;
        b=YRi0rCrgPwtjkpB05DH0eC5nBqKv8xuH58FIr9Nf1Ycq37uizX9jliLi6comnH2USC
         4NcmLgnxZHYnblm2TNaNIruBV8nObxd/mqo/RO4Lgw4uQVYhtnyrSEaNDDvB1LBdhwqh
         vUakOLpY3CD6uZGlvtTgOROfgF74UTfEKreScw/hpZv6vCGBYik3Ht9tJr7UjHnL+3V4
         T4J7ZmMjACHd+IeQbfLqItr6WXbHv0nPRvnFvQ0Roon+DxD06UwS/ibDGkTUZsjO7FyC
         IOJ5Tyl7IJT9V6NydrS0FL4CyrWIGYzuKyc/skpYoq32bTyRNYtBVl28ykHn8JPEEwsS
         ydmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MHOpn0x1n+X9bJMJ6KJ/yl+og8/86ttoBXUy6mB0ey0=;
        fh=Zw2mnjx5BjPhiTKAhKnbJI3StNrxiL0N7GEMH12MpLA=;
        b=PNAbBz2I2md2n4ocde/QnaCzLpY1mMqfmliQAbltr062gkMsJFA54Ph2ilAUyN7bjW
         ShVXmof5GW7BkAP0G9CQvN8Yci5//MRTrJAe/BndadKOFxpSaakZ++WFu0lIR6ivs+PI
         7J5qpr42eNo0ImGwjbcAsyZC+pQtVST6yhBYlQY2VOUgf4BzxY8KbZnyAdSl/AEK3RSR
         MPSz97YBxe4NWxM7xThnWlSJ4XZVshl3448rVu6j4Z2PJ6gMYigiy2o1ETNKodl7Uryz
         1cAq90QPzuHmIvCKXsq4oYsmFtD6BAsX8lRAkL5g1xWBSbrHU39bBFDIElMWtg0cUTRB
         42rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rgceiZk1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-329dca88bebsi360085a91.2.2025.09.04.02.59.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Sep 2025 02:59:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-70dfa0a9701so9413096d6.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Sep 2025 02:59:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUK6/B/TDbgcJSVeTA8o8aMM4QkWYrZ1Ye3GEqYQp2ezzMxq+UWXQmGcOhUTSkiTwT1bckjCrShl1I=@googlegroups.com
X-Gm-Gg: ASbGncsyKwvo5k46Gqr/X9Ui1cfLm/CUD7gdohxjwcMqlMUD+hywnHhVkqjtrTbVYLS
	RKZLm9fUg+x1VSuGdSga82zfKccaIRtHbhK3hL6ixti5pTgsNT6xOrUlG876ZoHBq304AblI1O/
	tnRjGOnz6tTs0bCG2o7Y5RvzCPuulAZEMb+LWrF8tOh0MzG9LwO4LHQ52pezcKmRT1xsq+NSZ+c
	mrJrEIUgmO4V/bhjR44LZh6Oe7Wejxwma2AsFkqI9tlVIsCJ6DWNQ==
X-Received: by 2002:a05:6214:e41:b0:709:c7de:ce70 with SMTP id
 6a1803df08f44-70fac700db8mr222215406d6.10.1756979986529; Thu, 04 Sep 2025
 02:59:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-7-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-7-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Sep 2025 11:59:09 +0200
X-Gm-Features: Ac12FXzQlIV_NpJ1rduhtC1FclDh1AxIHe380g_TpXDcw3vnB7j2ZNk2kb8WbdI
Message-ID: <CAG_fn=WJrdSr_6u770ke3TxyFimuMXXeTSQhsDR73POy4U8iug@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 6/7] kfuzztest: add KFuzzTest sample fuzz targets
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rgceiZk1;       spf=pass
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

On Mon, Sep 1, 2025 at 6:43=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmail=
.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add two simple fuzz target samples to demonstrate the KFuzzTest API and
> provide basic self-tests for the framework.
>
> These examples showcase how a developer can define a fuzz target using
> the FUZZ_TEST(), constraint, and annotation macros, and serve as runtime
> sanity checks for the core logic. For example, they test that out-of-boun=
ds
> memory accesses into poisoned padding regions are correctly detected in a
> KASAN build.
>
> These have been tested by writing syzkaller-generated inputs into their
> debugfs 'input' files and verifying that the correct KASAN reports were
> triggered.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWJrdSr_6u770ke3TxyFimuMXXeTSQhsDR73POy4U8iug%40mail.gmail.com.
