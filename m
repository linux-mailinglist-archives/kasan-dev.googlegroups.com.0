Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLU2SHCQMGQEX24EOCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id F2ABEB2BE82
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 12:08:47 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-7438205f726sf11421562a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 03:08:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755598126; cv=pass;
        d=google.com; s=arc-20240605;
        b=QB9ydsT8A2PxzhFIk+R0sOjx96bGdxGZuwmXHM6dgya7MT3XyEjuFh3MLOfsDOmqry
         cSQRSPIzMMkuYYibmX7zgqAFIyDhpJMZV1Avin4dg9Hntqaig/uPxEMOshmKeIk9TTIK
         uiKd2aTShsy4Q/CPlybqcLz8fp/eTH4KSuATHoOKO3rROY7bnsOYgIOq1+Ryd473Zec0
         NZta/1oU+pehP2Xy7d8f3NCqnkFI+C7zPUlrfrFV4V8yDyWFqxL6+00hoSyevxalRwl0
         OamtV20jENzdGuYyxb/Y935k20KfoTYv3EYjDUyxGkxt6DJ9hR+2tYaNhlQV+kTEpjtg
         emTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nXCN7FIolIHOpXyvitfBN5YxG7a9ZQe8dLJfEEFBpws=;
        fh=HpnAUkOX7Y8ovufb4eAsX/0s0DRmxJRux4TRPy9RnPE=;
        b=Jn56+dsbTgyFhQVKNlmZJnl9qUARhLFhVd1HRmpnG+Va+V5arRK919suez5sQ0A5Dd
         lTi4aOPimQtEYQeZTzLdMwBLq4VlztRsxyzPgtSxaBC/M8jOnWXX9t//x3YN1+M774ba
         NkNDSlyXzr6ImVfxgBSXS8FoWa21CpzCwkz1nSkLRJ6AnEPQ4UcIEzpodn6xgffgiTpf
         D9pFUH7XT2ahMJNv/MmxPg/u9YQ98HrePIyinUSTbiM1z8scAxgfGRtE2SYAgIzT47bo
         o9eFjLO63++XwYi1JcK6siv3ffq1iKd1JpFEZRqv9muYZfLdc4mIzilrvG/pLM2fAdXw
         ZBtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jzPqveIk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755598126; x=1756202926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nXCN7FIolIHOpXyvitfBN5YxG7a9ZQe8dLJfEEFBpws=;
        b=n8JHLxMIiPjsWlTtzxTfxKbHozxXkeliGLBlOX+yGFpYIzHXlfFAjbh+psitm29XiO
         cair1IVu+NGCjg5nRwfMMJJuBUzysvcsgANomLJx444RwXyvgrlBYVXs5rDZYIj4ThNk
         Qsd31ME9C7AypA+jUbfFLzqnrVoVIAs98qLN8/+omHErNfIlJ/YtE2juCT9x2POHuV9U
         XcaboelgAA7D607jmwK8ZMmb3pbQY3zo5Cu0eJcH19E6gaYRvvNA5IdMsSZhno3YZPYv
         KFmEAxkBep/U7Q/JbgDYBhVgNtT1oPx7FOi3ffyxoxgiYyppZNivj9mGlcYiGGW8PwUn
         konA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755598126; x=1756202926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nXCN7FIolIHOpXyvitfBN5YxG7a9ZQe8dLJfEEFBpws=;
        b=Rhtqb7PFTNCHBzHC3LfaqSRy5AagSUNcOnNiUyxE7ZCCIHQulZkp86Gws4m1CkMrTw
         oyoQXyUyA+kDNz3KefVFDEZ4je4mlbpYnh+hmvlOSa6JKXagJN6Ypu8nHcw8bi6xOgyT
         9z4fX3/Xsey7r/psprHswD49eWgtctABM9OJU2Jw5XMd/oiy6i35Hlkm/+/v7x4avoS/
         rt4cQ+SZaxYm4Pzpg6xjKrjhhtu4NoBxPH26Ebvpl2SI7OyhpX+HB+/Wn8L/Y4lsj+oo
         pC+kUQeSnPH911v/RrkOfnW0NoYnyYmybBPrzkHw/H7lf/hZ7SK34NqzU0BG59uSh5Sp
         I6ew==
X-Forwarded-Encrypted: i=2; AJvYcCWkG2kLmJyCOImi3TRtgXJ9/VRbvT6fPT6o2zKZflBixXF6L4FbVCqMgX4wWmzKBLdufWzVTg==@lfdr.de
X-Gm-Message-State: AOJu0YwnVKu5s1ytIdwUxiIDEcoOrmiChl/z0dHDCgQC6lVtKsq3ttfs
	L6PoiBL/JKXD0fgl73z3w/CIirso+rJz6/yFN58r8WvKAdEgG2XE+J9F
X-Google-Smtp-Source: AGHT+IFsTjn9HiT6MODvlBvKE5WtCqk20Jg/6oXDfdT8Jqr07boXvIQbEepFrynXc7YYGALt/gBNXw==
X-Received: by 2002:a05:6830:398b:b0:741:21b8:b24d with SMTP id 46e09a7af769-744e09dcbc5mr1291599a34.5.1755598126400;
        Tue, 19 Aug 2025 03:08:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdHij0hiClyKb4p0EBklz+dqvJPeQmnW1SZ7IP5goZbRQ==
Received: by 2002:a05:6870:15d6:b0:30b:c665:1d65 with SMTP id
 586e51a60fabf-30ccebf8997ls3017066fac.2.-pod-prod-05-us; Tue, 19 Aug 2025
 03:08:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqXz4ylwCP4NhaZVZ1V7c53yT16EUEd1/B4aGDcuwq+wgulKQbbVrwoXYlZhKv76mKRc9mMcoX9Uo=@googlegroups.com
X-Received: by 2002:a05:6808:690c:b0:435:80ec:5800 with SMTP id 5614622812f47-436da1d5cddmr1095812b6e.28.1755598125180;
        Tue, 19 Aug 2025 03:08:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755598125; cv=none;
        d=google.com; s=arc-20240605;
        b=eN/zt9F74WnDqpTyyLaC1DVrGUVhZqFZT6ROBVbyq13qH8mhSey/DcCOVooRX6gRDW
         sidOpvpDVlM6DhXdhgvF8tl0Z689CyCkNaKKK26wI7wqWJ8uUTN4fRyzejFbXZReybyS
         hYJ41BEa3LQyMB7cRjB/+t8k9/814OR8fD+rLJe7gstMiIiDZWFZ1eMuevssrRuB0lXN
         qRta1d09aG8R0aCar/woE4JPvPe0PXm4oRPKOVb1j/6ezD0CRZBCvmuKwGAWajw+zOCr
         OTP5NEgU48H07W5u9om6dcc5PeiwITzg4Tc2GWGpOTfVuKdi5tsCJh3KWlVcZViQJf1d
         ckxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xtwFnGhPjZbaJZhKpnnfvoiBniYG8b/g2aN0jXq3ohM=;
        fh=gOfhfd7HTvpoodKgOQuxRHbBzuRJmtcfeFvNtfcWKfQ=;
        b=jU+kSrT18CacJ1wV/hMKPgmZQfKVFDdzGvsge/J8ME6CnBIgqmlImyXpHiYCHZyCfX
         15LpnzS5ziPB7o5gI5kb/3ZcIbNso0kp6765bETx9KfpzlweaJdP/heiZXtGu2ARtdg4
         BHmxHRTPGKFB8LhdV4//7SlsPTE4h/megAeVQLAXgbc+iw5LuMIicInkY65Bnc60bymw
         9QuEHLMPa2Ho/hqj7aT0ZZP7QSokdD8XJDIVAetaPBbnwDv82WwUfC5AtubjdtdNBsKw
         swltwdct3g3lFFXYdqfXt3ShmlGgJ27qUWqZa9RwCw0gK6g17KnayEi9+0iteIwX9uXs
         3+rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jzPqveIk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed1496d7si474182b6e.2.2025.08.19.03.08.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Aug 2025 03:08:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-76e39ec6f30so4029626b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Aug 2025 03:08:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUvq5y9hBIC37J6dIjTLKjVkb8WxldG+C183rYFKS1rXjixiehDEAatXUhScBHmyU2z+QtpXKVqNTU=@googlegroups.com
X-Gm-Gg: ASbGncvbsw7rgoAmr7aj5kx+JtLb1EJDYEejtbD7vx/boYhR486RBU4gpH7XdgyVvqN
	zg9C9Xql6EAYtznIHZcdWD1CuSzmkEo1csvd6B/sYeo+gdZBBc7fusxcgjgzHpZUij+7om3iGTJ
	f57+7eXinA3amq16pWV+ZbnoAXFBNud7lHJDvvrq86nBoiDo9s9qVClvuiVC0ybICMycJb39Ipq
	yG5w6bJyElqtaqfaZfZw3zDbMFMtX3YFXLUqbBlsfcQdGTzZB+PW0K4
X-Received: by 2002:a17:902:da92:b0:242:eb33:96a0 with SMTP id
 d9443c01a7336-245e0328fc4mr25769245ad.25.1755598124032; Tue, 19 Aug 2025
 03:08:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
 <20250813133812.926145-7-ethan.w.s.graham@gmail.com> <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
 <CALrw=nFKv9ORN=w26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A@mail.gmail.com>
 <20250815011744.GB1302@sol> <CALrw=nHcpDNwOV6ROGsXq8TtaPNGC4kGf_5YDTfVs2U1+wjRhg@mail.gmail.com>
In-Reply-To: <CALrw=nHcpDNwOV6ROGsXq8TtaPNGC4kGf_5YDTfVs2U1+wjRhg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Aug 2025 12:08:07 +0200
X-Gm-Features: Ac12FXytHPioqIN3_h6-8LrUsWB3kDPFRbJegFs6XnxZaSOjKS1ectEm86g1kAE
Message-ID: <CANpmjNOdq9iwuS9u6NhCrZ+AsM+_pAfZXZsTmpXMPacjRjV80g@mail.gmail.com>
Subject: Re: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Ignat Korchagin <ignat@cloudflare.com>
Cc: Eric Biggers <ebiggers@kernel.org>, Ethan Graham <ethan.w.s.graham@gmail.com>, 
	ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, davidgow@google.com, dvyukov@google.com, 
	jannh@google.com, rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	David Howells <dhowells@redhat.com>, Lukas Wunner <lukas@wunner.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jzPqveIk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::429 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 15 Aug 2025 at 15:00, Ignat Korchagin <ignat@cloudflare.com> wrote:
>
> On Fri, Aug 15, 2025 at 2:18=E2=80=AFAM Eric Biggers <ebiggers@kernel.org=
> wrote:
> >
> > On Thu, Aug 14, 2025 at 04:28:13PM +0100, Ignat Korchagin wrote:
> > > Not sure if it has been mentioned elsewhere, but one thing I already
> > > don't like about it is that these definitions "pollute" the actual
> > > source files. Might not be such a big deal here, but kernel source
> > > files for core subsystems tend to become quite large and complex
> > > already, so not a great idea to make them even larger and harder to
> > > follow with fuzz definitions.
> > >
> > > As far as I'm aware, for the same reason KUnit [1] is not that popula=
r
> > > (or at least less popular than other approaches, like selftests [2]).
> > > Is it possible to make it that these definitions live in separate
> > > files or even closer to selftests?
> >
> > That's not the impression I get.  KUnit suites are normally defined in
> > separate files, and KUnit seems to be increasing in popularity.
>
> Great! Either I was wrong from the start or it changed and I haven't
> looked there recently.
>
> > KFuzzTest can use separate files too, it looks like?
> >
> > Would it make any sense for fuzz tests to be a special type of KUnit
> > test, instead of a separate framework?
>
> I think so, if possible. There is always some hurdles adopting new
> framework, but if it would be a new feature of an existing one (either
> KUnit or selftests - whatever fits better semantically), the existing
> users of that framework are more likely to pick it up.

The dependency would be in name only (i.e. "branding"). Right now it's
possible to use KFuzzTest without the KUnit dependency. So there is
technical merit to decouple.

Would sufficient documentation, and perhaps suggesting separate files
to be the canonical way of defining KFuzzTests, improve the situation?

For example something like:
For subsystem foo.c, define a KFuzzTest in foo_kfuzz.c, and then in
the Makfile add "obj-$(CONFIG_KFUZZTEST) +=3D foo_kfuzz.o".
Alternatively, to test internal static functions, place the KFuzzTest
harness in a file foo_kfuzz.h, and include at the bottom of foo.c.

Alex, Ethan, and KUnit folks: What's your preference?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNOdq9iwuS9u6NhCrZ%2BAsM%2B_pAfZXZsTmpXMPacjRjV80g%40mail.gmail.com.
