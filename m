Return-Path: <kasan-dev+bncBDKMZTOATIBRB6HD26ZAMGQEMYIV5NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 47D798D1F7C
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 17:02:18 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-529ae9c88d8sf710027e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 08:02:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716908537; cv=pass;
        d=google.com; s=arc-20160816;
        b=fEBlHJ1yF8bacn+B4rbpmRWgxgOBN3zq9/Nmj6J47cwfNQkdONDYFikxD3E9xZlLPv
         5arNylLQAynGz7QSSCSzeIRMgolm+fY3Y/xY8yO0vbbEVMQmvx3ss5z2UjXqDOIr0FGA
         WdrUbJKmULfMIdHY2md/p2yaZPTF13s9JZjrHqZN6isPPYqJKaGYY0Cmkw/AgtkaK2Jx
         WoTWK//qexlTzlJW2bD9OfPIeIALeVp+ZB5U+CRZr1J7ix1UoLt7SSCDfgkOkAYYFiAM
         2SV3BZ93GqPBG0PsKTBNO4FGw1MVcaTYOrNTb6ltJgnnKVFoWwZdvduwBgHbpmkSboD+
         y6TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=CcA8jmLHVmkwFgZE7Ouhj14ymQOjlzDqKSWHXNoW5/8=;
        fh=RfJ8RdzpNQtxYULof3FAmhAMiOTl7AX4O1v6mnS0qAA=;
        b=dEHuXd7Lv2nPlsDOwKe0DkmI6/v1cbVyMKRBaKRxCviJBcfqGSm7u5S8XX2kWIRcza
         RBa2rVC3aVccDSU//X1vVj5SnDcZHweDNVMdeE28INqzamamdUQ63zhLzrGzwkTuHOkx
         hE621COG+DwszOAejijDo/pQhZfBp2B8aoYltxl2OsrZZoZ6e7X5Z3qCzVjHWVq975RN
         02W/o5Tc4Pwe0CQA7j6Qt64NO6hsz/B2T6OTtbIa/xabHVIkkNq8dl500BjTjnYbmpTh
         oGq6uCcXnnM/jKe8vLU0NGAiQ7CMxklGCQ7ATr04lvOrbR94Vey4RAjIKbsoWbRN9CSv
         Rz4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=opoXfCNq;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.187 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716908537; x=1717513337; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CcA8jmLHVmkwFgZE7Ouhj14ymQOjlzDqKSWHXNoW5/8=;
        b=U7lKbXGdNi4nsB65mBSlxbRLXg31IgT0PWxaVf74bgULUoUxZx1JmYwkPkKcdHH3O5
         XrX6VgWD3uyQFkyPHU0h5d9rhYr4kypem2fUV8Uk/40qQYOyf5KdfQkPl4sqZbDOMy8H
         KQGxrWK6zwtog6l8x/TKi4G3x822ZNCTPTHKdBhzveZtwpzR+e8lLOLBVGYhKuRwG+Bp
         NAb7uL8bjFdBqJreiDUXPk+sNr13V0Ll6TaFEwsdga46ZeJgFNIgYbvDaBE16CT0V6Fh
         vAblxSibK4zINobGWh/lZ4k5ogdNljDid6Hc0blMPlw4u+ithTxTEliu2hqcVc7mG+yp
         IJ0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716908537; x=1717513337;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CcA8jmLHVmkwFgZE7Ouhj14ymQOjlzDqKSWHXNoW5/8=;
        b=MHPK4Qeg6bgKoQytMac90TvrdyoDkBORNbbxqCRbEjZR/6v8SsThhexQ4voyj53QRm
         pmmNouyEpvFb22J9L+G921Qyz9X+m0OxmcK/OxVMxajnhUbKUUqsBsVGXw6fWX/I6VG7
         I7SzoEIZ061sOff++peBjW1Zj8FE6fFp8PlSLnqfa1S3bGR8MwuFX0hclKJGcUxk7bas
         56QseMhRrz59pwU/C/owSBrLFjOtMkdF3z4zKMz7c5sd85tSJWn00t3GvG6TJhzkbPUh
         ZBmLeOUd2QvsTwOXpxtV3lCfFNq//TSmSDsV5aDuPjYqK8ASdgAvDS2ErLgaiUqs8m5B
         K1dQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVNJHi9YdTR9REcKYt8jjLz7fiXa3zxpUapAwS5SNqOKSmkmwZsrUvgo7ony8a4yR3qGXdqVIAq28ggTEuDmTz03KO+RO87Iw==
X-Gm-Message-State: AOJu0YwoF/iS8a8Ox92d7EL3anaB0hIPBTsacD5Nax8wwElicI5zjZfc
	pby8Y6O0nOhJ6Tva2YvfKoLCiYUKHdf8+xiZdKAVR0BQxCQ8Hi6r
X-Google-Smtp-Source: AGHT+IHmQ5J3GcDsLOyb92REKzMNC7gE16Ns7YIe6UBWWh2VCdl8n28f48zLyVoW1Co4Ws2t7wWQCA==
X-Received: by 2002:a05:6512:10ca:b0:51c:b73f:950 with SMTP id 2adb3069b0e04-529661f315emr11359585e87.43.1716908536784;
        Tue, 28 May 2024 08:02:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2252:b0:529:5ff:29b2 with SMTP id
 2adb3069b0e04-52936d9169fls879934e87.1.-pod-prod-09-eu; Tue, 28 May 2024
 08:02:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoLvQMm96HyNrdvU7AXU2jTd7MXX6oQZPPCIAbi6dMawhY8wrvsmT6QjYhEQn7H0DPX6pLX7kyw7ZOrpiYCLKf18i4Ysqe7sMGLQ==
X-Received: by 2002:a2e:b003:0:b0:2e7:6d8:3aed with SMTP id 38308e7fff4ca-2e95b24debbmr82089951fa.32.1716908532975;
        Tue, 28 May 2024 08:02:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716908532; cv=none;
        d=google.com; s=arc-20160816;
        b=jTgk177kD7564rUBiAX8ffQXqbDhib9V1xwN2nSMSOyTkSMQdPkXkrGnuWtLO3oQaC
         ZMkcGYVCw/rWYfA5LK0/ezkuWWKOV242T2Wl2FTpQI20f7qRd+2iFC2tIg5vu3x8h+Iu
         tnVmbs4pcWf+Nzldnje09AuToMNFNpt1EwH9chpV7t4/93t9XvRsWvKizsoTIThj6ExV
         Er4Evk7j2RLZWCzprBJImp0/pX1jkYRrgMgMD1YBVq3vJtJa1SxX3JokzXJZ+cQPOKSV
         2N+RSWufpacIbbAQ8pNkVxKZhAlPJ6ezQkILI0DjggWt+8a+7Aa9hoMfYTKaFx0KRqPN
         TF6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dKnPZ9OJHpypgolMUhUxX3o8dY3J/6CO95tM7cGqfv8=;
        fh=Rm/p3wQo2LHEsxhNQ6JLNopP//jmuEAIIvq/FmUO/is=;
        b=tt/fjyvZupI6bL3NoutqckxPnJv3Gx5jHCSHisI226Sfuo2IIaNB46RRNHWhhe77SI
         t2y7oJz82YrKQ5rN9IfxrYN7zpiUBciCSmj9iVG9g2wS64als69dSV60x7Jt5nD3Nc95
         iOpslsFfAV+nexKo9bUVG0W33PEFkafD8Ocz9UR7CHwi0mx2ADuprjlz76y4Uej4xOGl
         3bRfsIs1i4WSEc3bT0qjDvfKVmXe5ymHFFb+zFMBiOkLgEgvktTdSqdW8lZusOxr+Tpd
         d13UPs8LRSiP4HKhllGT4bgum4gHaZmJvB2ns6A3NuECyahZxsta7V/8TUmUG071QG4u
         xT0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=opoXfCNq;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.187 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta1.migadu.com (out-187.mta1.migadu.com. [95.215.58.187])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2e977ec779dsi1225301fa.7.2024.05.28.08.02.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 May 2024 08:02:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.187 as permitted sender) client-ip=95.215.58.187;
X-Envelope-To: glider@google.com
X-Envelope-To: mathieu.desnoyers@efficios.com
X-Envelope-To: bfoster@redhat.com
X-Envelope-To: keescook@chromium.org
X-Envelope-To: linux-kernel@vger.kernel.org
X-Envelope-To: linux-bcachefs@vger.kernel.org
X-Envelope-To: elver@google.com
X-Envelope-To: dvyukov@google.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: nathan@kernel.org
X-Envelope-To: ndesaulniers@google.com
X-Envelope-To: morbo@google.com
X-Envelope-To: justinstitt@google.com
X-Envelope-To: llvm@lists.linux.dev
Date: Tue, 28 May 2024 11:02:05 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Alexander Potapenko <glider@google.com>
Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Brian Foster <bfoster@redhat.com>, Kees Cook <keescook@chromium.org>, 
	linux-kernel <linux-kernel@vger.kernel.org>, linux-bcachefs@vger.kernel.org, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, llvm@lists.linux.dev
Subject: Re: Use of zero-length arrays in bcachefs structures inner fields
Message-ID: <63zx2cnrf5u2slmabde2wptxvq6a3opvrj2zrkcolw3gdkjdpf@bttdonbctura>
References: <986294ee-8bb1-4bf4-9f23-2bc25dbad561@efficios.com>
 <vu7w6if47tv3kwnbbbsdchu3wpsbkqlvlkvewtvjx5hkq57fya@rgl6bp33eizt>
 <944d79b5-177d-43ea-a130-25bd62fc787f@efficios.com>
 <7236a148-c513-4053-9778-0bce6657e358@efficios.com>
 <jqj6do7lodrrvpjmk6vlhasdigs23jkyvznniudhebcizstsn7@6cetkluh4ehl>
 <CAG_fn=Vp+WoxWw_aA9vr9yf_4qRvu1zqfLDWafR8J41Zd9tX5g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=Vp+WoxWw_aA9vr9yf_4qRvu1zqfLDWafR8J41Zd9tX5g@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=opoXfCNq;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.187 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, May 28, 2024 at 01:36:11PM +0200, Alexander Potapenko wrote:
> On Fri, May 24, 2024 at 7:30=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Fri, May 24, 2024 at 12:04:11PM -0400, Mathieu Desnoyers wrote:
> > > On 2024-05-24 11:35, Mathieu Desnoyers wrote:
> > > > [ Adding clang/llvm and KMSAN maintainers/reviewers in CC. ]
> > > >
> > > > On 2024-05-24 11:28, Kent Overstreet wrote:
> > > > > On Thu, May 23, 2024 at 01:53:42PM -0400, Mathieu Desnoyers wrote=
:
> > > > > > Hi Kent,
> > > > > >
> > > > > > Looking around in the bcachefs code for possible causes of this=
 KMSAN
> > > > > > bug report:
> > > > > >
> > > > > > https://lore.kernel.org/lkml/000000000000fd5e7006191f78dc@googl=
e.com/
> > > > > >
> > > > > > I notice the following pattern in the bcachefs structures: zero=
-length
> > > > > > arrays members are inserted in structures (not always at the en=
d),
> > > > > > seemingly to achieve a result similar to what could be done wit=
h a
> > > > > > union:
> > > > > >
> > > > > > fs/bcachefs/bcachefs_format.h:
> > > > > >
> > > > > > struct bkey_packed {
> > > > > >          __u64           _data[0];
> > > > > >
> > > > > >          /* Size of combined key and value, in u64s */
> > > > > >          __u8            u64s;
> > > > > > [...]
> > > > > > };
> > > > > >
> > > > > > likewise:
> > > > > >
> > > > > > struct bkey_i {
> > > > > >          __u64                   _data[0];
> > > > > >
> > > > > >          struct bkey     k;
> > > > > >          struct bch_val  v;
> > > > > > };
>=20
> I took a glance at the LLVM IR for fs/bcachefs/bset.c, and it defines
> struct bkey_packed and bkey_i as:
>=20
>     %struct.bkey_packed =3D type { [0 x i64], i8, i8, i8, [0 x i8], [37 x=
 i8] }
>     %struct.bkey_i =3D type { [0 x i64], %struct.bkey, %struct.bch_val }
>=20
> , which more or less looks as expected, so I don't think it could be
> causing problems with KMSAN right now.
> Moreover, there are cases in e.g. include/linux/skbuff.h where
> zero-length arrays are used for the same purpose, and KMSAN handles
> them just fine.
>=20
> Yet I want to point out that even GCC discourages the use of
> zero-length arrays in the middle of a struct:
> https://gcc.gnu.org/onlinedocs/gcc/Zero-Length.html, so Clang is not
> unique here.
>=20
> Regarding the original KMSAN bug, as noted in
> https://lore.kernel.org/all/0000000000009f9447061833d477@google.com/T/,
> we might be missing the event of copying data from the disk to
> bcachefs structs.
> I'd appreciate help from someone knowledgeable about how disk I/O is
> implemented in the kernel.

If that was missing I'd expect everything to be breaking. What's the
helper that marks memory as initialized?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/63zx2cnrf5u2slmabde2wptxvq6a3opvrj2zrkcolw3gdkjdpf%40bttdonbctura=
.
