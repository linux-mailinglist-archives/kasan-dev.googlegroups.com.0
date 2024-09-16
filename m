Return-Path: <kasan-dev+bncBDRZHGH43YJRBCWCUG3QMGQEULHLDGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id F135797A62F
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 18:47:07 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5e1b4d28e70sf1700932eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 09:47:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726505226; cv=pass;
        d=google.com; s=arc-20240605;
        b=hQgMycuIZockI5UW8ETlTYJHAmeW2Ff75bF/NOslTl6A1nWM3meM+MUi/41wxUczSV
         gFuyybO+8FsnYiV1OR5qmGGp39diCmfVbnHCHwV1mtLx7I5bWWDEhjT0zvOuev/yezdb
         otBnnU2GNkIoS/3DjmiJnVYm4dUP54xU47coOwFUN44ESp5rHUoZp2vRCwBwX96gMFnA
         QQXAQLjHXhj4m5jwWj0Atj2qC42qu/rNGoaIVWZsfQnr30LYHjQ0Mq6mTreHAwigzPlM
         rx5s1bhkAYv7jZzLPPn/HNns+cEdX0VyLLrIt0BIawExBAm1jYpwWj9B9Dda+09G0GG9
         8TOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3u82Htd/kLeToi4wnG6Jsd8oThu+B4heIOy6QUBWVnA=;
        fh=goId4H1Ul5e1iu+nZUFKuyQ9D8gb1xOt9u+kqy7kKIc=;
        b=cuW4WwEpB6PBwzCP50crov4iFsdUJM1SkXKEN75N7KLHRf1gtf9x3YvZ8A8tzYX99w
         yH0CXM3cIpGwngNckYiuZ6Ry97OY9xWFZMDSrNszmPcp+RG8JJ9mISWrkIH3IXXGB57M
         Lv2EniKNfZaCdshytu9pn2NMxFDkyJ9Zls64zXyMkaxzxsirSTDLka56KFCjZLy4qSa7
         DFtt9lKyOnKtb/13s205A8VU1zRe/4w3zuSpLiVWd5dby3WryDcbTAuP251yURy3telo
         FcXRZ8oocZUNihHFHawvVcm1k8mo1KPTd9BMzJn7+7onj7ri+8uBN/5j6lzELPj0yWKL
         w4Fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ub0bqxBl;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726505226; x=1727110026; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3u82Htd/kLeToi4wnG6Jsd8oThu+B4heIOy6QUBWVnA=;
        b=aN0Vs/5G64ZsyGq0k8nG7T2pDNg26z4Ll4Y/3d2DhkPYKbpTx9RIsyE1S8SvBUyM1L
         PVSqEo/Lk79dfCn90mX2VhF2jlFH2c/Avp97WmH/iWbOkCsP0RZSZuECIrQa9qhBVSX7
         136X6VztGE3yAh54/GatDUPKm3oy8BSO2jYFzeh0sV3c4Hh/p6Fsvh2/crhUaxbqMO5x
         DX7FPkj4XI9a+bDTEFGIs/TrOJ0A0nItFpxCHUHAxS1e66UnP3hwNImiY39x6ZXxwZJC
         6QWhGV2UCBtasMqwkceL0xTQ2Ekl7a+0Dbu9C22mRlWT43ADD5EIq/d96nvRa9g1M7ne
         SfzA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726505226; x=1727110026; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3u82Htd/kLeToi4wnG6Jsd8oThu+B4heIOy6QUBWVnA=;
        b=ghRTuKTVyYheJZHU3GuxAho1iCj7z7Zkdwv5jalt/fYN00xXFNPG23/9mZs8edYL63
         GSu7iRX+gmKWcIljzkg3qacA02QHHNl6VfF6F9/neJlMdS8CWNE/hI/UhMew8TSgo3Kh
         tZLXm2SA3ceSSuIOeO0ajcZ4xg1QmHx7Xs8XqbAoMxbiTZr4ls4yv6haD/8KWO9jv6TB
         TMHPZR9ZRM85zW2E+Vi7ga3H7H+QtrMaEaVbV6q7QDeJgt8TWt9hd9vYTvIu5WZsBX/v
         eQRJdqdZlGJ9GkXWQFO9yjSHOKzXjXcytgobJlS/eH2LtJ292yYf+RfNWQmo3gWcdKUL
         wzyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726505226; x=1727110026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3u82Htd/kLeToi4wnG6Jsd8oThu+B4heIOy6QUBWVnA=;
        b=N4szn+7c3wImo2NKT1ajH7oE4NajlFqybNKUQC0bJCa9QDzoVB8gjcqrc/2NFvq/dP
         8MM935/IaYHqQPgXVxbkw6x46ZqPiSWAqotf7181EMeVDAPmryvTLntu089q2L63t2Zc
         dCCpSwrDMiL1ruTR+bw4vAtWLmzwDeHNxVtY50zzqlVHOCoOzuxMT1JQd+AxrrsdkDGV
         KfjXvxzNHAlsOvztxuQJePBTCmdhbZffNs6CcWQf39lOAuw9rGJMMYC3+c4ZIoIKB8F+
         0i5ThKj2y9oxWznM7OXiKTNDfhKzrmNbeKV9IYSDw5IT6VGhXQKG7mlgk2ZcqoUZhIVv
         eJ9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcXhuR1MCNEJu6Qlt4f37OOdzB8WjhNnz+iSyKatOEpw9aSryHFbPwuTIgCQVDQIDaHYn46g==@lfdr.de
X-Gm-Message-State: AOJu0YxplKzhOBUvtgdL6qH7VuC+jCbJ0jLMxuV3N3bDg1OGizBTXLK3
	0gOXQZebsyaXf53dneyt0htdaws+5q8qPgDwvMuGqz9E+8sXHKl3
X-Google-Smtp-Source: AGHT+IFaaPwYldW1p6GNrmO0q1hTmp0dR/73vsdCAOmzSL4nVGmDvRl0Btg08pqsN8WiXbQSUvJx1g==
X-Received: by 2002:a05:6820:2292:b0:5e1:cd23:d451 with SMTP id 006d021491bc7-5e2012b6df4mr7602740eaf.1.1726505226335;
        Mon, 16 Sep 2024 09:47:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e0c3:0:b0:5e1:b910:c45c with SMTP id 006d021491bc7-5e200a4fcf9ls1626760eaf.2.-pod-prod-02-us;
 Mon, 16 Sep 2024 09:47:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUb7RRP0nPsyCoybqREhnCtbzbKkPGTLW3Vs3l1fOqr3ABiwynW/e5HWWQIms585FAbU+U+XuRv2OQ=@googlegroups.com
X-Received: by 2002:a05:6808:6491:b0:3e0:47d7:d6f3 with SMTP id 5614622812f47-3e071a8f5bcmr9463353b6e.3.1726505224973;
        Mon, 16 Sep 2024 09:47:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726505224; cv=none;
        d=google.com; s=arc-20240605;
        b=g1bB42ZRRkbUNmMG0zy9BPAxjBY5pTiCWvByWsaHqonj/kt7QyFka3EA6EzwCdRBRh
         xterGuFR/rOd/Yal4kp0Emd/mMtd+UzewdqLSKF0+BrgYqRRyAdUyZta+8aP65mQvevv
         9n0xlXgJmQnQ2TGT9Holk34IQQxD+O1+VFPbEZOwW5qhpIxU2EYRbQ7iO0St3DgCShbR
         LT+HLVh9irHRGj/rylwPJIp2nl3Mv7cX8l73eHpiSxLDJMfv+4D/+ZEOPRMoXaS+V+hS
         vJLv8B3+EPIifwCUODyDDUDcZOkI7SH7iQ3s8kaWGFL47Nk5ZI3bIV5nfMNLlkg6SndN
         jPlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OzAN0xAvRZHTYmrnU/A3fZSEHEklGK3Vjb/1gDLdIyc=;
        fh=2zRMg6jdTjXFfOkFaxBoxZj2st/amHkmdV2uQXbIMxE=;
        b=Lc0mxYCMPc4ddRFmND5Aos2/A7l8MmMZxNQuC84gcSM+p5H7GokCQcciYoz/30F0ew
         ard9esaISm3w+DB75f5AX3gKZDN7TCGlUURzTHDFeDhv4P5/yg1Vz8Gqm4ijowsR0qvN
         YF1IJCKz4RFwWIP6m00USLil/rwgWB7K1nOQIB38WJc9WTPY1ok8ZB5na0Yozc07UWo4
         wgmqKU2RYAXrD6TIbFvY2Tm8HxDoA6pJlfmEy1gHK7EXPkE8zdHq5rBQP6wYcWmvgrRt
         aStfV1XUIOAhZx6GhTbIZlINvUGF3ehvtlkzdzozL+yzSq4oSYqxrytWvB6W7UFoIcUs
         fq0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ub0bqxBl;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e166ff9570si208059b6e.4.2024.09.16.09.47.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Sep 2024 09:47:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-71797e61d43so654998b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Sep 2024 09:47:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU50vY82L8P0kFr7nbVGpDZgUdKM8XJtvuNdkOQRXCbfoU1DcjT1FjGUXpoRmYJ4ncnzvvI9Y7M7bE=@googlegroups.com
X-Received: by 2002:a05:6a00:9163:b0:710:5243:4161 with SMTP id
 d2e1a72fcca58-7192620609fmr9753938b3a.5.1726505224337; Mon, 16 Sep 2024
 09:47:04 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com> <CANiq72mv5E0PvZRW5eAEvqvqj74PH01hcRhLWTouB4z32jTeSA@mail.gmail.com>
In-Reply-To: <CANiq72mv5E0PvZRW5eAEvqvqj74PH01hcRhLWTouB4z32jTeSA@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 16 Sep 2024 18:46:51 +0200
Message-ID: <CANiq72myZL4_poCMuNFevtpYYc0V0embjSuKb7y=C+m3vVA_8g@mail.gmail.com>
Subject: Re: [PATCH v4 0/4] Rust KASAN Support
To: Matthew Maurer <mmaurer@google.com>
Cc: andreyknvl@gmail.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, dvyukov@google.com, aliceryhl@google.com, 
	samitolvanen@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	glider@google.com, ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ub0bqxBl;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 16, 2024 at 6:15=E2=80=AFPM Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
>
> Applied to `rust-next` -- thanks everyone!

Also, for KASAN + RETHUNK builds, I noticed objtool detects this:

    samples/rust/rust_print.o: warning: objtool:
asan.module_ctor+0x17: 'naked' return found in MITIGATION_RETHUNK
build
    samples/rust/rust_print.o: warning: objtool:
asan.module_dtor+0x17: 'naked' return found in MITIGATION_RETHUNK
build

And indeed from a quick look the `ret` is there.

Since KASAN support is important, I decided to take it nevertheless,
but please let's make sure this is fixed during the cycle (or add a
"depends on").

Thanks!

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72myZL4_poCMuNFevtpYYc0V0embjSuKb7y%3DC%2Bm3vVA_8g%40mail.gm=
ail.com.
