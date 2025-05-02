Return-Path: <kasan-dev+bncBDRZHGH43YJRB6UZ2PAAMGQEI6D5W2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ED62AA7421
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 15:47:41 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2ff64898e2asf2446483a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 06:47:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746193659; cv=pass;
        d=google.com; s=arc-20240605;
        b=cWws7SwgSyYh7Zx0eHflZQTh1FoRZivt0C9mfy8RDrlxQiYfZGEc+hcdoCCy4qbwR5
         w0Cv/dfiKSJBVrSiBjmfMBsGOiHR44ioZCpGsSFeH7PERuobazZawfPoZwV8Os9EH70z
         h2tyT8A1kOcUfT3Mr8qRO8Hi/BKSRWo19G7hefkaV8hAiZ3jWcJN2VV3g1rHhYFK7fXz
         aUsHJS1dV3dgCitA1TU9jO3rbbMBAe8Evcogq3kqik4m4ihpBaqG2Vr26uB7J/0zeADu
         +6lZszyU0qzs2o2+mFcvuvSGxmOpWZ+yfZgeIRaR3tfmh5mkrqR3uH0hBNFcITDGW8ey
         oFow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=upwTmX3xQaTjnBzVJKVbRONxyKYHHGN9eCYIcJhPYt8=;
        fh=miosNg3dj5ZO7T0F5AgQ077U/0Gu5bPNjmLis286tY4=;
        b=kigowHtd1RFLDURwT420YWlPGYfJuGllLpamKtdz059NJotuqROlWWBpnefx1lOxBr
         +zikZdU656dQ+270AVnp7LjOnGGnm4GjodZc3grxcMbHUTzHiPdJfwuEFpGopjcRAgjV
         HTt6KLFnOAC9ci+Dinb4dwvQMuz+8lQ2GdxOviNI0V6NWTnfUcitEepmGFFUUz+CymvD
         fHnDipVO2wenp28Hg2T0CYIA6QuxQNMJH4UzzPyBVn3NYOog6zoSRFy4zuV+Az4fuONb
         Vp+svnI/AbLKRBfGbcB/T7UKxHjjI6RKCnRzyPtGIlvWlPYJbGgpjRsI4rULim0xY1XP
         dgIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MV5M+XSY;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746193659; x=1746798459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=upwTmX3xQaTjnBzVJKVbRONxyKYHHGN9eCYIcJhPYt8=;
        b=kgEuKzmY8EEoewAQL5pmezzbEPiq5pJdJMCKqE9uOEE6c86pqX6FeE05ot43zTtDWW
         xr2W+fPI8JhByiDwuQaX3F5AvsVw3m2kZxIVw/t0n3OXJAthsUW2P4WoGZ1m72T0/2FL
         4aQ7LQcTthpJLObMwphaOlk6+rS2VNbY9Pf6OYcn0gQE44HFY/IdSkGh0y07JXfA3JTP
         rrwEzQBpCsJ/a5J6U+AqbEEk0bo+lmjvyXFpQYkQW+Kz0XKpTNlcbWwBj13uWWAgUsoE
         kF0u415qEbpy6J+MDnIUclv/73FjsA+qXbDx7TE/XY+SI4+isNnREBrqNNpWzmZ4aspX
         3A8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1746193659; x=1746798459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=upwTmX3xQaTjnBzVJKVbRONxyKYHHGN9eCYIcJhPYt8=;
        b=NdgVmHIkLUen0V33fUjda9V7brr52gzzgbIAXWA8LZd9ygt/cKsRKcx5F7P0rNp4Kd
         wAC9S7abiwb2OPc1LROkoU3SYFWCbwanCrWnubCV4n5fkpftz4SQ1GIrpdpWBnVD57RZ
         BlC3POz10sW8fcWR/Y5SS/me/Bpxq6Q6Btmf9Wbb7SMUyxUsmiMtCoVCwyurk6TKDOO1
         OZGUMARA3rQXclw6nITqvlZh5HxCngGoYCH2nIAU6zF+ar2qiB50yIvvBLuN7+c4NFuZ
         SkcOoFoC8aDqsOAZBWISHZgGNFUqb7LIEEChFvPiRMVL/1jBm66qUE5OGv4LsqXYQnkI
         l/fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746193659; x=1746798459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=upwTmX3xQaTjnBzVJKVbRONxyKYHHGN9eCYIcJhPYt8=;
        b=iBhn8+rHVuseJr/I4bufmZqpUFR2OjkH6vU4L826WPI/ebbGvFJ4JUBn9wxcAMazUy
         YqW5JoOhX6WddUA11m+1T3/EXb21IfiONq840j29LJagNSEItK+GLpaUq2rHPpGlZawv
         Z23Uhj7pB9wwo+t/Ij/es8FblyJvMzHyZEHfP3WVFWBp+ghPexKlkGj858glGYiRwmx5
         YUOKsHmnAPXMaxaW3/BhPc6ZdEITfEAG+2EgM5e5GOxSAmlUGeF4gMs4xcLBLVdyGg/w
         9Ckis12fl0SDuafpZE0xWDw4+SjQqf3zFvAqHQe1Jn/hTn8W9/uCkf+824ZgI5Ea/Qdh
         ka5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCViMAhPnz3hesoyT8v1Jnx3RPelbfJMUrrqCcvyuTddtwSMigzI5xAuG74q8U2YKgYssdx2eg==@lfdr.de
X-Gm-Message-State: AOJu0Ywscb1J78EGjKyvOuveh7QEIWPfp93cVp9my4/2q1cJMEdfgSxz
	IWS79Z/HLORhZwzH4O1svttQLNiCl2AfCzfaxgi/07hE40jfEjlF
X-Google-Smtp-Source: AGHT+IHHZldHgfHHuaZ8bqEGxZYbEoQNDsscDu/mH3eyyq2zjeOEINH62GzOf9tzFD213VQr7X/SOA==
X-Received: by 2002:a17:90b:4c51:b0:2ff:5267:e7da with SMTP id 98e67ed59e1d1-30a4e1c94c3mr4465686a91.3.1746193659224;
        Fri, 02 May 2025 06:47:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHRfKxDP8RTyn4TmbawuY0G8h/3Qcq4ih0d0YSaDKzTNg==
Received: by 2002:a17:90a:d382:b0:2fa:5364:c521 with SMTP id
 98e67ed59e1d1-30a3e898bd8ls1308712a91.1.-pod-prod-00-us; Fri, 02 May 2025
 06:47:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlIlc8XnHK8Rl8FXfPKoAXPv8G/pcootdrBDFOVFpqe8F+m0RklF1pwB9VuDkmWi8ojBoe+SnwR8M=@googlegroups.com
X-Received: by 2002:a17:90b:55d0:b0:2ff:71d2:ee8f with SMTP id 98e67ed59e1d1-30a4e228565mr4935179a91.13.1746193657484;
        Fri, 02 May 2025 06:47:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746193657; cv=none;
        d=google.com; s=arc-20240605;
        b=MRHWxRyQYFjo0Pxs4uU7BG/2+MnsvZ179qhSPflJkIWItwFgVrnSII6VjiQzR3vxpq
         lFhKNjQuXMGQgjmbotHMETNelYWn8h1PNhjVgVD47lJTXzQt3WD7Wx8eItDO+ysIM+CB
         3O/zUELNlKhpThXjP/Y3K992lVImw60mZWa/10QEhfiNM2N8GMmz9CouAF44JJsvuRGk
         7QqsUzgPbysSeABGNsCXaNJUYXgjrNYDRr0XNuAGZGn8ILoGdAEOdt9wKOz5Wsm+2H7o
         CZWX/mGwcYsSG/LyphyO59cval4ziYHAzJ0PSSkRTNrSO9CD37x4JqOIvf5pqkNhvJHV
         a5yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YO7DeRcZqOkyyJp/N9tF4f54dRAU+mGMvwJb68kNOUs=;
        fh=U7ZRLKQ/KFHhXz3H5N7k6GnnFbegM06jw/VIppuV3ic=;
        b=aJv+NFDVVOSqcSu9Lh+UnSVOzbo4Gd7hsKZGolLONK3mMgc/8filxj2HbXqXKUNjDt
         GIyMsZPE179FI2TLujKC3B0OOPL8l6xAhY95IrKzpRHWOevxRiVvHb5C/M3dI5Ymqj0n
         jqf0+aLLW5IVWNmNg89pa7j+NELWqmOqUQ5BhsnCg0R+bRTEmLTybADG63ko5wo4sMgV
         +HxT9IjE7bihTM7TocewQ5e5CCCBLGydkfNzFsRoFbPvUEeW3ZLYxacocCSUg6VLjLbg
         noellZhEBXZsR3OH96jKr1fW6/TBp2E8u/t+pPPgeNK1La0/r7n532eM2tRYLffQ+Lel
         RLMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MV5M+XSY;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a267d107asi442565a91.1.2025.05.02.06.47.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 May 2025 06:47:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-227c7e4d5feso3809175ad.2
        for <kasan-dev@googlegroups.com>; Fri, 02 May 2025 06:47:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVsCyqK/E+vaT0Ac5hlCqFo5nJnyZ80m7i4JPJHKfAVKR0Odc50QBY0pkGx7HvPJlJhbI5sBy07Oe4=@googlegroups.com
X-Gm-Gg: ASbGnctl3DPhnMB8RQL4srdOt8HVEYsWvMGtiZN7h4J853N/1fbQQi8kZmD91faiA8a
	TB9AQI3jCuQxpK71AVCuf8aP4gYNjd8ENzNOuiQraTfv1I13ShBmbKmFrsLRj6B5fFwRmz1W13H
	1AaL3Rchw1Jd27jYVyxNOusA==
X-Received: by 2002:a17:903:2f45:b0:22c:336f:cb5c with SMTP id
 d9443c01a7336-22e1031f5a7mr16755265ad.6.1746193657040; Fri, 02 May 2025
 06:47:37 -0700 (PDT)
MIME-Version: 1.0
References: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com> <CANp29Y41LKZg-kSP+j5hjUKMNeWnPsVd8VvDnOpN8+4WHHjEgQ@mail.gmail.com>
In-Reply-To: <CANp29Y41LKZg-kSP+j5hjUKMNeWnPsVd8VvDnOpN8+4WHHjEgQ@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 2 May 2025 15:47:24 +0200
X-Gm-Features: ATxdqUHPzjJxM4ztTNooAwhiGBxmesfG9DnCr-xy_d1ASwZ94NEytM0G2eVkbK0
Message-ID: <CANiq72m7GAZ4gfgiU5bXSb86R3-UMG2vsvi5J1Ua1EpVV5EdAQ@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: rust: add flags for KCOV with Rust
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Alice Ryhl <aliceryhl@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MV5M+XSY;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Fri, May 2, 2025 at 2:36=E2=80=AFPM Aleksandr Nogikh <nogikh@google.com>=
 wrote:
>
> Thanks for incorporating the core.o change!
> I've tested the v2 patch on my local setup and it works well.
>
> Tested-by: Aleksandr Nogikh <nogikh@google.com>

Thanks for testing, very much appreciated.

Dmitry/Andrey: I guess you may want this to go through your tree
(although I don't see a `M:` there), but if not, please let me know:

Acked-by: Miguel Ojeda <ojeda@kernel.org>

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72m7GAZ4gfgiU5bXSb86R3-UMG2vsvi5J1Ua1EpVV5EdAQ%40mail.gmail.com.
