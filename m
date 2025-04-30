Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSMZZHAAMGQE5WYP7LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id B480EAA5152
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 18:16:11 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6eeb5e86c5fsf854996d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 09:16:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746029770; cv=pass;
        d=google.com; s=arc-20240605;
        b=iCbvF468TBJe/MQN6PuRYWp7xUGucD2FfEnnVDyfdnxnfLr5MfpOkvTg7Hu8r1FMkl
         hkIPNboEpMlRVRNabH5ndUb8LEERALfBXXiTjqZ1yBTl6V3Y2IoG3HbTSKZI0hkWdp9s
         RcjAgkd3/5Y9WrCrVXwxofeCc+eMpdSO1TlhRHEJZJUI/CwagMM2/MmZMQxO0HGH/na5
         407wXS04ufmAxvkIMWkOeOAW66o7WHfccwE7Q1RJRjcQAppvU7aaQpdvCYuhflHGeBI0
         EStRjqTHFLEgi9LkGiqM6L2VNO/nJvsJWO5D0Np+ayQ1+qv9xzAixTWW1nqhIPBNBR2y
         Awzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=waZqKzVfXUHZbE6O0eKwYtOusueUGJbILcZ4oqEUJhs=;
        fh=xFQoBDK7NYEVdis5uFVeRachL2bBeADUaNJpPyZtTo0=;
        b=DPVgPsF+NKOYNcxEFZsY18kDog0GJpl4Pwoycfwne9EhbqQVx7VXYdzI+16xbyLYH7
         oPjMKN8NpsvCWiFaf/liPN7NpXqE0RLdnm1D+VePG3ryg26AAO3iT3P+RnhQJgsDfIjC
         SSOK6ZFz3Uf+8E81o9fdHCXc1Qpfj6ogpz45qObRyTGFxmVDHnwQkIGyUp5Vho76rin+
         hfcCm2aR0Xpd0YaQW3VKTpoYI03CrDiiYTh2prkAU2qnmCwOPsfMbuNzd76nXcd+HmxM
         8aaFocE+r2abxxGs8IzX+4tWHGaKkRvjGLbKRWT98nynzPfteOBVWXtLQ4KOos+smrgy
         vGZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=We+B+cvY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746029770; x=1746634570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=waZqKzVfXUHZbE6O0eKwYtOusueUGJbILcZ4oqEUJhs=;
        b=TuMmv9fIafZun7vzOicN9fr+7gZezO+qGBWU+bgutRfSDwqS9Fo8T3PcJLvkn+Ssqj
         y9bDW+31PAQDOytX2SfN9mSClxo2a5nDS4T8gVx/kf/k4rZ6Lpg+2Zl3t0PIIkLZvQ1F
         /uFFLv47ik909iYGuVpz+dUVsYi0bJ8HRc0HLimzXLQzM97oB5NFBTWgV6vtowrdw4/N
         TO8micq7kNCK5DHsY8Fx+jPeH0A1B6oNXf5/heX3ZPVzCJjVv1qCVvm/8SgbtOvfIG2U
         3KUCjOUIFXfAjPn2g27+X/5HlB8gMWqLRNmB+f4JqiJChF5nv4fOLio+c39wRIOm1uEr
         ag8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746029770; x=1746634570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=waZqKzVfXUHZbE6O0eKwYtOusueUGJbILcZ4oqEUJhs=;
        b=UKJvr/Ek39qte7gSxAGtcyVGPc5spo6MqPUdKFEBojn+dWOu3IvrK6u5DA0553qnVM
         xCSX+QY27d4JJolKGZMJRn8HKfpYrZFkBAZrhBxcjMR6XE0WYNs6bfjvrJaeuKR8BHHG
         DD+GJ/c+HGkn13LSf9WzfQf5ilXSxKzzVasS6lE7xorjMfi9B46UcPZDdeIm5KpMRXEm
         IstwMk0vXw5MGOzZfXYtNW5tTnxPgH0ur5PwwJY6LPqP6+EWKAZOFdCU5532Yq1cH28l
         Xna3VMSDc7DaFVajYyXor2qkpNy5Yb00Wve9AqvmNRjsInSN7IpMrWHVx6rjZETYuJvc
         ZDzQ==
X-Forwarded-Encrypted: i=2; AJvYcCWT+542DxKS2uzIXyaap4ksyy3qaNuhyve2sk2xpAQO7T+IJDjwB/DI9fgpSA73z2IRZAwYjA==@lfdr.de
X-Gm-Message-State: AOJu0YxCVseWr3uqeGkc6TSjSQEglQMSL+5fASEAXQrLTTF21Yh0/+YZ
	2e+WRVJ6am2NtioUY2kOzg5hZmgVGOxn+R/0Br4Cbo04Fr4ELKWC
X-Google-Smtp-Source: AGHT+IEBJGkekt/4qHdQlVxv1NLajiQk5eygh6RUgMhlVFtsbQ44fW3JddGHj3uyNJdmmxq/eYUyVg==
X-Received: by 2002:a05:6214:1bcf:b0:6e8:fe60:fdeb with SMTP id 6a1803df08f44-6f4fcea5432mr66044596d6.17.1746029770083;
        Wed, 30 Apr 2025 09:16:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFvepHh74YKa7gSJj4BzP4fS+9XMTSoe8L5lDrFdYDsBw==
Received: by 2002:a05:6214:1942:b0:6ec:ed6a:47dd with SMTP id
 6a1803df08f44-6f508523040ls1466136d6.1.-pod-prod-08-us; Wed, 30 Apr 2025
 09:16:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWskkhIpp/Cs4t2TkjIADBvEllDiT0DML8nf4z9In+SYmmIqgm39wpTLqmXdxAkXY1ZoPj2YM3isb8=@googlegroups.com
X-Received: by 2002:ad4:5ae3:0:b0:6f4:cfb3:9de1 with SMTP id 6a1803df08f44-6f4fcf9ef86mr54354916d6.40.1746029769101;
        Wed, 30 Apr 2025 09:16:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746029769; cv=none;
        d=google.com; s=arc-20240605;
        b=eCsvC4f5uFyT7nF6lSCExURvprRQE93CA0P8G4nqGx5MYG2pZ5sDrgJcjhQTq0xutt
         2lpXSRiJw9Qu2jfPdbrgCzPftqBvRVfjEVdbQ15mzB2LKoR/Xk/u2x6sPN7o+19PA71x
         I0sVfvXN/QZEr2goxN8MZHFji+VIa5ZUHFyyrj9dDU+KExlwOfOpNTL4oYVMpva0PS+s
         oCGLrdMCSJxvcQU4ImJtc2EMudmAdhB8vGttiDPigy7BHzqHG7cg5zx+FCdy0QFS11+D
         Btf5J0B8E5nTwPPV632FCPhLEVfqWKF8LyqNkihWG557gvngRycMW3eMA3DicW7CAHHH
         U6mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=k7I4v82gj5ha2wfX4LinxA1Yg1t64C5c1c7HVqM+iLw=;
        fh=/pQjUY5tEHB9MJ8hS6gGS35TTCMYoAwNOHcdauZVKwc=;
        b=QawDZ6busFoZw5FLugBb/54r7v0EORjrSbTr+Ida83bz3F1iEk/ufqwVYkdsyAzySD
         AYOVklmKm3mYG3+Rz/+4LZDbzYp2ItEL+kmmvfT/vvYDfJ/zWUffAs1KSJ4At5cVrQAd
         Gsv97JdVMRSGo6YQllro4+Q9QUcr3yYZn53EKdSj0xcBf8McSMeOtoSG2p+4YzVkJrVV
         k3YetUtMLqCBG08mlDmDtDA6raPXOcmUFUNkwOUhEjCYvNHnAXuQd+lKsJN8w6ScXwF0
         433RvIlBlPaA1fklFfyr+SX81krwFynPvwPUj064IYXRSV3WWxmCv4ad3par7tHYVUj2
         thtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=We+B+cvY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4fe6aa8a5si813016d6.2.2025.04.30.09.16.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 09:16:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-6e8f94c2698so633336d6.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 09:16:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+hw37upSHNQlLy9LXFrJcEu27V5w4aATwOmtvbB85UZRonn9oWWzp1WmIYsOYBgamWkOGumrOY24=@googlegroups.com
X-Gm-Gg: ASbGncu7R63sHMgAJ3At+SdMfeczqHlQ1YW27S4IysOgJRN859deL/fLiZbDo8WgaGZ
	BihSsz8dYb55cL/SxlV3iXNhykRJa4Oc8UF4uw1q7M0CyrIOXyKiYJohPcybGWUIpI5jnrVOalk
	qFihESecckjiVdrtFrjewdab//Ho70TO6tDE+OSC4/SxscMwpBYNU=
X-Received: by 2002:ad4:5c62:0:b0:6f4:c8df:43d2 with SMTP id
 6a1803df08f44-6f4fcf75780mr63178966d6.35.1746029768272; Wed, 30 Apr 2025
 09:16:08 -0700 (PDT)
MIME-Version: 1.0
References: <20250430-rust-kcov-v1-1-b9ae94148175@google.com>
In-Reply-To: <20250430-rust-kcov-v1-1-b9ae94148175@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Apr 2025 18:15:31 +0200
X-Gm-Features: ATxdqUFTsrw87yiAkUoAh6if5K7wSAisaG3kMae-iYUZsldqIbdRSg1dOLfX6vw
Message-ID: <CAG_fn=VoGiRmeYZ=tN+e+R=6VU+piSkdzewwVGuVhfddSTzu3w@mail.gmail.com>
Subject: Re: [PATCH] kcov: rust: add flags for KCOV with Rust
To: Alice Ryhl <aliceryhl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Aleksandr Nogikh <nogikh@google.com>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=We+B+cvY;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

On Wed, Apr 30, 2025 at 10:04=E2=80=AFAM 'Alice Ryhl' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Rust code is currently not instrumented properly when KCOV is enabled.
> Thus, add the relevant flags to perform instrumentation correctly. This
> is necessary for efficient fuzzing of Rust code.
>
> The sanitizer-coverage features of LLVM have existed for long enough
> that they are available on any LLVM version supported by rustc, so we do
> not need any Kconfig feature detection.
>
> The coverage level is set to 3, as that is the level needed by trace-pc.
>
> Co-developed-by: Matthew Maurer <mmaurer@google.com>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> Signed-off-by: Alice Ryhl <aliceryhl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVoGiRmeYZ%3DtN%2Be%2BR%3D6VU%2BpiSkdzewwVGuVhfddSTzu3w%40mail.gmail=
.com.
