Return-Path: <kasan-dev+bncBCG5FM426MMRB4O76O7QMGQEH36VZRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id ABE09A87EE7
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 13:22:27 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5e5d9682f6esf3682858a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 04:22:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744629747; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wq2ybWrZXPDS0xUiRDAkNigvt9FzfjWij4aQ+Ua+GcCTiln1b6IMk4y6cTBldcZN1u
         Q+GIB0WGv8rxmI4jR8i8uN+/Vvip/e3NPRhQG2cAh+zd3wSAitaKyyywtv46FeDBH+8t
         gVGhpBDfFqRwvgy0iZI5koJik+5b2ucHBqV4Mbg3S68ECEVwBB/bWF7tbm7+e4SXSmyN
         1lESSzYKt3mCdM1EHmrWjFU8puZA8NYBOc6qJI6n/FOaKjOO8pXyIO2Ogh/Vw4UeY2x7
         hZvhhVgrGjngtb2vVzvXwjiSJiPGIr3W2DaNWzo6xuLhljSoFSzb780pz8E4MzMDtqPa
         TKTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GdV/b6qzV0tonQcMmZ5VspePR69DcmmGu3yibig5qYs=;
        fh=8yjgjV8el+B2b4xdXLkgwge7zskoeeFeohqNfHsjkWY=;
        b=j4OLOyfBzMut521BVM6SWjdpfN6mOE9Ycdh1BsMstLoxpM5SSu4LzskIBeq4rfi110
         14ENGaSfrJ6V9CCopmmH97XmyDj9VcIw9wzY4dY0zRNIAhJjPSV+2kyZ8UcSARlvSvqK
         Q1IIKOzSJAAS9+h8vLWq4y7ZARXh3wzFB99GzETewVbw2m9Ox8oOg9rGUU+dJuLvRQg6
         j/3n049hMyhM8YapOLH37tMKma/uggdh6Hyu3cPBvUyjY+hPojtfPcRbj3TwbvrwrWfJ
         kwDMq7ZEteeuj0MyGLkTkaezooq7gJCaPrPgXPrc2Q9i1hHcJF4pORuooCAtKBBRDFDA
         o/pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TcGSP6Zj;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744629747; x=1745234547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GdV/b6qzV0tonQcMmZ5VspePR69DcmmGu3yibig5qYs=;
        b=M/CkL6snI729OddDlDQRbYu1RHnny8uzwduI6eb/vvEhS6VjP9iRm8SwK1miqB2MT1
         XVDYqY/J0fhgYBiCdZ+aOKRRVHnjhxCrVx0NwZKoDv7kxl3yAPEsu+ds5htBoJqXJ0/Y
         OZAZaqvVrqKPlt04IsGOE8wFqL4ih6KwoOr3Afklm+aN/cKgM8g/2nHZxt8LEoiV9LCQ
         h9tBI0RTf4bRpRf8pEaA1bQXopg83L+EAsRklCRyHmbgA0D8xQHF7MW1cBwEUHddddjw
         Dl5zTATFgxofPhrK5NWQQ3jL1BIkFAL6AuoO1Tf/KNOm9FCyN+LXH8ltCXg+nx8KqH1W
         A+JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744629747; x=1745234547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GdV/b6qzV0tonQcMmZ5VspePR69DcmmGu3yibig5qYs=;
        b=QmexHxwzWujOwB3jjiBie3Na+L301eckXyl7IvfnbJ8RPfx67SVBHUBl0sdB5iXJAz
         sfPc9b+1+QbKRJuUclFuYbbs9M5+x24yBbqWEXsJkDRH2vdt2Bp4hmO3ibIRqEH4qwMn
         01UfPaixVfsHfi3+voYdZ7HvIZP4/x1sgsjGwpmdav222Jz70v3k6+E9lGr8fProxkEq
         N4SOBXe+NgMAHrzM8X++I3+6lRqtNLiVVA1K/i6xmU2POwe1v6Fm2/MizCjUbl09WMhn
         ElEAsR71UVmz/7Ugovp4H5H9IGgDCN11izakny13A9FCWaYGmK2xOrYiTYx9Y5Kg73rU
         4bAA==
X-Forwarded-Encrypted: i=2; AJvYcCVLqAOSey9FimYal4j0lLbcSU7ijS+3VoDhhqDJ+zAXcswCbT7bhbJ5HvSIJcCMK0xoEf5iag==@lfdr.de
X-Gm-Message-State: AOJu0YxpvvxSy+nb1fzQ1zPQ0iL+WdJMhtHmwCPZ4juYoi5aYlEcFMfq
	bwZioLFmA5klzuTXEOEhyd2lhd5/xBrwMM3PPCzjNNGXfLJweYGb
X-Google-Smtp-Source: AGHT+IGQ8xLpZLjglofCIrOh3etn6HCmHDfB2+gz7et5bqir2vquPay/VeOVT9GrHZJXl6ObpNpMwg==
X-Received: by 2002:a05:6402:348a:b0:5e7:8be5:d189 with SMTP id 4fb4d7f45d1cf-5f36f780cc3mr10980372a12.4.1744629746036;
        Mon, 14 Apr 2025 04:22:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAItDlJCnsCmgGMznIC6kEgXFzG60Gsy223SQXkvgx9I2w==
Received: by 2002:a50:d499:0:b0:5e5:2962:b501 with SMTP id 4fb4d7f45d1cf-5f3276aae29ls140661a12.2.-pod-prod-01-eu;
 Mon, 14 Apr 2025 04:22:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDi+icXM4ax4oNPZ6TRNB6Ll0PqxTNqshP8Tzy50mu2iU0kzclwrlBXxe+SK1A2MV8OsYL3vdZrzI=@googlegroups.com
X-Received: by 2002:a05:6402:1941:b0:5ed:5554:7c3b with SMTP id 4fb4d7f45d1cf-5f3702879d7mr8977196a12.32.1744629743376;
        Mon, 14 Apr 2025 04:22:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744629743; cv=none;
        d=google.com; s=arc-20240605;
        b=cTNpVETwPwOE3/5MToLHJeD7puoskIGr1tsx/7IV8WuzM3w/lW3XTOrlACTgST9ITr
         KwNRzMijacxLjaOg50bKbrqlpvY6YgY05RqRYjh+PKaB3Wca7KdItcmjvTaM+AXs+9++
         ybqdRg41Awmap5wEXuUMhH4PBhwv0Kfq5xKgENwqqsx4evGwwoiimiWRLPxfdAY8zuSN
         rpw5VptDpS/0mzv94SX+nHHTCBMnUn0NaGHiKD2sw9HIqYIYDaH3abn4/ecBzMx3U/eV
         e4eqSBa17rRM5Fduob2Duupf5G+zRrG4EupwesvJM+4sb8U8GQ5Ec4pgCe485upROqMu
         CrlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Rft3EAUTLyhnp7+tWC0d5mWYcohYnVvJHm8W23d6BUU=;
        fh=/8Qtn0VpaWCwBiDUehU9vE/YmyRfWjuFJGugIQoOx5E=;
        b=MtyvGYzw8bzE5eG2h2+SC7fD+lIThRNHRRmFmg40oD3394ebacrc/BtCA59STOTHRO
         EgiGa2GlhOf5GLg+aqc0aJY9pUGvsiCWl4byE9FRa8YhF2CzpXxcts+IdgqdZpLgfoBk
         1C+HnPIJpxC6AhcS9WJF02NVW93cBnD33u2h2LG9o+UySQTjHWOvowU1ypwARnBDSTg8
         LKIVpMIxXMMmzFFpDZC+Bqbm6unQLO1Lt+PXgk2m8ECdof4mhtzEGbydIi82RC1KDo5H
         I7fH7Wo8FHjKEr42guon/Zpz787x5aviFwFy4zHqPP/um2RU3u8vBTGKJw47ithD06G1
         PlrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TcGSP6Zj;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5f36f2e64d1si192252a12.3.2025.04.14.04.22.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Apr 2025 04:22:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-43ed8d32a95so35409615e9.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Apr 2025 04:22:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfcIiWOcIOxCm2VV6NAPajRiX6o/eODYNK3RSBboMa5YvOJ3CzI6XYHBanunV+0SJzkPlVGFA1xZA=@googlegroups.com
X-Gm-Gg: ASbGncvX44JK679woDLj9ufk82n8zPGppsgb4kdLB5sauRDJZjDVSEMWngfhvjefiq1
	V6kBz3yMMBpuVfjvJk93rIwbdh1C1sT7QNb9EypGPD2WzdZoH2+daR9uqL4w8DjNqXYEGsU3gQI
	PqV3ASpqFxh1JbZgGFpw8NwaqLzFsrebIxPm5DAdBxpxfddqKaq5Y=
X-Received: by 2002:a05:6000:2405:b0:39c:1257:feb9 with SMTP id
 ffacd0b85a97d-39eaaed586amr8788733f8f.57.1744629742684; Mon, 14 Apr 2025
 04:22:22 -0700 (PDT)
MIME-Version: 1.0
References: <20250408220311.1033475-1-ojeda@kernel.org>
In-Reply-To: <20250408220311.1033475-1-ojeda@kernel.org>
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Apr 2025 13:22:10 +0200
X-Gm-Features: ATxdqUF9via54VPG5nlOhtSrUPwWIS_mfTXT8g_wST2xwdZg_Zg47Lq68Zxptiw
Message-ID: <CAH5fLgjb3Wxbkzvvy9H6QUYVpxXvkse1rnDmmR3nVHjp6zEx9A@mail.gmail.com>
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
To: Miguel Ojeda <ojeda@kernel.org>
Cc: Alex Gaynor <alex.gaynor@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TcGSP6Zj;       spf=pass
 (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=aliceryhl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Apr 9, 2025 at 12:03=E2=80=AFAM Miguel Ojeda <ojeda@kernel.org> wro=
te:
>
> If KASAN is enabled, and one runs in a clean repository e.g.:
>
>     make LLVM=3D1 prepare
>     make LLVM=3D1 prepare
>
> Then the Rust code gets rebuilt, which should not happen.
>
> The reason is some of the LLVM KASAN `rustc` flags are added in the
> second run:
>
>     -Cllvm-args=3D-asan-instrumentation-with-call-threshold=3D10000
>     -Cllvm-args=3D-asan-stack=3D0
>     -Cllvm-args=3D-asan-globals=3D1
>     -Cllvm-args=3D-asan-kernel-mem-intrinsic-prefix=3D1
>
> Further runs do not rebuild Rust because the flags do not change anymore.
>
> Rebuilding like that in the second run is bad, even if this just happens
> with KASAN enabled, but missing flags in the first one is even worse.
>
> The root issue is that we pass, for some architectures and for the moment=
,
> a generated `target.json` file. That file is not ready by the time `rustc=
`
> gets called for the flag test, and thus the flag test fails just because
> the file is not available, e.g.:
>
>     $ ... --target=3D./scripts/target.json ... -Cllvm-args=3D...
>     error: target file "./scripts/target.json" does not exist
>
> There are a few approaches we could take here to solve this. For instance=
,
> we could ensure that every time that the config is rebuilt, we regenerate
> the file and recompute the flags. Or we could use the LLVM version to
> check for these flags, instead of testing the flag (which may have other
> advantages, such as allowing us to detect renames on the LLVM side).
>
> However, it may be easier than that: `rustc` is aware of the `-Cllvm-args=
`
> regardless of the `--target` (e.g. I checked that the list printed
> is the same, plus that I can check for these flags even if I pass
> a completely unrelated target), and thus we can just eliminate the
> dependency completely.
>
> Thus filter out the target.
>
> This does mean that `rustc-option` cannot be used to test a flag that
> requires the right target, but we don't have other users yet, it is a
> minimal change and we want to get rid of custom targets in the future.
>
> We could only filter in the case `target.json` is used, to make it work
> in more cases, but then it would be harder to notice that it may not
> work in a couple architectures.
>
> Cc: Matthew Maurer <mmaurer@google.com>
> Cc: Sami Tolvanen <samitolvanen@google.com>
> Cc: stable@vger.kernel.org
> Fixes: e3117404b411 ("kbuild: rust: Enable KASAN support")
> Signed-off-by: Miguel Ojeda <ojeda@kernel.org>

I've boot-tested Android's KASAN configuration with this patch, and it
continues to work. It also passes Android CI [1].

Tested-by: Alice Ryhl <aliceryhl@google.com>

Alice

[1]: http://r.android.com/3584874

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AH5fLgjb3Wxbkzvvy9H6QUYVpxXvkse1rnDmmR3nVHjp6zEx9A%40mail.gmail.com.
