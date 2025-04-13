Return-Path: <kasan-dev+bncBDRZHGH43YJRBNPT6C7QMGQE2UC4YSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 157B7A87438
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 00:24:55 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-476623ba226sf64580821cf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Apr 2025 15:24:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744583094; cv=pass;
        d=google.com; s=arc-20240605;
        b=UeOBRE7EeaJGVWmLEjQhwvSpI3ZIbds7viJ98+Aqu8GzFCqVmebMEcni71IY4KIiIA
         a7/za8mxOdmiBlmXkmIEk9zCdsHSD6Wps9kOHiMBzm2qznT1DssuGtknbBo8/p5NOhPO
         ZBZmvoAd8S32aEU3VUWlt9Rrddp+tvqNk6a9kfDXnHQ17u44QRI3Ozqr0C+1Ay2EGFAY
         oV7/WV+4mlpoQmMRPhC/UaJKGN+VbAj4ufwsl6J8+t1/fliUdeXBe60sk2vb+Z8gMb1J
         xD6+MbdUejEFucdVvZGW1Us5+TRJHbMHqMHFJ+C8oNT66VGXLpP8G1DjKusw63tFv1Up
         h3Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=AFUaQSsAAAuty/mVq8v2ouy6JH1xY+lK0UWVxGJp++8=;
        fh=AShPJ0f92c+v74r7uReikqEbS1T+SPuvySRUzKtGU08=;
        b=kmOXPkVB8IXs1kEu0PrkZqAEk7kwhohY4h5+zEEIauaFUdFgW9LNJRl8w06XqSUGFH
         HesNDUSp3lfi8NTaQO+r47L1keAkYYnC0Mwf8wXak8/ntoAlMmYGcvVs53onW+AGSrCq
         LbDmjO3+PaoOj+XP1gFLQv3QQW/pkIdV7OIqFSdP59gcA5Zn5NkEM2sRMQfSc8zyu6ZW
         D56K8R8O6OzbnIgucjK02nRe56HSwpfpg7jV3jHrD4pzuStoDw15GzWPKslsFeOfAiRN
         MUgZxrtMK2yCHVe5FYHA2RYGV49f5coR2g2dhrVZPyz62l7pFzjuMu+GVwm+v4Z3NE7K
         W0/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CKiN25aJ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744583094; x=1745187894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AFUaQSsAAAuty/mVq8v2ouy6JH1xY+lK0UWVxGJp++8=;
        b=XdUu9qx0tFhC9ABUJVVK+tBFGn5lM7gGP4NNKbCF1+rm5gbLER8wJg14/ayG5jtHxz
         2cX6CgsfnH2WRukRU0NwW9kjgCeTI22/JOkr1xsDyCCLcjIF87CxQRgBHjvaSmXiVyYn
         6cC/RJajBMA0E3U7fvggqSAHuAhPywWt07aX4/tczAI/OdeWEAFenuuL4vGc5C9wrXbG
         Xxg/eV3/6WgCl/s7lFgJ+8vPt7JxpE6LsfgTo8ckfjyCqz3f4HDwrPVTyEzu5AdCBj2K
         cKL2ygSycUaPj0mMrpheO8oWAH8xh0o8SRkAVc7xiGtQo/xM35ZwAjEonASJQDmT6vAO
         pECw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744583094; x=1745187894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AFUaQSsAAAuty/mVq8v2ouy6JH1xY+lK0UWVxGJp++8=;
        b=SgeRhaL8a2Z61O4clUc50sr+Cfaf9eyX+Qh+aYZ9B1bICAEsEwS651MwFpG0qRPRFR
         xv6mwDhGtTrYS5y6/1oNXKOKX/rJgraBIlncosmovBPhiRezoV9OclQrDDYE5ZzDV+uv
         N90jHlN8Fd9Lfd699BcxIvlF0dRueE6lt0oVWO+O5uh+bpXmd4E4SiDqB37ltG0GHeDH
         BhZtX44+BKHNa5pJMNEY5NT66t07rgK6jemoW0UuuG0FO7OWnL4rQy+66PZKvwS8hhz+
         GGxjGMD612DGZb2O60sZCm7MZoPzbI6CxI/u022SH81j4Yra7pAHDQ0DPDokHnmx7+VT
         TTuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744583094; x=1745187894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AFUaQSsAAAuty/mVq8v2ouy6JH1xY+lK0UWVxGJp++8=;
        b=CxX9mYp74oL2kJ7Lspl3C8Hj9nXelsSen2wX1HQfMzZSL8DMjYIv5ZBUIO6xA6ZhSj
         MgSJsIeQx2OevbGgTAYgY599NHNszh1NT7B6++hMPMHECLvwOWV/8ET1uDLcmEXgYPYI
         WhdYMxQ/fGEHxBb9aWoM+ODHpOCnazblRG/kHcJbrEg1YIByZ0xC/vB0OxW8WGBMFU8F
         uqanwV9Aj1BmEQJS13d3N3KNITyf8DRzQLPg8ljheyonaircikpZrzjWCIgX/P1/fPCu
         1Gq4OzzQlBl+FLkfQu11vag8q/iv3+/rJ+Q3NCUQy+lWv2GfNalG3ZmwJ+dVsVK2Vs7g
         C+kQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhWGPdZYf//JOGn/pWqnlG776QhcLvuxyBzZoi6rq5SFpT3tlf+Aplniwbu+g/8bphn4mQbA==@lfdr.de
X-Gm-Message-State: AOJu0YzGzbCI2lpVDSNlSsXu6piILLlXs38kgVzWL0UUlKf00pLXrMkC
	GcuLo9wL1onsmdMVBjU+otsdnB2lAUcZkayqV6Cmw9a62s3EnV1x
X-Google-Smtp-Source: AGHT+IEgcceT9PloYg0ULl0MLnf0ecP/EyJozw7t2+IycEOAAdcVCFGu4y2MK4uw1BhvXoO/B75ztA==
X-Received: by 2002:a05:622a:202:b0:477:1e85:1e1b with SMTP id d75a77b69052e-47977526195mr150120231cf.8.1744583093441;
        Sun, 13 Apr 2025 15:24:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAINX/4UEE7tixgEY4U3lI9e2Er1w9locbgxNEKrUl4AeA==
Received: by 2002:ac8:4883:0:b0:477:5ddb:625a with SMTP id d75a77b69052e-4796b4d8309ls8693261cf.1.-pod-prod-03-us;
 Sun, 13 Apr 2025 15:24:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUm1wVjPJwja7aldXdQYs1xAO+l41enr5A9LnBX+9I7oQUmYQ49e47hI5Fyo1do3zx4IHkVGs8sCYo=@googlegroups.com
X-Received: by 2002:a05:620a:468d:b0:7c5:444e:3f57 with SMTP id af79cd13be357-7c7af0d4083mr1552859385a.23.1744583092370;
        Sun, 13 Apr 2025 15:24:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744583092; cv=none;
        d=google.com; s=arc-20240605;
        b=I4OJ6+itTV6bRC9mCkOUuLe3Bl7Z3x9a7bGwieU8nK4u5qGT5qA/A8ShFan7468XRM
         fZat8S5EAP/8GXcqcmHhHGhQyPHDJXF4lMHDNqjHzYGJs/oTyrEn7jX3oPekEPTU20hO
         b5x8DxuipxvjKyswR9VX+RuAlRGPhCws52MfD2CJ7ZVN1/RteG8KQCNJX4fuoUu2rZ5C
         dFMiBeg5U14ffFLIYQrLgptt4U/8YrbmoJ9yrRVGRjKwaEh4mLSmEuq5JuZSq+m7+JAB
         IypNflS77+ANyfgB7EihCS3g/u1muT6k2TU5iz5ZVNjp58u2SYeMDRevs0kKm4U4eIGf
         VKrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zFhWszMXgcrrhbxro47Xom7wsLkxxg0I4+qRejGxZ4o=;
        fh=QW4Zt3IVioqMbMP0P8eQuaVwytqNjtkmNPu2731L9+U=;
        b=U1nAB+g3IJjkCaQ+/DZPGdRO1bsoTp/49T7YbLWGvE3TglMGYZiYMmT/LTXhzUX4rk
         f2D9011+MZxhT237pOZMQta9sF/oLNxZqFFheYPphTJrVW6zcTbxeGODXr9M5EbNCsPF
         ien/Q2kKRVdR5iIhB9aP7xqWy0laJWHzlm+BgUZoFd7AzIbt9bwWBBmSpW1uXMMPIcKB
         IfoCcCci7lCkGditZdlctR+7m1zMJISOhXZLiUnpfMdNEFzxpse6KUg4bQRCoHjtfMh1
         IwHScE5gjcfLulIQbHArf3GlSFZEB2XreNKUTIlLtusqzBnimGxi1t4hKqvhD0s04OGo
         FzKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CKiN25aJ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c7a89437afsi32618885a.1.2025.04.13.15.24.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Apr 2025 15:24:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-301a8b7398cso699734a91.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Apr 2025 15:24:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWQKcRyUrxwKlK03EuI2k/bRWLJYCGax+CCfPVb8Ls/a1pzsTG3StxXlTDDUnOMovGXNffeefM+Fl4=@googlegroups.com
X-Gm-Gg: ASbGnctHDZbWVttR8+1aRZb4BIUNtjvgl0TGfOaauIUTtIpE0x9uPSN7zI3p/XDVqj0
	PckVv4a+L6qbyQaj+W90F/95w29+UhHvyQQD8FZBOHuN1cKY/Gef8pIDE5VVokVi5aMbJ8fgAyo
	L2TM3l9dF0t4L6Zzfl4Shd6A==
X-Received: by 2002:a17:90b:4a89:b0:2ff:78dd:2875 with SMTP id
 98e67ed59e1d1-3082378c78fmr5674698a91.5.1744583091360; Sun, 13 Apr 2025
 15:24:51 -0700 (PDT)
MIME-Version: 1.0
References: <20250408220311.1033475-1-ojeda@kernel.org>
In-Reply-To: <20250408220311.1033475-1-ojeda@kernel.org>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 14 Apr 2025 00:24:39 +0200
X-Gm-Features: ATxdqUHU76_51ZQ1TnRtKTvt1ZG1eN1xA3kopPBEH1n6HKtgRxWv-zmZkdx8n_g
Message-ID: <CANiq72mxi7_RXCzEmWeLYs5x0Dy9j8BNYTA1ZSZ-8=yJFrfMyw@mail.gmail.com>
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
To: Miguel Ojeda <ojeda@kernel.org>
Cc: Alex Gaynor <alex.gaynor@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CKiN25aJ;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Wed, Apr 9, 2025 at 12:03=E2=80=AFAM Miguel Ojeda <ojeda@kernel.org> wro=
te:
>
> Thus filter out the target.

Applied to `rust-fixes` -- thanks everyone!

I am applying this one fairly quickly, to start to get wider testing,
but it would be nice to get some tags, so I am happy to rebase to add
them for the next day or two.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72mxi7_RXCzEmWeLYs5x0Dy9j8BNYTA1ZSZ-8%3DyJFrfMyw%40mail.gmail.com.
