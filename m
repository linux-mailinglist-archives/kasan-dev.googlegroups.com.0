Return-Path: <kasan-dev+bncBDRZHGH43YJRBSWY3O7QMGQEOSTRDVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 98F07A833B6
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 23:53:16 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2c2545da7b6sf1098752fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 14:53:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744235595; cv=pass;
        d=google.com; s=arc-20240605;
        b=hl9OYHGjqwylbyR3NXlEbHtYFaybtatfGyvdyZU4dJv03TKvkde56KsVbYtgMCxo11
         4eJ5Tz34TPMVz3OY8iUlTV8HHs/KMlw9bdRAr7jxQq1Cl9mvEOXqKDS7GEXTwRZxjbVb
         /kUAvW+a+9XZLbwnbr8tlaHrM3RQvFSXW6aopo/4weyFp0yjPS0IPmRrFW60b0KBEcwg
         Zvk3roI7+q7k0U2pFZlWkdymhdXXOobKXXWKTj4SMT5gOo2+abJ3uf+2Rh8RRgHQ2Vv+
         ufcoyj08UhlT3LCHIWN34FdhIznJ1XN9W8uBufYo0pAr5fxK1hF+QGniGHr4lKJw7uUV
         D6bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6RKBKNNjNwTA3+BkkvnElwM023sf9QOLnldDrDnYSqk=;
        fh=lD1kkornI1c68BYvUYkLd5ZV+vT0Olu/DZnUUrJzK6w=;
        b=a8TlPOZa1dY/EEs28XKYG4eDr4TyRVX4Z1vZI2NZt2zsDRd8Bwi8fEdv+ye5Tyvptc
         zUEjHYu3hk9UHhesrouJrj+WI2n2dH5R711aN9e4xfR9ZwX43ToVgnNffBs6beXsWLXG
         hUd2pWv2Bb7Hx6fk+NB9YKEBEQIKWOGDGnhcLHGt4YFkUJ8sJumQupGkdtll/gUuXZUa
         vv9bhHj/5gl46Q0mcAwasC0wwm38Uuq2cTb3Dc2uur61X0h75EPJmV0P2Ra3k5tkImPh
         JlwsQRYPkjHTFezOsWEWx33c1jyYtUAMJo/ceMTFDVm+zLfclaBIXxm7vJmkrFX5K4Vk
         GLWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CdGSAcW8;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744235595; x=1744840395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6RKBKNNjNwTA3+BkkvnElwM023sf9QOLnldDrDnYSqk=;
        b=ihJQFDdeaKCmdmmGxusHE7dt7ep5c0BH92ObGQrKQoPD/xGRn6oUMiX3iKCnnUNNYz
         8q2gxzT5OHn66c2pGa7L2bvWEvyO2zbrudnGy94S8IYJSe4s5wimpDu6iJqhHRrgvm3I
         2kX6qEk2j0ELV7lYvPOFNm2ozCfY2rsrczC4GqqxCT7qpMRI50s0rIAYfNg2M2cDcAQm
         3zYnBL7eMRvpvGu+QDM1hAMITHTL6qiakY48lTaBvw4er9aMw/PEIuDLvOm8hmPpBYZ+
         6cqu+NhVe8KjND9EgGUFK3H7/eTWB/dw2G9aVFi/28xKfHZnC2/JPua1tvIj3dWDSgtd
         NZMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744235595; x=1744840395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6RKBKNNjNwTA3+BkkvnElwM023sf9QOLnldDrDnYSqk=;
        b=UXCZqoSvaN7N/wTKRduI3e0DmM7DDbZxahvBvNiSUQNIU9gPhdz+4rtImYPxfkylkC
         AOdybJ6bz615900mCBlXNmcalWHbQBzsgQ8Yc65439iPoGCkhGuR/Ssvby4WU41W5+iw
         BA/6A2U+5g4gHycu8kLMGpEWGQCizkXSylv1SsImdpFGSFbamFvpNYXUiR6dEYTJhHhP
         bjiOjO/QD3vNbrl1zZb7jGxZHkqXdtuNvfAdydXDCGytaPrufRQuGKmPBWXR+9+CzBYN
         W66ZP9tNHF51h3UwsCW+HRj6UYDXiOJaU4kIhwH/zVYtG2I4Tx1fT75lrMjId5geLUmI
         nQ6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744235595; x=1744840395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6RKBKNNjNwTA3+BkkvnElwM023sf9QOLnldDrDnYSqk=;
        b=cEpg8n7mS+lyMWCtQy0iFK7ysLvzNRCITtuF1Wy98hAupoGS7g/XkQZ0kC9O4MSuwU
         Hr6f14naLEesjsyO0NV2C2/cLNO7zU8jBAxkO4x/B08fW3GNP8xwZrSjRzpkyP1+r9mT
         Z1BIvRm3uaMLI6pYEtRNXvNElcrtJUPe2oyK8gS8HZlv4hkDi4r3ehPAf3LzOZnOJWU1
         1AjYq0F0iPS0NUYoxfNWY76/eucfZBmVs59az7AyHjmaJ/ybalACuTPTGotOdO9xN8Il
         iPpjZUMDUvVNxVFzHNdPPilBx93yYinZTxdPkmfuqNSoZQT47cXbr4E26JzQmBMes0jv
         Ih0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGtvVezQHsu2kfYrthq3KtDbj+6ziEHPi/9Y0cHYg4tm9+pVllbhwXoRNUeDuryCAvBUFhHA==@lfdr.de
X-Gm-Message-State: AOJu0YyzcbDOK4c3zGKIqWSFeQX2SRqMz7Do2nmjW/ttsElKQfRm/Ejr
	h4QCdHhBrSlhKkRihWA7xWoXHT62wByPNvg9le5sbdnT6gmVf8Yh
X-Google-Smtp-Source: AGHT+IGOAmBqRsFjr91qlYnQq5UARoO7+EuNMGRMMvKysSTspnmPyF0RNW8oxJTeGzKdhqLsC502kg==
X-Received: by 2002:a05:6870:888b:b0:2b8:41ef:2ca with SMTP id 586e51a60fabf-2d0b39c3a27mr195361fac.6.1744235595061;
        Wed, 09 Apr 2025 14:53:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJOwz1tjwJM05XIj7t6us7EscYTHBqG8/TizLWPM7PtGw==
Received: by 2002:a05:6870:6e06:b0:2c2:384e:1c12 with SMTP id
 586e51a60fabf-2d0ad0eb995ls154720fac.0.-pod-prod-00-us; Wed, 09 Apr 2025
 14:53:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz3RA7vrt0JhH5e5+aNk61KJN7XSSemaqeFdFBW3NNDbL0YZ/4vwTTros9pMtqvWxyWWteuKMSSxI=@googlegroups.com
X-Received: by 2002:a05:6871:6308:b0:2b8:65f7:8268 with SMTP id 586e51a60fabf-2d0b3240a10mr230725fac.11.1744235594071;
        Wed, 09 Apr 2025 14:53:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744235594; cv=none;
        d=google.com; s=arc-20240605;
        b=LSveO/+z6tVDONdX/L6IIMRuQeXwdxSK6VjyN31XrXyvRRpoqsgcYOAqCuH/94j0CY
         cDUaEnERYZIomzb83fbCu+XdrV//dVEb3IQNTbo6A2VLZqf9EJ/lWeyApdgF/J7tfS7g
         3GW2ALqXuq789jIqFQC2xPqeHfXgSPq3/xtVgiOCvzSPJ0Cg7lJt/cSurqC+GpwCSzTY
         6vvtxbehgaqfOH9DyscLO88C6iw/q12fKrKDN7m4AneF/9u2jTqvmvJT4HOJqIR7B4Sf
         6n24T0kPZbJd0SrRoQ3fppnfu2EEyo+VEnstV7OSF4Et00+Jxtyd+w92u4zJVpPGEhDX
         fkBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FDKPD1lNkys1gBdpLGebFxEB5tYdC6/xm01UvetLAMQ=;
        fh=7+S0CT4IZVn6gCG3zI+zG/p7dA17NxWUYKBRDeCN0+E=;
        b=JOOlLYpIJA90K5w5iMRkvxnkbu+DauHV267uiiAxZRAdIIre6wbsReccX+XN9TgBUl
         eNEw5HY8ZtS2dSU/JIK2scMYg+QSooc3ph018wuWOPC42qjIbLesD8ajVQrkWnYPy4uf
         Iti1A4kId85Z0qBeRt9InHzc4rHrkjvv4imrKXxV03o4niX6P14vbO4XlWmKeHQAntZx
         bq9SfVuRY+nfIpzudW87ObaRf3BwSawsBzTjz3NZmRlrt6v273OHojjgzTi7Q4bx5bI1
         erW2If5XO8Zi50okbAUd2cNpB9/T9sAbE8sTisuCHnbKYdwPMu8U94ePeIvllPM0WWqw
         csyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CdGSAcW8;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2d096c6b128si5275fac.4.2025.04.09.14.53.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Apr 2025 14:53:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-2ff6b9a7f91so19806a91.3
        for <kasan-dev@googlegroups.com>; Wed, 09 Apr 2025 14:53:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW8Eng0COn4dI0Ny7rq8YJAVj1UlJcvble7cPwpDrilVrOmoolVB39lerYoBbvy7Bwqb9GroMyWAjs=@googlegroups.com
X-Gm-Gg: ASbGnculm3RNmCq4LZiXczPj8Rhujx0WLQwZo85LI5nugaNLl2uxgmfUfVTy0ssNTcx
	9ZFGvfK6Mc98wVKwG6NZOASBskqMU1Ko8nDhzXeyQNeXNq3SoW75Dqy6i+wtk7xKv5PqPKrG/9Y
	M0jK4m1+FOGA2E+uYTIbtohA==
X-Received: by 2002:a17:90b:3b4e:b0:2fe:b77a:2eba with SMTP id
 98e67ed59e1d1-306dd32267fmr2318847a91.1.1744235593163; Wed, 09 Apr 2025
 14:53:13 -0700 (PDT)
MIME-Version: 1.0
References: <20250408220311.1033475-1-ojeda@kernel.org> <CAGSQo00QxBbUb8AxwqtRKXy96na_HUVmAG9nWmX=cVvozqwWaA@mail.gmail.com>
In-Reply-To: <CAGSQo00QxBbUb8AxwqtRKXy96na_HUVmAG9nWmX=cVvozqwWaA@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 9 Apr 2025 23:53:01 +0200
X-Gm-Features: ATxdqUEHQeM8b7saMWZkuyDOWEJ-eHfp3twazwBDYlb872_Qrhvs9x-AXSKsD9A
Message-ID: <CANiq72niPycmVwHBfqttgD+X1qvg2L_P-=X79YEREUGLitqoaA@mail.gmail.com>
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
To: Matthew Maurer <mmaurer@google.com>
Cc: Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CdGSAcW8;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Wed, Apr 9, 2025 at 11:35=E2=80=AFPM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> The problem with this change is that some `rustc` flags will only be
> valid on some platforms. For example, if we check if a

Indeed -- this limitation is acknowledged in the commit message. The
priority is fixing the issue, not future features/needs, so I went
with this.

In any case, if we need to test a flag that requires the target, it is
likely we can do the check based on the Rust version, the
architecture, the Rust's LLVM version, etc.

As for `target.json`s, the plan is indeed to get rid of them, since
they are permanently unstable. So any features used by the
`target.json`s need to be requested to upstream Rust (e.g. flags) so
that we can do the same without a custom target specification, so that
eventually we can remove all of them (and thus `rustc-option` will
work in all cases again).

Thanks for taking a look!

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72niPycmVwHBfqttgD%2BX1qvg2L_P-%3DX79YEREUGLitqoaA%40mail.gmail.com.
