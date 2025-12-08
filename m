Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAFZ3LEQMGQEAVMMSVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E9BC1CACB08
	for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 10:38:11 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-65997ee5622sf3191400eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 01:38:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765186689; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dynxf/aYStEx/rQqUQ0Cl0zqDwuZwVV9G5SvLNSbDp2MTe3aPFuBjJSygCkp73id7U
         abJR3/GzucTiP9zapt3HOJ14+3w044ujk0llD5SJGESJ1yPBsp04y032wfCx6kxGGRul
         LL3iXzaJEGLfHwQAQr53MQ2f1dRgXVK+F20SVAqf1QpSGMJVZNJ2zvUp+1dsvYbXIF5r
         9sV3304fhKmz4Ws7ljaG7QrHelE66l53IfSvdZlvwxnTBPyAPUFEeeJFnkfPPX5XjXK1
         I0mrFjQfFXphIoJjGGMpOlce93lc/jp50W1OtRczGj5qN2TApB3qSZk1kSFDkx8KCFix
         DQsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tiTcKn4eduYLBz+J6Lx3iJkNxYFUNnKJXCU8k6Sv83o=;
        fh=KRjaNB/9eLN9JgHRzJ1uxRiXloC8GTy8b9b7MSZJM4s=;
        b=lPEASY3JSCnHC3vzsFa6otrNRHby9RlphxbtXKlq8wTBxlvVAy/rv6ihHiq70RqWcX
         5tbgQftoEwTGHowpeOUAjvlxWQaIDxD/U280d/Vs+e72vrrO+pz7zR+zo+JCVTE7ARsy
         4w8aAhwyY24peeIDFqyQHBUYI31kXOjYBUSFRAMQKaep2fnt5v7I8tpGnb+7NM0u/8UK
         IR+J0uTMwYa6RuO0O6nSa5Y51iBaA3A/ebdrLKu5T0RKME5TADwOqbRbT+7WLfELww1b
         BFMl3IUUq7yprVF9FF0FOraxQpwHZz+7Wo8csotB6YBvfJcAOfKjBeEX6NKdIvcPQtRo
         ji4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tj24uPJy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765186689; x=1765791489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tiTcKn4eduYLBz+J6Lx3iJkNxYFUNnKJXCU8k6Sv83o=;
        b=FUMLEJ3jlLoOUDzPQ29ZTQjlu5XOLuAxJyGtxTDXln+mCHHi+p0eS7Li1Sc2FQRNz3
         0/fmR5rM7LwHAPldyB8IwNpBnNANedoL5ukZ686rUaZryp0ylUT5KQJspQ4neAoW5CMx
         GbAElAVXjifOrnI77DUqiR/1vf7Rc9DYKhf+PT6t+6mkmtNrTjHuc9ycNWlP4beQaG5Y
         4cj+WaIPVweqvwHPXc6VdA8/8uaugC/yiCqe1CE6StVUX4FsxBj7Ph8KNcW4s9kEWDxy
         7Yr7RA5VxYzUbVrM0jXuL1E7hVOJb1AKxQq5UfL2Qgd4b7wDe+SgJfcrU9sUFK3At3xY
         BZew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765186689; x=1765791489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tiTcKn4eduYLBz+J6Lx3iJkNxYFUNnKJXCU8k6Sv83o=;
        b=W5y6sWrsLjn1X9EQqr8+bPjCv289fylzfNas7JF5TwlpbpTx8okVqzteeK6KGIwKib
         JBJnVnzsaW7BLQYQFLwl4HREe58s4mcD7tCPskQJpTx/SMw6oks8vj4KT17eSu4H608E
         2viLW3VDnOB0kWVQaJbUj36YDajTQaBEmoBdn8+oXkEQhLPO7l6u1S2lz0pTKIb8fSAh
         DKyDBL/kY5iXiO7bA3z2EtOk26Hsp41lMCgdEIIkTcPTLhUCQFQkH8BIqjbyprs2156w
         jvj1Elpy/WrJVU81ZhpKw3lIdE+wxU7HXSA1XnOarbBc5B9Hvk4ZPESerqSKjKibjap8
         Ok/g==
X-Forwarded-Encrypted: i=2; AJvYcCW8r276rZT2/hd0pBjIqTC4CXpXfBGKyacUfyd2PcL8qwchlx08XDwAtFouhJHrNUItoCivSA==@lfdr.de
X-Gm-Message-State: AOJu0YyZwwfdrVnW5lkT+bpQE5WNTDiepPpH3jtFHxXfKflEMaZMNUhf
	ujF22+eAEKshx9sc7cVfKq2IJ2oX0M109dpuYRgnviM5JWpOrpPd4MWt
X-Google-Smtp-Source: AGHT+IELeGKqo/C/etPpd7fi5x9ZMWNZfmtlhMRxBxpHKEMrI0RQHgqAVXi7mkci8wnXeY7ju2PiTg==
X-Received: by 2002:a05:6820:60c:b0:659:9a49:8ea5 with SMTP id 006d021491bc7-6599a93ec1cmr2843204eaf.41.1765186688942;
        Mon, 08 Dec 2025 01:38:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY9crM4unJvoC2eL+7wqspOB+cP+jsIHDFb87Qougm6yg=="
Received: by 2002:a05:6870:b621:b0:3e8:2785:9a19 with SMTP id
 586e51a60fabf-3f508fe7b7els279132fac.1.-pod-prod-08-us; Mon, 08 Dec 2025
 01:38:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXbATmIp6sdcFCAVANYUUYtBez00WxAA9RpK9DmzG3IHmGA0S8KDZdZtnbGeXHT7Anlwb+HdYeaiZQ=@googlegroups.com
X-Received: by 2002:a05:6871:3322:b0:3ea:9b60:d511 with SMTP id 586e51a60fabf-3f5440f2576mr2994560fac.40.1765186687917;
        Mon, 08 Dec 2025 01:38:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765186687; cv=none;
        d=google.com; s=arc-20240605;
        b=dUS9QgcEczfXkKEQ6FxsTXWzUu+PcoSNWpZWzQ6pR+ucUStbthTVvj9Z522FyxlT/d
         WZ5uV2VAfifH+YM4mXKYiFJmMrn0o3H355cv+gKwL2mwN4h+/twTJ8lEjR4aNvI7cuBN
         C9dA2JSmExOq2pyQIWt1gjV7rPyvu1ceIZXFBiNSxqR6sBP28jNpCnijGtPkkuWkr4yT
         xcf20SZ1q6QlyIhs1aHjbbUCa1wHg+QD86VRhFXRffP0HYiM4gVVv1fONOLaeCOkv/PN
         Xki2WBLCVzfxibiPUEWf+k8Tu/HEvZt5fEjwB0VMgX6TDsifDJa4frYX2XCWKpmeMCX/
         q2EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IrwBHOkyTVmp9ECG7TrSffWBbBmE1CfoRFCQ7geMGpA=;
        fh=p6nueTnhhhAw3mO2rG5aSv4qBuagrnbdhcMb9xOIY5A=;
        b=FsFV6jpPZRAGjtTy9jfADMiAWjOh9B18tcP+VRUimBCLUmSiXjLJYqGnEvShqLoaBN
         HnAPOPv0Ef9P4T2oWzpv3Hl2Vm5pq7+xF5+Zd5Hwr9W6cOPIKIhhknyqRvXjM1wIUzHc
         TcVHXl0h4HFx3buv3v2LZRa8K9nzyuF3MJDbIyLa+tszWhph4FmGktziCGxnlovD2AYE
         TOMFgmVq5E8YR8A486+n6TgMUOdRgtDvISm3lZo+p6+Eiul9x/4tp7OAkohNBsA3vRKm
         +xb+FyFrhOqi+WcGYz6g0ejIgrh6BN3DlJ0wt0idCVRaHaJzJA7lPqBI6tte4/u3vzFp
         l4QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tj24uPJy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3f50b5d83dcsi271759fac.9.2025.12.08.01.38.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Dec 2025 01:38:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-299d40b0845so70520005ad.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Dec 2025 01:38:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWXZjjVAFsWZY32/7f8dPEzMBEIb95iFonmf6bq5KlqBuSss2qsK1q1EVNfJWDEhTmNkctFmxyQH1w=@googlegroups.com
X-Gm-Gg: ASbGncsAokyT9CdeCX4D3GHokeLbjHDegWM7XkvEF4NW5nBfn3RBsNL+yPCH0952Or+
	Bgg3Y+QexpGbRYmtqrCwQoCIZrYFIBXPOsJ0OpihHNTY/HYSFUOE7n+xksVnioSP2y4NHd7NNud
	QueZLrpFTmuSpVQ6/oDk/1xUl+r+4NBGBbUXYl0VjD+4v1m4LU1t46i+4IHUl1f5LH4FkirlG2Q
	SctoM9As+11hblUNf+1OKwh42Our3YwNT8bXPU7a60Ige//VonjFRDoCfarE6uz3TNWXRf1MBaA
	riCzOwb3uZ2zVRA8QxtCDKGKmw==
X-Received: by 2002:a05:7022:4583:b0:119:e56b:c75a with SMTP id
 a92af1059eb24-11e032948b8mr5973204c88.31.1765186686633; Mon, 08 Dec 2025
 01:38:06 -0800 (PST)
MIME-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
In-Reply-To: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Dec 2025 10:37:30 +0100
X-Gm-Features: AQt7F2rCI3ov0CLyet_5CZQM7cBWqMZuhIlOJ73T58e4EsdIzzieeg_6oTEQ84k
Message-ID: <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
To: Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tj24uPJy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as
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

On Mon, 8 Dec 2025 at 02:35, Brendan Jackman <jackmanb@google.com> wrote:
>
> Details:
>
>  - =E2=9D=AF=E2=9D=AF  clang --version
>    Debian clang version 19.1.7 (3+build5)
>    Target: x86_64-pc-linux-gnu
>    Thread model: posix
>    InstalledDir: /usr/lib/llvm-19/bin
>
>  - Kernel config:
>
>    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657174f0=
537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
>
> Note I also get this error:
>
> vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !ENDBR=
: machine_kexec_prepare+0x810
>
> That one's a total mystery to me. I guess it's better to "fix" the SEV
> one independently rather than waiting until I know how to fix them both.
>
> Note I also mentioned other similar errors in [0]. Those errors don't
> exist in Linus' master and I didn't note down where I saw them. Either
> they have since been fixed, or I observed them in Google's internal
> codebase where they were instroduced downstream.
>
> This is a successor to [1] but I haven't called it a v2 because it's a
> totally different solution. Thanks to Ard for the guidance and
> corrections.
>
> [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.com/
>
> [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54f7790=
d54df@google.com/

Why is [1] not the right solution?
The problem is we have lots of "inline" functions, and any one of them
could cause problems in future.

I don't mind turning "inline" into "__always_inline", but it seems
we're playing whack-a-mole here, and just disabling GCOV entirely
would make this noinstr.c file more robust.

> Signed-off-by: Brendan Jackman <jackmanb@google.com>
> ---
> Brendan Jackman (2):
>       kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
>       kcsan: mark !__SANITIZE_THREAD__ stub __always_inline
>
>  include/linux/kasan-checks.h | 4 ++--
>  include/linux/kcsan-checks.h | 2 +-
>  2 files changed, 3 insertions(+), 3 deletions(-)
> ---
> base-commit: 67a454e6b1c604555c04501c77b7fedc5d98a779
> change-id: 20251208-gcov-inline-noinstr-1550cfee445c
>
> Best regards,
> --
> Brendan Jackman <jackmanb@google.com>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNNK6vRsyQ6SiD3Uy7fNim-wV%2BKWgbEokOaxbbd02Wa%3Dew%40mail.gmail.com.
