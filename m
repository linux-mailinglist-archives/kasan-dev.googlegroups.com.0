Return-Path: <kasan-dev+bncBDIJPGN37QKRBRFDZO6AMGQEEEJ4NGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B3DBA1AD42
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 00:33:26 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-53e44a2a6cdsf726745e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 15:33:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737675205; cv=pass;
        d=google.com; s=arc-20240605;
        b=SZ2dsehrLX9DHzJjdwDuBh7736MCx6nRaDGObSWgzGtx0DNXvbb9J4m1vucDmz9exk
         P5ZtDaC15kg99faeR5Z8mEc5R+LZX089nIWl8Z/uPh6Zze4wm/Yhkrbp0q7sEBGi9eYY
         RI63UTC1PshEjV4WtLp77om2T3R4Bt7jbRs2f5lPTExHWMMBAWmJNfj14qXvYe6SkFDs
         CJ8Ox3kGpMWKj48y0WOG57w8TyZOoiJptYGfxVG3fO8XYNe3tUHfDfV3a2NHiSj0+/lp
         WnDD0Y47tRVxo5YYcYJIT0Kk4utgiYmCEX4H0kQnKVLqlpgf35TjQSZabnXhZ0Am64iS
         4hhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=MNKn9kFaHMOJ3OKojyISxRGsQCZv2N0w1v96kUlqF38=;
        fh=RcFB/MiHdZguWMC6AgYkfqbrv5xD1LqDY9+xq955DpE=;
        b=YXnfEGN2cT00aWpd8lwBwt3xGc4uzIuweo7qmY4ITnwiXs3315ZBlFbCqZUG7unSJc
         EHctub5FOrK+ebMWTekJZQu/gyRqr3JQwV1p+CKTnCy3EINuO2MwXMcpP1mFR5jg8LnB
         SeEawzzSzoU/wWedxBDUx+w637mIdyC3uCfbB6xetBptSIAFx4pPArEL/JrBacCyRoO9
         l9iwCCpyq/niDb7th0PDHeZvb7vQdxAqmXT89TNBC6xVtjPgSYuO/4plPp65yrweb4+H
         Xct2b2rrmiz3CF96AOEUErx276Eivi7o6KTxsxXf/nVNR31x9p0UuDmzshlGghVwqAXg
         A+KQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Dc/qhfkG";
       spf=pass (google.com: domain of shy828301@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=shy828301@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737675205; x=1738280005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MNKn9kFaHMOJ3OKojyISxRGsQCZv2N0w1v96kUlqF38=;
        b=Y21H6QsDz2Q8kOf02BN3W+rps6z+Aa9kQANIVraY88/3SIPFCaN8TASaIbm+kplKeU
         mnysNBiknCy2FQftwEcl+sPmHpZMBs7hsJvuh46er8ct3N9PDNLSkUmPa3KsMQw2hq4B
         6cPau7woUwpla39m2sDGqIEXns2+WY+pNAohOKwTi6RlDDTjgGbJZRKJqR1j2wFaHiRa
         BNZpqHwScnffFN93F/Pp3IFROJaRPitISgF6OuKbCi3pJvHfmGgwBVfogGSZC1YSGvSO
         2zhoQTsSzMI1UdA1iVd2nx6nXY8PorDsvCMAd4OQH9Qr7mzg0K27W6jzsbVou/4mtkrp
         hjeg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1737675205; x=1738280005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MNKn9kFaHMOJ3OKojyISxRGsQCZv2N0w1v96kUlqF38=;
        b=Os5ilPUiuVD9ViNZQGn9j5aBmkQT7xyXgvgaZo6nk+YJrFkkUfup4DJBphrQCu717B
         yxkFgvEcPoPO4+2b3znv0Al2bpXIMBuDKBfGBJc9n+fXxC587d3MIiXClfOebDRsk/4w
         GIEZ6AFIck3STAcqC4SQyPt3mRN/3Y9cGGW6C/VaCjtXDNX1MBnIkCTQdrChRecOwqWd
         ZQY4PebvS9mRrUWW2eD0xM3SJozUbtFYjmrVFmfvabPhZ/kDdwwTXsuT6OqvfaGsLprz
         IdT8SdPw6shznlkrvsaeO5rveKexiaumc+aAAtc/ZjN4VnnHePjIjOg2tIf9P7xpy87j
         FT3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737675205; x=1738280005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MNKn9kFaHMOJ3OKojyISxRGsQCZv2N0w1v96kUlqF38=;
        b=Og8q2G5TSPTDLHS/eQBf8Pf1L7+o/kSU2tHT1KojJXF29WrnZTw+RELV+GyRRzHO+E
         xykQmoG2Lkk4EktfGUrcPWbw0QcltsVLN0zTMr2prgQ8tPhZ7ttqNLWEcMpfIGgNHIqs
         /ZKrzLcfsR9TwymyC+G/LjWipiQkdN8IiKmNI8ANTuJInI8aGoqgNlZHa9ZBIjOOxYAE
         WkVHYdblnzSCqwT2aHDlNcAdq6DB0ZKjV8+j75z346HIJhf82mCrhUfOmktmU/rLXgCy
         xqBel/klGF0bvSGtezkScFgVluas0eLXUHL/UKd7JbcSRMpSf5NHqGgsVPPvhmUaIw8I
         vumQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsqu3ebmB4Z8FComkchIKlnnsMCVNV8E3ZamEwdvcyoF7owNMISyK6BWosJtv89bdsQDwb1w==@lfdr.de
X-Gm-Message-State: AOJu0YzlrA6UlXsQ0azK3gnEJUoFYEQfWw8XqMkYSjGjDef3aY5aThD1
	t4BA1ykfkJ9TcLgI0amVqa3DgvuY4Fi5LXEVTF22mQp6b00swDXz
X-Google-Smtp-Source: AGHT+IHoKw6OUMdfsVzcaUnOSB+Aw0na/TqW8ndf3OZXH7ll+Ok0C5IfW9LDqSy4+A2B6n6sqjCNWw==
X-Received: by 2002:a05:6512:3c92:b0:540:2201:57d2 with SMTP id 2adb3069b0e04-5439c27d0e5mr11032594e87.49.1737675204507;
        Thu, 23 Jan 2025 15:33:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:893:b0:300:151b:db37 with SMTP id
 38308e7fff4ca-30761d89c0cls3440461fa.1.-pod-prod-08-eu; Thu, 23 Jan 2025
 15:33:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXJNbxG5w9FKsxNxxJ5PvLEZRp3iHiNKsA/Wigegce/Sm5UAeqPVQUo1G3Ay4i79+ukPhLJpM949ec=@googlegroups.com
X-Received: by 2002:a05:6512:1044:b0:540:358d:d9b5 with SMTP id 2adb3069b0e04-5439c1b8487mr10899866e87.0.1737675202142;
        Thu, 23 Jan 2025 15:33:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737675202; cv=none;
        d=google.com; s=arc-20240605;
        b=jAOaVKZxy3YbGLb2ulXefRE5o+pC5ux0TrlfTf4yUIHfFDeeswhaK5CudnuZnQ2E5F
         L3U/fCsigvyR+6R5X/piUAsYIhFIP7iTiyGFXR44IV5zNH3qzqE6QliPXC8UJQ05/RbM
         C/LNCA9nWSvONjSCW9SyBFGRsM2eWF2E/ylQExEeBf2/RD1BhOLAIN9o8HL5v8XgcUuL
         L2snUMeHR/wRDrtysAxd/Nn+lrbjeqNWAvx2V8gvnkWdohLoQNtmUn8MzW83yW9m4F+E
         XJCGtyuQz/pn8UHK5Y62NsJYS67d/a0psbWVEVUQc0z9maNVeeZiZVBoAjv1xIsKXPKm
         QQdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mVSW8bIsfsFFqMRBCFdAmfhhGQMoicsNVoCASFEdJPs=;
        fh=fNmNXCUN1ukdxsgfDr+h0ZDkMGLqXNRy0vtt5E8NFAE=;
        b=brApane0tQVRVmYsXMUew/n1q9iZI1ulIBIOmcOnJtHoM2o6i+drBhPvW9P9eI/GGg
         mqa+L2V1X0UiUIM8FwfxTgNb3Zizcn3NaGDc0ZtFjNQsJM5N+9xbJR1K9jxveudKn5ds
         yjVjawIKE5VVS6p+FLkjOnVOghAPvzkja2i0SyayzuAScXwa5YW1FlmJ/aZtYxXrQUhW
         jrZyI3TMi0rytUGRwJPI/kzvEz7PJqjS254BcWhzIKrPwTnDVBbeoeR9TrgbUQFVmmBO
         aJ9vDjfFSZjU5le2skb05+9v2WiJx8LEVu/634Khrs8iSQ5iatqnQ/Dg7l486aRpGicN
         KwDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Dc/qhfkG";
       spf=pass (google.com: domain of shy828301@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=shy828301@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-543c8231e51si12880e87.5.2025.01.23.15.33.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Jan 2025 15:33:22 -0800 (PST)
Received-SPF: pass (google.com: domain of shy828301@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-5d3bbb0f09dso2750643a12.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Jan 2025 15:33:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVnoJjSbd7eqWhgP4KJZjNOr0H+VDekRroQKqNz69lvyHBlDaK1q+hXm+4Qi9/X6TMsNILK7j8TQow=@googlegroups.com
X-Gm-Gg: ASbGncsUAjQDHEKQYtXqOuRwOyQYE6CzPfr+b3fyl/EfwrOJXWFkxGGFFOC5OYV8A1Q
	BB94jyBnA51v3vk3RkWBj1/RiTRDwkw8uwLbeUWDAOXtta18CVyaTeLzQaZ/fGWGb
X-Received: by 2002:a05:6402:4306:b0:5d0:e570:508d with SMTP id
 4fb4d7f45d1cf-5db7d2fe766mr29121404a12.17.1737675201205; Thu, 23 Jan 2025
 15:33:21 -0800 (PST)
MIME-Version: 1.0
References: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
In-Reply-To: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
From: Yang Shi <shy828301@gmail.com>
Date: Thu, 23 Jan 2025 15:33:09 -0800
X-Gm-Features: AWEUYZkt0opVyUinbKW3yvK6FhHW59qmxiF3ZCbbeXr6_WOiSo_nj24cn27XASg
Message-ID: <CAHbLzkpTF-n85vHeFVEWQArpV=hP9Vo_tYm_LgUQEWLJp=ac8Q@mail.gmail.com>
Subject: Re: [PATCH] KFENCE: Clarify that sample allocations are not following
 NUMA or memory policies
To: cl@gentwo.org
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Huang Shijie <shijie@os.amperecomputing.com>, 
	kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Christoph Lameter <cl@linux.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: shy828301@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Dc/qhfkG";       spf=pass
 (google.com: domain of shy828301@gmail.com designates 2a00:1450:4864:20::530
 as permitted sender) smtp.mailfrom=shy828301@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Jan 23, 2025 at 2:44=E2=80=AFPM Christoph Lameter via B4 Relay
<devnull+cl.gentwo.org@kernel.org> wrote:
>
> From: Christoph Lameter <cl@linux.com>
>
> KFENCE manages its own pools and redirects regular memory allocations
> to those pools in a sporadic way. The usual memory allocator features
> like NUMA, memory policies and pfmemalloc are not supported.
> This means that one gets surprising object placement with KFENCE that
> may impact performance on some NUMA systems.
>
> Update the description and make KFENCE depend on VM debugging
> having been enabled.
>
> Signed-off-by: Christoph Lameter <cl@linux.com>
> ---
>  Documentation/dev-tools/kfence.rst |  4 +++-
>  lib/Kconfig.kfence                 | 10 ++++++----
>  2 files changed, 9 insertions(+), 5 deletions(-)
>
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools=
/kfence.rst
> index 541899353865..27150780d6f5 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -8,7 +8,9 @@ Kernel Electric-Fence (KFENCE) is a low-overhead sampling=
-based memory safety
>  error detector. KFENCE detects heap out-of-bounds access, use-after-free=
, and
>  invalid-free errors.
>
> -KFENCE is designed to be enabled in production kernels, and has near zer=
o
> +KFENCE is designed to be low overhead but does not implememnt the typica=
l

s/implememnt/implement

> +memory allocation features for its samples like memory policies, NUMA an=
d
> +management of emergency memory pools. It has near zero
>  performance overhead. Compared to KASAN, KFENCE trades performance for
>  precision. The main motivation behind KFENCE's design, is that with enou=
gh
>  total uptime KFENCE will detect bugs in code paths not typically exercis=
ed by
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 6fbbebec683a..48d2a6a1be08 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -5,14 +5,14 @@ config HAVE_ARCH_KFENCE
>
>  menuconfig KFENCE
>         bool "KFENCE: low-overhead sampling-based memory safety error det=
ector"
> -       depends on HAVE_ARCH_KFENCE
> +       depends on HAVE_ARCH_KFENCE && DEBUG_VM

Not sure whether it should depend on DEBUG_VM or not, but the update
about not honoring NUMA policy makes sense to me.

Reviewed-by: Yang Shi <yang@os.amperecomputing.com>

>         select STACKTRACE
>         select IRQ_WORK
>         help
>           KFENCE is a low-overhead sampling-based detector of heap out-of=
-bounds
>           access, use-after-free, and invalid-free errors. KFENCE is desi=
gned
> -         to have negligible cost to permit enabling it in production
> -         environments.
> +         to have negligible cost. KFENCE does not support NUMA features
> +         and other memory allocator features for it sample allocations.
>
>           See <file:Documentation/dev-tools/kfence.rst> for more details.
>
> @@ -21,7 +21,9 @@ menuconfig KFENCE
>           detect, albeit at very different performance profiles. If you c=
an
>           afford to use KASAN, continue using KASAN, for example in test
>           environments. If your kernel targets production use, and cannot
> -         enable KASAN due to its cost, consider using KFENCE.
> +         enable KASAN due to its cost and you are not using NUMA and hav=
e
> +         no use of the memory reserve logic of the memory allocators,
> +         consider using KFENCE.
>
>  if KFENCE
>
>
> ---
> base-commit: d0d106a2bd21499901299160744e5fe9f4c83ddb
> change-id: 20250123-kfence_doc_update-93b4576c25bb
>
> Best regards,
> --
> Christoph Lameter <cl@gentwo.org>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHbLzkpTF-n85vHeFVEWQArpV%3DhP9Vo_tYm_LgUQEWLJp%3Dac8Q%40mail.gmail.com.
