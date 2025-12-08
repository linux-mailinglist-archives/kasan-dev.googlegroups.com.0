Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRPF3LEQMGQELYP3XMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5234BCACF6F
	for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 12:13:17 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-8823c1345c0sf54157666d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 03:13:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765192389; cv=pass;
        d=google.com; s=arc-20240605;
        b=eelCGyIccjp7qpcxKC18ENb8Jicm6465UxghWWe9ayiyyZqmyCrm7KuKhoCBhs6+zm
         1ooRI/kLNxCx4y+ITtYRKColaQRSaOpNoRmTaLuJVC8tYlfXCQCkJSibSD8WtvIkDcZh
         Oza0CwaTu+8Y9gt1SdZOnS34fk0gbdHkJ3kwYKxQS/VE/cOUCCXRNP3518bAaVE4mZlY
         xeF5AnKeHr1w38uo6sR1yy+SgpTo3S35p1lHMrsLMHWqwxG2jEU+m+ZTZnKBfBHS8R4k
         uVC966f/oFdhyeUp2wJ6fiwnsKYeHc51eeCIRC2yXuZaAXG2SPk51xsn0pHMUtAFGRNz
         7FUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ERZgd8duepM7xWw8wpCI/PruFm6KLmFFccnP+d0oV4s=;
        fh=hX7d239Vm/Sl4grWE3jVbTGkBEmreOs3FyX5MywiDYQ=;
        b=Euv08qTBPKa/eypwGfL/V4ORsIfPDZsOwLXRdjXGzDHTLOwmY45V4yUtTLhKDtD2yW
         BqekxvkzNSbPrXTbt/Vg+8phlpqGtFPaBOo8NHOZyljU4n+1ncv7HZ80/9hgJisq4o7N
         xI+NmkhTu4AGoL+hcg2iDm4MkHwCapnU89hPX6znNU9Prf1e/anUuJcj0LIMZ6BHabM/
         SA/P5oh/34NisYiHR5HhQyRFG3crx2Sv2DlzGLXrognWsmmhLtU9VN0w/S58ZbtfvHHv
         A1iyFhax3m1438RcIsaHYKDcTyav2uvgATbSkwoswEXMCkbylPPVIJsLpuB8kq9ub49H
         nshQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WliJWZVl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765192389; x=1765797189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ERZgd8duepM7xWw8wpCI/PruFm6KLmFFccnP+d0oV4s=;
        b=lgbxMuIAeJQwvAQ8K543ZEjach0QRtMUxiSFptE0mWES+9CEudzNkC52zit20a3G8M
         G8tp+rNzyJ/aOYeWA4n2lSFZGJDyh+nT+qih8h6j01OhKMK11Oj0jf/+D0ueYCqvOYm3
         l39ExQdCGwAS0wss7GhOgHUMrV7V8D28G8+sLEfJ0Adyktd4EiyqW1QORUKykgA4nAef
         E5HVMQmUXCBczcfRNsY1aFxKAt5BOhtOk4UmvCQh0qQVBxJeQhAH1Jp/YjZqA6upO39W
         KHsor6UT39ifKPHv98tPf1BTREWY3pkVW5TqeWKMKnOPeqhIPkll8gzDomgNz8Xo9qan
         +uYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765192389; x=1765797189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ERZgd8duepM7xWw8wpCI/PruFm6KLmFFccnP+d0oV4s=;
        b=NC1TsVuOBOCSYTa06H+p9ReNMo1Wzv3c2SbtTILaKXivwd6d506yA4JX08Is9YrCZn
         W94552o50shGQiZAivFiCk+D9AOQu9I/O6iz+qpKR5kcFx3FNO7zZHwWU1xSAgAI/m5P
         QdQUw477f9SIKKG+FQzMB6nrsEpCzJ5TbMPG1RXwyUL3oU0EFZRnd/1AOkEWEOXVtvsw
         MqnDqxzC51IN33QnDLU2kL0Q/6HMfzRr2WwVXikA98ROPOFJnum8MQO94kSb1fopg7EE
         ZuS1B3Gf7EhNFn6ASnFa/UGUm/5bpeNQPPo9M6gQM4I2h7vlmhe/czKSlR3FMenGjvOd
         YJdg==
X-Forwarded-Encrypted: i=2; AJvYcCV9zF1aGcel3uks3Ciq3mF+1YI5W15BpMR99cjGxdqZZg2Wr2Z0Sgk8f519ldbzDwk6MPVIAg==@lfdr.de
X-Gm-Message-State: AOJu0YzuumyMmcpq/zeK9VXWuV587fxatkMyvtO0u13ypOfQzepwH6gg
	gQbA+ZHmhwcbm796ACsTu11xlgT4WsxAWYCefs2YG2yz4OahWJX2qDI8
X-Google-Smtp-Source: AGHT+IGOUjE0Lw3WmhhNdtvgu/HU4DNq8kA7VoTHqV2hXCERfqZ8CoeJOGkftIwwzCYOPjQAegvk0g==
X-Received: by 2002:a05:622a:5c19:b0:4ed:a9c0:1e30 with SMTP id d75a77b69052e-4f03fdb77f6mr98929001cf.25.1765192389552;
        Mon, 08 Dec 2025 03:13:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZa5pLcXY6Ixj265sGuOz/bbV1EGbG4LVPmiBlvHagIZQ=="
Received: by 2002:ac8:57d1:0:b0:4ee:1b36:aec4 with SMTP id d75a77b69052e-4f024a974a8ls88232781cf.0.-pod-prod-08-us;
 Mon, 08 Dec 2025 03:13:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV67pVeZdqoCMOSJD5j45Qaykgzciugcpm+/GGK9+FFDvVuW6BfqwoN6L4P0IF9OSwUI0mwmRIhm/k=@googlegroups.com
X-Received: by 2002:a05:620a:288f:b0:8a3:4887:227d with SMTP id af79cd13be357-8b6a23329d2mr1100364285a.5.1765192388190;
        Mon, 08 Dec 2025 03:13:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765192388; cv=none;
        d=google.com; s=arc-20240605;
        b=AjrBG+3ARP7bX3v8lM5Dg0MgCf1eLCu6h+dv+VXiDiFowkdwsAIYZO8DGSYB2Pgfm9
         MNVYgH6hUvDkUdCEd4u7AugebZKfxcO3k5DvzsoiXJ5rVlZNRFOXVdOkauqbCWNBN/i4
         I8IiQpI52VOdkgSAwUUcvJUPeMhSeHwVWR9I4iYtppmwUxE/c2dRPNuthCkTgJQDuWO+
         IHp296MH6Lw8THCMnqy7vQL0jQVbX+toV5eXHtcr+6OvFfaXq7ytWNqdj90wN5DbI+NA
         YCpBGdM26kXdKbyPBxbzY3+xq8GLnZJR2jQLDjn05tdsTjcwHKKwc5CpD/dKFF3DxnrE
         pMbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BGqGAtkP5/3IHsDau2gcLeufHgEnSHyUsdyxnCuzcbE=;
        fh=Kp2ksfFS8HwPmjHIa0RxUepxEiJaHpDyLZHLM2rG9Fc=;
        b=VKVwyjzm2O+wI5nOuOJLgU1G7btrKg/BB1n0Z3Mwryw1vo4Hx9DS/12X7hf5of6l7v
         wwDLdiXATr8EWBUUAT6iu3E1j4Hq0tMVgk0EmRabRvvfFA1Q5o9B5R2RPOfptxwBI/80
         uOhCWsBHVMIcgOZm5WzH4t2m/JIn9SYbA7Txi2si/V1r6h/DX9YlkuzgFMbGHaY4GXhL
         YBzDRSZeYskZ1O1gpQRks/YkronDjBeo7orTu+keA6QPWBISAEAtNF0fRiHyW3sdQ1eU
         CrD5WMhwbTRPB0TEQcnMAeZPe18A+/0Tr5RCkxa6VmpOkmsmAL116W9MCc7FJCHLWhWe
         CxFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WliJWZVl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8b627ade31asi43268285a.8.2025.12.08.03.13.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Dec 2025 03:13:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-7b9387df58cso6621997b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Dec 2025 03:13:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUJUy5C8GalKmuS+k2YCEhEO1/mcBFsE7G7uoHdBHyr9CFGfcJHr0gmTptPyGrVZDTSyidiwRwANl8=@googlegroups.com
X-Gm-Gg: ASbGncuZeGqF7m/kBHgiwOIVroXGk1D1mJnWUlRbz+cVCgwH8gNZ08ozR61DkxMiBks
	5eRlB9k5n99MhVt7YjT2Q1XX9nTqKtsc8MrMipIh5iXfoyYq1FPr8wFeIjmMH6+EavSUxI42v0z
	hxvqCoz8hhKbnMygFj/JO3LD5HE1+/Z9y5P4kWldJwTiOQgiT1p+4Z0nsijab5gKTVxLv6bEwbG
	tQbsst4cYxwxIM64baDtxAiPAfUmvZKfqx9n+ae/16IIUZ8n6XoSIgSQwUeFgYVNB3hbWj6HW6f
	3DP1RIBS8DzSYfCtRxxMlwZkNA==
X-Received: by 2002:a05:7022:a82:b0:11d:f462:78ac with SMTP id
 a92af1059eb24-11e032949c3mr4745882c88.28.1765192386864; Mon, 08 Dec 2025
 03:13:06 -0800 (PST)
MIME-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com> <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
In-Reply-To: <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Dec 2025 12:12:30 +0100
X-Gm-Features: AQt7F2p_WRh-PC8QyjZ_pxOT38izGIikdxt6_xyxNy5vZnN49d2oV0zNsu-pl5I
Message-ID: <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=WliJWZVl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42d as
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

On Mon, 8 Dec 2025 at 10:37, Marco Elver <elver@google.com> wrote:
>
> On Mon, 8 Dec 2025 at 02:35, Brendan Jackman <jackmanb@google.com> wrote:
> >
> > Details:
> >
> >  - =E2=9D=AF=E2=9D=AF  clang --version
> >    Debian clang version 19.1.7 (3+build5)
> >    Target: x86_64-pc-linux-gnu
> >    Thread model: posix
> >    InstalledDir: /usr/lib/llvm-19/bin
> >
> >  - Kernel config:
> >
> >    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657174=
f0537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
> >
> > Note I also get this error:
> >
> > vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !END=
BR: machine_kexec_prepare+0x810
> >
> > That one's a total mystery to me. I guess it's better to "fix" the SEV
> > one independently rather than waiting until I know how to fix them both=
.
> >
> > Note I also mentioned other similar errors in [0]. Those errors don't
> > exist in Linus' master and I didn't note down where I saw them. Either
> > they have since been fixed, or I observed them in Google's internal
> > codebase where they were instroduced downstream.
> >
> > This is a successor to [1] but I haven't called it a v2 because it's a
> > totally different solution. Thanks to Ard for the guidance and
> > corrections.
> >
> > [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.com/
> >
> > [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54f77=
90d54df@google.com/
>
> Why is [1] not the right solution?
> The problem is we have lots of "inline" functions, and any one of them
> could cause problems in future.

Perhaps I should qualify: lots of *small* inline functions, including
those stubs.

> I don't mind turning "inline" into "__always_inline", but it seems
> we're playing whack-a-mole here, and just disabling GCOV entirely
> would make this noinstr.c file more robust.

To elaborate: `UBSAN_SANITIZE_noinstr.o :=3D n` and
`K{A,C}SAN_SANITIZE_noinstr.o :=3D n` is already set on this file.
Perhaps adding __always_inline to the stub functions here will be
enough today, but might no longer be in future. If you look at
<linux/instrumented.h>, we also have KMSAN. The KMSAN explicit
instrumentation doesn't appear to be invoked on that file today, but
given it shouldn't, we might consider:

KMSAN_SANITIZE_noinstr.o :=3D n
GCOV_PROFILE_noinstr.o :=3D n

The alternative is to audit the various sanitizer stub functions, and
mark all these "inline" stub functions as "__always_inline". The
changes made in this series are sufficient for the noinstr.c case, but
not complete.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNPizath%3D-ZUVTDFAdO_RZL1xqnx_o24nHA%2B3tJ4-FOg%2BQ%40mail.gmail.com.
