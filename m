Return-Path: <kasan-dev+bncBAABBTVQXDFQMGQEJXZETIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A288D3A718
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 12:41:03 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-3ff590953b1sf7783743fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 03:41:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768822862; cv=pass;
        d=google.com; s=arc-20240605;
        b=OQcNyIp88B74karW6DnJBi1FpYSjRTxRE74sH7xBQwmokG+YfbcElWoNkz6EnBy+n5
         rP3F2w7p7xDDbUtZPbkKeEQD41H8dXfBI8bA/YJKcQ5PDZioCIV9CjSV7YEaaZ72FoRG
         7WXVq8T0mMi0TL5bhrqqox8EqevRKnz9WPMX8FLyZ1WgMFQ7DRCt0tYqmvweoYjN10GP
         RrMDrW77meQ66jaFAHCMRbFN68ynKyT4BKWRIJIM1I5CNILN10HXqPUww8nuWMOMOUPR
         VBU8/lGkBiIk3lkG5Fmdk3Zeo49UzX4hoV40czUfxQ0+FUoa8Gz10LOna96zqVnf3J3O
         VGOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=AMiypueD9eIDy5NK6QPRZSoxH6j4ZswNg/09DCogR4k=;
        fh=2uQAb7UQbEwQ0NRioBETiHqi6YxZ9Is5Flh642E40fA=;
        b=B+xpJdr9Fif15Bz9P07wVAQx5cnA9er9wXBWPAF64lFwnLPnXIxpTV1LzTRlpxgLsE
         FZCQlYhRZf7zN1YUlbdaaQU5hbaocGX8+MjewRt+/818DvoZm2ruJMiKp0GynxeH0ZdK
         5Xg9wHsUxvhAtgbTBbsjyRwqRx+CISEvDFeiJrQxP68RvZ+ArDXQOoJr6ckterB37/Re
         l0YLFnHeZdm6zPWNs3/Ar9bcXNb9rP66OezfspyAxmuTnuE/ZKA1I943NCt/u3UYvZ4F
         ROaY6h/2YmBv6wE4w68jTRp1l56HWlkt4d4D5OygDnRoNN89/UydUqD9gHg7LSvmY6Vf
         JQqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="pRxL/2Ui";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768822862; x=1769427662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=AMiypueD9eIDy5NK6QPRZSoxH6j4ZswNg/09DCogR4k=;
        b=vcDplYXwjuAWLvsr6cP7rSVpzb+b6HG+sZ26vpth+4i2BjRrPypDWQV5RjzEvOa7wi
         qrcyjUT9ZaEsQSPWlL07YfAqCrXugPXxO+JjxXbLi3DrFXAk1ez+zAGnXGehF3IiJfRS
         NG6kTvFI8Hvu4kh8LlSWV+Xrc97aANqqDUTG1WLRjqN9SkI2NM7CHZjmjechXwF9Zr9J
         Vi8h0PwIJLCx7VvwMLYY63DSE8VDsML2jrJGu4RKd7oEJik3tWU4plkRVTkA/lt3mA/z
         Kz9RhkwZYEt7Qvpw0T3Uy5C6G9CiRjuhyh9te/XVsSkMLhOb3JcHfyTuIixz4wKhIBqZ
         4HGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768822862; x=1769427662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=AMiypueD9eIDy5NK6QPRZSoxH6j4ZswNg/09DCogR4k=;
        b=f/62CuAsj9rOSESiyWNrZ74uaSR6SEVhEZ2KvB+kL7w2zRxIR5oNOoL4rf30sNhoBm
         9h6uyZK5PZpSyxNdv4M/eyZNsoPr2Yl7IVDYwPBk7oe+nfQRXa05393oopQNM+9NY5DX
         fYYfuCftnMJhnNYPAO+zo+NPQc/uswQE98EQnExzg52RhVTce/w5oGDrUrovJYOoqhTz
         N6GDF0oUWyg5yPTfAg/rvANOAa6bGPMRcnBJJpV4OYgIjoy6tzHwlNSAsa8Lu0uXPTaM
         7QNQcEEpF5dW/kHT8ZiRHAShWR+KXylO24sqbu5bJeRxU22WST+Uwi13YyTnEBgTYSNx
         brTw==
X-Forwarded-Encrypted: i=2; AJvYcCVjaaTJgFujoh7lOWC8TimSCNd9LcNPCz8lp1QaYPqmqq9uzY37g5iUiiVAmUS7FJeZ5YjtPg==@lfdr.de
X-Gm-Message-State: AOJu0Yz0AdBnXk5OvY5FDAwAfFZoBY1SN8MkzCDLO328IfI5tvZvM5pP
	IY/bq5ORyAIcbMz9XIVKTjjdFqzmA9KS361BbB6JPu1bopT2Qx39f67E
X-Received: by 2002:a05:6870:8188:b0:3f1:6d93:4386 with SMTP id 586e51a60fabf-4044c16488amr5033089fac.1.1768822862231;
        Mon, 19 Jan 2026 03:41:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EOvNFeJcpB2K5JLT1lgftNYquQ8OX4rX8XAdBGh7WxDg=="
Received: by 2002:a05:6871:b0a:b0:3ff:a5fa:7cf0 with SMTP id
 586e51a60fabf-40429170893ls2327189fac.1.-pod-prod-07-us; Mon, 19 Jan 2026
 03:41:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMlYGbFr7sAhOsM27frN/oHpk0zfwtFXM6IBhoZsd/bprIvz60cez3wOv6OKyIzMtLTHu/XiLg1hY=@googlegroups.com
X-Received: by 2002:a05:6808:2204:b0:43c:8714:fe3c with SMTP id 5614622812f47-45c9c0b5f41mr4231815b6e.51.1768822861355;
        Mon, 19 Jan 2026 03:41:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768822861; cv=none;
        d=google.com; s=arc-20240605;
        b=dq1r2mJ11sAS8ecTR/j27k6mLhWVhEjJDGktcgPp2va00OU9R8P7MnKCBvFb+Z2ya4
         nncEfxfQKQtQvafgtmy5ZuTojh4hhO0mYCgRbOTljBs00s0O2/H1MO7j9dqjFMy/u5gT
         S8DgqY3Kbpt4NPF11u5uoztHhGeFtOwE6tuxNI6NXXG3uaF9tMdxwZ9e6EOGfvemM9sJ
         2+G58KoC/6VpkNAAelA6J/mzGeQNfZjRiMAuymVlE4vSPxa6XQSRD8f9B02qwp9tSR5T
         WCCz9uE4id5teYCDuqbAeiZS64db6bKWJhGuxHViMcYUbv0kMb2tFUw8O9IBDyOk5M89
         RzBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=Ux9EqExLk0S9sgu0sjfNhFAgqMdUCgo2g+8tHNn15AM=;
        fh=h7y4lLUGVbT1Ds52fRLa9C4INAXfD90EjF47xC3gneA=;
        b=efCWayeeS6g+3XAsN/a5qGZ3ktrutPKmnoaqVReqQw3EosZICm6vYP+N8I4KxOIjSd
         HSNO7pAjNCjmxEWqqsV8/FTtV+EVZhwx+cAMCpiRSu6YvKQ9SetFXxVZL0DKy/6eYEwQ
         Qrv91rPPYaKAU5qNN6icgb8QF6BOmZHbmmFfFpA9l47CqvdUgBPHcmu3Xt5+aiNZ9tSY
         0gXIPZj6KmgNhhOpFNX1D6F9/9gEFd2LNJ9x3hVGvsima6tzbbsQrIJRb/m6a3MTOCKv
         GZiAGp7a737mH1TAUvOv+QfpAb3sJ260hWkCXBNZHZ+R5E+2PIzg0e80v9MlZLvx7zp1
         DguQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="pRxL/2Ui";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244116.protonmail.ch (mail-244116.protonmail.ch. [109.224.244.116])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45c9dbdbf51si315269b6e.0.2026.01.19.03.41.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 03:41:01 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) client-ip=109.224.244.116;
Date: Mon, 19 Jan 2026 11:40:55 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v8 13/14] x86/kasan: Logical bit shift for kasan_mem_to_shadow
Message-ID: <aW4XiqW5-P-f0_PI@wieczorr-mobl1.localdomain>
In-Reply-To: <CA+fCnZewHBm+qR=zeJ4DG6RJ-mHhLhF9G7f_xSaNt_PAogJv2A@mail.gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me> <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com> <aWfDiNl9-9bVrc7U@wieczorr-mobl1.localdomain> <CA+fCnZd4rJvKzdMPmpYmNSto_dbJ_v6fdNYv-13_vC2+bu-4bg@mail.gmail.com> <aWkVn8iY27APFYy_@wieczorr-mobl1.localdomain> <CA+fCnZewHBm+qR=zeJ4DG6RJ-mHhLhF9G7f_xSaNt_PAogJv2A@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: e92e8e19771804293aa60425c71ec8789b768681
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="pRxL/2Ui";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2026-01-17 at 02:21:31 +0100, Andrey Konovalov wrote:
>On Thu, Jan 15, 2026 at 5:43=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>> +#ifndef arch_kasan_non_canonical_hook
>> +static inline bool arch_kasan_non_canonical_hook(unsigned long addr)
>> +{
>> +       return false;
>> +}
>> +#endif
>
>Let's put this next to kasan_non_canonical_hook declaration.

Just occured to me that, as opposed to to kasan_non_canonical_hook(),
arch_kasan_non_canonical_hook() is only used internally in mm/kasan/report.=
c so
I should toss it into mm/kasan/kasan.h instead.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
W4XiqW5-P-f0_PI%40wieczorr-mobl1.localdomain.
