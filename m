Return-Path: <kasan-dev+bncBCMIZB7QWENRB6E5QS6AMGQEPIHDV4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FA2EA09008
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 13:13:46 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-43624b08181sf9879225e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 04:13:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736511226; cv=pass;
        d=google.com; s=arc-20240605;
        b=aXc+UDKE+W+YE0mxXokNsbHBhnrpR6skPRcnZ4VLvqbKpleHXj0ufn07gAc6lvYjnj
         UeuZXMyQOkSo/Z/EzYbWJPEHA8xK36+oSF9y78AaG8kurSZK4VgT06Uy4IrOwJhhm21O
         u0r4pCZ/N3Tc8eWH4JMPTSvfGf3+dVPoxQgD87IJ+eCJmSJRxcjEQ30oqGBhbLK0mXYj
         RbdCjQ/lFHhmfHoyD47a0kEZuGIsuRqbkcFSov7i4Kb0kKoFq3V7sdlAFquoPUTadcOM
         X5aw22tUmus7A5tcns1z5FeCcxeaFhFtEXhqbS69B05F1jvcfIIrv8OMpXpgtVjfaxr8
         QCwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RQ1SPLd/xekjsI8wjI/bF2EXpcN5gNdt8umBY9RwJhM=;
        fh=LM891DpJFE9174meoOi0E3XD51Na+/f4rUpKxwALU1k=;
        b=Vb+zVdadF4Y1aizof/mwJlL6dL6/ic5eWPz8QD2V/KpzT/1OPn+Xr7GSWWM+cdGJzI
         poomBoKh1+9s6esL9g2iYrd9b+wNVhN8y6yu0pvcVq2Zmt3DcXEbYoxpXp+VPTQ0plQl
         naII4YznpCG4GRpZI7YY54GQdyPcBEuNilPtWlrKTMOrM+6IK8cjoGt5/z5cTg/YgaM1
         0igrPVxL7fJzUUfNrBKvux7i8C/4EdxjL5ZHTU+NgWPWgpFbMVnLjLAsTxmTuwbQRgq/
         /3zdQ+mWm6c7oAOfVLyK65bpzfb9IBRpA8q9VlhXlglDfR4XglN6sqEtg/KZLU6LDbHS
         WWfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AdkCZtCJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736511226; x=1737116026; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RQ1SPLd/xekjsI8wjI/bF2EXpcN5gNdt8umBY9RwJhM=;
        b=u/co5QPjkvHogpT8AHUBcP6m+DoEdVn81Zk2IxbVJqpAN3Ix9DUSE935B9sZDZ/d9O
         rMW3dgvXo0TaJVgK8Z1zu2M3s58fFeSoLh/yxdfidIUQVLwkuWsM3VJTDcN9ktp6l9q7
         M/d5i3xmAI/kQGipCnRPEQhEWtOZuRPmeLFi3C+7EJiGRDnJBYLGtCmn5+XeBpWTAnXW
         yTT02uU5882ga7p6S4GlYKvTm0q48KzqOOIWBSbS7YVuPQYvbwfRBG1wnB2f5UOLH8as
         PhmNpGxx7tHyh2/cEDUw5H0+KYU55fTPPESCcTqU+lSlhA4rfF0zKWyNwibawE/9dPCS
         mM2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736511226; x=1737116026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RQ1SPLd/xekjsI8wjI/bF2EXpcN5gNdt8umBY9RwJhM=;
        b=bWzYO/V0rWdX0+iFcPy3Bb6VqQr/DabhgAVUe3BUATTMmiRnFo/6+fftSzrrlbjhp8
         9P94Ye6PBeq/lrC2dUZm0x++O7rE6lQUpSma9qrFMMv2viYiYgXy5PYul8aHno4XdUTX
         FsClTIlC8quLmrdM7+5mcTb4tR1g1CxjL7EXihFXgZ4W/r3vQvMbumTZNBwsTTsIJkuG
         X5npcGGAb7Gx6nxaSVn25Tmy7oqz9XvqeU3T2Oj+MbfggLfLFxZCd2TD9r5Z2bcv2bLK
         VSyh/qa6G6FcB9E7/sa5SrvUhB5nzskgi4t3zBFjwcMupkS5fKxeQaibSX+wRarUpSy8
         +sKw==
X-Forwarded-Encrypted: i=2; AJvYcCUmQLs1T34CoKv6qQV8Nq8BUmvGNlKLhXA8/n4ssNx0zZHhqqVzoERWhy+2ndqrIlEbfrlTJA==@lfdr.de
X-Gm-Message-State: AOJu0YygOCa7H8H2urpa16HfqfztYTjMEyA6joE7cEXXUg+gGqwPP4d2
	c2jSH2ZKqZRkvOAGQXcDQ+vsSsn17smjs5hljKGg98y4Kng7m+t5
X-Google-Smtp-Source: AGHT+IHbDKchUQBpRRQutUN4q8pgPMSzoNbhKUKC/GkNeGZLGSf+eHtN6mhx75ayicu6042R1pWyLw==
X-Received: by 2002:a05:600c:524b:b0:434:fc5d:179c with SMTP id 5b1f17b1804b1-436e9d808d6mr54933145e9.13.1736511224724;
        Fri, 10 Jan 2025 04:13:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:224e:b0:436:f132:b02a with SMTP id
 5b1f17b1804b1-436f132b139ls1458655e9.1.-pod-prod-00-eu-canary; Fri, 10 Jan
 2025 04:13:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV05NnGrd4gA5c8p49B4LYe8lOVPqO8b5dUTntZhiKcDpeYYRPKdBlvOYcDCi7mwsXqJ7KOt+LTxnM=@googlegroups.com
X-Received: by 2002:a05:6000:4712:b0:38a:8b34:76b0 with SMTP id ffacd0b85a97d-38a8b3476c0mr5695971f8f.27.1736511222578;
        Fri, 10 Jan 2025 04:13:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736511222; cv=none;
        d=google.com; s=arc-20240605;
        b=F5tRvZzHO9UUpHGMutEAhucR9k07O4s//9mVn8BslBY9B4iZH63l5swDxuxbmVExTT
         c4pbOL7jQC3ZUlAP2J+gyPwRzyNmB87e5BK1WHWwKT3EFTVdMCp5W/Tu8TgJMFZwl93u
         if5hTcdQ6TfpfKj9/7TUXsI0haZTma9y9BCrqSkAnd9j6FjEojpcq2vo2hguqP7pFkFo
         R3bYPPelWD2RI5t1kfR4Ths6ntIzF124VLWAWklrIkq1UH6mRYcBXM6b3DKbtfY9k/sc
         gm7XX6sOa6FOBKAaJaojtbjzN0M/SBdfVmGi2aWz4N9Ni9VNWPto+YCVZ9z3QEUWSmrO
         9bNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6WHLV1p9mzYESODuTx1hA2zS9TYkKVyUPvSyWSr55LM=;
        fh=573dgKuyf74+EWQrYUpl880ucJtXgR1VAjrNrO5vjQE=;
        b=caIpylUrOc+6P6b9bBhMhoLjacydMbYWKT9d/qa9jXnA4WCkLD57xVRVk5LXe3QRsO
         ov1ubX9ziFLZ70afjemvN6Eqn/SDcJ9CsHzNdh/dRYLThqVMctF8oGR5J/nZBjBVBIuH
         8iXs0gMWFt28tJDXw0L4ysqo2CU1fm+3AEIoGizOY8JuR61u1gG9DH/EeXEaCl0RgJUH
         IlJJ6d1EIzbNuIgjPjoGYwWdt5ywVonHwE2dOtdF6w7LsphtzE70JyjxmrjmCgP0YE3W
         kRMmFfVziMFgUNzWCn0hATVBmGETr4GU6qFbTTJkZsbuSc1AA/RICRIYKKtlKBh3TOP+
         IY1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AdkCZtCJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-436dcceb7ecsi4987625e9.0.2025.01.10.04.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2025 04:13:42 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-30219437e63so29012951fa.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2025 04:13:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWgpmMXNtqclCxFi4bP0RDL0mzOWn54Gz8O03L2C1eFyoSANVonC9IiXY8cKAc4wp/Hw6bPOOyEHLk=@googlegroups.com
X-Gm-Gg: ASbGncsxAVvJlEqimVLOSzoWzkPcq1dmNJ6/f2KGbgVtLzB8IbAYkF+beZntHbxNB/Q
	pexHe/T+rJ76kllQQ1XxL4d30Y5wcdDUK5ciz76JS7jZ06BNWOYJTNvRbMnXbwYsysEgBZpo=
X-Received: by 2002:a2e:bd11:0:b0:302:41f6:2357 with SMTP id
 38308e7fff4ca-305fee182f2mr16774751fa.14.1736511221423; Fri, 10 Jan 2025
 04:13:41 -0800 (PST)
MIME-Version: 1.0
References: <F989E9DA-B018-4B0A-AD8A-A47DCCD288B2@m.fudan.edu.cn>
 <CACT4Y+YkkgBM=VcAXe2bc0ijQrPZ4xyFOuSTELYGw1f1VHLc3w@mail.gmail.com> <FB52FB66-5210-4FA5-BF1B-415234AA62EB@m.fudan.edu.cn>
In-Reply-To: <FB52FB66-5210-4FA5-BF1B-415234AA62EB@m.fudan.edu.cn>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jan 2025 13:13:30 +0100
X-Gm-Features: AbW1kvY90kmGWCMYSBATc9LScnsZiwbcEmY_diHaJQoiz0n0kFpE_HAxWKN4xOQ
Message-ID: <CACT4Y+aXtpXOzesh=+52Vt4+hufixQ8HrHMJXAQ8MFeRR5D_Sg@mail.gmail.com>
Subject: Re: Bug: Potential KCOV Race Condition in __sanitizer_cov_trace_pc
 Leading to Crash at kcov.c:217
To: Kun Hu <huk23@m.fudan.edu.cn>
Cc: andreyknvl@gmail.com, akpm@linux-foundation.org, elver@google.com, 
	arnd@arndb.de, nogikh@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, 
	"jjtan24@m.fudan.edu.cn" <jjtan24@m.fudan.edu.cn>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AdkCZtCJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 10 Jan 2025 at 09:14, Kun Hu <huk23@m.fudan.edu.cn> wrote:
> >> HEAD commit: dbfac60febfa806abb2d384cb6441e77335d2799
> >> git tree: upstream
> >> Console output: https://drive.google.com/file/d/1rmVTkBzuTt0xMUS-KPzm9=
OafMLZVOAHU/view?usp=3Dsharing
> >> Kernel config: https://drive.google.com/file/d/1m1mk_YusR-tyusNHFuRbzd=
j8KUzhkeHC/view?usp=3Dsharing
> >> C reproducer: /
> >> Syzlang reproducer: /
> >>
> >> The crash in __sanitizer_cov_trace_pc at kernel/kcov.c:217 seems to be=
 related to the handling of KCOV instrumentation when running in a preempti=
on or IRQ-sensitive context. Specifically, the code might allow potential r=
ecursive invocations of __sanitizer_cov_trace_pc during early interrupt han=
dling, which could lead to data races or inconsistent updates to the covera=
ge area (kcov_area). It remains unclear whether this is a KCOV-specific iss=
ue or a rare edge case exposed by fuzzing.
> >
> > Hi Kun,
> >
> > How have you inferred this from the kernel oops?
> > I only see a stall that may have just happened to be caught inside of
> > __sanitizer_cov_trace_pc function since it's executed often in an
> > instrumented kernel.
> >
> > Note: on syzbot we don't report stalls on instances that have
> > perf_event_open enabled, since perf have known bugs that lead to stall
> > all over the kernel.
>
> Hi Dmitry,
>
> Please allow me to ask for your advice:
>
> We get the new c and syzlang reproducer  for multiple rounds of reproduci=
ng. Indeed, the location of this issue has varied (BUG: soft lockup in tmig=
r_handle_remote in ./kernel/time/timer_migration.c). The crash log, along w=
ith the C and Syzlang reproducer are provided below:
>
> Crash log: https://drive.google.com/file/d/16YDP6bU3Ga8OI1l7hsNFG4EdvjxuB=
z8d/view?usp=3Dsharing
> C reproducer: https://drive.google.com/file/d/1BHDc6XdXsat07yb94h6VWJ-jII=
KhwPfn/view?usp=3Dsharing
> Syzlang reproducer: https://drive.google.com/file/d/1qo1qfr0KNbyIK909ddAo=
6uzKnrDPdGyV/view?usp=3Dsharing
>
> Should I report the issue to the maintainer responsible for =E2=80=9Ctime=
r_migration.c=E2=80=9D?

If it shows stalls in 2 locations, I assume it can show stalls all
over the kernel.

The only thing the reproducer is doing is perf_event_open, so I would
assume the issue is related to perf.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACT4Y%2BaXtpXOzesh%3D%2B52Vt4%2BhufixQ8HrHMJXAQ8MFeRR5D_Sg%40mail.gmail.com=
.
