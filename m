Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMHLVHDAMGQEOQS56DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id C5381B7F102
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 15:13:49 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id 71dfb90a1353d-54a1ab16fe1sf6308148e0c.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 06:13:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758114828; cv=pass;
        d=google.com; s=arc-20240605;
        b=YbH/c5LUlFqabo8rjCGMr9kBMcWiO6cYe/QfzCJRTQJqM4CA5shCmPqZ78L2TASeKs
         K88fYXdcsw+IPZ+PNpvUfEbLDzy1A5TALJWp1LGw/q0pVfS6s9muGBuc7oxUmy9dPH/a
         hIgNQxoB9Twj53nDIFI2aA8a3R6GkFiAQGjBoWinX9J+37OYiLguPvafysybBXyNQmwW
         u79JoXQLfuN5Lxj5EAUrYK4cjxRwWhAtFQqzHm0ZbqzR6jqqEebVmX17KnER+89gOobY
         XYc7LWb7M5iJoPIbv5eYljl8ucR/KgVyPBOonf/OgT4+mukfXPs85S/dX0HM3fRNsP3h
         G4ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XVg6ww0l4Vip0wVzpR/l2BDlfb9956lcjhd6tDaX4ik=;
        fh=v/amaRT4iZ+nQw80qH93uFsy2U33QPOHWXSK0fnbbOA=;
        b=TKkEmy60rBgA4rl7nHM+itxHJx2pUljVaqQmgB/pSmCkcgQSSQX5nYlm9hlQE2fWwY
         mSBeVqXg/sbpXG1DxLWNgyIRw4js2NsuGclfMbwoIOOIHPaR/xkiIEeNAkhnG0OMMYc3
         RwYY1UbmhcX/R5/AXtDoolpQYHVGxrhEchM74cB20zo/KxMql5ci54crE/VHk16NZPwK
         3YZdiKR9pMiB1ZnaN30FLlb4runW5Hs0BBjkSlBmcaLSZIxnr/N9VVMN5ak/LXT4mTQv
         6I39BHKOBj0p3RdOh71ziEmkne3H/BP+wj65Q7XWqsyqMd0J6O4WqMH2ZeeCjGHNrLOz
         ZJKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tvR+VjVa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758114828; x=1758719628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XVg6ww0l4Vip0wVzpR/l2BDlfb9956lcjhd6tDaX4ik=;
        b=s2e0+fQ0yu5gdn6pvBzdrx3/flYZSl619futGv5rNAK59tEGxqyKHg2ytu59JXGvzL
         Yu4h9jCcmJ4KL0viilACrKjRmzY78u4RQzHV6isC0HNrepSmdf0/BSamc91PDDufuKSE
         IIxPVlMtezgGwEHz+AASwFClMq1CqT+71ALez/dBngjsXX8RiPmzlNnNtEshm7NhH0IA
         FrYWCA7AL793vvIFBq7cFNj3mJP4lwQ1boudA/FzTwAGAx/F1Q61KE8O836C9qCNNIlt
         Cq2mQTGYaxjWdyvCh/SbG/uiLwnWqumXnrYLtECEvszmj2IvkBsvxKs53EqI3KmFqj6t
         +rgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758114828; x=1758719628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XVg6ww0l4Vip0wVzpR/l2BDlfb9956lcjhd6tDaX4ik=;
        b=hQbsEsxOP4P8ZIhvLPwvAMSyfDja7yluKdV4GGI19UVdXvGjD90Y+mLndJ1k6j19I3
         th21pUUyZj2qVLq6xAPZ+2wB+vtGoIMyA80f3BWQoa+m27tF+yu1F3TkPKIYN/4Fbe2t
         gvTDC7/lJgDsirJpSRFB3Y5aD1xWnYrxeo3fjaoWHoYxYLun6+D+hbWggmZrVjenmR0M
         smnzAUbHqB08RGlBk8rSw4i2krFbcdI6JDznhoULpntBC2cbLyY/AHb3KuTJWqLuBZ4M
         +e2syl71Vf3kCc4VXvixfw2Ixi7bgGQLCSIbWBIlBSMzn27tNAjQeglC+HIdWKNc9daZ
         DwVg==
X-Forwarded-Encrypted: i=2; AJvYcCX2/yoPX92Qysb0Z0pf4/8S5sVB8cygUr7Qaol59ejzoRGSCLP/fnc3i12TVI4n9Ve8dUguXQ==@lfdr.de
X-Gm-Message-State: AOJu0YxmHqte6OtuouXEKjShk88VBpklzGiQmHLz8TWDpu/LCaFpyZWo
	01XtoYlz7Qgl1u6ar4C8stcYPi6xIhMC4CKM4ZmCj88TFcgHeXG85wPT
X-Google-Smtp-Source: AGHT+IEI7KVJ0rlc1U59KgL3Ofg5+kppBRBPyM4GhsfAN65bv4mpzUzTYjoUP7mzenrai75PFqXzGA==
X-Received: by 2002:a17:903:3d0f:b0:269:4759:902b with SMTP id d9443c01a7336-269475995c4mr8134895ad.53.1758098864540;
        Wed, 17 Sep 2025 01:47:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd55/zMK9CYSq8l+XCklPuY4ZIx2bxF+NYopAwyqe4JYKQ==
Received: by 2002:a17:902:d50d:b0:246:570:cbdd with SMTP id
 d9443c01a7336-25beddd8445ls70866815ad.2.-pod-prod-02-us; Wed, 17 Sep 2025
 01:47:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjMpgz4qa3oknVQf3w1IhLXHwcH2jmoJbcfscfHKqbW1jhLU5dEjQR2m1RmPMVr6GbF5LEiZ23yEM=@googlegroups.com
X-Received: by 2002:a17:903:2acd:b0:25d:d848:1cca with SMTP id d9443c01a7336-268136f9cccmr14552685ad.35.1758098863257;
        Wed, 17 Sep 2025 01:47:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758098863; cv=none;
        d=google.com; s=arc-20240605;
        b=fCR7oqHrSwl4xyvtR+8ZBWWznPfQF9z3xXZPekj6d+ykpBE2RpwjFGAnNnFWX7HyRp
         ViQtRIRzRt3lKayyEaRTlmHkcwLzmtDFjiKe6hlXAz7vX8K6jsRR+KwqL1pDZqOn3O6p
         zzqR0civDvGWG/L+MUDjk1D2TDtNpqupIbO7YwJZAgyng3rt9rep885N0nT+pw6Fx/hw
         xB4sWEKFn8j4WjfWWkVkkchsAZbIjzYbUUUU/8B6/Gqd75/pVPWPt2YekuR+0GokuKyw
         8ZcqaAFWpGRqhZhEVIHDBLjh8Z45+DzxlaF8Dgv5KosdHjm62CAp0fcaG36M5whDwEZj
         InAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qSQBwTY7x8IQoxtsTDFfPaHwMvtropOKYFv/BGH9LuE=;
        fh=4xpTI9gZ72TmyMl3fcASbjYGbQPekMaVq7aTJZypajA=;
        b=JAjiE8lFlyPakwOGUmjItRIvsN6jkPYrzzK6Jd2zqIEn9Kw7KM5HT7Lu0FFXJbtE6T
         mmI90QUfv58+G+E/caKpxdHMlNibOLx3b43HFn8Uz1laQs19q2o04qrAYn0sPz7Yx6Ef
         MUbmjjAer+AmL0+Q+vdCedSVxcgx/mIwtJT6k1tp/x4knNnUowK148j57rkx8stmwjpF
         YfVdCd4ZUAwYZvi/saWqU2YWkW+jKCgl7ht7daDJphHaC3K8Ns5WIK+0CCmNFfNFP6QC
         Mk/9mkyTIErv7IPpqx4qjNAsNWFkFJiUqyZehL6CUl2PW1rNMjuSWi19+AKMDuBkWITN
         dNag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tvR+VjVa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-267251c74c0si3391045ad.3.2025.09.17.01.47.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Sep 2025 01:47:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-78ed682e9d3so2930466d6.0
        for <kasan-dev@googlegroups.com>; Wed, 17 Sep 2025 01:47:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmxxKPCtJh3rmaphjcUFMb9Q4P9Rx+CaBAjYT47ex8QYhjEAQEwMQ6iCGQzqI9lTSNbkiHWZSjIB8=@googlegroups.com
X-Gm-Gg: ASbGncsJIJzlvFCSdYlvcrXMFzHAuGTZm/bKtZNy0qJ1fLDlR/NuBQt1TyKbhTin/Px
	ofZn32QfvGGwrFzBUqj/o/TJh6fIXa6y8xAjqYa24UQnK8n4cTBXzTgiksGtB7POVIKzCKdFYA+
	mxqJ3lA93fIXWmiSvltbz1VnSEAItZRNdoDMAyBfccGMHnND89anP9VG1mz161dgsuJ4yHRUvpb
	S+beEiCxr1K+WO5hoGM2NYJ540lLwgZgK+PkF8VW30=
X-Received: by 2002:ad4:4eab:0:b0:76f:6972:bb91 with SMTP id
 6a1803df08f44-78ecc6316d3mr11179046d6.10.1758098861793; Wed, 17 Sep 2025
 01:47:41 -0700 (PDT)
MIME-Version: 1.0
References: <20250911195858.394235-1-ebiggers@kernel.org>
In-Reply-To: <20250911195858.394235-1-ebiggers@kernel.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Sep 2025 10:47:05 +0200
X-Gm-Features: AS18NWCHIE1dESGpN9uvlB5H-Nyc3e2nakhbUlwz_P_LJD2Kd7WI7My-Di8UNK8
Message-ID: <CAG_fn=UY1HxmxpkM_YFGbr8W272F_bZgZHKiuvbsUjgFCs1RcA@mail.gmail.com>
Subject: Re: [PATCH v2] kmsan: Fix out-of-bounds access to shadow memory
To: Eric Biggers <ebiggers@kernel.org>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-crypto@vger.kernel.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tvR+VjVa;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
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

On Thu, Sep 11, 2025 at 10:01=E2=80=AFPM Eric Biggers <ebiggers@kernel.org>=
 wrote:
>
> Running sha224_kunit on a KMSAN-enabled kernel results in a crash in
> kmsan_internal_set_shadow_origin():
>
>     BUG: unable to handle page fault for address: ffffbc3840291000
>     #PF: supervisor read access in kernel mode
>     #PF: error_code(0x0000) - not-present page
>     PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
>     Oops: 0000 [#1] SMP NOPTI
>     CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G               =
  N  6.17.0-rc3 #10 PREEMPT(voluntary)
>     Tainted: [N]=3DTEST
>     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.17.=
0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
>     RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
>     [...]
>     Call Trace:
>     <TASK>
>     __msan_memset+0xee/0x1a0
>     sha224_final+0x9e/0x350
>     test_hash_buffer_overruns+0x46f/0x5f0
>     ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>     ? __pfx_test_hash_buffer_overruns+0x10/0x10
>     kunit_try_run_case+0x198/0xa00
>
> This occurs when memset() is called on a buffer that is not 4-byte
> aligned and extends to the end of a guard page, i.e. the next page is
> unmapped.
>
> The bug is that the loop at the end of
> kmsan_internal_set_shadow_origin() accesses the wrong shadow memory
> bytes when the address is not 4-byte aligned.  Since each 4 bytes are
> associated with an origin, it rounds the address and size so that it can
> access all the origins that contain the buffer.  However, when it checks
> the corresponding shadow bytes for a particular origin, it incorrectly
> uses the original unrounded shadow address.  This results in reads from
> shadow memory beyond the end of the buffer's shadow memory, which
> crashes when that memory is not mapped.
>
> To fix this, correctly align the shadow address before accessing the 4
> shadow bytes corresponding to each origin.
>
> Fixes: 2ef3cec44c60 ("kmsan: do not wipe out origin when doing partial un=
poisoning")
> Cc: stable@vger.kernel.org
> Signed-off-by: Eric Biggers <ebiggers@kernel.org>
Tested-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

Thanks a lot!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUY1HxmxpkM_YFGbr8W272F_bZgZHKiuvbsUjgFCs1RcA%40mail.gmail.com.
