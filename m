Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3NDZDEAMGQEFC3XAZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id F2285C47EB1
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:25:19 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-7aac981b333sf3088527b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:25:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762791918; cv=pass;
        d=google.com; s=arc-20240605;
        b=YlwH3cQLa4xKwL2sVoAbIjoGf1N7EdYumDG03QXdtBL5XgQmfNzk900I8lixqtBY/W
         dPS4UmgGIukBzNoI2U3pnQGPkCE68wJTiq4TNXsL86VXT7JHSRAOerjgyVpp1XSDuAfK
         wcIECzTA5AJV4PxnoqlJL1wcdkX/t/Q1XJoZ0BuOzND6DjvID+D9/1IsmQO00L7IE0UJ
         l2UXBRcvnkqFCsb91v6IX3IauP9U4BflX2YQj9ziuOUNy9kAL9RUAxKgyuxAkRJFVm3C
         ZZZ6i8hutca0Z3NC1A3QV5dh50n0EEygpLS1DlVTwXatfP861sDo4xFdafPQ3iBwTHXv
         eCWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rZ3JkfCZE1xceJc9OJ8zlA9rC8amrWq9H2xJVRe8rlg=;
        fh=QpNXiugTaO/PrZmYAnQZOp8jyT4DWJmN6i6pCsBf+2E=;
        b=MEV95BL1rLbLdvg+ydZVsj2GAWtjF1krllePUDwfQzC+l7C9b3JR1ZkhHngy8vWqbb
         ibUVwsjcFlNaTVMJQ7w7XM8Kn+8SKyIgCvL4POsZv11bUeIZc0lCWtyx97m5C5o8qn2O
         lBnEhVQ2AmEJ3Pza79C7kjPyhxZdJ3YumoncV3pqXMeP4QaspMBx3/Jh1YSXlixQ6Bhs
         c9yAja3cndgMurMvzF6pPzXImWrG8Zu7P4apYrowVCLuMG13KGvmSytUCTVktjyOOcnp
         Gy/DbdElbgBdTevJBb1HVQCuly0jnfhuWw7cM3RmeUw2M0B7FumqZX9HPdzAKxGkk+Sy
         EYdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JDuecues;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762791918; x=1763396718; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rZ3JkfCZE1xceJc9OJ8zlA9rC8amrWq9H2xJVRe8rlg=;
        b=UbWFJqXYMH1SRhhdCWhy79d6eJ1KDA40OsAu52sHY0FFWTt1GAj8PDIMwt6Wsr1bTy
         JgN3OiV4Ki51Mgt45lPCPQ76O5cQdxbnt+0Cua9Ae5CD+ZaHy3CEjdjZYCav8Z215RJD
         Ahoenvs68tTbkNybuKz6q46AqjX2y4lzG/re+5ANwXVYKq4LInXYoL68W5kCZMsnqnVI
         BtmqALy589Jh4thD9Yv52l3pMtRUlwXpmoMBcCbWENOw0rbqgnsVRdX7LiZcRo1ICti1
         1ABSUOBMrCpV6gTgBBWJBTnMFfTQ8y8YCiw7aQaCK/+4JDkA67gj5Xo+TLKsq/2sfUVq
         bSkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762791918; x=1763396718;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=rZ3JkfCZE1xceJc9OJ8zlA9rC8amrWq9H2xJVRe8rlg=;
        b=U3yIA54kD2MHdq6vinxFIDzNaKx7E4U+kE6zirfORO+T7MqJjtxFxKVibPVy7+Hi03
         sLqTPAccqdL9FA7zV6lD/pY8D4RoPoNFQfdt8LICVBChpQ59r0ND/we8rCX4w5gzcRBu
         ui7LjginR4xVFDp6kJE/Et62Twma40SuT/Fbq5BIXbCZgYXQPGLEhckS9WkhN8mjtvmm
         3kvkoS9z2QH1rk3QefDQXvMheDEvH/fwMq3iH4BWEr3aLN49uX9UaWiDCFDmi/n7POFB
         FK2v72sii3X1uk2R+oAOT9SB3qn+eo+E1OybE/mAxNzSkAjzVOb5mdNRzBXSzwt/kxld
         nLdg==
X-Forwarded-Encrypted: i=2; AJvYcCVLorRliD3Yopaq0Mu1yug6kN2Xy6gjSN++MANqfPBxwdaACTiKv+UG9JBm9W8PkmLZEZR4sA==@lfdr.de
X-Gm-Message-State: AOJu0YzpRF5Y2P+GhRywBGkL2ZFqRMIF8gwtfQKniVHnrzGpLbUY45RS
	xdaR2fYJLUc/DJ2W7tEw1QgooNGzIfgJIvDMffEKNw0c/UnVHRJ0YZxp
X-Google-Smtp-Source: AGHT+IEMcNVDUBuJ8Gmk07OVZwEBWB5kdorLowX1ZFx7uzsl6Tt+1pSlhAJKC7osXwR0VvQJik44QQ==
X-Received: by 2002:a05:6a00:1883:b0:79a:fd01:dfa9 with SMTP id d2e1a72fcca58-7b225aec692mr11538245b3a.6.1762791918100;
        Mon, 10 Nov 2025 08:25:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZeeqL+os/i7p3yYjFGnAOBX3WHhMLJEmJ60yhp8o5PIg=="
Received: by 2002:aa7:990e:0:b0:7a4:b41c:6a93 with SMTP id d2e1a72fcca58-7af798ea9a0ls3864153b3a.0.-pod-prod-02-us;
 Mon, 10 Nov 2025 08:25:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUH2VviJFJCNdrF+Gqns+TqBLBBgPSN4UfJRzeq8lFAniW0lqhN3/GZwKIncLPfWVCbRRr3X5BoHdw=@googlegroups.com
X-Received: by 2002:a05:6a00:1813:b0:7ab:4106:8508 with SMTP id d2e1a72fcca58-7b22727b3d2mr13816845b3a.28.1762791916700;
        Mon, 10 Nov 2025 08:25:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762791916; cv=none;
        d=google.com; s=arc-20240605;
        b=jAW1Aod4BevN656qA6o7kjBJ+YQpT0J+ca01CIE7AtXV/XpPKFAfyBa072/HICSpLA
         4/cOt1KjJ3GNhGRrp+V1z/MWTJQjsNvkjf+EoM7uDSDpxJKT2lYFyF0BtewicQxjItaq
         yH2PH2CAn0HYEZYhyphaYimeV42GmJ06AKJ9fNsTg9toL+kJwimmvrFzBGOdVlsFhG0g
         WhA+KBP3l66cz1QXre4/jMPT/0mAoTCFhndbSo5MiCZb9yEneeXRh2H+DWspBGSiuMUI
         PDdhwrUHO8O6KQAFXt+y55oXWqtfqv+5qiy9dYE2d5v5xSSSyEKV6J8cg2D415AoNhZk
         jqsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=c9SA+Oyt3urlxF8erNwoXRcqQ1B+Xtx2kUos6VgD610=;
        fh=MgSxWee3OLHo6NMgsrmyAm9dkhFvI3E2BCbQ7RfuTV0=;
        b=ftYU8ZCakDs3US5kNSk9jcrvKRr4tXI5J911l/lKn456peULShE4GwvH4190vJoYb6
         Jolliqbkri9dYuOZ0LQNK2uSJAb1vYG49LBB80aKsT7s0z/qITHmsvRSo2BqV3e717Bh
         hvmqoRZVwh+KFtJkhqetAn5dL1meLWTfXAUaeHFUrXGFiwPQ/XsVlw9rYoesAEUo2GFo
         gV5d6d4UZcmcdsiCSt6A7qfkX8fvrGR0TpsLJ6Aolhm68ooNf7gjRf7d94lB5HTYREgm
         Z3B+T0qHrLMGqBfDnjNF3OO91va+iKb3sOGLurRlstBdwvao8maw0KK/TIx3YGSDldR2
         5a+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JDuecues;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b0cb49dca9si404135b3a.4.2025.11.10.08.25.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:25:16 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-88246676008so18372886d6.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:25:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVnkx6nMM74WbHa80XJ9nD5xaiAkQh6FeFAd0mqMY0LgoqJLygZ4o5T1NxOqpLpp3970y4cpO4OEYM=@googlegroups.com
X-Gm-Gg: ASbGnctan3Lz86y2Ks/GTaHM0Bh/65lkNUjJ0S6qmECRsXyxQbRLFpB/xkdTAe/098R
	yd9dQiDoH9hLJp6fnKiU38TxpwsVbw6GLg6xUUxvRNsciYI/tzLZPGclPcGgFY8VpCra5HBURvA
	TkP3bw4Dc/BVVdIW+9iT4zWNoNUGWBBkZXxT1amm2qwykw4UcBM+0Uj3lofUCa54C9B03PfKfjT
	oTrb0WnIV91WuN3Bh/gOINfW7Z6fmqV5WaL+jWd1pS3CLZIRNib7jPxQwS1dPQEZFz+AqH0rsqM
	LEpgxiWSFRWGAHc=
X-Received: by 2002:a05:6214:600f:b0:882:4987:360 with SMTP id
 6a1803df08f44-882498705a3mr75490586d6.62.1762791915502; Mon, 10 Nov 2025
 08:25:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <da6cee1f1e596da12ef6e57202c26ec802f7528a.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <da6cee1f1e596da12ef6e57202c26ec802f7528a.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Nov 2025 17:24:38 +0100
X-Gm-Features: AWmQ_blSpUzzxuUgQTtcq9gjImncZd1NpVlVJACeWgHgjGc0p5BSkakhSm40GYM
Message-ID: <CAG_fn=Ut9JUpStLiO+GsoBpn3d_EyyttcuBby=EKzuxkKdcKcw@mail.gmail.com>
Subject: Re: [PATCH v6 10/18] x86/mm: Physical address comparisons in fill_p*d/pte
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JDuecues;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
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

On Wed, Oct 29, 2025 at 9:07=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> Calculating page offset returns a pointer without a tag. When comparing
> the calculated offset to a tagged page pointer an error is raised
> because they are not equal.
>
> Change pointer comparisons to physical address comparisons as to avoid
> issues with tagged pointers that pointer arithmetic would create. Open
> code pte_offset_kernel(), pmd_offset(), pud_offset() and p4d_offset().
> Because one parameter is always zero and the rest of the function
> insides are enclosed inside __va(), removing that layer lowers the
> complexity of final assembly.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v2:
> - Open code *_offset() to avoid it's internal __va().
>
>  arch/x86/mm/init_64.c | 11 +++++++----
>  1 file changed, 7 insertions(+), 4 deletions(-)
>
> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
> index 0e4270e20fad..2d79fc0cf391 100644
> --- a/arch/x86/mm/init_64.c
> +++ b/arch/x86/mm/init_64.c
> @@ -269,7 +269,10 @@ static p4d_t *fill_p4d(pgd_t *pgd, unsigned long vad=
dr)
>         if (pgd_none(*pgd)) {
>                 p4d_t *p4d =3D (p4d_t *)spp_getpage();
>                 pgd_populate(&init_mm, pgd, p4d);
> -               if (p4d !=3D p4d_offset(pgd, 0))
> +
> +               if (__pa(p4d) !=3D (pgtable_l5_enabled() ?
> +                                 __pa(pgd) :
> +                                 (unsigned long)pgd_val(*pgd) & PTE_PFN_=
MASK))

Did you test with both 4- and 5-level paging?
If I understand correctly, p4d and pgd are supposed to be the same
under !pgtable_l5_enabled().

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUt9JUpStLiO%2BGsoBpn3d_EyyttcuBby%3DEKzuxkKdcKcw%40mail.gmail.com.
