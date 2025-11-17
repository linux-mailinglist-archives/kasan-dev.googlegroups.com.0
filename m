Return-Path: <kasan-dev+bncBAABBRWZ5XEAMGQEU6QCWNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 32275C65C1F
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 19:43:20 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-3e225026ef8sf9131206fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 10:43:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763404998; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qsq1B8ayd4b2V/0NWoyXl4fTH4Jx4BOw44T5E8wNhbgRE5bULDCbZmhsbzGGkvVEa9
         N11Np4c0cYbaHDQr2BWqX7MZSGSn15eA12/mzt2dxEMiGHYodaajdupqWucx3JIr0R/d
         6Hd1ZX0cgjoXECOGiKieHyykjZgPluihvo6dMUEjBI5lszJf2m2fM6BDsUgU1ujcSOp5
         9DXguKAhIMBl3VIOJlwzrN5t7IvrQsTmYUCPYPlaSri+DCVFn9uN8KzbsIWk0LIcZlvS
         DOceH5xgq9dYZGTdkHDhGL5JorHf9ARGiNwNxMosTnf10882hGYo4ZH6mQBIxSON1qnI
         GZtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=LJ1bsFP302vosHTQudByIGedYHBQ3+1dv9v3wt2ANto=;
        fh=M1sTriK/TFeZ56/4p3aMznRtXw1o/ZT0UhQsZg3I7rw=;
        b=jecwmFNaA31gXCn9bKok6opz4qdxDHkhM6ZOpTyrZQMcBIfjt0n6Qx7dnsO94yNjLD
         oobGw0MdTkEenGA7gTApzaKSqiP6NgsPZjhiarkaXyJ0y96qWImtgYUSEKpFo2E7uTpB
         I1qmOFH3+mvjRh+IA7re90jX9gHe3IT6jlwrrTXoWNhxR/UAk/8eB4KWkhfZr4IHeiwQ
         MUHr8ArvfjziLL4TrLAoE305O/8/CfiAkS0rSZLCRsw0Sv1p+BwGrMMCf/f0lNURtiC6
         2LGQiA+GLwvCCILihDQYtmb9mlH0/oZp8CQZcmuA/ylYa4eZ96tBhgsEYAzeYUUCsUhu
         PR2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=h6XWinzQ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763404998; x=1764009798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=LJ1bsFP302vosHTQudByIGedYHBQ3+1dv9v3wt2ANto=;
        b=QmpgkrT8NRsCyWQfH4F1jobE0Mmnq45vLE/XHlzTFfUQDm1NDRayTHDGSfwoof69VO
         NZC0lbVJUUMBtD9FURX5qC4j9Pm4bGWXCbftbBdICVgxhkUGRmov3GUvotfmn4Ul2jtb
         myb/nmk1y3eYM/bwzs7/a9Erl4fPistInjcNEwl0jUCF1rFDs9CY+YlmW20nQsyT+IwX
         GP5r1432mpkzwqAdZPZ1PJPUdKgSP6iSKbcSuCxR390KFuLJ9H1Eu/bhqJDnMG4Wi8lh
         2Ecimx6Yi5UeHA0TRuzLJJRQkILSb5c7i2DPVwdH2S89WCKltTTbVGwtveqnpi7VUgpB
         R+TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763404998; x=1764009798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=LJ1bsFP302vosHTQudByIGedYHBQ3+1dv9v3wt2ANto=;
        b=tGImQSeCwBZbqBM8965GMVSUiCVvYm0c0G2KNuPa2LtATCGF4umB4JajV+0wonZN+0
         wh1ugdjfOg4JkhxsEUi1xsan06zQP00XyrWcOBmlj16WOFiEVEwPi0YQBlndqntfbb/9
         upnhRwlU9nXjuU1mYX9xxDNR4rPSC9DKCzlPLSGgLZN9NyN0Ig+l5DhoFO7a9U8o3XSt
         EzmJWQxoGdJAkT67FCGur6TPi8A5U6kCu3A06kwAuaOrjUGltSXT5xqzkWZ1D204gTiq
         JrJ3s6Rw5kJ50XiLWVy5LMYTXS0vhRo4djq+yR11aF9eSiKz1KW4uohIdWgzWm6Eaqz8
         SYJw==
X-Forwarded-Encrypted: i=2; AJvYcCXDCa+6Oo+YhFqKLh2inJXbzslvZdgsCyQEsMttHO3znDfaUvRh/R+O7hCi6fMtDz1i9RdVBQ==@lfdr.de
X-Gm-Message-State: AOJu0YyUfeiP1Idf8m6FhkV+3Lu+NQkNeYzWINyqStS0fd0iCXyoVRpH
	BJDLcEv6ugqeK10tji0GasqyPdTqLBbDqdBivkwW6pRoNX4OEGChSjZx
X-Google-Smtp-Source: AGHT+IHNWVw+rdPjDGrD1jCvUWOPgNJG5V55vXSikN1Q5hec8wR+iT1OQvb4iBHae3geCeP0z5u2PA==
X-Received: by 2002:a05:6871:4b05:b0:3e8:8e57:a7a4 with SMTP id 586e51a60fabf-3e88e57bd98mr3974581fac.55.1763404998607;
        Mon, 17 Nov 2025 10:43:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YnJu0kx3ryQqcB9dlGvaRbgEPoSj7tYFzNQ30hbcqnzw=="
Received: by 2002:a05:6870:19c:b0:3e8:2785:9a19 with SMTP id
 586e51a60fabf-3e84bd45059ls2998837fac.1.-pod-prod-08-us; Mon, 17 Nov 2025
 10:43:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUOdYWeJ2kWPLq61OTlE8h4mY5XkZnf3nAdXwtt7kKU8oHxy+tWatBvbUph8+PCxF/GESb4LGwfx8U=@googlegroups.com
X-Received: by 2002:a05:6808:124e:b0:44f:6def:3f3b with SMTP id 5614622812f47-450975f4c4amr5656995b6e.51.1763404997719;
        Mon, 17 Nov 2025 10:43:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763404997; cv=none;
        d=google.com; s=arc-20240605;
        b=ZDBxtTIq+YL3SoXKEKOgo70pR7QAees1/Q7oeBThtjmC+Xv3t4qHsN3jbwmRfOqOs6
         tJlwPrzXPUleJOGmhB2vkujqQ5B924PQmAmwBzlTBVGK7ZJW1hE32bu5XJWzkn4ArDKr
         PNZ1SRiOjBLYLtuFEicBKwRJCg9e0BU7atwGFvohIl1HWoeK/gHNXv8+ssGKvcBUWk2M
         i5xJ3AnTyOtOYMqFhdixGLwD0ThCo73K857YzYv23m9oDssM/CM0fGSJV2j3V5AMNkPI
         07rLPq2VSGsB2IXLLeioIgaG6U5nlFX7P1tLVaUlaR51HCvftiI7mC1lpiDSZxTZCH2l
         pTSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=+lJV/EDhYGKx5mOX0qR2rU2PR81YfrrZnkEYQ//hRhU=;
        fh=k/v3HmGt1ClsgCYHhLlDuddeI/n3RsPAzSnvJM/IeI0=;
        b=Y7dXe6koJelDqFzvvxwHmBnCNO36QpdyEh9YCem3jfahYeOPs8Wwwru83P93OX6Oml
         UuRoH5zU3LFLLFqTkWbK0SZc9rScKAwM3sTU2awYVD7sZ4uwu3yAxoIaEvCAs/yHkAOu
         BoVS3BuMpFtwDX1tNIeRfMRYfS+Nsef9y3fswc6t3v85IfgAIV46vR/aLGgWCfT1lfiF
         /YIcvFIfR2g2vAmmP9nKVTWjhfcg/+kQLQkN5GnWpcdtrI3QLWJR6GbsstG6GtdG5Jqc
         J+klrscptUVF5Hwq8QfzCbcp32T798nGlG7awA0BtzGtp+5+2+kA89ianXyHYdqpiL+2
         SKTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=h6XWinzQ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244127.protonmail.ch (mail-244127.protonmail.ch. [109.224.244.127])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-450b16f3ea9si255252b6e.1.2025.11.17.10.43.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 10:43:17 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as permitted sender) client-ip=109.224.244.127;
Date: Mon, 17 Nov 2025 18:43:09 +0000
To: Alexander Potapenko <glider@google.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 09/18] mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
Message-ID: <5ty6jsrleekmymktmyayidc5jdvqvzz622vsh4fqk3rjtgyalu@argn7tfm3efv>
In-Reply-To: <CAG_fn=V4jVyS41MDxJeN-A2zk6WhTnxp7m3FRWmkXMpy5f+haA@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <d6443aca65c3d36903eb9715d37811eed1931cc1.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=V4jVyS41MDxJeN-A2zk6WhTnxp7m3FRWmkXMpy5f+haA@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 267961a08d80088fa15811f1ce81d028c93e6629
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=h6XWinzQ;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-11-11 at 10:13:57 +0100, Alexander Potapenko wrote:
>On Wed, Oct 29, 2025 at 8:08=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
>> vm_reset_perms() calculates range's start and end addresses using min()
>> and max() functions. To do that it compares pointers but, with KASAN
>> software tags mode enabled, some are tagged - addr variable is, while
>> start and end variables aren't. This can cause the wrong address to be
>> chosen and result in various errors in different places.
>>
>> Reset tags in the address used as function argument in min(), max().
>>
>> execmem_cache_add() adds tagged pointers to a maple tree structure,
>> which then are incorrectly compared when walking the tree. That results
>> in different pointers being returned later and page permission violation
>> errors panicking the kernel.
>>
>> Reset tag of the address range inserted into the maple tree inside
>> execmem_vmalloc() which then gets propagated to execmem_cache_add().
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>Acked-by: Alexander Potapenko <glider@google.com>
>
>> diff --git a/mm/execmem.c b/mm/execmem.c
>> index 810a4ba9c924..fd11409a6217 100644
>> --- a/mm/execmem.c
>> +++ b/mm/execmem.c
>> @@ -59,7 +59,7 @@ static void *execmem_vmalloc(struct execmem_range *ran=
ge, size_t size,
>>                 return NULL;
>>         }
>>
>> -       return p;
>> +       return kasan_reset_tag(p);
>
>I think a comment would be nice here.
>
>
>> --- a/mm/vmalloc.c
>> +++ b/mm/vmalloc.c
>> @@ -3328,7 +3328,7 @@ static void vm_reset_perms(struct vm_struct *area)
>>          * the vm_unmap_aliases() flush includes the direct map.
>>          */
>>         for (i =3D 0; i < area->nr_pages; i +=3D 1U << page_order) {
>> -               unsigned long addr =3D (unsigned long)page_address(area-=
>pages[i]);
>> +               unsigned long addr =3D (unsigned long)kasan_reset_tag(pa=
ge_address(area->pages[i]));
>
>Ditto

Thanks, will add some comments on why these are needed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
ty6jsrleekmymktmyayidc5jdvqvzz622vsh4fqk3rjtgyalu%40argn7tfm3efv.
