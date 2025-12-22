Return-Path: <kasan-dev+bncBAABB4UYUTFAMGQEZYXAHGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 13DBACD547D
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 10:16:37 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2a0f0c7a06esf73967935ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 01:16:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766394995; cv=pass;
        d=google.com; s=arc-20240605;
        b=ECj/yOtjdSENrg7sKvYGgS9mmoyiXD2PyEEDz45tUHcHBFsBROnMQP2Jl//goNoT+d
         NgcKLmLbv/z9SeOqzS6bOqtNXXLxgdx5O1D55ZJjoi+MSFmHjMSzevhZaX/rfqTf8aGR
         5TsgHS3ILjaqI3eJVA+sD5RTAsLTo4npWHZRp0OthVyTNqpKxwfQpRvUW4YXHHr1cPjh
         ZgCgmqGwnuJRo4rRVzyveQym4f+EnvSEOK9xonbmlQi7NDqFR/bXu/ARdgHpEghwnG6/
         6YnBcN9nt8GWLWxa20DpQrplj7lwqrc7uL+fwopRqNwnDrgvw7DbEFcG7+zST+MplcuR
         RwnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=5fXX2+GZoG2jvPBVw92nzdxjNf/84kiUrr1t2PoLXA4=;
        fh=wUIfeaGAGztSFoxzBNj9/h7wmI80fS/4jOPT+tZ/kyw=;
        b=NWkekvjtbC5d1XK1EAhB/KqAkKcGbPr9udnkbcchcVMVl2PO+dw8IfBKFHmVuOyQe8
         ocTZJRguXkonRbYNbscMob07dof5REIGam+qolZlRuSWKjEuAxO7FQ9SXNxNdj/jxei0
         3h0DwNy8zP3P9CWwJj8qhpMQG0gMvavXGGJapV4veEiTqxllDaPQQVOIkmfQhdCMk1VD
         AZHPYder6JYi/+mVL9XQg157d/bPcdvXo2GoukOSKWt8ZT0a9KJg9Q9eYwHlJW6zJ9cT
         PzVgX/KCrkens0j6QXiUY4CbL0wDzCiy/mtceMHlDOP7Oz6oumw3R0wR7E01xjsRkNbz
         XEGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766394995; x=1766999795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5fXX2+GZoG2jvPBVw92nzdxjNf/84kiUrr1t2PoLXA4=;
        b=DOu9+GbNt7s4EZ9RdHbpQlXXcDtGOnhzzfUulJK7ftNmRK57+EJg8lpGiDoFk6czFi
         /KsaDyjCYSpzz3fHuKvltrdaqYCZGLXaSdG0F6O7hViGHSMg/hfNiCJdJpnmYY9bbcS1
         baTL4nxa2fqtSoWoRFkNNoCBL1EW7Divg20RWtpx/TjVA1PzW5nipvDgI50Gj+T4LYd8
         WT5vwU+hgF649ZiGTxLtXHBeaE9KAVc7LcuU2BE37AjSnjgeVHALgZxroFbte0mLfBoj
         2fT+eeUgiUxCvQh9ftS8k4Ec7ARdnU20uGO1Y/S7yn2cVgPfm5WrNPUMlbxkxQk7x3fT
         jyvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766394995; x=1766999795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5fXX2+GZoG2jvPBVw92nzdxjNf/84kiUrr1t2PoLXA4=;
        b=UiL8Ls44ImaG2yX9QMglrNd8b7uC+rkXHc6CoBslHxIi9vP9okcJRe0vZGNbeel3AN
         ec5m35NJ6KFN7V5nU0bwv8Bd9ioKQI+gRfNmGx+CUXq91Ke3mjNeRoaIGTtPdNoQUmfk
         X1D6HqVPqhCBOYBfioGQqw5plQUIkAGwRO28E9B5EKu78+z5w5KiYYaTszNCcbWlJhcn
         IWfzorxOOZm5A3/aCbd9Dvtb2vR+lUWFUfu0kalZIXy8kwt4k/MCEBpiy0SkmrYV7+6o
         gxHLFffxcAdN2IgSZ/AlcuWlHHLvCB7j9+6xwPovPQDxUOL4Z9rqLMxQgF4AjBdWDHsp
         OdPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWO8LRHaybgAhjV8i8jxmX+yda52dePqR1Z2KyYbKxiOacipwe9zBbImUdigJok2NY46NnVwg==@lfdr.de
X-Gm-Message-State: AOJu0YyEt8AUDh+tfNW4oSwvj9GPmfXmvS/WaBM9S4JaMCtpQg412trM
	IrPtIXoRe0Jb5WOsCVROk9G5kbICwU+XE8J2/OI0R91Pd7TbH8mddlFJ
X-Google-Smtp-Source: AGHT+IH5mMoSh2NhdOgE3B9DyeA56IYOmXi8VLEfJsgxSjh6y2P0A2pT0OisErDFDF5hNX+2n9dP5g==
X-Received: by 2002:a17:903:2285:b0:29b:e512:752e with SMTP id d9443c01a7336-2a2f293b6c1mr104482505ad.47.1766394994984;
        Mon, 22 Dec 2025 01:16:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYCvdzLE2WedBmEmbhvCSBm4EOHA4rrRO/jHev5/ExE9w=="
Received: by 2002:a17:902:fa10:b0:290:8ffc:aa6c with SMTP id
 d9443c01a7336-29f2361bfebls65541175ad.2.-pod-prod-01-us; Mon, 22 Dec 2025
 01:16:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVzA0/wxn3eiY0LZaq5o2YOHt5bZA0E033wolmLEtlKEfHE5X/RtNyhlfA0Yqaqum7HCUSyOvc3jw=@googlegroups.com
X-Received: by 2002:a17:902:f706:b0:29f:ad9:f705 with SMTP id d9443c01a7336-2a2f293d057mr98049755ad.45.1766394993663;
        Mon, 22 Dec 2025 01:16:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766394993; cv=none;
        d=google.com; s=arc-20240605;
        b=FGUyfeH6u+ahVrZUcJEvRERmC+Xd4XTHTjSkrqMN8Sd71LGaPJLb+pmQqFqiG/bB58
         D6ME4zuB+hIXrQKJGYKzo3YJ2Weyh0LlCR8VF3l6PvwzFpkxfJ1i9gGeUID35qIe+0eW
         7YNs7ckZSMgA37M5PI6RKOSzmv4kNPZxE48ANvcgHG+nUdtJF+okPWgfurd5xxJhV9Dw
         RCg/RQUKLonoBXDCBKLEZpVLrg9ZyYB1aKI2C5eAV61WJ4b9tM2Mb1g+seoxpq1I77/r
         iyUyFWyJRKx1vtg8Ty2wSne5nA8ELGt9xCIqNW39Qx3H7bOfjHrk6VMoXaHNAf64pfyS
         Tfaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=n8yoF26tQkodqYh0wMoOhivOAO11RUhpUb9ohKB9TwI=;
        fh=c7qqHJXag6eMhGEtc3MwbiVjsuESuehS6ubx76j6qA8=;
        b=K06yT97KIiELLE9dT+Be9r/hiotC8bhdJKglmZ7k71UV54LOu2vype3mtL1ydr4NS5
         4MMQFc8CinJhOeItSJjGGa+tbqznERCJk3PC7FKbS946uOw0J+e6kaJoyx6WgLETx4V/
         rs5NHxF4IwapMfunASq3hvYcBOeLDfR1tOKjdYeiX40ZYHeVtVywBWUolzFUbuzN2rHa
         AhzYfG0wHD/HlWYr/whJB0aqtnlsjMzI4T0jxuR7AzGOTESQAPw1Qn+UB+JtMgMYmalu
         N9GWrJaHtGIaPeh9mhnAKCo/G1bFMnABuosakffL8VtKU8yReukLhxEdWPavtmmvhC9X
         yf5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta21.hihonor.com (mta21.honor.com. [81.70.160.142])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a2f3d1b87asi2222405ad.6.2025.12.22.01.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Dec 2025 01:16:33 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) client-ip=81.70.160.142;
Received: from w002.hihonor.com (unknown [10.68.28.120])
	by mta21.hihonor.com (SkyGuard) with ESMTPS id 4dZXWL0TzYzYkyXB;
	Mon, 22 Dec 2025 17:13:50 +0800 (CST)
Received: from w020.hihonor.com (10.68.31.183) by w002.hihonor.com
 (10.68.28.120) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Mon, 22 Dec
 2025 17:16:29 +0800
Received: from w025.hihonor.com (10.68.28.69) by w020.hihonor.com
 (10.68.31.183) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Mon, 22 Dec
 2025 17:16:29 +0800
Received: from w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9]) by
 w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9%14]) with mapi id
 15.02.2562.027; Mon, 22 Dec 2025 17:16:29 +0800
From: yuanlinyu <yuanlinyu@honor.com>
To: Enze Li <lienze@kylinos.cn>, Huacai Chen <chenhuacai@kernel.org>
CC: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, WANG Xuerui <kernel@xen0n.name>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "loongarch@lists.linux.dev"
	<loongarch@lists.linux.dev>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "enze.li@gmx.com" <enze.li@gmx.com>
Subject: RE: [PATCH v2 1/2] LoongArch: kfence: avoid use
 CONFIG_KFENCE_NUM_OBJECTS
Thread-Topic: [PATCH v2 1/2] LoongArch: kfence: avoid use
 CONFIG_KFENCE_NUM_OBJECTS
Thread-Index: AQHcb+kJ0Mrpi/YLLUuMpTbvJeaADrUntCKAgAHNJgCAA+WFIA==
Date: Mon, 22 Dec 2025 09:16:29 +0000
Message-ID: <ab69f5a942824394af6010f75a06c5f7@honor.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
 <20251218063916.1433615-2-yuanlinyu@honor.com>
 <CAAhV-H5n_3Ndk5yRm=S-9WktD9xivVF8-JLaycV8JB-pVuybbA@mail.gmail.com>
 <b2e84054-bf3b-4a1a-b946-bd024f341512@kylinos.cn>
In-Reply-To: <b2e84054-bf3b-4a1a-b946-bd024f341512@kylinos.cn>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.165.1.160]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

> From: Enze Li <lienze@kylinos.cn>
> Sent: Saturday, December 20, 2025 1:44 PM
> To: Huacai Chen <chenhuacai@kernel.org>; yuanlinyu <yuanlinyu@honor.com>
> Cc: Alexander Potapenko <glider@google.com>; Marco Elver
> <elver@google.com>; Dmitry Vyukov <dvyukov@google.com>; Andrew Morton
> <akpm@linux-foundation.org>; WANG Xuerui <kernel@xen0n.name>;
> kasan-dev@googlegroups.com; linux-mm@kvack.org; loongarch@lists.linux.dev=
;
> linux-kernel@vger.kernel.org; enze.li@gmx.com
> Subject: Re: [PATCH v2 1/2] LoongArch: kfence: avoid use
> CONFIG_KFENCE_NUM_OBJECTS
>=20
> On 2025/12/19 10:13, Huacai Chen wrote:
> > Hi, Enze,
> >
> > On Thu, Dec 18, 2025 at 2:39=E2=80=AFPM yuan linyu <yuanlinyu@honor.com=
> wrote:
> >>
> >> use common kfence macro KFENCE_POOL_SIZE for KFENCE_AREA_SIZE
> >> definition
> >>
> >> Signed-off-by: yuan linyu <yuanlinyu@honor.com>
> >> ---
> >>  arch/loongarch/include/asm/pgtable.h | 3 ++-
> >>  1 file changed, 2 insertions(+), 1 deletion(-)
> >>
> >> diff --git a/arch/loongarch/include/asm/pgtable.h
> >> b/arch/loongarch/include/asm/pgtable.h
> >> index f41a648a3d9e..e9966c9f844f 100644
> >> --- a/arch/loongarch/include/asm/pgtable.h
> >> +++ b/arch/loongarch/include/asm/pgtable.h
> >> @@ -10,6 +10,7 @@
> >>  #define _ASM_PGTABLE_H
> >>
> >>  #include <linux/compiler.h>
> >> +#include <linux/kfence.h>
> >>  #include <asm/addrspace.h>
> >>  #include <asm/asm.h>
> >>  #include <asm/page.h>
> >> @@ -96,7 +97,7 @@ extern unsigned long empty_zero_page[PAGE_SIZE /
> sizeof(unsigned long)];
> >>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
> >>
> >>  #ifdef CONFIG_KFENCE
> >> -#define KFENCE_AREA_SIZE       (((CONFIG_KFENCE_NUM_OBJECTS + 1)
> * 2 + 2) * PAGE_SIZE)
> >> +#define KFENCE_AREA_SIZE       (KFENCE_POOL_SIZE + (2 *
> PAGE_SIZE))
> > Can you remember why you didn't use KFENCE_POOL_SIZE at the first place=
?
>=20
> I don't recall the exact reason off the top of my head, but I believe it =
was due to
> complex dependency issues with the header files where KFENCE_POOL_SIZE is
> defined.  To avoid those complications, we likely opted to use
> KFENCE_NUM_OBJECTS directly.
>=20
> I checked out the code at commit
> (6ad3df56bb199134800933df2afcd7df3b03ef33 "LoongArch: Add KFENCE
> (Kernel
> Electric-Fence) support") and encountered the following errors when compi=
ling
> with this patch applied.
>=20
> 8<------------------------------------------------------
>   CC      arch/loongarch/kernel/asm-offsets.s
> In file included from ./arch/loongarch/include/asm/pgtable.h:13,
>                  from ./include/linux/pgtable.h:6,
>                  from ./include/linux/mm.h:29,
>                  from arch/loongarch/kernel/asm-offsets.c:9:
> ./include/linux/kfence.h:93:35: warning: 'struct kmem_cache' declared ins=
ide
> parameter list will n ot be visible outside of this definition or declara=
tion
>    93 | void kfence_shutdown_cache(struct kmem_cache *s);
>       |                                   ^~~~~~~~~~
> ./include/linux/kfence.h:99:29: warning: 'struct kmem_cache' declared ins=
ide
> parameter list will n ot be visible outside of this definition or declara=
tion
>    99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fla=
gs);
>       |                             ^~~~~~~~~~
> ./include/linux/kfence.h:117:50: warning: 'struct kmem_cache' declared in=
side
> parameter list will not be visible outside of this definition or declarat=
ion
>   117 | static __always_inline void *kfence_alloc(struct kmem_cache *s, s=
ize_t
> size, gfp_t flags)
>       |
> ^~~~~~~~~~
> ./include/linux/kfence.h: In function 'kfence_alloc':
> ./include/linux/kfence.h:128:31: error: passing argument 1 of '__kfence_a=
lloc'
> from incompatible p ointer type [-Wincompatible-pointer-types]
>   128 |         return __kfence_alloc(s, size, flags);
>       |                               ^
>       |                               |
>       |                               struct kmem_cache *
> ./include/linux/kfence.h:99:41: note: expected 'struct kmem_cache *' but
> argument is of type 'stru ct kmem_cache *'
>    99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fla=
gs);
>       |                      ~~~~~~~~~~~~~~~~~~~^
> ------------------------------------------------------>8
>=20
> Similarly, after applying this patch to the latest code
> (dd9b004b7ff3289fb7bae35130c0a5c0537266af "Merge tag 'trace-v6.19-rc1'")
> from the master branch of the Linux repository and enabling KFENCE, I
> encountered the following compilation errors.
>=20
> 8<------------------------------------------------------
>   CC      arch/loongarch/kernel/asm-offsets.s
> In file included from ./arch/loongarch/include/asm/pgtable.h:13,
>                  from ./include/linux/pgtable.h:6,
>                  from ./include/linux/mm.h:31,
>                  from arch/loongarch/kernel/asm-offsets.c:11:
> ./include/linux/kfence.h:97:35: warning: 'struct kmem_cache' declared ins=
ide
> parameter list will n ot be visible outside of this definition or declara=
tion
>    97 | void kfence_shutdown_cache(struct kmem_cache *s);
>       |                                   ^~~~~~~~~~
> ./include/linux/kfence.h:103:29: warning: 'struct kmem_cache' declared in=
side
> parameter list will not be visible outside of this definition or declarat=
ion
>   103 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fla=
gs);
>       |                             ^~~~~~~~~~
> ./include/linux/kfence.h:121:50: warning: 'struct kmem_cache' declared in=
side
> parameter list will not be visible outside of this definition or declarat=
ion
>   121 | static __always_inline void *kfence_alloc(struct kmem_cache *s, s=
ize_t
> size, gfp_t flags)
>       |
> ^~~~~~~~~~
> ./include/linux/kfence.h: In function 'kfence_alloc':
> ./include/linux/kfence.h:132:31: error: passing argument 1 of '__kfence_a=
lloc'
> from incompatible p ointer type [-Wincompatible-pointer-types]
>   132 |         return __kfence_alloc(s, size, flags);
>       |                               ^
>       |                               |
>       |                               struct kmem_cache *
> ./include/linux/kfence.h:103:41: note: expected 'struct kmem_cache *'
> but argument is of type 'str
> uct kmem_cache *'
>   103 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fla=
gs);
>       |                      ~~~~~~~~~~~~~~~~~~~^
> ------------------------------------------------------>8
>=20
> So, this patch currently runs into compilation issues.  linyu probably di=
dn't have
> KFENCE enabled when compiling locally, which is why this error was missed=
.
> You can enable it as follows:
>=20
>   Kernel hacking
>     Memory Debugging
>       [*] KFENCE: low-overhead sampling-based memory safety

Hi Enze,

Sorry only test on arm64.

Could you help fix the compile issue and provide a correct change ?

Or I need sometime to resolve the issue.

>=20
> Thanks,
> Enze
>=20
> <...>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
b69f5a942824394af6010f75a06c5f7%40honor.com.
