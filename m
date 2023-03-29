Return-Path: <kasan-dev+bncBAABBW4JR2QQMGQEAJ7ZHYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E5056CCEB6
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 02:22:53 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id k17-20020a170902d59100b0019abcf45d75sf8332451plh.8
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 17:22:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680049372; cv=pass;
        d=google.com; s=arc-20160816;
        b=YTDOmhdIN4yiLsv6Y7EN9G0olTeF9tJqxTfiualFx+hvJWoL2blPFNkeRiHSn8gucb
         Qd7RIvQNU1ZJg8OtqSXRRiCHm8hoktsvm5D6X7krTdvBwTSFpDd7ysARXbCSinLVVt1R
         huIW/oSnoTpkej7NWieMgTinRquH2cDHfu70GS14VKZAJQADqPgqSAwK1jo2Tdta/jxG
         yV5MrkHpGeWmTnzgKGe9J4tYT9eo+Mh8xzaQ9JGGjoHNShr6PoGVLBca2s2vCGXvC/ys
         aE7RbuNOCawHeXjze1tHnjFdDZJprkFd9snCnlpnXPK2iXHMO7+uwFg3N8u4e7Y0EdMK
         zG6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=pojLyizrccWr2rDdI+4uQCR6/EQVyDIaCXgBS0OtNwE=;
        b=ITzSln437Hlrx4HojmRMMxm8sRilBvCcJJgKChuhrKeNlncuesOPscuGpUKHF4N3zn
         FM3XdHFndL3D6d9op4Hd8nfH9EUtlZjhMh8Q8veGK7bql9Zm7LZJmmVHrqUHT+mjVnDz
         oKgROjP7UOueuB7gVtTDDeqCqEVq/k1K8nw2r8VTtVcWgH22D85RtysAgQJwEEHj0z4h
         LnoKq1ZoqUXEsIup7HI/MZ80hH3Mt2ikPIJ5MVv7UQDOrJZwKKJ0ka3QdwA31m0pUnHQ
         GIavmPFqjWCTxpwq4NJT0g+r5Mbq2pvYBrOfrVvQ1EjUCEnEuId4N8/a5eJHmgko5j3I
         YNZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kohoHxDp;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680049372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pojLyizrccWr2rDdI+4uQCR6/EQVyDIaCXgBS0OtNwE=;
        b=RXUrW0zvYAAU2iwK0RxX0JomQsqueynoG2nEMn2kqEfKUIP3D3L7U0M1PGFjvPFJAl
         Lxkl84+A7+SWQ7jrvP2NFQ0njS7q28+KJEW8w26bkLRFobqtWHd5GEBglIMl5/1S4k/P
         8b+Sku0COCEAP09Q0xZTTgobHfmeosf2KIkCjkFa5qZR0bJ0Ci0azcK+TQIW9g+LFguy
         ePF6LmR5kcWSRlH0/mlrdBQagsdKjKzr56t9yErw9I5VKrDQxinxKNmGMeTm1v4BxL09
         TNls/mod+vQd5RIaQUwK5+NcN1eNOcKmfbFG3o2S8soeeN5ye9ugaXxwxVsJiImSBHEc
         2UZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680049372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pojLyizrccWr2rDdI+4uQCR6/EQVyDIaCXgBS0OtNwE=;
        b=us71hhSikvqnfeG3J669oDh4Xox4pdIoTqimjpfQn1zldlKwofP82wGHqOpe/w2DfU
         yRpKyy8plPiD/mdTCSt83cKIAL/iZwijZW9Lv4O2THdLfq0uy2IGWkhRJYiGiY7lEMbj
         v/WWdPpe7JBwjVNHZCaUa828dwwapkHtIoM4tPBAzWWDBSQtQmxee9FCI8KEUFsofS1Q
         O6Lj6ymD/ugVO98UExAp+tQq3+1eozU8o5sxoIQ3eIfi0XESqX4QhIRjYnSTlBCObV0r
         QY0x1lp9eZdkz0TjAu3f6L2yCb5k6XMGjTGvQGttD+Slkf9JWK5Hkw4EEQhpxZM4MMyh
         Ur3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fCdJMAXbOJIetdniPvKzS1JFCj41eVKAz/jNRMvnCgevfBaExB
	PwcKMO8xU6iipqpsef8CbE8=
X-Google-Smtp-Source: AKy350YnH1smKKRPAZBqX3WFhH9DaZfMaPz2GPpVxuWQgwLGTB7NAlpYcYbhDk3xK5PNkmw2us2LQA==
X-Received: by 2002:a17:902:6943:b0:1a2:23f8:d122 with SMTP id k3-20020a170902694300b001a223f8d122mr5037379plt.9.1680049371917;
        Tue, 28 Mar 2023 17:22:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e388:b0:230:cffb:708e with SMTP id
 b8-20020a17090ae38800b00230cffb708els1271252pjz.0.-pod-preprod-gmail; Tue, 28
 Mar 2023 17:22:51 -0700 (PDT)
X-Received: by 2002:a17:90b:1bc4:b0:23f:6d4e:72b3 with SMTP id oa4-20020a17090b1bc400b0023f6d4e72b3mr18788913pjb.25.1680049371324;
        Tue, 28 Mar 2023 17:22:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680049371; cv=none;
        d=google.com; s=arc-20160816;
        b=ARXWpsulXohSieeVhK+2dFtbq4XOptL6ptsz4ussPAo2z/iZPHwViHwORR6GpXO+fS
         TqKlnZPioztE2/hm7ArM8y1+P3ZLI8iINNHgVzVFImiQdxzEBTHlnWfysKjKPzpjCxgv
         lQwTM73eJsBfEtAX5NlLovVjLvbA1MZs6AxH7txn6+UDlvOa3T45xd3R+V2wKAWc4vE7
         3Nmzcd8fuebJ477o0+u+AJUhCuTJdtajtSMn/nCwV9q7cT9hMWm13UwkoB6sJL/g8kBT
         9VmApJNQ/2ytwvHM3l+6ADz7dwmoLocVraDqmU3zlDLlhyHvgF+g6i8DNAnM/Shubbsc
         GKVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gvRM19O0+ENuKqUmsDi/B/LiIIqhUnSvjpgPO4O58bI=;
        b=DzymB/JUD3G2NsNnrTh2wmfT31oYdMKAOr4wcDa81l3li6RcThYIB/UF/fSJupbRre
         ShYwRT2tDRXPlMdSh1jehysNvWHSfsr7tZqeCVT1zDgj1zhcHkG3izjaFMcJRRANhFdk
         rQzwLGOTYQb9dTa1VNs26I7ThyQikeO8Z8o85pffoQ8bB8BHEmhyJ7VK1Eqng3KX0aPA
         Va1KCVRHXMImA34a21tKqkGuZOyraVa7IceBll1c90lvB+e3cc9JHTw/Sxaq8zqfnvn/
         EizNe4tBMSHIi7ZcWBTSwQ99jFWSq2snmChZV1Jh4S8HURhOVKCDcGj/Z1objlTfqDeO
         QY8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kohoHxDp;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id x23-20020a17090aca1700b00229ee755cffsi185762pjt.2.2023.03.28.17.22.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Mar 2023 17:22:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C767B619C4
	for <kasan-dev@googlegroups.com>; Wed, 29 Mar 2023 00:22:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C08ACC433A0
	for <kasan-dev@googlegroups.com>; Wed, 29 Mar 2023 00:22:49 +0000 (UTC)
Received: by mail-ed1-f42.google.com with SMTP id x3so56603525edb.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 17:22:49 -0700 (PDT)
X-Received: by 2002:a50:a444:0:b0:4fc:6494:81c3 with SMTP id
 v4-20020a50a444000000b004fc649481c3mr8371871edb.1.1680049367907; Tue, 28 Mar
 2023 17:22:47 -0700 (PDT)
MIME-Version: 1.0
References: <20230328111714.2056-1-zhangqing@loongson.cn> <9817aaa043e9f0ed964bd523773447bd64f6e2c0.camel@xry111.site>
 <1c231587-3b70-22ab-d554-ebe3de407909@loongson.cn>
In-Reply-To: <1c231587-3b70-22ab-d554-ebe3de407909@loongson.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Wed, 29 Mar 2023 08:22:37 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5APsBxC8nNa81t3HXum1EU1hOj4S6UC7xLHD7_BCJd7g@mail.gmail.com>
Message-ID: <CAAhV-H5APsBxC8nNa81t3HXum1EU1hOj4S6UC7xLHD7_BCJd7g@mail.gmail.com>
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>
Cc: Xi Ruoyao <xry111@xry111.site>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kohoHxDp;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Mar 28, 2023 at 8:15=E2=80=AFPM Qing Zhang <zhangqing@loongson.cn> =
wrote:
>
> Hi, Ruoyao
>
> On 2023/3/28 =E4=B8=8B=E5=8D=887:39, Xi Ruoyao wrote:
> > On Tue, 2023-03-28 at 19:17 +0800, Qing Zhang wrote:
> >
> > /* snip */
> >
> >
> >> -void * __init relocate_kernel(void)
> >> +unsigned long __init relocate_kernel(void)
> >
> > Why we must modify relocate_kernel for KASAN?
>
> When the CONFIG_RANDOMIZE_BASE is enabled, the kernel will be updated to
> a random new address.
> Kasan needs to call kasan_early_init before start_kernel.
> There are two situations:
> 1> After enabling CONFIG_RELOCATABLE, call kasan_early_init.
> 2> After CONFIG_RELOCATABLE is not enabled, call kasan_early_init.
>
> In order to prevent code redundancy and semantic problems caused by
> calling kasan_early_init (before jr a0) at the old PC.
In my opinion, you can call kasan_early_init before relocate_kernel in
head.S, then no redundancy.

Huacai
>
> Thanks,
> -Qing
> >
> >>   {
> >>          unsigned long kernel_length;
> >>          unsigned long random_offset =3D 0;
> >>          void *location_new =3D _text; /* Default to original kernel s=
tart */
> >> -       void *kernel_entry =3D start_kernel; /* Default to original ke=
rnel entry point */
> >>          char *cmdline =3D early_ioremap(fw_arg1, COMMAND_LINE_SIZE); =
/* Boot command line is passed in fw_arg1 */
> >>
> >>          strscpy(boot_command_line, cmdline, COMMAND_LINE_SIZE);
> >> @@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
> >>
> >>                  reloc_offset +=3D random_offset;
> >>
> >> -               /* Return the new kernel's entry point */
> >> -               kernel_entry =3D RELOCATED_KASLR(start_kernel);
> >> -
> >>                  /* The current thread is now within the relocated ker=
nel */
> >>                  __current_thread_info =3D RELOCATED_KASLR(__current_t=
hread_info);
> >>
> >> @@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
> >>
> >>          relocate_absolute(random_offset);
> >>
> >> -       return kernel_entry;
> >> +       return random_offset;
> >
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H5APsBxC8nNa81t3HXum1EU1hOj4S6UC7xLHD7_BCJd7g%40mail.gmail.=
com.
