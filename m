Return-Path: <kasan-dev+bncBAABBMWN7WSQMGQE53AEXQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C5A5A760A0A
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 08:07:47 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2b92dd520a2sf39727211fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 23:07:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690265267; cv=pass;
        d=google.com; s=arc-20160816;
        b=hV32s5CS+vBkyn5eyP/DMiGu3KQEc66Ev7bNy87i3+PSqsUby7UVLRE1o2RtlHt6++
         XvgohG080C8LncXi8uQ5HU2pcd/1fO9fUCAbvthYxAbVeL7NO8TN5erdESXMLFJtQp1v
         YLR+BjfycOzsFxdriWy/OPlZNB6RXfDrowtVeCF6qAd+c5r4Bx82nXCkzoxdO9dy572k
         aBT/pSTkV9yGGmhitr3BupgMTE2f3b9plemvQEjZ7sN3t7DWAvCe/DhbTzydrwdbCS1g
         xvCJUvsZ4Cf/63fZPs697ywmWNOChQ4Bw+Qr9SefxWxzLNhHxhAdw0oFGwwZUzPnqL8V
         OUew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=UvvC6mI4/knMCgw2FtWGeGYmre/csOUWzbcbDLU7hPA=;
        fh=r90P4k1LpUFTTXjuC8jpM6PCssRJaARMc0sTKc3mQLE=;
        b=0TXYvH5xuKJSRr1oZSi1FBVt1iL6r5vqRj8NZmzoOEEojDZmpShR+fz9z7Xle1UHgU
         zATqZ1/5Va+R9cVTxApmKK2BmAY8eJyMKLAqDl6IaqKGidbuBvbIFgslQ0K1kZH/3ab1
         pF5NERd2q4m01vHDdBOHk0L6yZvYHhb6C3rWH810VMwvYcR1UukxVM/lxB8BOoPPNt3L
         ger4eUZtcW4sYqmdlkkF3UOJSKSJohLaSXCpAqxUwkNX4KYThNvQ8x9Xg/g5NDEQ3mfS
         SO4lnAqwKYAVdn+M7RYW2g1vYOajP93ButZIkky2P/RAYsK5WTkPwHzrUvuSY0MyLhgS
         HieQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z1mmOZtv;
       spf=pass (google.com: domain of enze.li@linux.dev designates 95.215.58.26 as permitted sender) smtp.mailfrom=enze.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690265267; x=1690870067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UvvC6mI4/knMCgw2FtWGeGYmre/csOUWzbcbDLU7hPA=;
        b=IwARu0vIDvw5/3nNQeOx8nQjewyD1XZf++bqw1zAnlcK1BfovNws56Brzp1BYGdulo
         aLR45Ni9EAhJAYCI63baLGbYhPww0SqPv4jZqwHRdVejXZblBPpWQn5ywPKRpch7aB3F
         dZceqpmZWRyEAHEKJnixQV+N/mrNXf0Ic6uN9lhl1SEceRYXA3Y7QX7F/bu+kC+Xjm1E
         tgRwoa5+cqU85iA6kYHpDWxqbv2RjemqJhchKZdU8dS8t1BPv2o43b2rbVzyVzD5Qm98
         jaSJuI0n62biNInRffpGvKNftO3cMa39Az9YyQ3uiORnXzIPsHaMH8gUuDQAAVEsd4zy
         qlyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690265267; x=1690870067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UvvC6mI4/knMCgw2FtWGeGYmre/csOUWzbcbDLU7hPA=;
        b=VUIsQSdCw4awHhhWYOeFpSjub4R9DT5UkaEF6RcgCZoIe+uJNPV9FGi5EeYx+KRujJ
         PRbXsrqYHpUH//0i6Q/lEoaXLsRdnI7rS8e/9xi4c0Ny1roxRd1fNytxNQ9IxcUspL5Z
         JeouhjUt/L70qUmFCwE2QXNcJEC5wTWSNeEb3Dbw8JzN1aqR/7DeOzJQNEh8xYPcnUNn
         uhH3hgff3nKND4pVbrsWRNxexS2jZBJs+GOboA5Ns+CwGVbdXKjmFXriP7SCwhbuceLX
         7qDD0g1W06QUvEdk2rV7lG5iO9gLTHW9dfDLR9yoBMtdDaI3W3PqQCMfMfvNvBuraE0Z
         Fzhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLY8sZW4utIIaPDscS7Qz4Au/ArkIt4uByf45daLBNIzGMatYYpr
	XET1Fkg6bxA1aLKipsp3VRw=
X-Google-Smtp-Source: APBJJlG/byvxv6rQAqNcW15oefvCC/KWVEtxu6Jg6xnABQWxQxF7sJ1mqZ2z4dWh0X7oekrr0tuLFA==
X-Received: by 2002:a2e:98c9:0:b0:2b6:df25:1ab0 with SMTP id s9-20020a2e98c9000000b002b6df251ab0mr8512616ljj.34.1690265266373;
        Mon, 24 Jul 2023 23:07:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4c3:0:b0:2b9:34cb:5cdf with SMTP id p3-20020a2ea4c3000000b002b934cb5cdfls663301ljm.2.-pod-prod-09-eu;
 Mon, 24 Jul 2023 23:07:45 -0700 (PDT)
X-Received: by 2002:a2e:b6d2:0:b0:2b6:bb21:8d74 with SMTP id m18-20020a2eb6d2000000b002b6bb218d74mr8094930ljo.1.1690265264931;
        Mon, 24 Jul 2023 23:07:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690265264; cv=none;
        d=google.com; s=arc-20160816;
        b=XEl72jHcs0KdqjToufht5Z+8yobVNo/iJ/4s9FQe6/AXhHd3ScNv19fvAhMLvvOhNO
         K+7snjm1mq6CsdbJBteSAD6XAH+/03yQuCSIIWmmeIxg6eTPlMqmq0iPz4wMC3cDcfD2
         tFGRGgowXFFcfnPu6EEp4YzwdEUbwgEItkDSULoUlv2rLSUKZrNiXD2oyUpHdxh31PTa
         zy946AJg8X2YyvXnPOyNHRgv+t8sxVJ3i7wMn//SMOmAmBBgQDmX9MXTAAySYliKV18o
         Y/GDd6JJCKrtCIaNhlqZ35MaUa4BCr2dZWn7suQYaFDPkvbVm+UJVp3cj6QpcUNbpyY8
         Ilyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=9RhR3Z+kw1Y/Wd/w+yq7BdbxI7CNxW0pkaVU5PxwFqo=;
        fh=r90P4k1LpUFTTXjuC8jpM6PCssRJaARMc0sTKc3mQLE=;
        b=q9zWGtALFhd2vKVAMwl8OyTPL1Ofg7H07mibR0nx2OG7DdrsUdu5LiExizOYQCobzo
         blax3S/8Zk2zFqYmuMldcU9L1O3h0SIWpjE1WXj6VHxSDhNpD1xoDNSgRb1dCihUUGvT
         ARsGBFiaCG7DGXXjS0C+6dBFaAeVPiZJ8OfU1rCLINfUbrjT6w+YYsnojrdCJmM0khoE
         qzDJLH24eL1qWRhNU027wr37yBqSm5kk03Xj08OFsjo0ELrIg3Sj7S9v0pCGnxutiYNe
         +TzL+PV0chXmGUKB7YVnt4P0UNR2HhDvO1ZHFsMhJouUqt4AKoWHFkdxocwJoCdNo0YD
         Tg1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z1mmOZtv;
       spf=pass (google.com: domain of enze.li@linux.dev designates 95.215.58.26 as permitted sender) smtp.mailfrom=enze.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-26.mta1.migadu.com (out-26.mta1.migadu.com. [95.215.58.26])
        by gmr-mx.google.com with ESMTPS id bx33-20020a05651c19a100b002b657edbea8si580876ljb.4.2023.07.24.23.07.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Jul 2023 23:07:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of enze.li@linux.dev designates 95.215.58.26 as permitted sender) client-ip=95.215.58.26;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Enze Li <enze.li@linux.dev>
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Enze Li <lienze@kylinos.cn>,  kernel@xen0n.name,
  loongarch@lists.linux.dev,  glider@google.com,  elver@google.com,
  akpm@linux-foundation.org,  kasan-dev@googlegroups.com,
  linux-mm@kvack.org,  zhangqing@loongson.cn,  yangtiezhu@loongson.cn,
  dvyukov@google.com
Subject: Re: [PATCH 1/4] LoongArch: mm: Add page table mapped mode support
In-Reply-To: <CAAhV-H7mpjeqnv1MXn--EPDUam6TTcHwqiMsEL4OsmAFS5XNMA@mail.gmail.com>
	(Huacai Chen's message of "Tue, 25 Jul 2023 10:06:01 +0800")
References: <20230719082732.2189747-1-lienze@kylinos.cn>
	<20230719082732.2189747-2-lienze@kylinos.cn>
	<CAAhV-H5pWmd2owMgH9hiqxoWpeAOKGv_=j2V-urA+D87_uCMyg@mail.gmail.com>
	<87pm4mf1xl.fsf@kylinos.cn>
	<CAAhV-H4+8_gBMMdLhx=uEAsCN5wK7kFONsKDyGPqm0kxW8FU=A@mail.gmail.com>
	<87lef7ayha.fsf@kylinos.cn>
	<CAAhV-H7mpjeqnv1MXn--EPDUam6TTcHwqiMsEL4OsmAFS5XNMA@mail.gmail.com>
Date: Tue, 25 Jul 2023 14:07:27 +0800
Message-ID: <87bkg0zfq8.fsf@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: enze.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Z1mmOZtv;       spf=pass
 (google.com: domain of enze.li@linux.dev designates 95.215.58.26 as permitted
 sender) smtp.mailfrom=enze.li@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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

On Tue, Jul 25 2023 at 10:06:01 AM +0800, Huacai Chen wrote:

> On Sun, Jul 23, 2023 at 3:17=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote=
:
>>
>> On Fri, Jul 21 2023 at 10:21:38 AM +0800, Huacai Chen wrote:
>>
>> > On Fri, Jul 21, 2023 at 10:12=E2=80=AFAM Enze Li <lienze@kylinos.cn> w=
rote:
>> >>
>> >> On Wed, Jul 19 2023 at 11:29:37 PM +0800, Huacai Chen wrote:
>> >>
>> >> > Hi, Enze,
>> >> >
>> >> > On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn>=
 wrote:

<snip>

>> I've also tried to include mm_types.h in advance, but in this case that
>> doesn't work because the _LINUX_MM_TYPES_H macro already exists.
>> The "forward declaration" was also taken into account, in the end it was
>> found to be unavailable as well.
>>
>> In summary, I'm afraid that rewriting tlb_virt_to_page in asm/page.h as
>> a macro or inline function is not possible.  The root case of this is
>> that both 'struct mm_struct' and 'virt_to_kpte' belong to high-level
>> data structures, and if they are referenced in asm/page.h at the
>> low-level, dependency problems arise.
>>
>> Anyway, we can at least define it as a normal function in asm/pgtable.h,
>> is that Okay with you?
>>
>> It may be a bit wordy, so please bear with me.  In addition, all of the
>> above is my understanding, am I missing something?
> Well, you can define the helpers in .c files at present, but I have
> another question.
>
> Though other archs (e.g., RISC-V) have no DMW addresses, they still
> have linear area. In other words, both LoongArch and RISC-V have
> linear area and vmalloc-like areas. The only difference is LoongArch's
> linear area is DMW-mapped but RISC-V's linear area is TLB-mapped.
>
> For linear area, the translation is pfn_to_page(virt_to_pfn(kaddr)),
> no matter LoongArch or RISC-V;
> For vmalloc-like areas, the translation is
> pte_page(*virt_to_kpte(kaddr)), no matter LoongArch or RISC-V.
>

Hi Huacai,

Thanks for your reply.

> My question is: why RISC-V only care about the linear area for
> virt_to_page(), but you are caring about the vmalloc-like areas?

This patch is a preparation to make LoongArch support KFENCE.

One of the core principles of KFENCE is that pages are tagged in the PTE
and then synchronized to the TLB.  When the MMU detects an improper
access, it can generate an interrupt signal, which is subsequently
handled by a handler function (kfence_handle_page_fault) provided by
KFENCE.  In short, KFENCE requires the support of the TLB.

There's no need to take this into account on RISC-V because TLB mapping
is already supported in linear area.

Best Regards,
Enze

>
> Huacai

<snip>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87bkg0zfq8.fsf%40linux.dev.
