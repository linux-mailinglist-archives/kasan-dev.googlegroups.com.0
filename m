Return-Path: <kasan-dev+bncBDLKPY4HVQKBBJFH7SMQMGQEZMBNHRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id BD90A5F6D16
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 19:43:01 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id d15-20020ac244cf000000b004a1af6792cbsf861444lfm.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 10:43:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665078181; cv=pass;
        d=google.com; s=arc-20160816;
        b=gB40okJ4ae758QsmYIG+7H7/OnGIDUBaCd+JYx9rGbxSCVHzgpmr0/8JOVR/glVMMM
         0WKC9oHhJTHC6b1d5TLXi/TmoA9UAPriB6ov5Jkk3M6TgPrCkUz5PXpjr7Mup/ku+r1y
         vglBSZwk1IurAUH4oBCMCRPmUA1+BfuyjS8F2Mg327to3gvfCC2d0WiTYRTb5y0aFg3Z
         yLsT/ZCvgVOA3oJPn8jyKaOJLXGUnw+tN42fFcd2KAbteaX+GRJzV4HGllS4LLmxtDWL
         kD5HCfwJUu/sdVu6oOeVY1Rh2293jRwSpKFsQQHpqmjcwqf8EIBaTDuC7RR3GehHQz0t
         P1hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:references:cc:to:from:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=NKTNSXRMDV6L/ZZjMjRMwmIrmjYVUZYKe878w4H0kmU=;
        b=H3pCJWHmPb9mXmTFHFYejuR2QUUZAhOLq3raEaDIiFMb+M2T8R5sFI5AVIvWr6PYHD
         9qalc/JydkEbzuvZNKN5MeQoBteERqDL80sETIPtGwFy33tw08UDEK6wLVOzLiFnOIGt
         nSJf0dQ8gEdXrOwLMVgx5AdsxO0hUYsx+tJBJ7/z19+vRatuSphlYvNRKyzjzvodMHaR
         qksf912DPcFjinDTfBlfKrw7drPX5poYrvYzJjEuw4u2/pN0sUUNuI815U5/A2JcTph5
         oElVQCT/KN16knNIZcXlubMFY0TFrG2IhNcb+WyrAwI6m/iVRwdkvx4eEWPWHVpkdRfv
         YsGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:references
         :cc:to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NKTNSXRMDV6L/ZZjMjRMwmIrmjYVUZYKe878w4H0kmU=;
        b=S/Omp7fZ2fQTkoBynUrPT2rziJev2PKK/+onMsEnTtcuXL15fbPD3N9wvtupIf/bYI
         u67FQOuPMQ5+Zam0aDg28/HUKfAa1u3W734i3VCs+D/lYd0xGEHI5nEZDQ9HDlAaYH0v
         uDEQEIbmkYBEMMVxdzOYDEP2gGSxRH2cPL6ajp4K3nIb8hcP86sWQ9CC6Du+pa1PIsSt
         ETYmsMaDsuEnrG6Lu5zg3hGkIVXrbJt2Nq6lfSShB8RrlGsh834F17D7BJuLYd7gUBtS
         E/Q0JehPXVQFb3VH+u0irUtfZ3uJd5CaK5dxwOsyil7XOL9rvAxtqg792WIaB3UjF/+8
         m6DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NKTNSXRMDV6L/ZZjMjRMwmIrmjYVUZYKe878w4H0kmU=;
        b=puDpwUjjI35vDXEhzAtJ/W6QOZRXSTcUTogR0VvOMOmPaIfTA16cGCbriO1B/NaTQM
         T5nX4oxK/I/m8COoI1VlYirtoP7qvMu+7O+QuAl10mUbOuxDfIZW7u87C2OL/h9RcgUj
         DdwmH3sZfne1RVvVQdTbGDspTXXfqawxsV4M/a/LxexxEEpRjsU5D4fa4jGGt5uxFDgJ
         sYX2ZK3VjtjEeXujqpwG/ydf7VrzspRxT/oOtYE5B+CGrBbmGDKa1UAOU9emf3+J7ZeO
         4ZIQxp2ttQdIIfBq8+5Dv3lKigSpOoPThicquykfH5wa5hagpzZyelXdtx7ysKqj8Fh3
         jMMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf00X9NhdsW+gTL0YhhhDhTaHNa4WuepRiSHR4WL19ridywrW/E2
	5x9nKbHGUmea3Ws0kFP6ctQ=
X-Google-Smtp-Source: AMsMyM5D1LVDBrTWPjWgJXOzVDIOx+5r3Xofwf9Xi/NkH2+lN44u588GARJ5OoG43LsHkAd1JjKtYw==
X-Received: by 2002:a2e:549:0:b0:26d:ff5f:53c1 with SMTP id 70-20020a2e0549000000b0026dff5f53c1mr304025ljf.450.1665078181000;
        Thu, 06 Oct 2022 10:43:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91d5:0:b0:261:d944:1ee6 with SMTP id u21-20020a2e91d5000000b00261d9441ee6ls549076ljg.0.-pod-prod-gmail;
 Thu, 06 Oct 2022 10:43:00 -0700 (PDT)
X-Received: by 2002:a2e:be22:0:b0:26c:27da:2692 with SMTP id z34-20020a2ebe22000000b0026c27da2692mr276012ljq.481.1665078180030;
        Thu, 06 Oct 2022 10:43:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665078180; cv=none;
        d=google.com; s=arc-20160816;
        b=Rn/zc0KfZu/bXSMYoSB2PgrP/EYAm02ej2oTHEjjW+rFj17L7ftBm0qHvP3gOp3/Iq
         1R5oFE8hX1sTzsdVLCxXPHVI7xs41PWN0uWqHdihu6+etCnjhRbhiZ9afuF8TKugphZo
         6bNLHNObMJ3hRWES/mVl14G5Ida8mh2xb6nKT5LJ3LsOD74hqGyNG8MM5ETF2s/p2w2E
         xAPHsiFLsoBkM/y/T1isP0GtGQB7FzMUsoRBz1B6sxGpWA2UticsSzdr8tHDWApW75nS
         SzEOQmq2gHlP07XYLWrwySn/Z5RnQ/KSuGi6J5lEmkDIHhW93j+8g0n27NOxrElSjfmQ
         btCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=xV/g8UUaOZTAfElJMdzKRr4WPzEp2UTWXSAym3LtymY=;
        b=dbLF7Tzz6m6KmBm2qq4KHGNdgkioeOa9zbcIUQeBTVFbSXCAif8EO3jC/nAdATrBd6
         CSSriUFqLdJt9rjSCzdF2hkXb5yVnCEWNjchglMpwn2/fXu03kNepNitmgLqzhZFA9QZ
         X3/ShNva+jRVjXOFfheJXzlR/AHHyLWbJsDOndjxgyWSr7BUznrNsMb5TQfT3OsttpNj
         orAYNzp5sFc8ErLnTZi8RsinT6OiENiNCIpVG/XUiW47/y0ETyVj/qI8PIaomqTER1zb
         8km4gCdR1/b5vRPEd3Jdd/14f46LZyLnLYS55307BohZJKII4g7gsJ0espylwje7e8Yt
         RfHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id i12-20020a056512340c00b00497f1948428si762279lfr.8.2022.10.06.10.42.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 10:43:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4MjzLC11Gzz9syB;
	Thu,  6 Oct 2022 19:42:59 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id LsXJRIhoNC1h; Thu,  6 Oct 2022 19:42:59 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4MjzLB5Dvqz9syS;
	Thu,  6 Oct 2022 19:42:58 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 8738A8B78C;
	Thu,  6 Oct 2022 19:42:58 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id z2OiiiTjoE_O; Thu,  6 Oct 2022 19:42:58 +0200 (CEST)
Received: from [192.168.233.27] (po19210.idsi0.si.c-s.fr [192.168.233.27])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4E53E8B77D;
	Thu,  6 Oct 2022 19:42:56 +0200 (CEST)
Message-ID: <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
Date: Thu, 6 Oct 2022 19:42:55 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Content-Language: fr-FR
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "patches@lists.linux.dev" <patches@lists.linux.dev>,
 Andreas Noever <andreas.noever@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
 Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?Q?Christoph_B=c3=b6hmwalder?= <christoph.boehmwalder@linbit.com>,
 Christoph Hellwig <hch@lst.de>, Daniel Borkmann <daniel@iogearbox.net>,
 Dave Airlie <airlied@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>,
 "David S . Miller" <davem@davemloft.net>, Eric Dumazet
 <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "H . Peter Anvin" <hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>,
 Helge Deller <deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>,
 Huacai Chen <chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>,
 Jakub Kicinski <kuba@kernel.org>,
 "James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>,
 Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>,
 Johannes Berg <johannes@sipsolutions.net>, Jonathan Corbet <corbet@lwn.net>,
 Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>,
 Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
 Mauro Carvalho Chehab <mchehab@kernel.org>,
 Michael Ellerman <mpe@ellerman.id.au>,
 Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>,
 Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>,
 Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Ulf Hansson <ulf.hansson@linaro.org>, Vignesh Raghavendra <vigneshr@ti.com>,
 WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>,
 Yury Norov <yury.norov@gmail.com>,
 "dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "kernel-janitors@vger.kernel.org" <kernel-janitors@vger.kernel.org>,
 "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>,
 "linux-block@vger.kernel.org" <linux-block@vger.kernel.org>,
 "linux-crypto@vger.kernel.org" <linux-crypto@vger.kernel.org>,
 "linux-doc@vger.kernel.org" <linux-doc@vger.kernel.org>,
 "linux-fsdevel@vger.kernel.org" <linux-fsdevel@vger.kernel.org>,
 "linux-media@vger.kernel.org" <linux-media@vger.kernel.org>,
 "linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-mmc@vger.kernel.org" <linux-mmc@vger.kernel.org>,
 "linux-mtd@lists.infradead.org" <linux-mtd@lists.infradead.org>,
 "linux-nvme@lists.infradead.org" <linux-nvme@lists.infradead.org>,
 "linux-parisc@vger.kernel.org" <linux-parisc@vger.kernel.org>,
 "linux-rdma@vger.kernel.org" <linux-rdma@vger.kernel.org>,
 "linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
 "linux-um@lists.infradead.org" <linux-um@lists.infradead.org>,
 "linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>,
 "linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
 "loongarch@lists.linux.dev" <loongarch@lists.linux.dev>,
 "netdev@vger.kernel.org" <netdev@vger.kernel.org>,
 "sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>,
 "x86@kernel.org" <x86@kernel.org>, =?UTF-8?Q?Toke_H=c3=b8iland-J=c3=b8rgens?=
 =?UTF-8?Q?en?= <toke@toke.dk>, Chuck Lever <chuck.lever@oracle.com>,
 Jan Kara <jack@suse.cz>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
In-Reply-To: <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 06/10/2022 =C3=A0 19:31, Christophe Leroy a =C3=A9crit=C2=A0:
>=20
>=20
> Le 06/10/2022 =C3=A0 19:24, Jason A. Donenfeld a =C3=A9crit=C2=A0:
>> Hi Christophe,
>>
>> On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
>> <christophe.leroy@csgroup.eu> wrote:
>>> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
>>>> The prandom_u32() function has been a deprecated inline wrapper around
>>>> get_random_u32() for several releases now, and compiles down to the
>>>> exact same code. Replace the deprecated wrapper with a direct call to
>>>> the real function. The same also applies to get_random_int(), which is
>>>> just a wrapper around get_random_u32().
>>>>
>>>> Reviewed-by: Kees Cook <keescook@chromium.org>
>>>> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_ca=
ke
>>>> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
>>>> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
>>>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
>>>> ---
>>>
>>>> diff --git a/arch/powerpc/kernel/process.c=20
>>>> b/arch/powerpc/kernel/process.c
>>>> index 0fbda89cd1bb..9c4c15afbbe8 100644
>>>> --- a/arch/powerpc/kernel/process.c
>>>> +++ b/arch/powerpc/kernel/process.c
>>>> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
>>>> =C2=A0=C2=A0 unsigned long arch_align_stack(unsigned long sp)
>>>> =C2=A0=C2=A0 {
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!(current->personality & ADDR=
_NO_RANDOMIZE) &&=20
>>>> randomize_va_space)
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 sp -=3D get_random_int() & ~PAGE_MASK;
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 sp -=3D get_random_u32() & ~PAGE_MASK;
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return sp & ~0xf;
>>>
>>> Isn't that a candidate for prandom_u32_max() ?
>>>
>>> Note that sp is deemed to be 16 bytes aligned at all time.
>>
>> Yes, probably. It seemed non-trivial to think about, so I didn't. But
>> let's see here... maybe it's not too bad:
>>
>> If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
>> (PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the same
>> thing? Is that accurate? And holds across platforms (this comes up a
>> few places)? If so, I'll do that for a v4.
>>
>=20
> On powerpc it is always (from arch/powerpc/include/asm/page.h) :
>=20
> /*
>  =C2=A0* Subtle: (1 << PAGE_SHIFT) is an int, not an unsigned long. So if=
 we
>  =C2=A0* assign PAGE_MASK to a larger type it gets extended the way we wa=
nt
>  =C2=A0* (i.e. with 1s in the high bits)
>  =C2=A0*/
> #define PAGE_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (~((1 << PAGE_SHIFT) - 1)=
)
>=20
> #define PAGE_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (1UL << PAGE_=
SHIFT)
>=20
>=20
> So it would work I guess.

But taking into account that sp must remain 16 bytes aligned, would it=20
be better to do something like ?

	sp -=3D prandom_u32_max(PAGE_SIZE >> 4) << 4;

	return sp;


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6396875c-146a-acf5-dd9e-7f93ba1b4bc3%40csgroup.eu.
