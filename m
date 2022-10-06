Return-Path: <kasan-dev+bncBCLI747UVAFRBJ6N7WMQMGQE7IYVWBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C7F9B5F71D9
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 01:37:12 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id y1-20020a2e3201000000b0026c3cb4c13bsf1278354ljy.11
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 16:37:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665099432; cv=pass;
        d=google.com; s=arc-20160816;
        b=J8W4tvqOFqVG6YpQJrY8ONkIQYraMBWNfz/yjsfwp5SLrrCVB2+X7S+JqwywDdZ6SS
         sXOpQ7wy8Lu0nC1xvP4ai57tjS6g6FC9r08wKaYYaMkSNs0PWbzHR6WTtaf5UtE86BgB
         pCYyFaAoC5mE0t9WIyEfJgZZOOXyjgMbGOWQpaNzFMvIN607LHeU0wIo2Iu6WPIzb1e7
         5qDkJPTBj+KRgkCXCgebA7m5o6TJiPV2hJF8CFi4hzw9E9aooUDucPeeWF8w3SKx4lXO
         hqrJOsFML1IB5ura1ax4R4s+wwiyJBM75PuouQBg08MMcvzyq+k/y7m7vDGRjFxMpAs6
         iQ3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:references:in-reply-to
         :mime-version:dkim-signature;
        bh=LtwvkwNDN2t2ciAq993ZUF+3ELMW+9JeMtBZ9yyU08A=;
        b=X2xTksgwwFGQTXtZgG37fYMlpCD09UCKweAzwaY/tj1HLDPCfLDYKf2+AN9eT4sYQq
         +YscSZTpTKo8CD5qaumQlif20i7X3P+ZrDCgkibNhbGvYdt2bEy++Vi+8FI1P810Tdc1
         8filK433lLEFwra/UOp9yDOHc7WIuLL3kUDUJ+leokLom5MAzTyZ004zozCVFqjlYSob
         DUfSb6bzFHkPS3eg9O3cRpyafJxzSujyQJX4de+lCnRgyQkd3txPp3v7IeTKrD2W0te1
         YXG+J3Jv8YVUK5BozzJn/VOVgUS0/EqmPQXyZfVmM8fT9wRK0weg2axAVRDj76DyeHyn
         fZMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=hvGmGUp7;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LtwvkwNDN2t2ciAq993ZUF+3ELMW+9JeMtBZ9yyU08A=;
        b=H7uftvL4nsu3qhmESA8Tv2h3vUKn3rxd+fZO2A2mZaSpJPvUHEyscbcrf+YdKI+ket
         7XycYPW8srn9myEb1+bX8x8KzCEiy5lyOeXJbq332/UPFM0LcSssnSFdpaiM9JllmL9e
         dJgq2plbit+q6CkBICKWDKNrXqCsAbEBk4cTrnPVIeDaCpLrz5TxTsBHC7byBLdsVrPe
         jBb6cxfEGbmz2AEkKenDhXpqgUsiNtJA7pQttZ9rM68HqsvQdlcmW/fa5I2wYLHU9aIq
         ualIIGuBpr50/8HM027mnypj/tPpTmSJ3SG+pjefqjqA3YsI+1c9qp01w6U635Cn5eSM
         gUhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LtwvkwNDN2t2ciAq993ZUF+3ELMW+9JeMtBZ9yyU08A=;
        b=P+bfh4To3kdCQIfeOSH9Aefvwr3PLsghluFrRi3wfE2hFnC66liSKnlS8uM6atjv9s
         HG0gvr4YZSg+gohyWPi8x23bEovo2RGj+AKp7vHrmTC04o7s4kSwxnvcT7K10cmk/JwM
         tsl0UKmYhv8t3Dm3TWaP7zvlvQBSpr8BscOMh/eiCXgNrM4j4GTxLxAeInh+M3HZm1US
         NuzpnQ01k+2SlO18SYXbndcgjofJxSyxOud63qjOgc4KZnKm6gwlDSRQLxghRgPjShXO
         lxhX/NYIfCGPdhmUPCWy0SrGQyMVqThOt7EaLZlrLS3t8kRWw8xhRpmkdPqUl2fdkmlV
         AXSQ==
X-Gm-Message-State: ACrzQf1qtBOLwxQSZ5kaR6k2K2iTJL3SjvGoePK6MB3lnd78pM9mfS0N
	WV4zoBg5llndR+eL37V+JhE=
X-Google-Smtp-Source: AMsMyM5lxbL0wdnzd39vW4fLb0jAcrZ0RuSUj9KGWDN6aHrNIKf3uT1dNEvYZzVGhMBEKkWxQTOKCQ==
X-Received: by 2002:a2e:a602:0:b0:264:5132:f59 with SMTP id v2-20020a2ea602000000b0026451320f59mr748986ljp.0.1665099432069;
        Thu, 06 Oct 2022 16:37:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ec6:0:b0:4a2:3951:eac8 with SMTP id p6-20020ac24ec6000000b004a23951eac8ls2380540lfr.0.-pod-prod-gmail;
 Thu, 06 Oct 2022 16:37:10 -0700 (PDT)
X-Received: by 2002:a05:6512:3614:b0:4a2:375c:f918 with SMTP id f20-20020a056512361400b004a2375cf918mr781165lfs.653.1665099430789;
        Thu, 06 Oct 2022 16:37:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665099430; cv=none;
        d=google.com; s=arc-20160816;
        b=HGA/S/RVFdh/TD4Jh97YEMNnAfonxRN1u6pQAF6FSWVUBdHaxa1ELTLR0nyQKK6dI9
         HNIFjgznivSF7Y1IYzJMNgIYW63WCagdom2TufWOU/o1Kw/wKq5rksNd0mWrOXYnjBuW
         myJTpQSBI4D+cMIonrDc01iHAuNzmNfC3sqQe4HgDM+g64tNn+10BDPvNziRQ79IzeUQ
         3yEVcLPDgaTBPhdY69hWGMZnzvjMDALys1S50gaAlASXU6qbgzvEmpjMHZCpSLGnvr69
         eBzv3LBv4PgOOHxzY/8NhKlvfVnXPk6H+Ty9MjSG6Ib6JDPQjLgzgnKQ3aZq/X4wOSye
         8UBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:dkim-signature;
        bh=eDWvYu+uSvuLU1D2yrcps4Uxg3s4afpQR1DZP1HAENk=;
        b=oc0vcIaNS/hoHvmpW1zRbDBb4rabVwwEKC9oSmZU70OS5JPZ5WERT8muv8vPCrQ/rB
         zWOiQNccU9XNB0eqAv3FuaT2DngUjYSTOnbdmW+9bJniKqawNN32lnH+Mw83pj2lCvIH
         llAJMurdllMaymNw+dAZTVlatULJTAx+BXrgNQpbAxZqjusPq5cwbt8uAerrGLENwpMC
         XC6Jrr0FRYuP4KDVN5UVZ5ncixmouGEofWZ3WixYOsNWRAtASRNIo0jVwhtA/GzJPJtZ
         2GfXF7OdH/Rr3w2NhQHcmFigE1xs+S6hgV+RAPrpBfstcOeuUBe1vl9RfrUdPhY25S1T
         u7EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=hvGmGUp7;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id c2-20020a056512074200b004a225e3ed13si20211lfs.13.2022.10.06.16.37.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 16:37:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 47188B821EF
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 23:37:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BA7E0C433C1
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 23:37:09 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 80d30118 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Thu, 6 Oct 2022 23:37:03 +0000 (UTC)
Received: by mail-vs1-f42.google.com with SMTP id x124so3490381vsb.13
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 16:37:02 -0700 (PDT)
X-Received: by 2002:a05:6102:2908:b0:398:ac40:d352 with SMTP id
 cz8-20020a056102290800b00398ac40d352mr1292105vsb.55.1665099409449; Thu, 06
 Oct 2022 16:36:49 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab0:6ed0:0:b0:3d9:6dfd:499 with HTTP; Thu, 6 Oct 2022
 16:36:48 -0700 (PDT)
In-Reply-To: <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
References: <20221006165346.73159-1-Jason@zx2c4.com> <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu> <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu> <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Oct 2022 17:36:48 -0600
X-Gmail-Original-Message-ID: <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
Message-ID: <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"patches@lists.linux.dev" <patches@lists.linux.dev>, Andreas Noever <andreas.noever@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?Q?Christoph_B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>, 
	Christoph Hellwig <hch@lst.de>, Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "David S . Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen <chenhuacai@kernel.org>, 
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	"James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Jens Axboe <axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, 
	Jonathan Corbet <corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mauro Carvalho Chehab <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>, 
	Russell King <linux@armlinux.org.uk>, "Theodore Ts'o" <tytso@mit.edu>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Ulf Hansson <ulf.hansson@linaro.org>, 
	Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>, 
	Yury Norov <yury.norov@gmail.com>, 
	"dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"kernel-janitors@vger.kernel.org" <kernel-janitors@vger.kernel.org>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-block@vger.kernel.org" <linux-block@vger.kernel.org>, 
	"linux-crypto@vger.kernel.org" <linux-crypto@vger.kernel.org>, 
	"linux-doc@vger.kernel.org" <linux-doc@vger.kernel.org>, 
	"linux-fsdevel@vger.kernel.org" <linux-fsdevel@vger.kernel.org>, 
	"linux-media@vger.kernel.org" <linux-media@vger.kernel.org>, 
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
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
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>, "x86@kernel.org" <x86@kernel.org>, 
	=?UTF-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?= <toke@toke.dk>, 
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=hvGmGUp7;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On 10/6/22, Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
>
>
> Le 06/10/2022 =C3=A0 19:31, Christophe Leroy a =C3=A9crit :
>>
>>
>> Le 06/10/2022 =C3=A0 19:24, Jason A. Donenfeld a =C3=A9crit :
>>> Hi Christophe,
>>>
>>> On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
>>> <christophe.leroy@csgroup.eu> wrote:
>>>> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
>>>>> The prandom_u32() function has been a deprecated inline wrapper aroun=
d
>>>>> get_random_u32() for several releases now, and compiles down to the
>>>>> exact same code. Replace the deprecated wrapper with a direct call to
>>>>> the real function. The same also applies to get_random_int(), which i=
s
>>>>> just a wrapper around get_random_u32().
>>>>>
>>>>> Reviewed-by: Kees Cook <keescook@chromium.org>
>>>>> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_c=
ake
>>>>> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
>>>>> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
>>>>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
>>>>> ---
>>>>
>>>>> diff --git a/arch/powerpc/kernel/process.c
>>>>> b/arch/powerpc/kernel/process.c
>>>>> index 0fbda89cd1bb..9c4c15afbbe8 100644
>>>>> --- a/arch/powerpc/kernel/process.c
>>>>> +++ b/arch/powerpc/kernel/process.c
>>>>> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
>>>>>    unsigned long arch_align_stack(unsigned long sp)
>>>>>    {
>>>>>        if (!(current->personality & ADDR_NO_RANDOMIZE) &&
>>>>> randomize_va_space)
>>>>> -             sp -=3D get_random_int() & ~PAGE_MASK;
>>>>> +             sp -=3D get_random_u32() & ~PAGE_MASK;
>>>>>        return sp & ~0xf;
>>>>
>>>> Isn't that a candidate for prandom_u32_max() ?
>>>>
>>>> Note that sp is deemed to be 16 bytes aligned at all time.
>>>
>>> Yes, probably. It seemed non-trivial to think about, so I didn't. But
>>> let's see here... maybe it's not too bad:
>>>
>>> If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
>>> (PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the same
>>> thing? Is that accurate? And holds across platforms (this comes up a
>>> few places)? If so, I'll do that for a v4.
>>>
>>
>> On powerpc it is always (from arch/powerpc/include/asm/page.h) :
>>
>> /*
>>   * Subtle: (1 << PAGE_SHIFT) is an int, not an unsigned long. So if we
>>   * assign PAGE_MASK to a larger type it gets extended the way we want
>>   * (i.e. with 1s in the high bits)
>>   */
>> #define PAGE_MASK      (~((1 << PAGE_SHIFT) - 1))
>>
>> #define PAGE_SIZE        (1UL << PAGE_SHIFT)
>>
>>
>> So it would work I guess.
>
> But taking into account that sp must remain 16 bytes aligned, would it
> be better to do something like ?
>
> 	sp -=3D prandom_u32_max(PAGE_SIZE >> 4) << 4;
>
> 	return sp;

Does this assume that sp is already aligned at the beginning of the
function? I'd assume from the function's name that this isn't the
case?

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ%2BGAA%40mail.gmai=
l.com.
