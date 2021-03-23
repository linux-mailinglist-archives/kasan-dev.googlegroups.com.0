Return-Path: <kasan-dev+bncBDLKPY4HVQKBBVOZ46BAMGQENTEUZWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B22D345F9C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 14:27:50 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id i5sf1103871wrp.8
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 06:27:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616506069; cv=pass;
        d=google.com; s=arc-20160816;
        b=DY0aanmmma+Ncnxowyhbjtu082yLVLMd7RAEmpu5ic1iPKYB1qGRIvGApV0fwkYh69
         OcB3/GC++0hxLH3x05RwPUlgtOQN6YhXMDZdWarn8Yi2hkqSsvF7muP/CGMFgl+itFn/
         8H9q2onEapXZ0P9lQA5tYLIdzYD+Sco6RcF6FZYzn7yIn0dOQSbW0X4JNZ+Isi155L6H
         o0SfBpOVJG7eyCZ4RdJTLfJWpqDP3xWhvAq6CuH38rj+MbKlBDht8CTw7r/9OhrkZOCL
         C0I5LjK5Iegv+A2NzDNDP9JE2ii6mSim2C1soBBD3RnZgmqb21EN5xzM0P2Qrk8GOTYv
         Z7hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=BLNL4XqDHYixH2ycmOuQQBVO0jsrkqDjAVoXKDCPt1w=;
        b=XmhVWF5cU8pWkuLN5oxe1LdMul3faqGgU4qP+1TQIbZBj+8YVM/lCGGPw3dohY3t3j
         EHn9h/OECyZpf/sW9gg3YUBJEv9Kw1KznFYjEPhlVe7vV7rANcXAmeMyLxFuY+OW/dWY
         cdD73HYyms9TlX7K5sQ2QevE6AqIWxfZP+tEEgYYL5ZhDSW1DBJMXVPVbY+mOnLPDYcy
         J7wce4Fo7H299y9XUnpJAdZuNloHS+8R/e1CVogfbxPjB2ouUAeNSdB0xL56dnifkUxW
         FmLOobek3AgBkgi5E4Z1n2hFfqh5oXImHO6H87sICGl8go2rbMpKIs+FdSPzXtXXs1Jv
         2u0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BLNL4XqDHYixH2ycmOuQQBVO0jsrkqDjAVoXKDCPt1w=;
        b=GGvDxPuaW2eRtLA1eT81z5lSeJSr7rvCQQQu01yBya/snUF3SwIi6+pPSsCJmTSAh6
         JuxJxG2Mym0rTjs8N8aJrCvgexRphWozWnbc13gBTy2Yy1NXDfRwl8EosZW/59330Vm1
         FtQLe07xubphZ+0YBItDoTEbrRu59h4CMbd89FUdHe9RLzMv4YTxubu5lnSKwrGdo+ee
         v9DOJx3w+AYXEVQnIpVSqBADfUoRd9cMovo65W5SDSNX39y1bMYOvqhfEDgYix92eJeI
         kdHDQMGAlaJrKvnG1TIEYFXDRfw/6LoRM1VfJuqCgaQvS24SZSVH4NWLT41GZ3tlzV1i
         sLtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BLNL4XqDHYixH2ycmOuQQBVO0jsrkqDjAVoXKDCPt1w=;
        b=hDKnxgnUZyx//LNRvWThFSHncArCS446IKXcCLPoFU7yk0CxL19PuhG1gA1zHHc2TI
         62SMkEtvX69QDr8RsGQGNPKhS3EmsxvAtjpdcjmVV3LlPmG+Ub6VRJdOQLLoYBF6I/mk
         Wvis3YLVJFHVbIPFeqCoDF6isB7X/5KDyqrIc018U7MhBnOJKZEynH9yGaBLBbrTjp9t
         nU1CvHroON6NHALYQx7aKn4cEvkDIKtt/zNdij/fsu8zpBJayVPjS0QeKUsx8PsYTFyv
         483fiZhbGTHAHoJTEBu8AmLoAaXqGIPYJ+8/Nhy36dwZ5CHCrqrYjHJTCsmhrKi7Ddxv
         soKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310m5ugXhYPOfFiAg3zFGiGvDrRs+GEGQaB+qsSyN3rD1U9wYy0
	4GWI0wzn36gjmvTzLU4PSnQ=
X-Google-Smtp-Source: ABdhPJzyyArmTKtaIB5LL6KbeiURCGlr9VuSYGH/a6Wttpx4cUPs0citWwwMy34iFzQyGKU0XSgsOw==
X-Received: by 2002:a05:600c:2947:: with SMTP id n7mr3465513wmd.61.1616506069851;
        Tue, 23 Mar 2021 06:27:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls2890776wrd.0.gmail; Tue, 23 Mar
 2021 06:27:48 -0700 (PDT)
X-Received: by 2002:adf:e5cf:: with SMTP id a15mr3923673wrn.226.1616506068887;
        Tue, 23 Mar 2021 06:27:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616506068; cv=none;
        d=google.com; s=arc-20160816;
        b=PDa6O9od3Azy7wozUGv1uQUrMsvieFs6ozVh+G3GnVuexg2rCiJGnIEafwFL4f53S7
         HkdoAs/HRUOhlaICJGzZFcStxVL6GUlciohmcZ62gP1WkYJIM6g2gxUm58aGVcUiRPWb
         NPlneh9ZmL/tdkvFMYbhqkckG3mXho9sr4fDXelQm9N5bOsIiVTHCn+tIuYMY2kmqub4
         JewIuXB7SokavsUo1eHiOoRDsCBDGuKuO6WHiiDX+zbp16H4d+yd2FK1CqRdt4wRWx/V
         oOIGqVUgquAC/ocyI1t1EkHCq5EleO1j/SOCuV0KQavYQlKAtSeXWVIC+nTt944UEOIU
         3CRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=1rOUnW7NvGNH2LyWXIunVzbWEl/X2yO1xmTpmk4o97U=;
        b=HJVi1UXtFUhFq8SYHL6dvS4gsUkkQ2Tyx4dOQY8M3kHvAAjkJV+M5Cv1OnDTGzfEww
         /BK+T2frlqFo3oHDmBN9YD7nkk9jdSDAUHCF5GbmSw4YiNx6jj+lyoIiaCcOpYzACn0E
         hlG2aKPPpNxH9HVsBu+x3WIvZZxBBe/JzU+HUif8/4zQrKcQ3FDKY5hBUtg1K4pMG4br
         ZI0ja/jSMxaT1EXQhURC9EXpLA3dyMGv54224REluTlU4Mos/ExCIFG7MO0jCmYopG2u
         1uu59YmDWkyL0uNyO5VcaNWfxkPCGrXJSUj6eJ2ota1schSpuIS7WHOeK/ZrMPippYra
         z/LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id w2si113411wmb.4.2021.03.23.06.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Mar 2021 06:27:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4F4XH70jjqz9v1GL;
	Tue, 23 Mar 2021 14:27:47 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id RzqWHqF5nznC; Tue, 23 Mar 2021 14:27:47 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4F4XH66lWHz9v1GJ;
	Tue, 23 Mar 2021 14:27:46 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4CFA18B7F7;
	Tue, 23 Mar 2021 14:27:48 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id TWHHaF8PUfFg; Tue, 23 Mar 2021 14:27:48 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B4B0A8B7F4;
	Tue, 23 Mar 2021 14:27:47 +0100 (CET)
Subject: Re: [PATCH v11 0/6] KASAN for powerpc64 radix
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20210319144058.772525-1-dja@axtens.net>
 <5a3b5952-b31f-42bf-eaf4-ea24444f8df6@csgroup.eu>
 <87ft0mbr6r.fsf@dja-thinkpad.axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <a5e1d7c5-3ebc-283c-2c9d-55d36d03cf48@csgroup.eu>
Date: Tue, 23 Mar 2021 14:27:45 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <87ft0mbr6r.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
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



Le 23/03/2021 =C3=A0 02:21, Daniel Axtens a =C3=A9crit=C2=A0:
> Hi Christophe,
>=20
>> In the discussion we had long time ago,
>> https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20190806233827.1=
6454-5-dja@axtens.net/#2321067
>> , I challenged you on why it was not possible to implement things the sa=
me way as other
>> architectures, in extenso with an early mapping.
>>
>> Your first answer was that too many things were done in real mode at sta=
rtup. After some discussion
>> you said that finally there was not that much things at startup but the =
issue was KVM.
>>
>> Now you say that instrumentation on KVM is fully disabled.
>>
>> So my question is, if KVM is not a problem anymore, why not go the stand=
ard way with an early shadow
>> ? Then you could also support inline instrumentation.
>=20
> Fair enough, I've had some trouble both understanding the problem myself
> and clearly articulating it. Let me try again.
>=20
> We need translations on to access the shadow area.
>=20
> We reach setup_64.c::early_setup() with translations off. At this point
> we don't know what MMU we're running under, or our CPU features.

What do you need to know ? Whether it is Hash or Radix, or more/different d=
etails ?

IIUC, today we only support KASAN on Radix. Would it make sense to say that=
 a kernel built with=20
KASAN can only run on processors having Radix capacility ? Then select CONF=
IG_PPC_RADIX_MMU_DEFAULT=20
when KASAN is set, and accept that the kernel crashes if Radix is not avail=
able ?

>=20
> To determine our MMU and CPU features, early_setup() calls functions
> (dt_cpu_ftrs_init, early_init_devtree) that call out to generic code
> like of_scan_flat_dt. We need to do this before we turn on translations
> because we can't set up the MMU until we know what MMU we have.
>=20
> So this puts us in a bind:
>=20
>   - We can't set up an early shadow until we have translations on, which
>     requires that the MMU is set up.
>=20
>   - We can't set up an MMU until we call out to generic code for FDT
>     parsing.
>=20
> So there will be calls to generic FDT parsing code that happen before the
> early shadow is set up.

I see some logic in kernel/prom_init.c for detecting MMU. Can we get the in=
formation from there in=20
order to setup the MMU ?

>=20
> The setup code also prints a bunch of information about the platform
> with printk() while translations are off, so it wouldn't even be enough
> to disable instrumentation for bits of the generic DT code on ppc64.

I'm sure the printk() stuff can be avoided or delayed without much problems=
, I guess the main=20
problem is the DT code, isn't it ?

As far as I can see the code only use udbg_printf() before MMU is on, and t=
his could be simply=20
skipped when KASAN is selected, I see no situation where you need early pri=
ntk together with KASAN.

>=20
> Does that make sense? If you can figure out how to 'square the circle'
> here I'm all ears.

Yes it is a lot more clear now, thanks you. Gave a few ideas above, does it=
 help ?

>=20
> Other notes:
>=20
>   - There's a comment about printk() being 'safe' in early_setup(), that
>     refers to having a valid PACA, it doesn't mean that it's safe in any
>     other sense.
>=20
>   - KVM does indeed also run stuff with translations off but we can catch
>     all of that by disabling instrumentation on the real-mode handlers:
>     it doesn't seem to leak out to generic code. So you are right that
>     KVM is no longer an issue.
>=20

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a5e1d7c5-3ebc-283c-2c9d-55d36d03cf48%40csgroup.eu.
