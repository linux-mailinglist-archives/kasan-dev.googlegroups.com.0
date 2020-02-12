Return-Path: <kasan-dev+bncBCXLBLOA7IGBB7VJR7ZAKGQEBR6GH6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BD5E115A688
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 11:35:42 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id g26sf542989wmk.6
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 02:35:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581503742; cv=pass;
        d=google.com; s=arc-20160816;
        b=gNhGim8kpWZZbHCXaOjkRyF5udey7E6Aetu9Eu6WsuNa7mnfqZkpAEzZwRDz4Lhq3u
         x57fR7z0zqo/Dnr25sT50mXXB6bZ5sMKDu413lJhOQn9bCWgnRRzVKvndzS0EQmzFoOK
         a1QpyKRMC+Ab1Pfm0T/qZ6L2E+r8l69Eijx9PNSmC5jAhdFy406hYfF99nxaLQa72lOf
         NODFaFzOJSFz8WVdnkdo7ccQIegw4sgV5sgN8QpKSAsKljOPBkcgXubVJ84uIJpLpk8+
         tv964k7+qh2wxh2OFBVAXUAKOaFBIoidSCei+jPT3QF+vy0RP0UdbaMOwpuZJNpNaV5+
         r9ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=xDpBVK/CAsY13t4S+dPaoJsIeW+J6HSducK2Tghm3GU=;
        b=KJaEpnqshw2xUfsjo0l6UCuoX/MEiQIVyixhI0/K9rQ+6cx4Pq1htbRkPAyWhLHEuA
         93qmZR2rFtjLnn+6f/duRzOfwOCYMasv07azrdNsz6SGwHNwxnB6f/AqxrJJdteNRSfW
         YaOGQuoFHqf4oBQT/BH6Ur6Ly7/27tHJ+p3uQtzN+YpxxvXdrZS3LU1YHInxFDMq19Dv
         5ZTpxEfkgbxlY6O2fShalxqgFYXcHfTFKZ0AzJ2oVv/uh1YeU34tyP382viQIDj0qHEz
         zIGGBy70AG7694QJgrEiAlHuXylmMh4bFX4T1cxXXYyBW0gu/EsClZgSBTGy1mdWHYi7
         DIkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="lstPK/Ib";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xDpBVK/CAsY13t4S+dPaoJsIeW+J6HSducK2Tghm3GU=;
        b=IvMo1JWj/a90BitZIk56L6ZM/LNhjvZ3AHM82/slVthgKKKm/tC3SefFAKKLgeovMt
         2aAHx3gi8XG+T+BTKAoYeps58Wllx/EmCikmjBdoFyxTnnc+/ei1j3nBpZV/66eUSw0Q
         lQLYag95OtmaLCHOj4O8YjiTMkHn7EnaHIYWTqnwEQNcXW0dYalh7jmsPmEh7SvBrJys
         fFggyVDP0niT3SbHKjSUXJ0DFCLOg84o6vW8Ai6Wv0n4iUyHXXIlyp57Y8TtW2U4zusw
         LLv5SdtQ0ZbkGzM1sI0jAT13aEgcbmgPnV1FNNKPvTME72jGYHyLsi2XyD1iJdKU5Hbf
         bWyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xDpBVK/CAsY13t4S+dPaoJsIeW+J6HSducK2Tghm3GU=;
        b=DtfAPAWFa0GS6gZ8zXSQbUnklPnpgO4dtvdhHY3dEy9psQFCKynW7HpV+w6fjaZGdL
         UUJdtXJ0KnRyZ8hStRvduOqtiNLMKeNvY8Aw9nTKzJlp4VjeoUmqKC5lHBO5L6kcuAim
         RZ0A9hSk45YNiPROcpL04n0Qz6ExAhRyl5YkUsTzUZLHwbCHM/dNhFjeZdYabVbobLpn
         qlDuwulAfwyDIGCMbSPZ/b03PO9G0+ygOZ+Y070herkJlaqzqrOANGXxHpTqXn4a0Ppf
         wWN5UWI9ly+2A8yVB493YZOtQZWvNPw72XbxUic4eQH5y52LC0kJGqnz0Nuw2s2mHje7
         TmMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUVRCMBVII+Ko6TqwFa8MQc6+G0u96Gip5r3uSfJG+WXZHe4peu
	WGjLWxBdWZVqD0M6NpAFq6E=
X-Google-Smtp-Source: APXvYqz8I0Q3pyDJHcseWItkGjcXdxeiWBuySUBMVcqL2ziq/uphv1rfeVDP7YHbGPkU9qncpIOEFQ==
X-Received: by 2002:adf:fd8d:: with SMTP id d13mr14728200wrr.208.1581503742530;
        Wed, 12 Feb 2020 02:35:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb4c:: with SMTP id u12ls10473393wrn.6.gmail; Wed, 12
 Feb 2020 02:35:42 -0800 (PST)
X-Received: by 2002:a5d:4bd0:: with SMTP id l16mr5936420wrt.271.1581503741995;
        Wed, 12 Feb 2020 02:35:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581503741; cv=none;
        d=google.com; s=arc-20160816;
        b=cTNUUqUaSgNASI8wpfC0fKPBtR7px0a4WDLOkqWbsN+67V1hUvGD1y1ozntK6zYDii
         ebVTsjMsxjCreaeUqzhRxEW37hGTyTbjjol8qhbwZ0P0Qal5NfYxTP1K0Qb7x1I2U3lD
         g7iKmmujvequH8zbWBOOsv1b4SA/Q2nD2J5Eho30bAfFCbBk72GtcjcliO6PQ7PFd3s5
         01gW4aqbu+p/GCukJqm2O0/PpUCZe5KAvNzZL1ZLcc7V17qwb0UMZdUnk+NYqcPbRnVP
         m20+fOLizDVH6D+zBeH8xg3VW95aGmou4TszvtJ/g83igXtEJIIuE0EW5RNWGEcedcwa
         M1QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=JvA0CG6jDvr0RSzi8Qrt1q4uSzBaTaD34CT+eJj09s4=;
        b=KqSesffRy+lgplMeEoDtwuTS39rubS1NjKnhjvlewmN9lnPhEA1r06Hs0j8LCcXzRl
         pXTThcYXwhRcX8kN5G2Rq5h8Q152m8ICxolFJRAbg/8T4LBb6dO9wRffDQr6htKmZPB8
         4kGgkZbwNcV94JxlV4zmCQndCik3vJ78Z7V+f4xxCexTrvcqHnhgyE3e8uPI7cmw91HV
         gzs/9DhunKK4TuM0AghZqIggthROrT0xSOCwfFGMfnHQEQrPPWdQEiXqD42VHHcJMJJ6
         tmteSZ60KRyxexeNi30vPG38VnjEx1CfNaxClxlFHmjOvG5d5hinSPi4BSwpmz1ddaBe
         OiHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="lstPK/Ib";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y185si204007wmg.0.2020.02.12.02.35.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Feb 2020 02:35:41 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 48HbdS2CM5z9tyYb;
	Wed, 12 Feb 2020 11:35:40 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id HsF2zY7jBGR0; Wed, 12 Feb 2020 11:35:40 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 48HbdS0h0Gz9v3Yf;
	Wed, 12 Feb 2020 11:35:40 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 417A58B80C;
	Wed, 12 Feb 2020 11:35:41 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id wbLwY91DPYyD; Wed, 12 Feb 2020 11:35:41 +0100 (CET)
Received: from [172.25.230.102] (po15451.idsi0.si.c-s.fr [172.25.230.102])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 13B278B806;
	Wed, 12 Feb 2020 11:35:41 +0100 (CET)
Subject: Re: [PATCH v6 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
References: <20200212054724.7708-1-dja@axtens.net>
 <20200212054724.7708-5-dja@axtens.net>
 <224745f3-db66-fe46-1459-d1d41867b4f3@c-s.fr>
 <87imkcru6b.fsf@dja-thinkpad.axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <5e392944-50ac-ed06-5896-2664894335d9@c-s.fr>
Date: Wed, 12 Feb 2020 11:35:40 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.2
MIME-Version: 1.0
In-Reply-To: <87imkcru6b.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b="lstPK/Ib";       spf=pass
 (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 12/02/2020 =C3=A0 11:12, Daniel Axtens a =C3=A9crit=C2=A0:
> Christophe Leroy <christophe.leroy@c-s.fr> writes:
>=20
>> Le 12/02/2020 =C3=A0 06:47, Daniel Axtens a =C3=A9crit=C2=A0:
>>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/as=
m/kasan.h
>>> index fbff9ff9032e..2911fdd3a6a0 100644
>>> --- a/arch/powerpc/include/asm/kasan.h
>>> +++ b/arch/powerpc/include/asm/kasan.h
>>> @@ -2,6 +2,8 @@
>>>    #ifndef __ASM_KASAN_H
>>>    #define __ASM_KASAN_H
>>>   =20
>>> +#include <asm/page.h>
>>> +
>>>    #ifdef CONFIG_KASAN
>>>    #define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
>>>    #define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
>>> @@ -14,29 +16,41 @@
>>>   =20
>>>    #ifndef __ASSEMBLY__
>>>   =20
>>> -#include <asm/page.h>
>>> -
>>>    #define KASAN_SHADOW_SCALE_SHIFT	3
>>>   =20
>>>    #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>>>    				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>>>   =20
>>> +#ifdef CONFIG_KASAN_SHADOW_OFFSET
>>>    #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>>> +#endif
>>>   =20
>>> +#ifdef CONFIG_PPC32
>>>    #define KASAN_SHADOW_END	0UL
>>>   =20
>>> -#define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)
>>> +#ifdef CONFIG_KASAN
>>> +void kasan_late_init(void);
>>> +#else
>>> +static inline void kasan_late_init(void) { }
>>> +#endif
>>> +
>>> +#endif
>>> +
>>> +#ifdef CONFIG_PPC_BOOK3S_64
>>> +#define KASAN_SHADOW_END	(KASAN_SHADOW_OFFSET + \
>>> +				 (RADIX_VMEMMAP_END >> KASAN_SHADOW_SCALE_SHIFT))
>>> +
>>> +static inline void kasan_late_init(void) { }
>>> +#endif
>>>   =20
>>>    #ifdef CONFIG_KASAN
>>>    void kasan_early_init(void);
>>>    void kasan_mmu_init(void);
>>>    void kasan_init(void);
>>> -void kasan_late_init(void);
>>>    #else
>>>    static inline void kasan_init(void) { }
>>>    static inline void kasan_mmu_init(void) { }
>>> -static inline void kasan_late_init(void) { }
>>>    #endif
>>
>> Why modify all this kasan_late_init() stuff ?
>>
>> This function is only called from kasan init_32.c, it is never called by
>> PPC64, so you should not need to modify anything at all.
>=20
> I got a compile error for a missing symbol. I'll repro it and attach it.
>=20

Oops, sorry. I looked too quickly. It is defined in kasan_init_32.c and=20
called from mm/mem.c

We don't have a performance issue here, since this is called only once=20
during startup. Could you define an empty kasan_late_init() in=20
init_book3s_64.c instead ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5e392944-50ac-ed06-5896-2664894335d9%40c-s.fr.
