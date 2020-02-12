Return-Path: <kasan-dev+bncBDQ27FVWWUFRBHWZR7ZAKGQEW6TBCLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id B0FB115A8E9
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 13:16:32 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id h6sf1229408pju.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 04:16:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581509791; cv=pass;
        d=google.com; s=arc-20160816;
        b=P0WUspTUA7h9wl4oo5uz0oj+6N0OwskXD3TNQMBXrtqwhIYFN2YFbqvIQ6H2YMUna5
         N1hQPH9ulK7VQebos2TATx4GD60goBWpM4RrDc+2KVdvp2Qty4DC1S6h8Qvvq5s7vpXi
         rNLJfMcxlnO416LMTrUl1VMY1Uo28GGUvESOzX0d4ICg2cqmsBiWK4E9FNu2QAFx+9v9
         EcLstQDFB4cc9exFSliS+bpPtbE6BBRCyyKuGuQcapgtcrs0QiWgzIc2xVCvqeRwxGod
         BMwG6s4nbAIqftHTtvNUwH0DGUwFXBimK4K21wZYpXaZoQbd93QqVpKobVKU0Fvgi77f
         RJKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=TjEV5vfL6POliI0Q0Oz4wTqEa/ggCZ4IuRcN3OHvjVM=;
        b=Mjp7o1UdbeMi1Vl74MV3DPSlKbPiSgkh9B5fMZQ9EbmEF1CP7BnDqSrKeva5mKRfAK
         v0OCxnuqm9gtbChOkM942zR5K/NRV3bgYMNwHKsMfliZCwdaKdeycAYKnSv3EqnRYXH5
         THLT23JNN9tdxkEKhCFrgKaP16Kcwdfj7QrEmbKlgct0LcXmK+n4XsqrhSRx/eA/BY0Y
         eA/kJCQCS99oyAFdWRv/Z3RH9yeFSQLYaUwV9PIhpDkjJmwpj0D68W+/0Iulf0/rSukk
         PG7dejkXsPQ9lYk6YqP3CRy7Kl3+W4LV626BujRFKUG5Epd6OEqYcAICm8y5e4fN33Qa
         764A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XWCVr0we;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TjEV5vfL6POliI0Q0Oz4wTqEa/ggCZ4IuRcN3OHvjVM=;
        b=hvtYkuCewfWkL0Msh+0qZ+DyWzaoDrTP84291EWZpim6+AxeKc1C44whhi9/EVjVkn
         +Rpm5FRiy5KVWHrLnapL8rEp76zyHNdEgQCJ3U1bB97fjbGYcf2ffKz76PumZ+xlDqa/
         0uVNx/zWnbgrruxvvoIDhWd2//cAR+SaAEpCot2I0Ed0Ep/uTQaaCfytAeQa29HTUwy0
         c+J03Tta2R0fV4Y5R/+KB0R//aEJ97oir7hrXpT3Xh/KnqgoCqs98edu0FrnR5ORdk0l
         WYa1msYKf9s0GlO321hOHKIizYNZlvqVs+cDR3ZgQlg3fqhNXX7CbafCzXKmLn2dS1AU
         W6Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TjEV5vfL6POliI0Q0Oz4wTqEa/ggCZ4IuRcN3OHvjVM=;
        b=AEeKmnfWwS3U8SMQsGAfA5yCtKk9FlqiHMniNqYzUqsHxGaJEq/ELQ5xuDz6LERln6
         4J+THUb7KltNGFehsq3JRCAsAeJSLMqGNoHq50/gVKkV1nnBCb4y/Lmbrg6AQXPKBlXF
         76xVNlOb3+m0zlw8kCP1dzuy8zD4dxfZp0IUlrkDo2lqY2tVnZdRmOPuQPSPTF7P5B30
         juqt8MMOv4REaxXCfA+GWFbyQ1x2RSkx/1elfz8Qq/oXeXmCKHT4/oeWM1RfbAwpRqbd
         xIDnerwDtbiw4vsS5NtzMHe5BTpnUadsvCIYMxkTF0+EhJbg2Red2Sv8xneYxTKF/Lxz
         0Z3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVUthRffTJQ5gLJDAxYSHhFNskeqBOcsQM5FG7R0M65dhGhMM/k
	5AiEtf/nY0OaVtmmNyKy+Wk=
X-Google-Smtp-Source: APXvYqzQhiqJs/s2G0cuk5aF2/BuPEY5CwBkvFHM957K7eZE9JK28z8n3+7Dni3ISpNquTfwpJcETw==
X-Received: by 2002:a17:902:2e:: with SMTP id 43mr8231126pla.326.1581509790978;
        Wed, 12 Feb 2020 04:16:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2c97:: with SMTP id s145ls4989278pfs.4.gmail; Wed, 12
 Feb 2020 04:16:30 -0800 (PST)
X-Received: by 2002:a63:5826:: with SMTP id m38mr12470012pgb.191.1581509789821;
        Wed, 12 Feb 2020 04:16:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581509789; cv=none;
        d=google.com; s=arc-20160816;
        b=T0ocPpx6+SdJj1JH8FojeFuDYImpH4Qz5oFJE+lfokE1L6TBcxskoMQWuZMw36usYX
         UrdUiicqxIiydPNkdZB2ncFW44sm9jkpaoFDQV9wXxATtgRwmNEv1dXn0Hd6FIO6oSlu
         Ln5e7EWbE/XKVUMygUvffDIO7eKEye99ayB3DcrYZwTum0XMDc9rUZeW4iNJYKIAnlY3
         BpaeiGnr3hqhYcLHFK60c/nSA4nI1NycFplrJ8jzdyI/4030MiTnePyx9H9oJhsh2D2d
         JkfLYl0l16cIidFMdkhZUDyeHoVszWbNHq+3NgAfMWQT4TQrnxSXDyVFvT/zptPDFmbq
         vHJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=ORoK11ERH5m7YuJvIylQ/MWzmpJfOKr+pxcrwqBrMvQ=;
        b=0UsmE/iyVPmnl3QpMx4omBO3RhL68SzZ7fGy0C13K/Mm/Dui/lGMYxapyPohSCsfcT
         NVYHyKVHwpze7JGXHblQN4P+cmiwe9Ci+dXRJnR/U9ynaPckoFfm6PKi4D6qlJmv5MlX
         K7Q9p40XAhk0FfhBQc6aI/ad0RSbBX7xleP+tdlKcTNb0YKnHGfDbZz8NNJ7BwiqVXhQ
         09Dph4l+hJQmzfg4rMBmeVHyoaSdd0pwDREGblLmNzoVsSM5aSQnuAxSz1VBMkVspMGv
         w2n449ouSokQ9nUeN5FQKDV7DTXwvuOsyGs2R8uVd8aELkevt04irBy6O8NemCfb1fq+
         sMCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XWCVr0we;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id n20si3719pgl.1.2020.02.12.04.16.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 04:16:29 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id 12so820490pjb.5
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 04:16:29 -0800 (PST)
X-Received: by 2002:a17:902:34d:: with SMTP id 71mr7957844pld.140.1581509789395;
        Wed, 12 Feb 2020 04:16:29 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-65dc-9b98-63a7-c7a4.static.ipv6.internode.on.net. [2001:44b8:1113:6700:65dc:9b98:63a7:c7a4])
        by smtp.gmail.com with ESMTPSA id z27sm749357pfj.107.2020.02.12.04.16.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2020 04:16:25 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH v6 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <5e392944-50ac-ed06-5896-2664894335d9@c-s.fr>
References: <20200212054724.7708-1-dja@axtens.net> <20200212054724.7708-5-dja@axtens.net> <224745f3-db66-fe46-1459-d1d41867b4f3@c-s.fr> <87imkcru6b.fsf@dja-thinkpad.axtens.net> <5e392944-50ac-ed06-5896-2664894335d9@c-s.fr>
Date: Wed, 12 Feb 2020 23:16:21 +1100
Message-ID: <87ftfgrofe.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=XWCVr0we;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Christophe Leroy <christophe.leroy@c-s.fr> writes:

> Le 12/02/2020 =C3=A0 11:12, Daniel Axtens a =C3=A9crit=C2=A0:
>> Christophe Leroy <christophe.leroy@c-s.fr> writes:
>>=20
>>> Le 12/02/2020 =C3=A0 06:47, Daniel Axtens a =C3=A9crit=C2=A0:
>>>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/a=
sm/kasan.h
>>>> index fbff9ff9032e..2911fdd3a6a0 100644
>>>> --- a/arch/powerpc/include/asm/kasan.h
>>>> +++ b/arch/powerpc/include/asm/kasan.h
>>>> @@ -2,6 +2,8 @@
>>>>    #ifndef __ASM_KASAN_H
>>>>    #define __ASM_KASAN_H
>>>>   =20
>>>> +#include <asm/page.h>
>>>> +
>>>>    #ifdef CONFIG_KASAN
>>>>    #define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
>>>>    #define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
>>>> @@ -14,29 +16,41 @@
>>>>   =20
>>>>    #ifndef __ASSEMBLY__
>>>>   =20
>>>> -#include <asm/page.h>
>>>> -
>>>>    #define KASAN_SHADOW_SCALE_SHIFT	3
>>>>   =20
>>>>    #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>>>>    				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>>>>   =20
>>>> +#ifdef CONFIG_KASAN_SHADOW_OFFSET
>>>>    #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>>>> +#endif
>>>>   =20
>>>> +#ifdef CONFIG_PPC32
>>>>    #define KASAN_SHADOW_END	0UL
>>>>   =20
>>>> -#define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)
>>>> +#ifdef CONFIG_KASAN
>>>> +void kasan_late_init(void);
>>>> +#else
>>>> +static inline void kasan_late_init(void) { }
>>>> +#endif
>>>> +
>>>> +#endif
>>>> +
>>>> +#ifdef CONFIG_PPC_BOOK3S_64
>>>> +#define KASAN_SHADOW_END	(KASAN_SHADOW_OFFSET + \
>>>> +				 (RADIX_VMEMMAP_END >> KASAN_SHADOW_SCALE_SHIFT))
>>>> +
>>>> +static inline void kasan_late_init(void) { }
>>>> +#endif
>>>>   =20
>>>>    #ifdef CONFIG_KASAN
>>>>    void kasan_early_init(void);
>>>>    void kasan_mmu_init(void);
>>>>    void kasan_init(void);
>>>> -void kasan_late_init(void);
>>>>    #else
>>>>    static inline void kasan_init(void) { }
>>>>    static inline void kasan_mmu_init(void) { }
>>>> -static inline void kasan_late_init(void) { }
>>>>    #endif
>>>
>>> Why modify all this kasan_late_init() stuff ?
>>>
>>> This function is only called from kasan init_32.c, it is never called b=
y
>>> PPC64, so you should not need to modify anything at all.
>>=20
>> I got a compile error for a missing symbol. I'll repro it and attach it.
>>=20
>
> Oops, sorry. I looked too quickly. It is defined in kasan_init_32.c and=
=20
> called from mm/mem.c
>
> We don't have a performance issue here, since this is called only once=20
> during startup. Could you define an empty kasan_late_init() in=20
> init_book3s_64.c instead ?

Yeah, I can do that, will respin tomorrow.

Would you mind having a quick check of the documentation changes in
patches 2 and 4? I just want to confirm I've accurately captured the
state of ppc32 kasan work.

Thanks!
Daniel
>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87ftfgrofe.fsf%40dja-thinkpad.axtens.net.
