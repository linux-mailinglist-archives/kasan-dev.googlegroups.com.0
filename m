Return-Path: <kasan-dev+bncBDQ27FVWWUFRBAM7R7ZAKGQEJQRVGQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B38B15A5D8
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 11:12:18 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id 128sf462104vka.12
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 02:12:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581502337; cv=pass;
        d=google.com; s=arc-20160816;
        b=oHx2hvMVVR6wceUnxsV0OlegqeIX1msp5DemqX9a+s/2J0v41BEHxrR7x+RW/iiaeX
         W+HgPP7gG0UrDxO82w32TOMp66LPO7v8rwVCZde7P0JmWF+14v+lVB+0ffJiDqiZUmoZ
         6Z72NzPgEuS8T35vBTOKSM+gXgcMg0DCFCxBvd9c3BcGc1A7beTjlv9jRXzt+viXV9Ec
         l8BIgm5fKgJoybuRBhjqcDTxnayOjqZQL9rh+l2If2cJSjFD/soOVALaWbgpvQkq0zIp
         wbGviKgSuda4Pua9adsLRnRvh0CAQ2tAVXN0xYCHg7yQ9h7VN5VgP7onrALuspq6Atuu
         NJkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=ZYOkhd2ocmR6ovK7xezMkX37OYEZXOJqp0jA17zjgh8=;
        b=T9eZ9al0hLH4eoFM5RXd/06MdW8oMjody3abbFFgNBnH4+Wys84Ytq/enjiPFWAEG2
         LwLbQxE4wN4Sdm1i8kLnQOGeGjJUiMyqxe6TqcgRV+XrW8xGq+OrEqCYDlV/2yPkMU2Y
         TNtQsTIhA9R8JpgT1TktNJZ1p0048/DKbF6TrOnEd2EQvU5T/lYmenzVxij6+LSDPycE
         tw5BdSbvAibBN8LxlcfBSDNmqNQYwymprH+2Dbo5Iw+oowImeIet4XSeB/zQxRNCvCqs
         ud7DJijTyjJzVT3s/vFy0iGUaR/2lIAm5XssF5H2WiXtGIl3ROL6NmqwDAytt2b3yJmP
         FPUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=l9MckMLM;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZYOkhd2ocmR6ovK7xezMkX37OYEZXOJqp0jA17zjgh8=;
        b=eYTh2s8cv2VjMIv4jgnftPs2STyi8n1D19z8WhbcN2u10y7YlFCjs8mXAyYFvPfIJG
         +9NSBijNNvjdAZmnvJH/+UjFs3c6F0/hlZIlOAeU2GU3caHjn4/8/6htsl6TEKenCpUV
         e4zuqpDZFLlbwvKRRahm5tePmY7lm+kNobzV06RLTiclTZA5uxiSGWqH2PuE4TZqC4AG
         vg8DhjEWnF9TeqqoOgPHGnlK4agPEQ4JX8TkvsMcu0J+k29vp0bgmGWaO8abuCE8xEF0
         61/QjswN1QO9wqdzVA2XQ1JBuVpieu5tNHYiCx+JPIbP6k1UhGfPkCpS04J1udwAVgpL
         HppQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZYOkhd2ocmR6ovK7xezMkX37OYEZXOJqp0jA17zjgh8=;
        b=drUR4J2WwFdCEi35APCUeBDzz6xhRGS/Dx31XT+bosiNqXkOLRWnAPNKl5aXbSH9vk
         kV5ydV2VxlZQHs/QvBYg1mY4UUY8pZdFBeRjbyuNV1/CUTDiJO7TS0205eEJF1C79dm8
         qkimuRm24q3zeFpogi2WAQxG2clu/i4FLbqn/ab5Zv0coEUsi5SwO6cfWVRqskrbk5Fc
         3I5goQ1ItKhFMHq7oFtXWcZTJUOZcEZUpbJHq6AChRNJCerTzBssi3EfBzRwPj+Eok8e
         tRYrYO4NBIa8h1xkRU9OLKT08L1IssIk+RzWsBgsr0ON3MU98ktOUjIh9nbfDWuL3a//
         pO2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUcpHtouX6Z7V7eU1RYI8wQehSlNl9L2rVXnbolsRtP7qMw5V+w
	89azGhhHehirkAwr1t2DPug=
X-Google-Smtp-Source: APXvYqytXInRbA8qFOZzNgfs2klDqUIEQC1sADGWhe/vUD6M6Fb5gsD1tc0Rtl3vha8AbLcB/+FkKA==
X-Received: by 2002:a67:c204:: with SMTP id i4mr12567235vsj.118.1581502337099;
        Wed, 12 Feb 2020 02:12:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1f83:: with SMTP id f125ls727387vkf.3.gmail; Wed, 12 Feb
 2020 02:12:16 -0800 (PST)
X-Received: by 2002:a1f:acc6:: with SMTP id v189mr7378216vke.86.1581502336722;
        Wed, 12 Feb 2020 02:12:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581502336; cv=none;
        d=google.com; s=arc-20160816;
        b=DbjJAZsR+ynvDZOrdjfMWQ0L/0XnSCUMOiEAhX99baD2LSdkU7lsozqtOjxznZfdkQ
         YkQ7MXbnEUSY+62+sR8TQV7uQ7rGr4ceEJ8/LfX7NJRatg6WATolFmZPugnL9Bjsg1Zy
         Lxg74Fb+Jh2iYwSEEiS9rrLEmc/h7pjjFalX16PbHgsVMhvj09jZtNa+gvT0SVuOEOVo
         NmFpIpH2Lv2msMpx2cjxbjXADBenSmudQVoxPqlf0zoctTQQZrrVLONldJGnuS+ABqbh
         fwMn8PxEBH48Y1XAXyK5KY0UqUHCsG6yyFJv8lWA1J97N5hAErML2xfZoIQdEMC+nAWU
         O2ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=KF/rQa9b+YDdw75c1nDcpos7LuX+EOPNM62K9KllEpE=;
        b=TfoR4/IdSTdoaUMRC9j1sClbiWL2+yfwsyusRoh6FCtCQ7sR8BNPuEbsGDF2KPGANk
         I38ZVMobFeMvYX4oaPYoy/ALXw7Hz2xcn7s85wK2W7ij5cC1xt2Kpa2WIVzAyRT8RcSp
         AANxx3iiShJ9OQPujy24uVYmuck/SLd/kbCc0RImILGtyUlHQ8uFZEwDDfOcYtOUzFB8
         heuUPf6a4C0L6jrkSqT87ReXsFgL3bbA1I61P+RgEDffcKMINK5EDwHJwH/PvJuLof9c
         eMG0ZBjEjqgT7hjL0WxXlsyCtsASIomDxc6YSUclF0gSao2d9dlTFTr6XivjpXBc07fr
         wogw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=l9MckMLM;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id h7si381417vsm.1.2020.02.12.02.12.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 02:12:16 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id q8so1006418pfh.7
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 02:12:16 -0800 (PST)
X-Received: by 2002:a63:d44e:: with SMTP id i14mr7939813pgj.417.1581502336089;
        Wed, 12 Feb 2020 02:12:16 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-65dc-9b98-63a7-c7a4.static.ipv6.internode.on.net. [2001:44b8:1113:6700:65dc:9b98:63a7:c7a4])
        by smtp.gmail.com with ESMTPSA id e7sm190440pfj.114.2020.02.12.02.12.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2020 02:12:15 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH v6 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <224745f3-db66-fe46-1459-d1d41867b4f3@c-s.fr>
References: <20200212054724.7708-1-dja@axtens.net> <20200212054724.7708-5-dja@axtens.net> <224745f3-db66-fe46-1459-d1d41867b4f3@c-s.fr>
Date: Wed, 12 Feb 2020 21:12:12 +1100
Message-ID: <87imkcru6b.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=l9MckMLM;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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

> Le 12/02/2020 =C3=A0 06:47, Daniel Axtens a =C3=A9crit=C2=A0:
>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm=
/kasan.h
>> index fbff9ff9032e..2911fdd3a6a0 100644
>> --- a/arch/powerpc/include/asm/kasan.h
>> +++ b/arch/powerpc/include/asm/kasan.h
>> @@ -2,6 +2,8 @@
>>   #ifndef __ASM_KASAN_H
>>   #define __ASM_KASAN_H
>>  =20
>> +#include <asm/page.h>
>> +
>>   #ifdef CONFIG_KASAN
>>   #define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
>>   #define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
>> @@ -14,29 +16,41 @@
>>  =20
>>   #ifndef __ASSEMBLY__
>>  =20
>> -#include <asm/page.h>
>> -
>>   #define KASAN_SHADOW_SCALE_SHIFT	3
>>  =20
>>   #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>>   				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>>  =20
>> +#ifdef CONFIG_KASAN_SHADOW_OFFSET
>>   #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>> +#endif
>>  =20
>> +#ifdef CONFIG_PPC32
>>   #define KASAN_SHADOW_END	0UL
>>  =20
>> -#define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)
>> +#ifdef CONFIG_KASAN
>> +void kasan_late_init(void);
>> +#else
>> +static inline void kasan_late_init(void) { }
>> +#endif
>> +
>> +#endif
>> +
>> +#ifdef CONFIG_PPC_BOOK3S_64
>> +#define KASAN_SHADOW_END	(KASAN_SHADOW_OFFSET + \
>> +				 (RADIX_VMEMMAP_END >> KASAN_SHADOW_SCALE_SHIFT))
>> +
>> +static inline void kasan_late_init(void) { }
>> +#endif
>>  =20
>>   #ifdef CONFIG_KASAN
>>   void kasan_early_init(void);
>>   void kasan_mmu_init(void);
>>   void kasan_init(void);
>> -void kasan_late_init(void);
>>   #else
>>   static inline void kasan_init(void) { }
>>   static inline void kasan_mmu_init(void) { }
>> -static inline void kasan_late_init(void) { }
>>   #endif
>
> Why modify all this kasan_late_init() stuff ?
>
> This function is only called from kasan init_32.c, it is never called by=
=20
> PPC64, so you should not need to modify anything at all.

I got a compile error for a missing symbol. I'll repro it and attach it.

Regards,
Daniel

>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87imkcru6b.fsf%40dja-thinkpad.axtens.net.
