Return-Path: <kasan-dev+bncBDLKPY4HVQKBBK4OWKFAMGQEMFP3F4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 288E741604D
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 15:54:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id r193-20020a19c1ca000000b003fc8f43caa6sf6134692lff.17
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 06:54:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632405291; cv=pass;
        d=google.com; s=arc-20160816;
        b=epwh+dPtCyJgc8rpQKOvDhiyL75Y5wBBZ7Yg/WI0MfvBzH7n/Q5Xmd6hW2jhHMga+x
         FeRXd0c6TuK5HPRvFgtR0u0I+a5aILgOA4dhwr8CRivj4gG6I2sP2NIcYLzsSubcpbLK
         n/F3FkmVDXfTJDA5pxMw/KCek5kZjLds/IVM1hjzER6tMoBUqBJ+bSk/VE3x5WX9nb2i
         BtgJFjreb7ZSBBt9cDhyivI84ToB++2OIus9PgYCjCla10KYQ35D5mGuqc81DLzmI3To
         bD8xoz5f1cXlWaobpbRZo9fV83iTZM0G35+TU6ejezePdYIb7KaJSlLvMIffXA3GolxU
         BAMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=xiduNyQm0Wgk7rMLTTaGa5duoDFWU1W2djUryxGLrHg=;
        b=e6TXJrjAN5Y8hHlyZiulEw8HLuIk9AsCtWMD+jbvS9ur15eTxs/7LnF563kRlylJKb
         zm8gb3tJf0Dr4irJ+MJDs5LGyxx050wqoP5obpzFnNSyVV1C+OGWLX4BOA7A8uZEqv7H
         ioxQYDI9TmxaokE/jWcifQ5okyI4W83TDq3CHffrej1vHdWZy7RLt6kOza3RuytT0aDA
         fVTkNZ1Qv+U7IEDbZYnxv9Tjntz4aooUjr0Pa/C35Q0n68l6CSzZy0DgGUHKKl3WdeOW
         XRqHKWYqkXs7w6H5ushFd5pdDVaDLPTOfFqDbOJUKjQdwQWaqHZdgX8dWZZpuGSzGpRc
         oBgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xiduNyQm0Wgk7rMLTTaGa5duoDFWU1W2djUryxGLrHg=;
        b=qeQ/yl/a0GjOaaMeAa0OCQSeXChvHp1etdehEtdlqwBGYG17UOoD7vsQEtFxRUI8Uu
         WLHyIaCwO5acP1Y8+jIAd6XXCspZdWeKQQppslHp+lxvE5Pd1S1+ZoujA4E0sVqca9Fu
         DtJM4DuMhzeRGgCRhVNo5DtGlbW4oLZWs+/ZjWQpll4RgDyyLX+oWqCfWqr2uot5lRpN
         URoMFk78xUcqJuewr2xvA7oTFRRWzOzkM9beb0ZXRiNUTxd3pKFGfOQ2WHFv1fqGEc7t
         tyPtYAe/Pu/1g2EQzLbcYSXlXSRTdffOCkCK/5/YV5k4p0QVkMMLBPJHQxFIK03DesUg
         vA2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xiduNyQm0Wgk7rMLTTaGa5duoDFWU1W2djUryxGLrHg=;
        b=UCSktT66x1Lk2coD0fCAmTGGHmTCnT53Eoyfqj8txPih5mNMkP84voX/QYcRxb91IW
         cOoSP/Xt5rvIFuItsDWtkpH8tUYGXtWy8n3ZqcJyacNg3HPYl8Y4nm5nte9xAMmIpDQo
         7nhxE9fT1sy5VAychqekgHYQ1597xSf6D2WTct6ALrVz/99270UTwJn1nNpECQflV8kD
         JdrBPrFqvpmT42ghOwdigbqyLgamPFZ5sBBgOpqtpsVRNf/u5p4YrfQ9WEpMWDSMW5X7
         maaZ68ffP2wFjDfyzyil9RyRIU782uiFD08V5YNqPCMGWpQYPtcECVzzbVddEXX0dq+l
         coEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531n1LMBtF/IjOkvdPD4KV5BaXDCj7Hx1Dl0thvYqOOr8PT77cif
	6w5L6C0oBFdTp13DdVwrigs=
X-Google-Smtp-Source: ABdhPJxTnwQtPXGv7NKSp/Xoh9ygEx+q67HO3i9rMBNzboNrJ1qMBBlIcS7R3m8/zJ7nT63hlB0Uvw==
X-Received: by 2002:a05:6512:22d5:: with SMTP id g21mr4153328lfu.544.1632405291720;
        Thu, 23 Sep 2021 06:54:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a48d:: with SMTP id h13ls1201148lji.8.gmail; Thu, 23 Sep
 2021 06:54:50 -0700 (PDT)
X-Received: by 2002:a2e:a49c:: with SMTP id h28mr4323726lji.387.1632405290704;
        Thu, 23 Sep 2021 06:54:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632405290; cv=none;
        d=google.com; s=arc-20160816;
        b=uLnOAShUb5J6E9EP6HQ8he8zxUmktBsyGh6Us1brYLP9uN9D6E914tVu1IYgDd6Q4S
         +s80Czt+AgpgwDeITwl9PvLCmOtKfLZLh55UDhphI2kSIqL3NuoaQFNYbZkEA0R/g+OU
         d0PuJaqcG9B9rgmYa3cXZgUDE/KnADrD1Qajc7GDXWcijtro3kjhXQTTkUE/m4/b9Y6t
         XVmVUaYEZfA8ZtAdKPseaJgs3NUSGPZXcuf17+MKFKpjWC4/db04x9IleIuIFchr+JIa
         MQLVigZPMHiC4RAqhWDn2H0/wOfcrTvnIhmcNM1wZsJ6vmHKl4dRgTjwnthUe+5arHQe
         7PfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ZXQkC7V2JNT5Om5z5+jdDIZMFI/bmMUtbhTlFb1DBj8=;
        b=z+nkZxt5iqFkh73D70Lu9KoNRlZnvszclZSpD/ySVTRuA68Eb4gNT9GbQhBX5+zBjc
         Fb9rydw+vcJomcdSH9q1xfTIOhKixXTaynH17wh1zWtiYQqT/gBXfF+RlN3u9gy9w9MB
         Q6YT+FkHAvMTVCX90ZlvtQWJEJtfqzGO3ydkSZarUpUZ8QqBX6J2hD0dLhy66N/Wrij1
         b5GKJSZVBi8+tOBCpOqfQtp/Wzvf9nkGQl2LslACwMxD5zV2EFetKDd2mLpOvpe49RNW
         ahEef83QgrmTDSsisAIj3ZJKBV1GmGsBYqkVLePDFlUdomDWOcMJ73HNfMytS8Ju63Cz
         MVKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id i22si233241lfj.13.2021.09.23.06.54.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 06:54:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4HFc9P5sHPz9sV7;
	Thu, 23 Sep 2021 15:54:49 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id xdm1Ouzf8XXu; Thu, 23 Sep 2021 15:54:49 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4HFc9P4lm1z9sV4;
	Thu, 23 Sep 2021 15:54:49 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 8BA938B776;
	Thu, 23 Sep 2021 15:54:49 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id i24VgXHaAF2s; Thu, 23 Sep 2021 15:54:49 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (unknown [192.168.202.200])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id ACF658B763;
	Thu, 23 Sep 2021 15:54:47 +0200 (CEST)
Subject: Re: [PATCH 3/3] memblock: cleanup memblock_free interface
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: Mike Rapoport <rppt@kernel.org>,
 Linus Torvalds <torvalds@linux-foundation.org>, devicetree@vger.kernel.org,
 linux-efi@vger.kernel.org, kvm@vger.kernel.org, linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org, linux-um@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mips@vger.kernel.org, linux-mm@kvack.org,
 iommu@lists.linux-foundation.org, linux-usb@vger.kernel.org,
 linux-alpha@vger.kernel.org, sparclinux@vger.kernel.org,
 xen-devel@lists.xenproject.org, Andrew Morton <akpm@linux-foundation.org>,
 linux-snps-arc@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-arm-kernel@lists.infradead.org
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-4-rppt@kernel.org>
 <1101e3c7-fcb7-a632-8e22-47f4a01ea02e@csgroup.eu>
 <YUxsgN/uolhn1Ok+@linux.ibm.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <96e3da9f-70ff-e5c0-ef2e-cf0b636e5695@csgroup.eu>
Date: Thu, 23 Sep 2021 15:54:46 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <YUxsgN/uolhn1Ok+@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr-FR
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



Le 23/09/2021 =C3=A0 14:01, Mike Rapoport a =C3=A9crit=C2=A0:
> On Thu, Sep 23, 2021 at 11:47:48AM +0200, Christophe Leroy wrote:
>>
>>
>> Le 23/09/2021 =C3=A0 09:43, Mike Rapoport a =C3=A9crit=C2=A0:
>>> From: Mike Rapoport <rppt@linux.ibm.com>
>>>
>>> For ages memblock_free() interface dealt with physical addresses even
>>> despite the existence of memblock_alloc_xx() functions that return a
>>> virtual pointer.
>>>
>>> Introduce memblock_phys_free() for freeing physical ranges and repurpos=
e
>>> memblock_free() to free virtual pointers to make the following pairing
>>> abundantly clear:
>>>
>>> 	int memblock_phys_free(phys_addr_t base, phys_addr_t size);
>>> 	phys_addr_t memblock_phys_alloc(phys_addr_t base, phys_addr_t size);
>>>
>>> 	void *memblock_alloc(phys_addr_t size, phys_addr_t align);
>>> 	void memblock_free(void *ptr, size_t size);
>>>
>>> Replace intermediate memblock_free_ptr() with memblock_free() and drop
>>> unnecessary aliases memblock_free_early() and memblock_free_early_nid()=
.
>>>
>>> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
>>> Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
>>> ---
>>
>>> diff --git a/arch/s390/kernel/smp.c b/arch/s390/kernel/smp.c
>>> index 1a04e5bdf655..37826d8c4f74 100644
>>> --- a/arch/s390/kernel/smp.c
>>> +++ b/arch/s390/kernel/smp.c
>>> @@ -723,7 +723,7 @@ void __init smp_save_dump_cpus(void)
>>>    			/* Get the CPU registers */
>>>    			smp_save_cpu_regs(sa, addr, is_boot_cpu, page);
>>>    	}
>>> -	memblock_free(page, PAGE_SIZE);
>>> +	memblock_phys_free(page, PAGE_SIZE);
>>>    	diag_amode31_ops.diag308_reset();
>>>    	pcpu_set_smt(0);
>>>    }
>>> @@ -880,7 +880,7 @@ void __init smp_detect_cpus(void)
>>>    	/* Add CPUs present at boot */
>>>    	__smp_rescan_cpus(info, true);
>>> -	memblock_free_early((unsigned long)info, sizeof(*info));
>>> +	memblock_free(info, sizeof(*info));
>>>    }
>>>    /*
>>
>> I'm a bit lost. IIUC memblock_free_early() and memblock_free() where
>> identical.
>=20
> Yes, they were, but all calls to memblock_free_early() were using
> __pa(vaddr) because they had a virtual address at hand.

I'm still not following. In the above memblock_free_early() was taking=20
(unsigned long)info . Was it a bug ? It looks odd to hide bug fixes in=20
such a big patch, should that bug fix go in patch 2 ?

>=20
>> In the first hunk memblock_free() gets replaced by memblock_phys_free()
>> In the second hunk memblock_free_early() gets replaced by memblock_free(=
)
>=20
> In the first hunk the memory is allocated with memblock_phys_alloc() and =
we
> have a physical range to free. In the second hunk the memory is allocated
> with memblock_alloc() and we are freeing a virtual pointer.
>  =20
>> I think it would be easier to follow if you could split it in several
>> patches:
>=20
> It was an explicit request from Linus to make it a single commit:
>=20
>    but the actual commit can and should be just a single commit that just
>    fixes 'memblock_free()' to have sane interfaces.
>=20
> I don't feel strongly about splitting it (except my laziness really
> objects), but I don't think doing the conversion in several steps worth t=
he
> churn.

The commit is quite big (55 files changed, approx 100 lines modified).

If done in the right order the change should be minimal.

It is rather not-easy to follow and review when a function that was=20
existing (namely memblock_free() ) disappears and re-appears in the same=20
commit but to do something different.

You do:
- memblock_free() =3D=3D> memblock_phys_free()
- memblock_free_ptr() =3D=3D> memblock_free()

At least you could split in two patches, the advantage would be that=20
between first and second patch memblock() doesn't exist anymore so you=20
can check you really don't have anymore user.

>=20
>> - First patch: Create memblock_phys_free() and change all relevant
>> memblock_free() to memblock_phys_free() - Or change memblock_free() to
>> memblock_phys_free() and make memblock_free() an alias of it.
>> - Second patch: Make memblock_free_ptr() become memblock_free() and chan=
ge
>> all remaining callers to the new semantics (IIUC memblock_free(__pa(ptr)=
)
>> becomes memblock_free(ptr) and make memblock_free_ptr() an alias of
>> memblock_free()
>> - Fourth patch: Replace and drop memblock_free_ptr()
>> - Fifth patch: Drop memblock_free_early() and memblock_free_early_nid() =
(All
>> users should have been upgraded to memblock_free_phys() in patch 1 or
>> memblock_free() in patch 2)
>>
>> Christophe
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/96e3da9f-70ff-e5c0-ef2e-cf0b636e5695%40csgroup.eu.
