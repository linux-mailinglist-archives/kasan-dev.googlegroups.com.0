Return-Path: <kasan-dev+bncBDLKPY4HVQKBBCPJV23QMGQEY6JHS4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 083F797C3D3
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 07:20:11 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-374cd315c68sf207134f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 22:20:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726723210; cv=pass;
        d=google.com; s=arc-20240605;
        b=gtLVpBMXgUdjuZguqyDu7KnaMSSUZbWWXEuA70+LMIsJdEcE5aGk3h2wE6e7TurytN
         hscfIRJVB7CEtVXm0GMGvbh9xODT6CsJVaJXvOgkpz5Tomj/XoslNmeawJjh636mSX9/
         9OPP14LBYRkVFUsyOfwjPnmZzFaL4nyoYcGzjV8xi+8L2fXR114DHBFkt2+x7bwPZFYq
         RgUuBIInsAtbJwJEs/g/Jght8K9m1HWvswn7CCipUOLaC/2BNgyDsCDKf7HDn/X1IGPA
         1Xv68Dl7maeCm+hNZX2CtDpwf5Q+zUaJUKLdc3S7P0cngBKExaTh3X21OhFkjsHXkWtj
         g2zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=LqFUhZ/IKjm2WwRWs/r9Bc7t4QaKyZ9A3SawPvu9rd4=;
        fh=a9+yP3OeXFX4Y01QptLiH2eksUMKpEdrUqtjkKd3fXQ=;
        b=Pa4ELDCOsP/ubkP/rN+oRdNNTT5h1jnBg+rMA17SitP0KEfVeNoDNYCBuCCrDslcGq
         9ZV3CKfaeNnKmpLXTSyRA9rBHBtXGNu97qeF7TBOcr6c5OQMGUW1av30VjvUImlOfdgu
         j25LBnLVHCe5GAqrE5IOGyOAPWZ9mM1mklqM8ELDLR27gA4cH1j66u5JU7EFYnRQ2El+
         4/iRWYsnDuEvMyczJHbDt5zxMFVRDPjq2gMyn2396nUG2gCtJYT/pDR4UD64oIjZMKfb
         18D1KqEg4gtQrrgH3/BV406IrSG2mXBSX2w5tfOC6MHAszm2Qc8TfoJh4cZGoCG/BKAf
         mgFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726723210; x=1727328010; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LqFUhZ/IKjm2WwRWs/r9Bc7t4QaKyZ9A3SawPvu9rd4=;
        b=nZkscuVy9oggoQXDnlKZKU6N+ZiMGUyt/R1DC/hJ0b4USE5FddoJSjibu625fAD18s
         nRie4XGOaYo3sE4JhpU/ifxgyFy+/XSgzT7zoFa9eyHm6XOgQSTkWm9KLe7vrtz7Iw95
         5+YoGrWBe7eqVR5e/x+HzBBB1FF+xDsv/eZJZFvaOlFmlABJjb8wA5ecMg/n6U2aTehX
         jmiN4Ik76CemvCpnkaGUe+lgg2aoR0ysRINhu4P80X28mlOC8LzlV83CrGK7UbbAhhgZ
         z5oCkNWNmjSMGL30Mv+VB3RvVN6diMbxcCKNFNUcqcAcbws2uPB1NAI4UIKlpuXTDSUg
         3uuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726723210; x=1727328010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LqFUhZ/IKjm2WwRWs/r9Bc7t4QaKyZ9A3SawPvu9rd4=;
        b=TxnxS71e5adTc2lS3KjB6EkdJJRqLmeNIHUFOr7yeFN1PrO2Uo5O7unmN2UMOSJO6w
         lsCwdVRfLAjuzThMrPS2KiI2GiD6q/iKJP+ZMIwcAKoyidkAnk1lsy6qE3QuQ/9CDOJJ
         ZOFh1zojT+cWyhzIVeagzDRcb66AsCW63bYIitzzimKtF4Oc7jCoJNCWxDPklE0bvBJJ
         uzrh69K+xfD1f9gxXqtz962Xa8lUtynXgPYqZYt66e/XN43dkxHfIRt9xtUbusqiqeVX
         g8L8I+r+56EWOHrRUxwjtDCibgJJWpv9EoBZ9fBuBJUjHvqxpGudfSMx7jYWsefYsh+Q
         Y2gg==
X-Forwarded-Encrypted: i=2; AJvYcCV8XYJIzSPmIBnRZsscJzURk0Epg6b9Ll6pPy4iAkC6NrOMsQp9RFgurGrjjsn/CaSA1x09PA==@lfdr.de
X-Gm-Message-State: AOJu0YzQxnc6EmoARCDKQ88IrQhX8a2XB7t00OkI72kM9k+DRK+HMnhn
	R4bylg/XspsRnNsSrnHQctFXj6Z/o5pkC5e0rFfxpkZSnOfiMvJa
X-Google-Smtp-Source: AGHT+IGlJOvcyxTZdYllrXzDs2kEIFYm1Mo6mdyCKGunZT8uKoj7+QQnIUQCBwwwe9+Db7bEC/5I/g==
X-Received: by 2002:a5d:6d84:0:b0:374:ba83:8d73 with SMTP id ffacd0b85a97d-378d61d5179mr14217853f8f.8.1726723209532;
        Wed, 18 Sep 2024 22:20:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9b:b0:42c:ad31:384a with SMTP id
 5b1f17b1804b1-42e74554df9ls2024295e9.0.-pod-prod-06-eu; Wed, 18 Sep 2024
 22:20:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7bs6rtBui3gMgLLFSHQ1ElhI9u+QBmwC9OYeJS8HjdhpJUOrVUwxGLyiDsufLgmRczq4HgfhU3lo=@googlegroups.com
X-Received: by 2002:a05:600c:1ca8:b0:425:80d5:b8b2 with SMTP id 5b1f17b1804b1-42d9082a676mr176580205e9.16.1726723207870;
        Wed, 18 Sep 2024 22:20:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726723207; cv=none;
        d=google.com; s=arc-20240605;
        b=lBXj5iAJwcDueFvYtAY5oMWqDjFf0oJjTkTHTaubleYpcwzWK9i8es4vfGp5O/mA31
         2iUJw21e+j0C/mFjqZK/nQMGZRNPHXPUrUwDkiOh/jpecE721KIqwiYI9IiyWLdneh0B
         +OwBFtJumv7wVbNtmY4udnprQaSrbac1X7HRxf5a4/ODS9ey/X+6V9qOCFlmUSEuoU8L
         6O+tGTugpkWzarYFWqd5dUgXEz6ltYAiWtrMnUCU2jxSEDL8QDxzGsiXrNP3YhJTM36j
         J/RkZOXcAjTJOYa7Tx3aiTjEwSmPIzh73OZCnrDzhyBkJkQqN/IEcUMYdLynGksN1mJK
         axwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=eeb7w/1v4Ofhr7/e1H9bOmNGtnsKRSsPsVLtf50K0i0=;
        fh=I083WXjQTmeQgsUgHJov5LiY/oUnz6B0e2LAlEZQ23Y=;
        b=BlJbtHH8etv8X7dQa7ncZAULPNBo45ltB4TTcs6siiysuzXnVlYaUDFOnDRPPimd3b
         YhhMFXpHjDCraa8Ah2iPq7o+KVOuytqHK+aFqmhfTZekiunj0Xe19V+yMsLPAksgJAJq
         rFBY9hR4WprDe7bUxXFzxzvvKPScDAOy6LYyN0oRXPmQIih1VVJKmEPeLx9xZCOGczw9
         n+Cp865eDU1N7jli8Oc2Szhgd6U5JjSxLYXsr/aIU1Ddl0g5GkWKSBnVfDbXg5vgaq8l
         GYjH6AfdDtITqRMG2QrAPLJf+sJcCD5alaff2QC7lppOGUkPMqmnsrrwb7Ydq48fhwdH
         pFQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e6c719640si3068785e9.1.2024.09.18.22.20.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 22:20:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4X8P3W2mtpz9tNv;
	Thu, 19 Sep 2024 07:20:07 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id AxoTRCMwyPDK; Thu, 19 Sep 2024 07:20:07 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4X8P3W1rdTz9tCB;
	Thu, 19 Sep 2024 07:20:07 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 2CD878B775;
	Thu, 19 Sep 2024 07:20:07 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id FP2B8C9gMap0; Thu, 19 Sep 2024 07:20:07 +0200 (CEST)
Received: from [192.168.234.38] (unknown [192.168.234.38])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 9794F8B763;
	Thu, 19 Sep 2024 07:20:06 +0200 (CEST)
Message-ID: <d9d8703a-df24-47e3-bd0d-2ff5a6eae184@csgroup.eu>
Date: Thu, 19 Sep 2024 07:20:04 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC v2 03/13] book3s64/hash: Remove kfence support temporarily
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
 linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin
 <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
 Hari Bathini <hbathini@linux.ibm.com>,
 "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
 Donet Tom <donettom@linux.vnet.ibm.com>,
 Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
 Nirjhar Roy <nirjhar@linux.ibm.com>, LKML <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com
References: <cover.1726571179.git.ritesh.list@gmail.com>
 <5f6809f3881d5929eedc33deac4847bf41a063b9.1726571179.git.ritesh.list@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <5f6809f3881d5929eedc33deac4847bf41a063b9.1726571179.git.ritesh.list@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 19/09/2024 =C3=A0 04:56, Ritesh Harjani (IBM) a =C3=A9crit=C2=A0:
> Kfence on book3s Hash on pseries is anyways broken. It fails to boot
> due to RMA size limitation. That is because, kfence with Hash uses
> debug_pagealloc infrastructure. debug_pagealloc allocates linear map
> for entire dram size instead of just kfence relevant objects.
> This means for 16TB of DRAM it will require (16TB >> PAGE_SHIFT)
> which is 256MB which is half of RMA region on P8.
> crash kernel reserves 256MB and we also need 2048 * 16KB * 3 for
> emergency stack and some more for paca allocations.
> That means there is not enough memory for reserving the full linear map
> in the RMA region, if the DRAM size is too big (>=3D16TB)
> (The issue is seen above 8TB with crash kernel 256 MB reservation).
>=20
> Now Kfence does not require linear memory map for entire DRAM.
> It only needs for kfence objects. So this patch temporarily removes the
> kfence functionality since debug_pagealloc code needs some refactoring.
> We will bring in kfence on Hash support in later patches.
>=20
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
> ---
>   arch/powerpc/include/asm/kfence.h     |  5 +++++
>   arch/powerpc/mm/book3s64/hash_utils.c | 16 +++++++++++-----
>   2 files changed, 16 insertions(+), 5 deletions(-)
>=20
> diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm=
/kfence.h
> index fab124ada1c7..f3a9476a71b3 100644
> --- a/arch/powerpc/include/asm/kfence.h
> +++ b/arch/powerpc/include/asm/kfence.h
> @@ -10,6 +10,7 @@
>  =20
>   #include <linux/mm.h>
>   #include <asm/pgtable.h>
> +#include <asm/mmu.h>
>  =20
>   #ifdef CONFIG_PPC64_ELF_ABI_V1
>   #define ARCH_FUNC_PREFIX "."
> @@ -25,6 +26,10 @@ static inline void disable_kfence(void)
>  =20
>   static inline bool arch_kfence_init_pool(void)
>   {
> +#ifdef CONFIG_PPC64
> +	if (!radix_enabled())

No need for a #ifdef here, you can just do:

	if (IS_ENABLED(CONFIG_PPC64) && !radix_enabled())
		return false;


> +		return false;
> +#endif
>   	return !kfence_disabled;

But why not just set kfence_disabled to true by calling disable_kfence()=20
from one of the powerpc init functions ?

>   }
>   #endif

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d9d8703a-df24-47e3-bd0d-2ff5a6eae184%40csgroup.eu.
