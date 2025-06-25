Return-Path: <kasan-dev+bncBDLKPY4HVQKBBYVA57BAMGQEAOP5PUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 5535FAE7F62
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 12:33:12 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-32b316235a2sf26903421fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 03:33:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750847587; cv=pass;
        d=google.com; s=arc-20240605;
        b=i+lN7GeKRn+CjmY52nNFy81VudhGZORm7LjIFMpsdffMzz3yWEgXQUk99thhVcmiYh
         aNV7a6fNbbFlc/s0BM0J48BmzRAtX95QOYVaw05SWBNoasurQXM99uzMTGeYg09q+6ZF
         usbOg/Q3jX9gNz5ZIwdniS9ADxcBwRqMVk0SsqsDbhxOnbsDNuDkMlBtkLqz+pDHY1Hh
         flirvWGZGRy72Pt73YPcJkIXBw2ympIeDi5h3Ob4ZzdvTh3WaAUJS2fnsyddfxnbDNgN
         7P6gh5RVaB7ne9MKJmByKHc79LuTcvZ/sIJKlTtEp+6dK9He/gGr7CN8jUKDCGAbC+fD
         WZbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Pfg3lqoAYTCISWfebtzuCo7YAES4ZUVE45SiPSkFq4w=;
        fh=d5yN0z/h8hnG7CrQFE6jP00XvW+yFt4zt34M80mk7H0=;
        b=Ww/EKkCUIJnMFeWJKXFI+YX3JqBXpPK/yGJGrAuQwm2ZGTGMSZq1bCurUHxEwKWKGj
         4+BOg5eyXKogQTSZJyYu9gkmz0QEm1EKMoTgrWAZewz1YBGcSpbSPsU9YE3Ko3FLaUpd
         7Y1re/EMJ3uZzlgU/WjE0G2yLPWtjT5QLCnIkzlVizvcH+3vAK8BIIQieJFgqzq9M1ge
         E1ansopCht48YrTUuS+W8KLZvcjsjYJuwQnPA6/bFhVAEpzRP/+coYUVOKLM0hk52KAm
         cEKYB7iFVMOJF7L6VPCDRoKH2COjbuUl4w/8PXLfOJkiTiZRElaBK7wCHMbqZMA2354U
         6Cqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750847587; x=1751452387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Pfg3lqoAYTCISWfebtzuCo7YAES4ZUVE45SiPSkFq4w=;
        b=m7WQfraWEe3RuX1Yxz9fNfULjTi7Z+7vlzVx9vkxAJ2umb6egyvmjCaif/OHMQRUGU
         GLhrQ8rukW6IUYslNI7Qf7sZ18lVl9Oiz40nVwnsbMDwlYFN4mfX+zz/bZFWwzI+Vn9n
         u2ZvlQby0X8tYd7wA6NuQQXi+qni0eLsxK4QuIG4iQHoykc7Imvt6qk3ZkPvIb2JaUne
         7CKZhJ2jQ9nNHnJrR+XLGRtWT9QqLhPvg6Kp98PhHTPSfNDMaN8/G73krLzQJMWsGOS4
         NYycNNKJRUsqGJy3gx4C9JnxcJ87qUFzdvkS5DbnlHLelaL3GhAMGL6z8C+5NHqCh6hz
         i1OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750847587; x=1751452387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pfg3lqoAYTCISWfebtzuCo7YAES4ZUVE45SiPSkFq4w=;
        b=GnPhxvFJOB+ZJHyRVdHsdzee6nLiTo7doOT3+q+aDwrqy7GA5IrjIFrXIfAShD8h1S
         QpcC8WUhnTF177+TRsRJmC+hiZ4U9I/q1B1vJJW4LZp6tjTpoGGdST70PMIshq9+4MTv
         gqmMkSTQsfg6EIzeIapDHC3i8VR3Elt0dFOGn3FeK2SEm7D4IwZ8+lQ0lQYfmU16vIAC
         Td3oGN+HKWReTl3SUiA3xfda0PVEOGdwtlzYBp7gk7KbUXckObVCvUge9LviZAkWh+ZF
         xO2KqOcOMyNlkW1lyVi+qmHAlKmbcXPpH5bIzcR0BiXuWg+PsMH4Dec7ISRccDlIROMI
         J60w==
X-Forwarded-Encrypted: i=2; AJvYcCXRjWDLi+l7gcJq9euzCPfN0aNuU5H1uOZl44cln09HQ7IBXGBoHKg3nDPSjQTmwm2ah0VGsw==@lfdr.de
X-Gm-Message-State: AOJu0Yx7NapphvxjH5vSh8t5US7nzwCQ/QmmaYO7wyU4wUQ6jR21Vg/W
	h4PIAPTLrLYYfPEqyCf0rw+ntTgDsHFlrlEFQ6VVXmzKgW5WOKNIL8m8
X-Google-Smtp-Source: AGHT+IFZnAPcDqRzbqwyBnagec4IxwPdVWhJNR5dK80/ifau2oCz08HpUVyIGYxcRR69DmXpDmfpzA==
X-Received: by 2002:a2e:bc1a:0:b0:32a:66e6:9ff9 with SMTP id 38308e7fff4ca-32cc65904a1mr8807061fa.26.1750847587224;
        Wed, 25 Jun 2025 03:33:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfRX46d1oGYYdb+pfFRJB9WLt1c9nm/ytyTIF0Vd6PuyA==
Received: by 2002:a2e:aa0d:0:b0:32a:8058:e2e7 with SMTP id 38308e7fff4ca-32b8970e87els12822541fa.1.-pod-prod-05-eu;
 Wed, 25 Jun 2025 03:33:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnvRQ3vF5g6j6MiPJWwyGii5PoW1+tbciSqOrkvR2a2krSzYAufuJk25yBwEg7y0OheMKE6yVzqY4=@googlegroups.com
X-Received: by 2002:a2e:b754:0:b0:32b:47be:e1a5 with SMTP id 38308e7fff4ca-32cc65c1285mr4235131fa.39.1750847584446;
        Wed, 25 Jun 2025 03:33:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750847584; cv=none;
        d=google.com; s=arc-20240605;
        b=a5DYBC7bUBPXfiTU2IzUW5tYGadg1sTXorcsdT4gMDyaRPuoE9rG8hA0/Dm57ZCxYC
         WyQNU1bXzfvyTUU2/NprHPVTxT1Zi7ujZ4Qx+qSo0UQZDg6y+aaSKhupCUZyCVa/oVO7
         gvjqIrSpRpaIcDptjPWAanMam73XFeUGPvjPl0urPUZa9Rwcf8PxA4fmU5BGiAZaNTDS
         I4xf1bWfRK0SeCRSTvIpHaT2oH51noQ9/H3KcJj8IVznMowcILEe7DkidJigwjdFsBpI
         JQnh9eMwMAT0YbRhhbeXn350Cc6w1GFjV3RlllfnnguX3CGO91fZXMgxeGhC9WgRz/q9
         1gTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=aekhGqf6P/O199m3eOaLFTaZxD8oT2lv9cl8d0b7XDc=;
        fh=SFdHZR8zxg6TEbE6MgAXQj1yZoKJ36rM9pB/hubh7sU=;
        b=aC30NTQCJpnjFwuTyBfetEeySIVVMUVvMwgPPmn9Pwv42JK0NZXHAIdg17m61Nb9vX
         ZMlLo5NgAATTaPz/Abo4JMKKfeOyV32YrJEPf3As7mml8oUM6tgmtHT/l+BSmvAfN32O
         UWs6TZax3AyYI/p2KOKhmbc0ijOi4qXde1sD/WwzVY3+LySinFRyugGXDP7Uyfzd10fL
         26ZqP3bAwcYShJ0IfxqUSynpNrH4ttGz4tuUX23rj/B8MIHusJ2iSaN25NkGmk6gLTm0
         GSR8hCHvWSfoaHsjJYr6wOIxUkmpvRbPoMQXYmYFBbn18FdBpJnq5MLG+1mW/H7un7Al
         seKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b97dd0a25si2887361fa.0.2025.06.25.03.33.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 03:33:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4bRynq72Rpz9vCc;
	Wed, 25 Jun 2025 12:33:03 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id Wkd8VwLop-3S; Wed, 25 Jun 2025 12:33:03 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4bRynq5zBhz9vDF;
	Wed, 25 Jun 2025 12:33:03 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C1DE58B7B7;
	Wed, 25 Jun 2025 12:33:03 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 3S-OpwLkq4z3; Wed, 25 Jun 2025 12:33:03 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id EAC428B7A7;
	Wed, 25 Jun 2025 12:33:01 +0200 (CEST)
Message-ID: <4d568111-9615-4fba-884a-f2ae629776fe@csgroup.eu>
Date: Wed, 25 Jun 2025 12:33:01 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 9/9] kasan/powerpc: call kasan_init_generic in kasan_init
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, catalin.marinas@arm.com, will@kernel.org,
 chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
 mpe@ellerman.id.au, npiggin@gmail.com, hca@linux.ibm.com, gor@linux.ibm.com,
 agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com,
 richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
 dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
 hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
 akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org,
 tiwei.btw@antgroup.com, richard.weiyang@gmail.com, benjamin.berg@intel.com,
 kevin.brodsky@arm.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250625095224.118679-1-snovitoll@gmail.com>
 <20250625095224.118679-10-snovitoll@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250625095224.118679-10-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
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



Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> Call kasan_init_generic() which enables the static flag
> to mark generic KASAN initialized, otherwise it's an inline stub.
> Also prints the banner from the single place.

What about:

arch/powerpc/mm/kasan/init_32.c:void __init kasan_init(void)
arch/powerpc/mm/kasan/init_book3e_64.c:void __init kasan_init(void)

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
d568111-9615-4fba-884a-f2ae629776fe%40csgroup.eu.
