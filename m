Return-Path: <kasan-dev+bncBDLKPY4HVQKBB4WAZ63QMGQE4WCB6XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 36B4A9856E0
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 12:05:40 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5365a82e3dfsf4354049e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 03:05:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727258739; cv=pass;
        d=google.com; s=arc-20240605;
        b=asHw8/+y3vOc3jCvIuyMcRE+SShAf/jCexmr8/YsERYpPifa1hfbeZVPNJTuBzB5T4
         GzFKycaFsrUpHCmHDe9i3HbKZCq2t2X0m7ZRCkLH7V2nz62Vc89VefvJvTNDQHXyI/bk
         qZdsWSEuIrwVTTTKHKgME3V9CpcDYefC4q3ZYidPh9E9oyGVXgV1gNTg4Vv+5v0quOO1
         UIKx8psK6W5YRBbXb9lDbKRdX1FqhGp6RIzGe2qgwUexoP05cIAEqDBKGR3GiM/NcDdH
         iLCkq21yGxwVC7U3vcplUna22xV7FIbFwDScNQcIKo1W6QyNTlRK5zySqApY3DC2dhLl
         d6oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=6Hwfy+WjAgfYQCdtzWzWUFcNdyhwCq9Ij/t9Y9AC6mo=;
        fh=0AQvAw4d8wX7/6t7q2pzMY8KRbogH113ywpPeIypuu8=;
        b=JsTEJobQ24fooUkl4iEWq3gnMyPQ+7ZVLEduVccztpdeEq3pHlfzdylQBb0sv52Y70
         6+r8Wk2GIOvKYhU6TQlmfTSWzcr4/7L4QiH97CyIWovmOA/npZN6ULeIFJ898rrhfO/U
         TvmLzXzNIVngjHZGsPnfNnA3NYg2gAwm01blU2TZWLB/Mix8ZyWgYGKR36co1pBEVqpG
         lco5M/F7MzbXWmr3YDy5lMabxzaFBU7qlfWMa3e7NidVTH2b79zVszhMYkSNb9szpdIO
         iavqFrkA0iolS+6q3SbNrrQPCg6EaujDIRTydUj2m38+AYhFnDakTeVSXz5xYIlnXoNn
         hGeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727258739; x=1727863539; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6Hwfy+WjAgfYQCdtzWzWUFcNdyhwCq9Ij/t9Y9AC6mo=;
        b=Zr037xKo0jVMQQ5Q3zMsapwwYNSOcuHuHJS7JK5YQagPWRWZHg4popbNoFnpnxLWKR
         6E7IzEqOULi0fxu+U5mFchk1mlvIwyEQ1DUpcKNiUDAnj4QO+I0CVBBbMLe+bxm0B3fs
         ///g/Ip3mcruHG3y1V9cGmd8ht6v2wOMg2wkttkjxyZy+v/awIYikds2lc6p1L6yavD5
         Pd8Wlz4SqUweHJoOluAgU4Ds12SLJvy/d9Hxw/eW9vUl3+aZD2x4WGghh49ID7DI8hRe
         YCAKlZg09Uiq9dRx5Tz7J5ErWts5v5W5e9zQ/KLLf3SGrECkAyd6HIksNn66JlL3fXBL
         1Cdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727258739; x=1727863539;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6Hwfy+WjAgfYQCdtzWzWUFcNdyhwCq9Ij/t9Y9AC6mo=;
        b=b8YIx+q4eRZbtRCTCst1iT45dSpTpQuE9KGqRq7T2/81cKBkAD0D0T6d/2wENjMw0z
         2uVUCCDyA9djDz8njt26gNhIM3CMNTW+shi4yk/Ibf4chpdRTigXz5Bcc2dTF/ts9QtH
         cidPkHN8PLCmPvjt6ptq+n+TTyY0bH5dYS4St+KzdlXAX+yG5/BAaVN0o9DxsaGgGIco
         sobcZ2Ewa0CQhntaWVyok8qmZxa2Jt+EqyYrpfFfHFJg8r46kqOqpYoV7jYjujBLI2oC
         t5OSGyfqln19wAlZguo6Sft51C7WrV/dsE+2C1bJHMDgO6aM7Y+AC5+WRZAcHdtlZLKY
         0GtQ==
X-Forwarded-Encrypted: i=2; AJvYcCX+EPRepTbchzTW1/S4dp7oL3xh/Nau+TEzJzBeDBI+qz084v9rox2BGe4vEvm5euTQ4PghGg==@lfdr.de
X-Gm-Message-State: AOJu0Yx+K0Qa6GMOQcVZiGudJ5aHqfHqjLybE6AGGt1byrBEkEnw8bYl
	YQf3ZKgxxbF7a5UojPVLfWLEtDLjF2VfUOAWF9Km5tAGX12J1+8i
X-Google-Smtp-Source: AGHT+IGgvtxj0gxt4K/RmNg0WBbFBmFTT4vztyQD1IiMtba9VRvxlHZZUoRJp2b4ftbnZjVi6FSYZw==
X-Received: by 2002:a05:6512:104f:b0:52f:ca2b:1d33 with SMTP id 2adb3069b0e04-53870498612mr965650e87.20.1727258738561;
        Wed, 25 Sep 2024 03:05:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2524:b0:537:aba1:16dd with SMTP id
 2adb3069b0e04-537aba11932ls528033e87.0.-pod-prod-01-eu; Wed, 25 Sep 2024
 03:05:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqTy0u53q0o77cGzoqUSDot/SkKMIHS+A0PJ1maYi7EULY4pYEsYPZ00tKn2KS9FuXXE6vOC1zk2w=@googlegroups.com
X-Received: by 2002:a05:6512:238b:b0:535:69ee:9717 with SMTP id 2adb3069b0e04-5387048bc5bmr1133917e87.3.1727258736539;
        Wed, 25 Sep 2024 03:05:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727258736; cv=none;
        d=google.com; s=arc-20240605;
        b=FzXLnofLyHJxqzPmMhL/gvulXqotG4KUUWH1WrjsRpzrfS20rZtY11J7a/qCRp+5YH
         hwZMGPGwixH3z9RHZWPQNzRiibqEETK2ew/AUXZIoo8i9NY+F1MpXl1D7em9ojRcGJZA
         giqfqWH4FVdXUj6kQ8MkaPgzUUBNOVBJKqHjEIoQER+i2DjfnKmqjh/GJqFfS6PpKpDU
         B3ocp+S2OWcLPiLqJxGg8bv5UJR7AFMYxgmK7VuAHIUCyA0wM04qeNpuPUtwEWtc3SkH
         nf+gpbNWwkNfF11zlQNsHosa+gRcK0ub+I0sUt2zVRXurhqHCMbbc+gMWB2IRoy/Bd4t
         8GPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=e5ySudKEzO3otYcm2RSI2zoDblMQoInA4cXkcyXtubc=;
        fh=Nid7WRGluN0tR8kYSrDoFfWtWhgMdFarH+pxOkw2yyQ=;
        b=fiicTbcMrqLellaqwCoZh9qG4nKhWdsb9CkGw3nijmEoZVkggqHKTlsRQe9FNidE5p
         07rlvtfFr7LhyaA0wSuzyB6nIU8E7ZWeaHymsiybE+0ee59nqe1tHkymUolpvpWxckN5
         oRdnZHxoA1jTcx7gfaCRCXQ7fnCkwVW6n6DGARBDvODlAOdsSSn6HIcViGk48Lz8ge+k
         5cDc1plCdsrZdn6/2woMFLx1WDMCo9LCTGtshKSzZAsB6XH9bK6pOPgIq+ir17VSW4AH
         oOmxws/VGNnZhYVujDkvhIrPt9KO4ieZ6E15AMR3WTWdRZokKt85YpdrzZGLN1Oau1vs
         ETbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-537a862be35si64799e87.8.2024.09.25.03.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Sep 2024 03:05:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4XDC664Lgnz9sSK;
	Wed, 25 Sep 2024 12:05:34 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id tdRuDw19ZA5l; Wed, 25 Sep 2024 12:05:34 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4XDC663XQwz9sRr;
	Wed, 25 Sep 2024 12:05:34 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 66F1B8B76E;
	Wed, 25 Sep 2024 12:05:34 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id PJHxtpbIOOEt; Wed, 25 Sep 2024 12:05:34 +0200 (CEST)
Received: from [192.168.232.90] (PO27091.IDSI0.si.c-s.fr [192.168.232.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id CBE218B763;
	Wed, 25 Sep 2024 12:05:33 +0200 (CEST)
Message-ID: <f40ea8bf-0862-41a7-af19-70bfbd838568@csgroup.eu>
Date: Wed, 25 Sep 2024 12:05:33 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 0/7] mm: Use pxdp_get() for accessing page table
 entries
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Ryan Roberts <ryan.roberts@arm.com>,
 "Mike Rapoport (IBM)" <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 x86@kernel.org, linux-m68k@lists.linux-m68k.org,
 linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240917073117.1531207-1-anshuman.khandual@arm.com>
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



Le 17/09/2024 =C3=A0 09:31, Anshuman Khandual a =C3=A9crit=C2=A0:
> This series converts all generic page table entries direct derefences via
> pxdp_get() based helpers extending the changes brought in via the commit
> c33c794828f2 ("mm: ptep_get() conversion"). First it does some platform
> specific changes for m68k and x86 architecture.
>=20
> This series has been build tested on multiple architecture such as x86,
> arm64, powerpc, powerpc64le, riscv, and m68k etc.

Seems like this series imply sub-optimal code with unnecessary reads.

Lets take a simple exemple : function mm_find_pmd() in mm/rmap.c

On a PPC32 platform (2 level pagetables):

Before the patch:

00001b54 <mm_find_pmd>:
     1b54:	80 63 00 18 	lwz     r3,24(r3)
     1b58:	54 84 65 3a 	rlwinm  r4,r4,12,20,29
     1b5c:	7c 63 22 14 	add     r3,r3,r4
     1b60:	4e 80 00 20 	blr

Here, the function reads mm->pgd, then calculates and returns a pointer=20
to the PMD entry corresponding to the address.

After the patch:

00001b54 <mm_find_pmd>:
     1b54:	81 23 00 18 	lwz     r9,24(r3)
     1b58:	54 84 65 3a 	rlwinm  r4,r4,12,20,29
     1b5c:	7d 49 20 2e 	lwzx    r10,r9,r4	<=3D useless read
     1b60:	7c 69 22 14 	add     r3,r9,r4
     1b64:	7d 49 20 2e 	lwzx    r10,r9,r4	<=3D useless read
     1b68:	7d 29 20 2e 	lwzx    r9,r9,r4	<=3D useless read
     1b6c:	4e 80 00 20 	blr

Here, the function also reads mm->pgd and still calculates and returns a=20
pointer to the PMD entry corresponding to the address. But in addition=20
to that it reads three times that entry while doing nothing at all with=20
the value read.

On PPC32, PMD/PUD/P4D are single entry tables folded into the=20
corresponding PGD entry, it is therefore pointless to read the=20
intermediate entries.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f40ea8bf-0862-41a7-af19-70bfbd838568%40csgroup.eu.
