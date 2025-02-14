Return-Path: <kasan-dev+bncBAABB2N7XK6QMGQEZPQBGUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 98BA2A353DA
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 02:44:11 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-220cad2206esf31984005ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 17:44:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739497450; cv=pass;
        d=google.com; s=arc-20240605;
        b=e8Hfx+fD1fq/RD19PlOVMa4AlKU1brtVmCGUimh6sAM82lDXrpaud0y5kdjmwwn3me
         2IYKo+KEh0A+zhD5o9GkYcIuFfggirqqcWpM6SodC43CcsCP8afaXfo2eoI1Kqkijeiz
         PtEOMXirIhgn1QVd1opPPXQ8JnMwy8Duo/aVNLGp/pQuEYrUMczHf4Ip0UMrz857AIwW
         Vol+Hir32OwIfzHbUdKKvf1e4RHuNdkLBkV4WIfaixPNdyPiULLTmpl+ISI+RKgKS7iz
         04o5ldaQtFVaNJPqGi9UnvdAijXrJIq73yPbxd3N9d6HVnop671yHNHRRqbhrtosPAJJ
         qYwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Dow6pYyI3epHLwgLhc5M1GMPXX3Fhtf+8hIccSe0DRk=;
        fh=1mNoTdoWJpL7Z9j8XAQtrFJ6M3iDR/P68zvIpN6Ua5Y=;
        b=WsJiyFRB7YfsKzirCnAjKbe6ApdKlp1aWWs0j5VBNqSixy+MIqDeQA1eiZnNq/ofVy
         k61wAKyLaqe56Fjf2prxRNT1GPhi+PjwVNDa9oegnItdswfDCspzlRSTLZEzSVIAS1ke
         hOyVW6NTb2+9P6l6ZpHmlke47DTSBv4nbNHH3AI22246oqtu2s7LiVrrYforT5yvf7yq
         DlyNYN+CBEw4wEn3Bmz+oF635HL6SSoQnxYVwklwp3qk9LBfpWFapbVsADrtduyDQhrG
         C8A8qCc5qqU89502COoATrShsis1bYMorRhQPjKM3pR97ytvBwUHy4SoFZaznW7ntque
         DFfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739497450; x=1740102250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Dow6pYyI3epHLwgLhc5M1GMPXX3Fhtf+8hIccSe0DRk=;
        b=jp2dOWJ3arvpfY2D+ILICE8Irx/XHxnrwDpCOe92DcNNz+9nx/UFpfdK6LEKeVFj4T
         iznOXS7y86e6rN/Mb6FXUUWiXH8rdxkHe5qf6tseOoIKk01GHsYYndr3NIf8P05/TKIr
         RV8jAJ1BY7CCiVT0w34AyDbrGY5lcvfBcbwrKZldVwzNt22t3eBEguBVfXs71FGCbYJ1
         EqnMN9hiXSq10iKprjOpsL/P/umccxPZsZy5Dop5017u7zLHDI114KRjrv+Eb3Z1H7bB
         ItHC8Czlh/2w284QHuaTDNbpgSVkX6autrU/TQI1+hLimml6PVynwC7kZCoz/uPPuBkz
         TEtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739497450; x=1740102250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Dow6pYyI3epHLwgLhc5M1GMPXX3Fhtf+8hIccSe0DRk=;
        b=f9+jd7BH0fxGUxqNr1IYAcvDbAhL6Z16dfUzergj8QzlzuwgjBBlVIU+o6kKuTHdse
         9IQDrBUr1oyj0CZuCZ8M3c1bAXNYIMdOfu+TqMuhBYGtZfN+W6ypoOy2Q3rfohklQNgj
         +X+qP7U1yt1VcxJ+mQn6Ob9EpAaeHT9z/Q+LOTG6Y1V0NDldcSDk28xjeqVdbL8PCi6Q
         dGYM+M0YdZLJQTLeOVQLTKY7/HqYTaptEkS7bjM74YCX1JHtabligdtpara97sPWC3py
         0mb2oiMQqbvHzXHCcgd9t24TsrW2nwDMBFABahOxOvzAJwwcqWLIVDKa+31z3voP4ehW
         EGcw==
X-Forwarded-Encrypted: i=2; AJvYcCVo+MdVJkLifITSKuMsD651zKcNMhG/+sAgluUgix5ofJ/lFn6Z/DC4saYscbFc8D6EIjWodg==@lfdr.de
X-Gm-Message-State: AOJu0Yzf7xuwpd4oUGL6/It88bEvXcKXfmHTh95XJkNHGf9hR3eSulas
	lB+MgW/dAEJbZv78BxJpfMdnn05zVYX5PO+DOwnwyqbZQv0Qr28T
X-Google-Smtp-Source: AGHT+IEVhXqPUvbIqkPERsTYnmPmyNZ9AvlXDGGW4E+swCubySb+aNQGku695fuqogqdvNyMCNR/Sg==
X-Received: by 2002:a17:902:f60b:b0:21f:ba77:c45e with SMTP id d9443c01a7336-220d212694fmr86069475ad.45.1739497450074;
        Thu, 13 Feb 2025 17:44:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHMjj6AVoKyycfVn2ayEwTqvxD5aNh73c06D2A1W4C0cw==
Received: by 2002:a17:903:25ca:b0:220:c6e0:e9be with SMTP id
 d9443c01a7336-220d257ac22ls14721665ad.2.-pod-prod-04-us; Thu, 13 Feb 2025
 17:44:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUNgvLiYgLLUS6stf35yWU5LnAldBbYdcFzZmOS2yeTQEH0qUQD0YUbKE/GAcZJ0sdp2T8/5oAm5xQ=@googlegroups.com
X-Received: by 2002:a17:902:ec8a:b0:21f:515:d61 with SMTP id d9443c01a7336-220d1ee59e9mr93342525ad.21.1739497448544;
        Thu, 13 Feb 2025 17:44:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739497448; cv=none;
        d=google.com; s=arc-20240605;
        b=O4BVhmYBy978TCzmTIQVGj8R1nlg4aknlU2ww6sWylOg5UETocN8zy/OxMNmM/Md92
         neLL6INwK5VL8p0v7sBOTECjCjVBeZqNcG3AwfcPgBVqwPcvOnjo+syVuxpqkXl1KeWG
         qTezYOKAhVY5K21uy4WuQLLxAG7C3uczvE522kfBs+GgjmbHMIdldS0VZAStlIOnA3Mg
         YSfdrxMEVYbNWyDEGdIUZ0rD9d+SJZ0g014b+7JFIOtkKleV1JCnBqbM1lTpM2NEuF+W
         syUzze3oCpKGV9gqzI7wX0F4LGVXCiE1dsBiud2L2GwjW3bPxIQx0F4HcBr7h+KdfuIe
         gqdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=s6gybk0sDxsKPqVranOYHJNAYoMVjrehj07uCNXs5vM=;
        fh=RzQbsIRJIGcsOahvYzttPrzbIb6n8kVsMKDOWJddbjk=;
        b=Lgv477p5z3AEt822QeOtpBFdr46S9eNvR12h3AIPZw9CsbvmgenlJZHYAMXXFnoyC4
         2SKo5TD+K6PDFBSiP+aqT+3e1/6Y5IUZyqIZ9hmqrfRhJ2U2QV3VC+vgXShlJtAhmZNn
         uAORuzSaVdQ7+/cfjZKc7JCc7PFuPOk53EBNWeuFNTgtNcfuKYT/8bPWarqF00yjbTG0
         PpTOMapRSxMRbaugmlD6jLRftKdZFkM61Uf7vpAVYQ+fqIfTkI1tfZGz0u7jUi/S1dLw
         Wd4Z/MH4urZQS2Upj4X4U0O3qmt6EhCBrDH5ktqzqT/plzRj8mVl6/PcXIV4o7ViJg0A
         4eng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-220d542d60asi1146385ad.11.2025.02.13.17.44.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Feb 2025 17:44:08 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.163.252])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4YvF8m1vkrz11PdJ;
	Fri, 14 Feb 2025 09:39:36 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id 9BD7F1800EA;
	Fri, 14 Feb 2025 09:44:05 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Fri, 14 Feb 2025 09:44:03 +0800
Message-ID: <df40840d-e860-397d-60bd-02f4b2d0b433@huawei.com>
Date: Fri, 14 Feb 2025 09:44:02 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 2/5] arm64: add support for ARCH_HAS_COPY_MC
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Will Deacon <will@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, James Morse <james.morse@arm.com>, Robin Murphy
	<robin.murphy@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Aneesh
 Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <wangkefeng.wang@huawei.com>, Guohanjun
	<guohanjun@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-3-tongtiangen@huawei.com> <Z6zKfvxKnRlyNzkX@arm.com>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z6zKfvxKnRlyNzkX@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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



=E5=9C=A8 2025/2/13 0:21, Catalin Marinas =E5=86=99=E9=81=93:
> (catching up with old threads)
>=20
> On Mon, Dec 09, 2024 at 10:42:54AM +0800, Tong Tiangen wrote:
>> For the arm64 kernel, when it processes hardware memory errors for
>> synchronize notifications(do_sea()), if the errors is consumed within th=
e
>> kernel, the current processing is panic. However, it is not optimal.
>>
>> Take copy_from/to_user for example, If ld* triggers a memory error, even=
 in
>> kernel mode, only the associated process is affected. Killing the user
>> process and isolating the corrupt page is a better choice.
>=20
> I agree that killing the user process and isolating the page is a better
> choice but I don't see how the latter happens after this patch. Which
> page would be isolated?

The SEA is triggered when the page with hardware error is read. After
that, the page is isolated in memory_failure() (mf). The processing of
mf is mentioned in the comments of do_sea().

/*
  * APEI claimed this as a firmware-first notification.
  * Some processing deferred to task_work before ret_to_user().
  */

Some processing include mf.

>=20
>> Add new fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR to identify insn
>> that can recover from memory errors triggered by access to kernel memory=
,
>> and this fixup type is used in __arch_copy_to_user(), This make the regu=
lar
>> copy_to_user() will handle kernel memory errors.
>=20
> Is the assumption that the error on accessing kernel memory is
> transient? There's no way to isolate the kernel page and also no point
> in isolating the destination page either.

Yes, it's transient, the kernel page in mf can't be isolated, the
transient access (ld) of this kernel page is currently expected to kill
the user-mode process to avoid error spread.


The SEA processes synchronization errors. Only hardware errors on the
source page can be detected (Through synchronous ld insn) and processed.
The destination page cannot be processed.

>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
f40840d-e860-397d-60bd-02f4b2d0b433%40huawei.com.
