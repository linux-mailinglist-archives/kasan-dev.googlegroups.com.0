Return-Path: <kasan-dev+bncBDLKPY4HVQKBBC44WHCQMGQEILAQQYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 825CBB33E59
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:50:38 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-618af99f6e5sf3284013a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 04:50:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756122637; cv=pass;
        d=google.com; s=arc-20240605;
        b=bhK3WyVfBWCqPVxQ7g77mgdEjPoIJ+Y0TdpUI318HEEAftgJht75gBjSPczeFBi+UT
         wTSUJRZ6fVEgRQJIH6tGMyzNBvlQa9zZaLHdSIKIajAzgBf+8qqksxDFdnS4Gl2lcva3
         v5hVyZmbp6dMOpXcrrxRM8JBHHtMJKj0fiBYE1haVLOLZbCpDRVDvqVTt2E1iSvFLSon
         /Y+45Uv/ZUz93eUXX1XOUCGuuyiS0pXiJvMS8NTyzAIkJVmgFCmhl2evaiJ41sfFQzJN
         0mYt4T7zXznvck1t9om//rq2p0IEg4nBoXZBpurrfSK3le8M5QTvyS25XUn8yCzDFF6a
         KExA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=yR92zo+2KpWRLkXuSaWuT8ZdGK7v35moSx7n1MfCE58=;
        fh=eNcl41ViXEKcKGs+ApQjnkSibu/FRpxD6hs6tSQOQ1c=;
        b=DvP0qYey4AHkCR+tgJ4EXn4gOP351LhqCcIBJIW4KnoWq21ziUTE+CTUKOJZqoBIU2
         Xd0a08973ibcOjkaKXGXCkYnxE31N74Me86yyCU18M79wqvBilOZXYyF9WMQ+WdC3sV6
         8dD+7FzNnEPYO4HGf9x+b2guYINGJCkjWA1ib3/+Me6LlSrm5643QxNFYkW5jaI8d/5t
         5Oni/wE0EVBp0MN3LbyFFmx7zAZgbE3qYnuv/MGvKfhdqiFv9Ksi7viD0xolbgDzeGK2
         gVFhYfHJxktQckr4LFYI8pT+BA8BMt+toHP+13qJTws1p0Pm4rUzu7cQjYU+z4Zkt8if
         3yNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756122637; x=1756727437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yR92zo+2KpWRLkXuSaWuT8ZdGK7v35moSx7n1MfCE58=;
        b=BWfJAGOgOFGkbkaRPe+npLJWWK3U5rRbQ9POgS3SU1cpEOuM8h4JOxH3av+LUVYLbb
         efamgEBI+fWJWZo4I73qr8IaKttXLQ6AUEfDFmpq5J48I382FEfDtAnjOZE2y2sMGw8y
         F6NWE3jF3CBv/mQllY0J4G+9i56z9WcWiOIxvxdtC/17mpzcVZ+3z+KNCWF5V6wlBiGJ
         fnzv3zO6eDq/PuihnItifKSbq2HTp0qSM9J36dcfnYkCslagNGmu+5EJALts6+Bxejdm
         n73th9IOv70eshFS5385oMlgaTeHh1pOn/S6zXmxpFKrJfcFVXpsy2ek8jJPQBZXx85P
         l1hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756122637; x=1756727437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yR92zo+2KpWRLkXuSaWuT8ZdGK7v35moSx7n1MfCE58=;
        b=CxTEes03I+LKQZ/bmT+uLal10czwNSRglJIMhJdM6pysVwOmiZlgTkKc/wha6KUxCP
         5hzRx1hkx55Y/Txy7vqexNG7d9wlGsnqousqdiT7eH/g9MsVCWr3aM1g7CiSdfrDf0Zc
         OaJc9RMll8fQlFw40LjCOWQ7Iaiqha3FGwfjORwVgwqBUiIStlkN22vyzulE+bD/ihyj
         OoWBO219oQ9+uXuv/HLEVPycvh5EZuDu470oWqePqOnc/WeGtq71cQyxl7THRPB8Y1/8
         pop/9w0mfuMEANQohyVnsSE2sXXvf6ntyVVxdRT6p5iZEU/I8bPpiLo9V65kN9oA1nuA
         5Rqw==
X-Forwarded-Encrypted: i=2; AJvYcCWF0qhwU4TEiHxP+Jw815pBo9blPVxQnNPn/JkAH7Z8UpbMNoaUjkNaS0YYiVr1OjOiiryQ5g==@lfdr.de
X-Gm-Message-State: AOJu0YwFqdUHo7eeFndomsTIlEUhV4h9hA1kDRs7mkaiQ11xvBK/f/90
	CXoYpzXCN9WdH4IcB87Ruyro2HyIntpfo6PYUMcNFwE9y7cK8ku9EGVv
X-Google-Smtp-Source: AGHT+IHX8X/aF9pil5zfcaG4JlUJm2q2pLu8+s63B6FWaGCA8k/xyuQEzDrjOf9AyPPyCWp+LaMsaw==
X-Received: by 2002:a05:6402:35ca:b0:61c:5cac:2961 with SMTP id 4fb4d7f45d1cf-61c5cac2c66mr3783406a12.14.1756122636431;
        Mon, 25 Aug 2025 04:50:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdkouAaxclgEjJapUbKG+Xo/LlEuzzRj1QY5a+J+ZSqMA==
Received: by 2002:a05:6402:4383:b0:617:b4c7:71c2 with SMTP id
 4fb4d7f45d1cf-61c5128dfebls976908a12.2.-pod-prod-05-eu; Mon, 25 Aug 2025
 04:50:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwzYcb4ekw7S23bYI3JYIDEavkARpQ0ql7ecH4oeU/wqZtZQQCP2A3obpXCItCiJ2vyzz1LtqoCj4=@googlegroups.com
X-Received: by 2002:a05:6402:354c:b0:61c:6ab8:574d with SMTP id 4fb4d7f45d1cf-61c6ab870f5mr2237915a12.11.1756122633795;
        Mon, 25 Aug 2025 04:50:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756122633; cv=none;
        d=google.com; s=arc-20240605;
        b=irJHTELRTpyGw5fDGxQvFsSLZh+4s2I4aaMb6CIld+zYHFtqtsDN80YE2MrxaW0Tx5
         gWvqMUliqqbhbmUq1yb98nsMjHnQ3R/IGawVXGBmGaIjSgrFvm7w1bxl4JeksbPlfLIW
         ybtIUc8NoVbm2Q4vgYOdtZiZ/i3522h7O/61vuZx3JPjhbPg2zJMZ5TgOjdx/iOhifrk
         SM2iNXP4BPjo361aiJ55V65fYwfKLhijbgx4a9ltyIWssIrcv+2J7/PKelGwtOCp2w/Q
         269KF10eMqyu8wMyQyX2oFXepbhhNVIP7gD+3w/ngFTyp8r0+gRtGp4E1YobsdyRYcE1
         AaWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=otgw8qHqXPzZM5+2y6XXu4fW6dpPzOVTknOMvuNTb0Y=;
        fh=eycZxR8pBQCpI/dCUaqaYEGEpXA7Hl1yMQV/0S0YqUU=;
        b=WNYOCreDFnVYb3Ax1CLZiZz7lsmx2jLfLwhQl/2rAA34HeuzDnyhzDBTE+60rvp+sS
         XAtrzFEAtUsbhX3kJV4yfziN2hRZTKUsF0TTaupKivKVsto2c/SWoFLJf9H3yDmqOJmk
         Ic4ilO0xz38rdapR4VHmyRakJwEffKx1VsAMm7kbha+WrN3YaOMk4i+WS/2eF7N01tIT
         w5oM3QPmhMk2vvao3mAQci5DzlvXIGpQlJ+LWoh9mscGIs3yIC+QbANFydIKl6lCJNR1
         NtnCtIA1uBPOsFWgu0EhZ6uZ+zkVOxlvRMu2nWfNSeKtRO7dyXCc1Wm5deDls5R09MSE
         Z80A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61c58b208c0si74870a12.2.2025.08.25.04.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 04:50:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4c9T6K4ff8z9sSZ;
	Mon, 25 Aug 2025 13:27:21 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id I9OzpNMcgXWv; Mon, 25 Aug 2025 13:27:21 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4c9T6K3JwMz9sSY;
	Mon, 25 Aug 2025 13:27:21 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 5974F8B764;
	Mon, 25 Aug 2025 13:27:21 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 45RSxQ1kXYeU; Mon, 25 Aug 2025 13:27:21 +0200 (CEST)
Received: from [10.25.207.160] (unknown [10.25.207.160])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E37DF8B763;
	Mon, 25 Aug 2025 13:27:20 +0200 (CEST)
Message-ID: <26796993-5a17-487e-a32e-d9f7577216c3@csgroup.eu>
Date: Mon, 25 Aug 2025 13:27:20 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use
 {pgd,p4d}_populate_kernel()
To: Harry Yoo <harry.yoo@oracle.com>, Dennis Zhou <dennis@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
 Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
 Andy Lutomirski <luto@kernel.org>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Tejun Heo <tj@kernel.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Christoph Lameter
 <cl@gentwo.org>, David Hildenbrand <david@redhat.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, "H. Peter Anvin"
 <hpa@zytor.com>, kasan-dev@googlegroups.com, Mike Rapoport
 <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
 linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>, Vlastimil Babka <vbabka@suse.cz>,
 Suren Baghdasaryan <surenb@google.com>, Thomas Huth <thuth@redhat.com>,
 John Hubbard <jhubbard@nvidia.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Michal Hocko
 <mhocko@suse.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 linux-mm@kvack.org, "Kirill A. Shutemov" <kas@kernel.org>,
 Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
 Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
 "Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
 Joerg Roedel <joro@8bytes.org>, Alistair Popple <apopple@nvidia.com>,
 Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org,
 stable@vger.kernel.org
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-3-harry.yoo@oracle.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <20250811053420.10721-3-harry.yoo@oracle.com>
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



Le 11/08/2025 =C3=A0 07:34, Harry Yoo a =C3=A9crit=C2=A0:
> Introduce and use {pgd,p4d}_populate_kernel() in core MM code when
> populating PGD and P4D entries for the kernel address space.
> These helpers ensure proper synchronization of page tables when
> updating the kernel portion of top-level page tables.
>=20
> Until now, the kernel has relied on each architecture to handle
> synchronization of top-level page tables in an ad-hoc manner.
> For example, see commit 9b861528a801 ("x86-64, mem: Update all PGDs for
> direct mapping and vmemmap mapping changes").
>=20
> However, this approach has proven fragile for following reasons:
>=20
>    1) It is easy to forget to perform the necessary page table
>       synchronization when introducing new changes.
>       For instance, commit 4917f55b4ef9 ("mm/sparse-vmemmap: improve memo=
ry
>       savings for compound devmaps") overlooked the need to synchronize
>       page tables for the vmemmap area.
>=20
>    2) It is also easy to overlook that the vmemmap and direct mapping are=
as
>       must not be accessed before explicit page table synchronization.
>       For example, commit 8d400913c231 ("x86/vmemmap: handle unpopulated
>       sub-pmd ranges")) caused crashes by accessing the vmemmap area
>       before calling sync_global_pgds().
>=20
> To address this, as suggested by Dave Hansen, introduce _kernel() variant=
s
> of the page table population helpers, which invoke architecture-specific
> hooks to properly synchronize page tables. These are introduced in a new
> header file, include/linux/pgalloc.h, so they can be called from common c=
ode.
>=20
> They reuse existing infrastructure for vmalloc and ioremap.
> Synchronization requirements are determined by ARCH_PAGE_TABLE_SYNC_MASK,
> and the actual synchronization is performed by arch_sync_kernel_mappings(=
).
>=20
> This change currently targets only x86_64, so only PGD and P4D level
> helpers are introduced. In theory, PUD and PMD level helpers can be added
> later if needed by other architectures.

AFAIK pmd_populate_kernel() already exist on all architectures, and I'm=20
not sure it does what you expect. Or am I missing something ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
6796993-5a17-487e-a32e-d9f7577216c3%40csgroup.eu.
