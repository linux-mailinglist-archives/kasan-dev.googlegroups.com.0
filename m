Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZGPTXDQMGQEPXU4XWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 53749BC7BF5
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 09:44:37 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3f3c118cbb3sf757882f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 00:44:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759995877; cv=pass;
        d=google.com; s=arc-20240605;
        b=bfHzSEge13teUeSdns/S4JJpkl/nzMhjOKpVAdX6NeFbtubWz48UrLdy8VRvc7ngk5
         CzHhDhSV7+Dh0nx/u/eOa07I/Krak9wnOugYrFLPmIYstEVJmFHQOPMtFxEMw9lPv5Rx
         bHz+N1Hyrlzq0mIGfDVFpImOLNfEJeeIJePkv1Z11Qd2LcLg9tU8ak/CIjePK9Izjzb4
         9fFeXp3y1Nyfe9a/P6nstg/Ycbc2g7vMeI6FbK6UkidBTigZNnzbxhx01hY40yEm3MeV
         XYCq3MpGzAMuXLLbpRvJTnOXV5Zl3/Z8lz05WyaGXWgXmvdO+DCz7oAydMj0PXY2JLqX
         BkfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=cEh2bDxYvmHP5eKJ2+a/doefYtZuBVdRypRJC9HYv5g=;
        fh=7qgV8PzTALTRa7+KbXLR1I5skmpKimWKrb89VLVTL9E=;
        b=e9RrExfdzrewzUZRJYtx826YeqLg55DSjntIUwKXbGzEBM3WNuq+zzOroKYoTDpfaA
         FqI4Z1oy1HxKrD9GdY63bLPQf2VehdMTN8gsTY2UVOniERhbwsOfWDI5BaEjOy3z0KHV
         XphKjsm+OCbFS+8wqq1189kzVXrHVo86hOlSRquyMs5FsZ7aKdT/33rA38C9BJNreF+y
         wg8Py/si+AyAuCnnqKlMXwGM6FZ2nS1Xib4/DrMqTZ6k2UcYtGZy03xhHWbYlCb5xW2n
         l70hQqr3pa8fogQRHa5N2rRNn28/KcNlxluXfPOe1/5IfY2n1T0PkYUR4FNzo2Dho/NU
         bIgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759995877; x=1760600677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cEh2bDxYvmHP5eKJ2+a/doefYtZuBVdRypRJC9HYv5g=;
        b=MyBCQZ3W1kCgCW2RgtVOOy1Q1M/P+FwVB3nAMqSvo4tNoiWbzNEhxr1i02z0sVjtTw
         oz2AqUpUNXh4AmRsoGe7sdNynqH1Ze71jPautC4q3SeplW07RIMS0nJEo/ibLM+cMBMQ
         2B8gdVUrfbt7HElpvl8XAAYuVdHByR0NhG9gQPXgh8PCVmg9e/en0D/PjrtK+6U0xV1X
         GCI3if4ZoJ/YpBDorNADQk0zaue9DOagFzjeggF8JJ6AEQcabAo3pqQ1FO70o2GKwq87
         KsTv4YKWTNC/veyvuO9dBGp1oHFpSIIWwmS4G1BDaMxZ/4Ij1G2i9KTRIecK0NYRsnTD
         +DMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759995877; x=1760600677;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cEh2bDxYvmHP5eKJ2+a/doefYtZuBVdRypRJC9HYv5g=;
        b=Yh7iOneFEGLcaaPy2j+YLJf1ypWMtVNBJXDRT4binuxqqioLBt4qqW/umMbMLiJYI9
         FKMn9yjQlD66k3S2aa18JHomJ9I/7qt91AdCeiDKEEJC8MSWpqxdv9YxgdlMxQll5K8I
         f2hCAgFhfnm7bj1YTfKqFAT8JlFp+PkGxGzUVj9sktEbH303UePknopcKvUxZl17cReV
         ZEaacE1Sti0981Qg3aZfVrmESTnI2MeP9JJBdKMRFtHB7EZ1weHs5BmVlLrD8Fo3E9Z2
         Iivqnx47YLO1yoFYj6tGON1zH3DMemH62RDFlalTSS1hPfXopgz6XW/rWMqskeiaQE7m
         3WiA==
X-Forwarded-Encrypted: i=2; AJvYcCWd7gamhtnES5QucuIu4T7eChrbkcAE/d6b1u1c3vqQiqmJcsKmtuDm/xiXWRdgkffE8bKtIw==@lfdr.de
X-Gm-Message-State: AOJu0Yz0Cuw2quyuxp3Pm2TpW5yAfsu3pqVo3K1DleAg6HuKkPIiqR6Y
	A+YVgF7EdrVQ2X5DOCyeRH0d4tRs+zQ/PxThsfJsHBiT61E4l1A84+la
X-Google-Smtp-Source: AGHT+IE02Q0rhe63Z7AajMnA/SC0KR68w+h6xFbkMsYGjt+/Dr48gmhdBZQZbGHUB4MZ3qVNqycXbA==
X-Received: by 2002:a05:6000:2681:b0:407:4928:ac82 with SMTP id ffacd0b85a97d-4266e8dd3fcmr4020132f8f.53.1759995876628;
        Thu, 09 Oct 2025 00:44:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7U5RFG9KRSPSJNIqEGZsWGk/ybfXw3rhWcShymxAYV5A=="
Received: by 2002:a5d:6383:0:b0:412:ab9e:8222 with SMTP id ffacd0b85a97d-426c7ddd70els512205f8f.2.-pod-prod-05-eu;
 Thu, 09 Oct 2025 00:44:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYaSKl3lLmOSH0M8MvmoVe0vYiDlOTXsmDa03zIX9Wko+cpe8IN03UA20I2KwxgfKnamRu5CzM2es=@googlegroups.com
X-Received: by 2002:a5d:588b:0:b0:425:86c2:7b4a with SMTP id ffacd0b85a97d-4266d0da0a8mr3802343f8f.24.1759995874068;
        Thu, 09 Oct 2025 00:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759995874; cv=none;
        d=google.com; s=arc-20240605;
        b=NvxOuR7aww/DtY6CF8TIHIvFbOVZeEDqy+GVog7vDNbxK0B4BURlbSuYLNjv6C6O5m
         aEBg0Zr2OeK4erHW/CFWWCJSaG7IvEGgrq2SQa783M5YsiQeHUoDB5W6Yy/3QExuuvgW
         RKgnVIhIvx/MEf9/dRzn0KrsXgezbFk/4/+gy9mN0OTsi8ACFf6o6BCdQ+Q3xl/dJKpB
         gqqDWUNf9qpngMF7WNinoh531TOzm7lZVlx8dxLGX/6oWgPmWC7onMLjLWrJHkLGb7Mi
         iqhM7UGJ4oibfhyGfS8Qg1oLULRVJJFaoh2jcwsavCwPrqVlwZeM/w1F8to6FW6edj3m
         XRKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=s+XtmwdKc8QKMPTZ9xcrxbfmEnkdKPymPLn6kJMJIBg=;
        fh=7wgiGZD7GN9L56S35I5R8c/eoPZ2zJ2PKdmpqRxCfmQ=;
        b=GiQsMqCv2Hf9eY6SSA4Zw60eVpdaezpvM2oWUBLGz40Piqj1++dKjmIq/n3EBDtUoo
         YtVTch+rf+utV8XVvgolB8H3A79oVw0hd22Bs0X3GdOtIuApK0+gg4z1iDvkkFLGtZgO
         TIppXAam4Is+I1WGF9LE7s6BFThxCozjs3hgbyp90MTkXrniJOC7V/gk7WXrb1TEeghl
         WqYcC+s8MbWwslMjwLVhX2eRMvyWp/HmO20++KleYcR00FKopJ4fSGCMrN/cvwM+K6uq
         mJiDUpTdPI+Oavm10LmegeEoL+qvM6+PYyQ/ZFXFfVApmStE5j48YRY2PSnplPhK0X+z
         4+Pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46fab36dd87si830225e9.0.2025.10.09.00.44.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 00:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4cj22T4GVLz9sSy;
	Thu,  9 Oct 2025 09:44:33 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id e-hrpkSiMM5A; Thu,  9 Oct 2025 09:44:33 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4cj22T2bCVz9sSq;
	Thu,  9 Oct 2025 09:44:33 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3E1858B768;
	Thu,  9 Oct 2025 09:44:33 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id iEsvyTlwygx4; Thu,  9 Oct 2025 09:44:33 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4940A8B767;
	Thu,  9 Oct 2025 09:44:31 +0200 (CEST)
Message-ID: <1fb2259f-65e1-4cd0-ae70-b355843970e4@csgroup.eu>
Date: Thu, 9 Oct 2025 09:44:30 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: (bisected) [PATCH v2 08/37] mm/hugetlb: check for unreasonable
 folio sizes when registering hstate
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Zi Yan <ziy@nvidia.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-9-david@redhat.com>
 <3e043453-3f27-48ad-b987-cc39f523060a@csgroup.eu>
 <d3fc12d4-0b59-4b1f-bb5c-13189a01e13d@redhat.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <d3fc12d4-0b59-4b1f-bb5c-13189a01e13d@redhat.com>
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



Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
> On 09.10.25 09:14, Christophe Leroy wrote:
>> Hi David,
>>
>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>> Let's check that no hstate that corresponds to an unreasonable folio=20
>>> size
>>> is registered by an architecture. If we were to succeed registering, we
>>> could later try allocating an unsupported gigantic folio size.
>>>
>>> Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDE=
R
>>> is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc,=20
>>> we have
>>> to use a BUILD_BUG_ON_INVALID() to make it compile.
>>>
>>> No existing kernel configuration should be able to trigger this check:
>>> either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
>>> gigantic folios will not exceed a memory section (the case on sparse).
>>>
>>> Reviewed-by: Zi Yan <ziy@nvidia.com>
>>> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
>>> Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>
>> I get following warning on powerpc with linus tree, bisected to commit
>> 7b4f21f5e038 ("mm/hugetlb: check for unreasonable folio sizes when
>> registering hstate")
>=20
> Do you have the kernel config around? Is it 32bit?
>=20
> That would be helpful.

That's corenet64_smp_defconfig

Boot on QEMU with:

	qemu-system-ppc64 -smp 2 -nographic -M ppce500 -cpu e5500 -m 1G



Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
fb2259f-65e1-4cd0-ae70-b355843970e4%40csgroup.eu.
