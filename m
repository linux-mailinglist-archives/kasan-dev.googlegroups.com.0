Return-Path: <kasan-dev+bncBDLKPY4HVQKBBQWETXDQMGQEKL7GT7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 46F71BC7A9B
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 09:20:36 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-46e41c32209sf3249005e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 00:20:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759994435; cv=pass;
        d=google.com; s=arc-20240605;
        b=IZTum2FnDtQEvLOqiYx05PJUvNHJKVw19oBdMmTSuCulRAdQ9m2XYwsN2od9X6jGDN
         yCWYaKxdetoIbXb8p1xyBF6Knzz6/AusZCGDP3wuCDSMcJyQcDF+YpkE/K6BjDC7s1yQ
         3HkL2L+VXoZSLbyj+Br9R/Baos1t4OKQJw5iiRnrZHyo+IRrT/qcijnmb034GLRYBhpk
         S1wz3v8iCRoshYJI7P5Nmk215Se1+j55BhVujQp1307QD0rgfDJBf984vB29AH71kPat
         9hqHO+CHpA661rM86pV9VNq3moEoaxFntVebxO0zBKqRG8eTGBBilbKmzIkbd4h3t2Kj
         CDqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=rxThKgd40L9Yl8ZWsTsAm6MQSAmg1RKmlJESEch9c4o=;
        fh=qoN6SJkvg6Jtlt+bUVZqLdo5llqbSNBHjI+TQxSmtc0=;
        b=BRM6VTXxIbJYQev+7UqxuskaPukNH/xaOWO11lyFIy1fwkQK2i//D37FAVF4edHHjz
         xgG8lzRXGIcPrEtTC7hV2LKJm4FFHkf9usDinRyW//74NV6//1AJCxPHFZWUC60u9dpv
         EMdaTRgQ3UI7wQVExKGYwAuiwdC+y0uAMCJOpxWdQ1f4oVHaY6rSwFs6zOrSwscWCAtP
         RUFuHMkLqivBw0uNQFzYk1GsATcLKDnZiCgvdUlkl/UajLubrRbOKekPuq1+tdONuInY
         hnP7hytiC2LqAufgS55ttqI5TE7HGgW4GI1+0KhSd9jExJ1x6QWLB5UpynbB/siji9cs
         SFoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759994435; x=1760599235; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rxThKgd40L9Yl8ZWsTsAm6MQSAmg1RKmlJESEch9c4o=;
        b=WiFCavjEBgz8iaCSwpLjiDV3GKCYAXysGorj3SOT5oiFlwhwXAEeN8IXAxJHzcO4/P
         KUniZRUIQGfdzzC3e+hqhsYE3+TLMT9EynZzV//nXXmxtYaVwPgOfQprdOfqOmGQ+06p
         tBts16rfZIqae50iiuZPBU5h9Wd65GBqlesNlirOS/LilC6n3FXCovNN2lrdHP6sByR4
         kfiWmWjAJZd9tp4jBeBq9m6E5tgbKzftmCThODWll5n/yVq69RLqBuF1AFtZOFSRrhXy
         LLxqAtwHWwiQYUy6Z3nuL8j1UGJDKEXVBgsXDC9dM2voUkEpTWUolMBkIVoVdW3SPEBL
         t6SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759994435; x=1760599235;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rxThKgd40L9Yl8ZWsTsAm6MQSAmg1RKmlJESEch9c4o=;
        b=HgA2uOIsYCRm/RIjWpeHozeZ14q6s7dj4trqzEnseuyx21xd1ngBzgCrnJRUocLbnO
         4P5vUGaOCWbiqJU/3f3+qyZb+d/mj1HCJMlf5/gsjqMtVDSjRvF+o6GFkk73uqr+1BBS
         ZLEsEB37QzQHylyK1iw1b3gUFl0+ZUv5gZM0dfqvtciImIal/6KZd+ONNaoLaMzK/+Ay
         2kAkdnRU9+Mtz0LPXQ/VMpbTT92hSNVqRY5vPTsTXvYlT4EFvqb8LhXV5SZh7uCxS1S7
         wyfphQ10/hkEsWekfVkSeSLgQ4RYWVQVfKHxi08k+byNRr3C25YFt+hrjP3B+Xgri8zZ
         0I+A==
X-Forwarded-Encrypted: i=2; AJvYcCUwUWcdixBOrIBE2NthToQkuPCMlFtdLlbyhttWLDgDWJ+vd+j0J246c4hOBiImIoBVT9S/7Q==@lfdr.de
X-Gm-Message-State: AOJu0YywHaJZtZlWR7YfPUfTz/MNN65buHmKpeo18T3yoYfI4mGc8eXT
	BRqUM0oL7hWVteEblI25tpqwyTIhTXnoijpM4qAi5NCe0UDRNon1Q8QK
X-Google-Smtp-Source: AGHT+IFgeu73Sf0TVakjZn0AaiZU2vaPVtKwEkAjSZN3cGv41xqbxVtgQi7s0ii96mnI9s4PX2qwaQ==
X-Received: by 2002:a05:600c:c0c3:20b0:46e:39ef:be77 with SMTP id 5b1f17b1804b1-46faef4161fmr15249805e9.14.1759994435297;
        Thu, 09 Oct 2025 00:20:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6w1f6a1VgRVU34tqmTSedhx838BhIem4LBJyuUxg8VtQ=="
Received: by 2002:a05:600c:2d94:b0:468:7a59:f88b with SMTP id
 5b1f17b1804b1-46faf5c8a63ls2384505e9.0.-pod-prod-01-eu; Thu, 09 Oct 2025
 00:20:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVL7jR93HEcRvSfXju2e2UFowD3LS/eO0qv19LOWsEby5Cs+oZBtOrg2q8KvwWZCeh0q/Nl6OSZ5HY=@googlegroups.com
X-Received: by 2002:a05:6000:2285:b0:407:23f7:51 with SMTP id ffacd0b85a97d-42666abb54emr3733132f8f.1.1759994432742;
        Thu, 09 Oct 2025 00:20:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759994432; cv=none;
        d=google.com; s=arc-20240605;
        b=aLhaPjZ8y1R/kQoSmul/9fXSrWgA2hRbXxI8ZgjVDeeNJLCdlYOReXayR28A6Ca9Sf
         /YoFC1zBK95uXR+9SFHDMtUaqSNUqoqdoQSgeJQYnFCWLWfK8QW1NA6oLBA5uYSIxuuX
         VAha6T9UMVM+WDNCuGxOW+jxp8xg3g+bKM4MSCxcg2Mc1qAOpT0DnEcLEMtMkRdY+uQa
         //cXgXyt1ORFGgfdljj7qRHt2W8a+Aza22Pxuc7wTI5JzXFBwVat1yrZ5T2WKOPsAoU5
         CNU+kienaHBpSvMsqFU3Gu6WMOnbBL1XPq8AwmcrkhgD2kNb2M4MiMbpD3j7QaIGEtMJ
         /0+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=K8cf0AOs/mVNsDWJRMHcPMT4OicAVe2fATkFfoZ8F9E=;
        fh=7wgiGZD7GN9L56S35I5R8c/eoPZ2zJ2PKdmpqRxCfmQ=;
        b=FYRk+zADnAi5HvvkkqU275YN/fOX6AN6pJmtn+lcfEHXFskXYUEqcDJUP01XP8hUS8
         DUXLHW6sfS+bC0QRXjGzKeOsx3YFRWYZ1Ki8GGArw31O4+R5pEEfanedsL9L0x3ff8z8
         D0bw80B60NkKiyJzvjOdV5mWqSsqZLl1MhbuKA7hk8WjYcr0rRkbudKn44J9ImiohBM8
         bLaXy2vGsXj0t1QNsv3zy0hdPWIZbwc1k+flwHYJ6wO+ikpV39Fre1UILSOA/Eow9UO+
         86VHOrdcAueA+oZaF3KKIjwkYgyymIo3ai55PjaExapG5SAb5LeKBQxV/Q50oW0vGZF8
         SeLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTP id 5b1f17b1804b1-46fab36a004si1566815e9.0.2025.10.09.00.20.32
        for <kasan-dev@googlegroups.com>;
        Thu, 09 Oct 2025 00:20:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4cj1Mm20R5z9sSd;
	Thu,  9 Oct 2025 09:14:28 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id IrXIuvb4y-IU; Thu,  9 Oct 2025 09:14:28 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4cj1Mm0p1dz9sSb;
	Thu,  9 Oct 2025 09:14:28 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id F24048B76C;
	Thu,  9 Oct 2025 09:14:27 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id wHEaqnf6dd0R; Thu,  9 Oct 2025 09:14:27 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D85288B768;
	Thu,  9 Oct 2025 09:14:25 +0200 (CEST)
Message-ID: <3e043453-3f27-48ad-b987-cc39f523060a@csgroup.eu>
Date: Thu, 9 Oct 2025 09:14:24 +0200
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
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <20250901150359.867252-9-david@redhat.com>
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

Hi David,

Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
> Let's check that no hstate that corresponds to an unreasonable folio size
> is registered by an architecture. If we were to succeed registering, we
> could later try allocating an unsupported gigantic folio size.
>=20
> Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDER
> is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc, we ha=
ve
> to use a BUILD_BUG_ON_INVALID() to make it compile.
>=20
> No existing kernel configuration should be able to trigger this check:
> either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
> gigantic folios will not exceed a memory section (the case on sparse).
>=20
> Reviewed-by: Zi Yan <ziy@nvidia.com>
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

I get following warning on powerpc with linus tree, bisected to commit=20
7b4f21f5e038 ("mm/hugetlb: check for unreasonable folio sizes when=20
registering hstate")

------------[ cut here ]------------
WARNING: CPU: 0 PID: 0 at mm/hugetlb.c:4744 hugetlb_add_hstate+0xc0/0x180
Modules linked in:
CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted=20
6.17.0-rc4-00275-g7b4f21f5e038 #1683 NONE
Hardware name: QEMU ppce500 e5500 0x80240020 QEMU e500
NIP:  c000000001357408 LR: c000000001357c90 CTR: 0000000000000003
REGS: c00000000152bad0 TRAP: 0700   Not tainted=20
(6.17.0-rc4-00275-g7b4f21f5e038)
MSR:  0000000080021002 <CE,ME>  CR: 44000448  XER: 20000000
IRQMASK: 1
GPR00: c000000001357c90 c00000000152bd70 c000000001339000 0000000000000012
GPR04: 000000000000000a 0000000000001000 000000000000001e 0000000000000000
GPR08: 0000000000000000 0000000000000000 0000000000000001 000000000000000a
GPR12: c000000001357b68 c000000001590000 0000000000000000 0000000000000000
GPR16: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
GPR20: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
GPR24: c0000000011adb40 c00000000156b528 0000000000000000 c00000000156b4b0
GPR28: c00000000156b528 0000000000000012 0000000040000000 0000000000000000
NIP [c000000001357408] hugetlb_add_hstate+0xc0/0x180
LR [c000000001357c90] hugepagesz_setup+0x128/0x150
Call Trace:
[c00000000152bd70] [c00000000152bda0] init_stack+0x3da0/0x4000 (unreliable)
[c00000000152be10] [c000000001357c90] hugepagesz_setup+0x128/0x150
[c00000000152be80] [c00000000135841c] hugetlb_bootmem_alloc+0x84/0x104
[c00000000152bec0] [c00000000135143c] mm_core_init+0x30/0x174
[c00000000152bf30] [c000000001332ed4] start_kernel+0x540/0x880
[c00000000152bfe0] [c000000000000a50] start_here_common+0x1c/0x20
Code: 2c09000f 39000001 38e00000 39400001 7d00401e 0b080000 281d0001=20
7d00505e 79080020 0b080000 281d000c 7d4a385e <0b0a0000> 1f5a00b8=20
38bf0020 3c82ffe8
---[ end trace 0000000000000000 ]---
------------[ cut here ]------------
WARNING: CPU: 0 PID: 0 at mm/hugetlb.c:4744 hugetlb_add_hstate+0xc0/0x180
Modules linked in:
CPU: 0 UID: 0 PID: 0 Comm: swapper Tainted: G        W=20
6.17.0-rc4-00275-g7b4f21f5e038 #1683 NONE
Tainted: [W]=3DWARN
Hardware name: QEMU ppce500 e5500 0x80240020 QEMU e500
NIP:  c000000001357408 LR: c000000001357c90 CTR: 0000000000000005
REGS: c00000000152bad0 TRAP: 0700   Tainted: G        W=20
(6.17.0-rc4-00275-g7b4f21f5e038)
MSR:  0000000080021002 <CE,ME>  CR: 48000448  XER: 20000000
IRQMASK: 1
GPR00: c000000001357c90 c00000000152bd70 c000000001339000 000000000000000e
GPR04: 000000000000000a 0000000000001000 0000000040000000 0000000000000000
GPR08: 0000000000000000 0000000000000001 0000000000000001 0000000000000280
GPR12: c000000001357b68 c000000001590000 0000000000000000 0000000000000000
GPR16: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
GPR20: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
GPR24: c0000000011adb40 c00000000156b5e0 0000000000000001 c00000000156b4b0
GPR28: c00000000156b528 000000000000000e 0000000004000000 00000000000000b8
NIP [c000000001357408] hugetlb_add_hstate+0xc0/0x180
LR [c000000001357c90] hugepagesz_setup+0x128/0x150
Call Trace:
[c00000000152bd70] [c000000000f27048] __func__.0+0x0/0x18 (unreliable)
[c00000000152be10] [c000000001357c90] hugepagesz_setup+0x128/0x150
[c00000000152be80] [c00000000135841c] hugetlb_bootmem_alloc+0x84/0x104
[c00000000152bec0] [c00000000135143c] mm_core_init+0x30/0x174
[c00000000152bf30] [c000000001332ed4] start_kernel+0x540/0x880
[c00000000152bfe0] [c000000000000a50] start_here_common+0x1c/0x20
Code: 2c09000f 39000001 38e00000 39400001 7d00401e 0b080000 281d0001=20
7d00505e 79080020 0b080000 281d000c 7d4a385e <0b0a0000> 1f5a00b8=20
38bf0020 3c82ffe8
---[ end trace 0000000000000000 ]---
------------[ cut here ]------------
WARNING: CPU: 0 PID: 0 at mm/hugetlb.c:4744 hugetlb_add_hstate+0xc0/0x180
Modules linked in:
CPU: 0 UID: 0 PID: 0 Comm: swapper Tainted: G        W=20
6.17.0-rc4-00275-g7b4f21f5e038 #1683 NONE
Tainted: [W]=3DWARN
Hardware name: QEMU ppce500 e5500 0x80240020 QEMU e500
NIP:  c000000001357408 LR: c000000001357c90 CTR: 0000000000000004
REGS: c00000000152bad0 TRAP: 0700   Tainted: G        W=20
(6.17.0-rc4-00275-g7b4f21f5e038)
MSR:  0000000080021002 <CE,ME>  CR: 48000448  XER: 20000000
IRQMASK: 1
GPR00: c000000001357c90 c00000000152bd70 c000000001339000 0000000000000010
GPR04: 000000000000000a 0000000000001000 0000000004000000 0000000000000000
GPR08: 0000000000000000 0000000000000002 0000000000000001 0000000000000a00
GPR12: c000000001357b68 c000000001590000 0000000000000000 0000000000000000
GPR16: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
GPR20: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
GPR24: c0000000011adb40 c00000000156b698 0000000000000002 c00000000156b4b0
GPR28: c00000000156b528 0000000000000010 0000000010000000 0000000000000170
NIP [c000000001357408] hugetlb_add_hstate+0xc0/0x180
LR [c000000001357c90] hugepagesz_setup+0x128/0x150
Call Trace:
[c00000000152bd70] [c000000000f27048] __func__.0+0x0/0x18 (unreliable)
[c00000000152be10] [c000000001357c90] hugepagesz_setup+0x128/0x150
[c00000000152be80] [c00000000135841c] hugetlb_bootmem_alloc+0x84/0x104
[c00000000152bec0] [c00000000135143c] mm_core_init+0x30/0x174
[c00000000152bf30] [c000000001332ed4] start_kernel+0x540/0x880
[c00000000152bfe0] [c000000000000a50] start_here_common+0x1c/0x20
Code: 2c09000f 39000001 38e00000 39400001 7d00401e 0b080000 281d0001=20
7d00505e 79080020 0b080000 281d000c 7d4a385e <0b0a0000> 1f5a00b8=20
38bf0020 3c82ffe8
---[ end trace 0000000000000000 ]---


> ---
>   mm/hugetlb.c | 2 ++
>   1 file changed, 2 insertions(+)
>=20
> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
> index 1e777cc51ad04..d3542e92a712e 100644
> --- a/mm/hugetlb.c
> +++ b/mm/hugetlb.c
> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>  =20
>   	BUILD_BUG_ON(sizeof_field(struct page, private) * BITS_PER_BYTE <
>   			__NR_HPAGEFLAGS);
> +	BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLIO_ORDER);
>  =20
>   	if (!hugepages_supported()) {
>   		if (hugetlb_max_hstate || default_hstate_max_huge_pages)
> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int order)
>   	}
>   	BUG_ON(hugetlb_max_hstate >=3D HUGE_MAX_HSTATE);
>   	BUG_ON(order < order_base_2(__NR_USED_SUBPAGE));
> +	WARN_ON(order > MAX_FOLIO_ORDER);
>   	h =3D &hstates[hugetlb_max_hstate++];
>   	__mutex_init(&h->resize_lock, "resize mutex", &h->resize_key);
>   	h->order =3D order;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
e043453-3f27-48ad-b987-cc39f523060a%40csgroup.eu.
