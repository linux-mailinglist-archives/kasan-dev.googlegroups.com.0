Return-Path: <kasan-dev+bncBDG6PF6SSYDRBXMXRXDAMGQERFOU2ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E806BB53E97
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 00:23:26 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3dbf3054ac4sf652959f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 15:23:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757629406; cv=pass;
        d=google.com; s=arc-20240605;
        b=S9tp3te1vsjkwCA4eHPdEl9LHb9Jc+TEQXMt+k1xaTjIRSjfJQU0IM2svPBAsoeQv/
         RLZvI72st7Z0c5OvMp/MqQYDW4a6SLyx6XjT6uuI8/g0m1T+FX6rNC950NQpjm4ymEdn
         l0P8U6IDtFvDlIRLKyOvZYMQpPIp9JaGp3FQ5T+qYrEkdOKsa2fGdBuQ4AR7fC+NXp/R
         Yzm2dU4jqL8jSusCXdLV3YnQdooB20CPgzo69y7AuZaunObyjQGotsLzZUzkCWOfxrNN
         xx9yqarKbzUaPXrnlx4AgyUCwMyfUYWBeGnVnSNbH+g33zYtunTfNoISXl3xiUXprvHi
         ftpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=gKaCAI1qd62cUAOk4qclAc89b0OguHem8u8lA04Eo78=;
        fh=0iR7ixV+DRXX+CE6Q0EwYXMCH4DRtr5gIlwu/sCKsk0=;
        b=Avjd+bN0Ux/cK/uwKbeMeFOpXiHMQRxLeLAt7PXNnOknmSK2b2HbhA+92VEptyUe0p
         0ldXxIYOVf0Jo6AMY/xfSWSi2sdoDb5srNcloZNxVxTlfDpX5Qo9oYbvHnqUpxv+AmVv
         nb9I+RxsKYje+fpsR2kdg2Vcewvwt4xGd8KNfwsQYs/YgKNDuS+aMim0MkrhtmapYCcv
         zBU0Q5OoDFd7/M9fSEfQF9o7HeRjCKDNYOlo+G9DrLRKIZvJi3FeIYJch30aRZn5UeFB
         HA3Mpg11WhDpDvVZ+CEilsjdqBpo4qA3umAWcba8PmE2PJkyAa743kTc1kynTdT/IVla
         vNQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="oYf4Wl/v";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757629406; x=1758234206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gKaCAI1qd62cUAOk4qclAc89b0OguHem8u8lA04Eo78=;
        b=IosQvWqX0LKLKQE8nBlK9xkAQjIbEP6VBvGkrILecY/DUs4LPOZ5TUheDqGvaIMqmx
         CQ7XPZve2ny5QVmAQLlAbJh3+66LJhvmoU/QDbfQTZcGO4x+Yrt05Hupgf8bAPRThZf9
         ww8e3MnYlEuknOKIbbF+KIc2KK67IiltmwMTtQBCa6KTc+Lgi4s29F1qTpLOPMBJ31al
         JsJtnALOpTarsXtHFEFx2BUXB0gv44kPKhnunGWDHJz7NKptE0sYooI93dfGIrY9koUg
         NLJxClt8IePUm0rj7Q8GIvyU7jBdv41PAJb705aGPKYiRX5ei3S2sV5FuHBPoFmXTuo1
         BgYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757629406; x=1758234206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gKaCAI1qd62cUAOk4qclAc89b0OguHem8u8lA04Eo78=;
        b=JAnygDREPeHd5yWMEcVErGMUSJtMVB8C7bKzTgeAVShgrpTSqDWBPzYMGakxkh7/Hd
         IrgQg9JR+/OIfOl9EWeX4enILSSwuwjteHb9cqNVfwHQT4Jcbhd/fSqWCbn/O9aJmQP5
         oY8QAhjYcsFsM4ukHyyE41jaMtxGT/oqnpkeNEa3RjCFlf+wkaN/8QPyRjQNwCuIKzSl
         da/j37SrjJKnM7ee6qjhBBBCbVWHDI+HJeVUcY4eKlPc33HlYX5bICWOZ7Cfq2SBrYrY
         WADsF+nrteKT6vo1fRRC3dmcnODFJgDO00epJd6UtCWBwhajZ+0az8yDy5DOQwdhOHfP
         5TCw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmsdzpduRvWnki8bY9pTyzw90fcvsE4jv4AIcUAVQukCn2ZpLbPy0yUpXnEs8s5Ibd3BSswA==@lfdr.de
X-Gm-Message-State: AOJu0YzmMiLchurKtDwOMB3wnSapa7kuKbdB+itVDEbZgLutkv3uBoQ9
	uZXE38OoVBgMZLPX8GlbX6cF+Ly2ihRRp6/+yNu+QjKTnHiKVf/4kiXM
X-Google-Smtp-Source: AGHT+IG97AoS6GFHeTQxhBf2xY0lbZ3zKogUrG30+JsRpwlwruhTc4f8g+KFqGURFTJggQycjQrJ3g==
X-Received: by 2002:a05:6000:290b:b0:3e7:42aa:1b3 with SMTP id ffacd0b85a97d-3e7659c1c37mr893832f8f.27.1757629406020;
        Thu, 11 Sep 2025 15:23:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4zGKoN4q5ozqlLtWFPgWOfu0s8rOGCudv2rwNeOd5M1g==
Received: by 2002:adf:fe4c:0:b0:3e7:63b9:afd5 with SMTP id ffacd0b85a97d-3e763b9bf2als288070f8f.1.-pod-prod-08-eu;
 Thu, 11 Sep 2025 15:23:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGuunuZwu7ltCUgFH5mT4sZe4+yW+MNNjtTrAGtNbcmuV58Cr9OJT9VCyZa0nIAq0rgN/YvwpHx6M=@googlegroups.com
X-Received: by 2002:a05:6000:2403:b0:3e7:486b:45b0 with SMTP id ffacd0b85a97d-3e7658bc32dmr777113f8f.26.1757629403026;
        Thu, 11 Sep 2025 15:23:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757629403; cv=none;
        d=google.com; s=arc-20240605;
        b=cdea27P1NQgy6Hw+uwYUwOnwbOBLMi/a+tPzQ47OWk+NPAdomy8Thcty2fABkFwBd3
         YTfQVfP0g9xT73wD9f5xFOtp5O4kfhLvH+Al3ImsMJBYbmsB6wPE4pCvN4NDosFw1Q6s
         B4IrbdOmGrbitiYqXkYsP4C84Gz5jlsB++/rQSDCpAcUfloBdOPtX8eATIYi/msMHACl
         K/atZU3Dirlg2DrQoqZiBdxfd8psySwQY5329zq3AlmRuS00BhEmNszCBvg2FTBHpjY4
         Kt6L/pyExWnXH73djPxaF7B82qUM0WLoomMt8Bm+2C8iJk74dxM1MjvhybNwteDvaZr/
         nHqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=9atdt/om7OmffbDgov9WTxIsiO59X0BmEMtINP1uP9A=;
        fh=7WVQAQokcltWARD9cjMeQiAwgWq6NbUWVhbXV4o034s=;
        b=iQOzlg+uv/8KyPPKh84oc4/ntKgL8gvXvOkWnDVWThuCcH6zDHzOI4TyRTVY1G3C7z
         Ir3gB51+aqZYaDB4JnvNpafpWX1Tp5g6dJhYlSLkrIfOXYLTzSIshJ9YmD2h8/r8NTn/
         BbR+B5HZW1ebqvntQiKN0AZMxrB97moc8O1diLU+nROzWUK9fTpaeEnIhuYEy8z4koG+
         KfOI6Wsb4NEl3QLeFGACDWUuLavWssLuZuMDlnQD5G2SGuYQX7egey4H5uSoxZNUFqq0
         bV0yGox7j+uGsLfhqjKC+OQrrcZZIIhjRxf0kWZUKQDFONi2+pre7Uxhg8U3nEIoMv+6
         +BUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="oYf4Wl/v";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e760816158si60838f8f.7.2025.09.11.15.23.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Sep 2025 15:23:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250911222322euoutp011634560d57af0d6769ea82508ee6c7b3~kWqER7Qs81513015130euoutp01K;
	Thu, 11 Sep 2025 22:23:22 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250911222322euoutp011634560d57af0d6769ea82508ee6c7b3~kWqER7Qs81513015130euoutp01K
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250911222321eucas1p114043a72e011e2fff92df33a2133b21e~kWqDhtt8p0600006000eucas1p18;
	Thu, 11 Sep 2025 22:23:21 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250911222317eusmtip2aabd06b78078a7146730dff557f2cb71~kWqAG3AB-1019110191eusmtip2F;
	Thu, 11 Sep 2025 22:23:17 +0000 (GMT)
Message-ID: <5ffc63e9-19bd-4e12-92fc-57fe12d10f4f@samsung.com>
Date: Fri, 12 Sep 2025 00:23:17 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v6 03/16] dma-debug: refactor to use physical addresses
 for page mapping
To: Leon Romanovsky <leon@kernel.org>
Cc: Jason Gunthorpe <jgg@nvidia.com>, Abdiel Janulgue
	<abdiel.janulgue@gmail.com>, Alexander Potapenko <glider@google.com>, Alex
	Gaynor <alex.gaynor@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>, David
	Hildenbrand <david@redhat.com>, iommu@lists.linux.dev, Jason Wang
	<jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joerg Roedel
	<joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>, Juergen Gross
	<jgross@suse.com>, kasan-dev@googlegroups.com, Keith Busch
	<kbusch@kernel.org>, linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org, Madhavan Srinivasan
	<maddy@linux.ibm.com>, Masami Hiramatsu <mhiramat@kernel.org>, Michael
	Ellerman <mpe@ellerman.id.au>, "Michael S. Tsirkin" <mst@redhat.com>, Miguel
	Ojeda <ojeda@kernel.org>, Robin Murphy <robin.murphy@arm.com>,
	rust-for-linux@vger.kernel.org, Sagi Grimberg <sagi@grimberg.me>, Stefano
	Stabellini <sstabellini@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <20250910052618.GH341237@unreal>
X-CMS-MailID: 20250911222321eucas1p114043a72e011e2fff92df33a2133b21e
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250910052628eucas1p160daa0dadb6f81d7831d8047628aa9d4
X-EPHeader: CA
X-CMS-RootMailID: 20250910052628eucas1p160daa0dadb6f81d7831d8047628aa9d4
References: <cover.1757423202.git.leonro@nvidia.com>
	<56d1a6769b68dfcbf8b26a75a7329aeb8e3c3b6a.1757423202.git.leonro@nvidia.com>
	<20250909193748.GG341237@unreal>
	<CGME20250910052628eucas1p160daa0dadb6f81d7831d8047628aa9d4@eucas1p1.samsung.com>
	<20250910052618.GH341237@unreal>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b="oYf4Wl/v";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates
 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

On 10.09.2025 07:26, Leon Romanovsky wrote:
> On Tue, Sep 09, 2025 at 10:37:48PM +0300, Leon Romanovsky wrote:
>> On Tue, Sep 09, 2025 at 04:27:31PM +0300, Leon Romanovsky wrote:
>>> From: Leon Romanovsky <leonro@nvidia.com>
>> <...>
>>
>>>   include/linux/page-flags.h         |  1 +
>> <...>
>>
>>> --- a/include/linux/page-flags.h
>>> +++ b/include/linux/page-flags.h
>>> @@ -614,6 +614,7 @@ FOLIO_FLAG(dropbehind, FOLIO_HEAD_PAGE)
>>>    * available at this point.
>>>    */
>>>   #define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
>>> +#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))
>> This was a not so great idea to add PhysHighMem() because of "else"
>> below which unfolds to maze of macros and automatically generated
>> functions with "static inline int Page##uname ..." signature.
>>
>>>   #define folio_test_highmem(__f)	is_highmem_idx(folio_zonenum(__f))
>>>   #else
>>>   PAGEFLAG_FALSE(HighMem, highmem)
> After sleeping over it, the following hunk will help:
>
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index dfbc4ba86bba2..2a1f346178024 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -614,11 +614,11 @@ FOLIO_FLAG(dropbehind, FOLIO_HEAD_PAGE)
>    * available at this point.
>    */
>   #define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
> -#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))
>   #define folio_test_highmem(__f)        is_highmem_idx(folio_zonenum(__f))
>   #else
>   PAGEFLAG_FALSE(HighMem, highmem)
>   #endif
> +#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))
>
>   /* Does kmap_local_folio() only allow access to one page of the folio? */
>   #ifdef CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP

Okay, I will add this fixup while applying the patches.

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5ffc63e9-19bd-4e12-92fc-57fe12d10f4f%40samsung.com.
