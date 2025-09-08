Return-Path: <kasan-dev+bncBDV2D5O34IDRBGGI7XCQMGQEMI6BH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 56C62B49D62
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 01:17:46 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b5e303fe1csf97504741cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 16:17:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757373465; cv=pass;
        d=google.com; s=arc-20240605;
        b=OCUKUg1ACMZoAhTjhtdHuI2UdKt8AnB2Jb+JxbrJHpYRFj4OZ2U5A3hPNpoV8Wfb5P
         9Zbs9HExplEPsKkYTK5/W2a9K1ADGMRN9jMOb53Cjgf55xjPnH6MjpkdQ6cGhDRnW+1U
         OpoyWzk3DwArKmyL6w1ITz5MllFlljTpSz8Q+TfYLhZYyjmnbA+aIsT/GMtHGPwxYAd9
         bx/ZevnRvTlGAFxdNAgj4wUu4xRPmquZPfvo774V1rs+PAjWXZPoyKGWdTZFGtch2sUq
         hqk9aSN5nBig97Tygaz5RzJlXItAea/Qs+TJ5AfBfo2R/TYp36GixbDp4w3PdRq1jOdk
         hIlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=88a+0k39z5p4SfmqmQN3mC2AEYQCkbJIYf5Ot25y+GI=;
        fh=G1Y3KLww9T396oGcIVVqmGvCB+REz2UyCe9Jz2xuFeE=;
        b=Aj7DPad5vZMYFcOaqip9MNFsMp4WtJL63JFeS8tdy7cLRkGCwE+u4MuOQi3I0wJA7Q
         wQhjVdMco8zhLvKBfai2v5A1tXqOhrbNiRsQtZt+112Dy1XjXSVHAkUkbW2PfAjUUrUp
         SDBnJHUt4EWkjUgRAObYK87CsmvKX1rmkhKLTjHebs7WS5BM+SIvSUjptQlgHEp2Iu2H
         sylZeWWpsUHO2fTT0WhIjQfzQOMlT/+MORa1o09SXZEBJcJUdEJxFxxiBCaGTKiHNBO2
         HmWhd3/YuouNoGfCWi5SLdurfWgmsSmuAVocenNMVLtnjSDRdUMbYyyLznrwUPTxcX4x
         idmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="o/yhZAT6";
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757373465; x=1757978265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=88a+0k39z5p4SfmqmQN3mC2AEYQCkbJIYf5Ot25y+GI=;
        b=QBtbHuKUICLhV2ltyTjJdYLPC010/3/IBFfhzaKXRjzCXdc8zwIngoXMt/n5c3Y5rA
         9r+JZffNnfdI6XYCCkv6JDYLns2OMTHWgD2MVPAheLGv+iL3fctAOAxBNsEwdvbhpwiC
         WrDmoe9lxRlZR5L5nG7xGQCn0YqsB12eEXxRptHDkPSHwCvW/bdgSXstgRGR0mgnZJaL
         S0FRpwtEelmbYhVljtIx4vnjnOwcgpYq66lyAsi72o6QKnffsxB1zFS8lMqcUUbV3Q/e
         Eb7lAj8jkcD4oosN5HS/CtXTKbUX8gs9Uumwv4IjnTH21DcQpazYLAF3zR4vLPWSeaFv
         a30w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757373465; x=1757978265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=88a+0k39z5p4SfmqmQN3mC2AEYQCkbJIYf5Ot25y+GI=;
        b=PpshsDwYm+qzMs3JI4etllkO1+GYc+wGLvu0ZOMEAE5aiAOvhnupm+7ZEAA+oo82ZZ
         psxSrMooPPpwLYmoM+a7CP3K43F8d8+D2WUeXZoX8m/YBOwH0XlVRHU2mRtR1Oh+52HL
         6qqNr8fjECsnoadIvJ8afMUzG1t/dLsl0YipxDFeq2HFmt5RkY4Q91RkG3MzpCNDI2dy
         IhtwQW5EpBNCCPtFzY2TmEJc5V2799sa/2WHABuw2J9tdJNkaZ72stBjb6vY5XCgj0WK
         hy4gfz3GDUh0rprjNdHUGdaGcr69g33pTbWRM8j6xSB8yG/7JbWwdUvMR4OlIuKJb9b9
         RCxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbQdlRFOdErHOC3ioJRnMXcN4HeAADJETOnkG2adwkQiW1nHEWFAT34iPPrmL/cP8J5G+t0g==@lfdr.de
X-Gm-Message-State: AOJu0Yyg3BtoKI5Dj3A06nKr9qjhyLOveiDpXWJMgeEoxjDerujSNqAZ
	2J89OzjW4ydISpcF6/SeNAorH3Nte9qxHsyld2hMjWpox9sO9wGo3He7
X-Google-Smtp-Source: AGHT+IHvMX2EDRmxi0oYiuTaZkC8+OZjelsoJJGWOiD7/sxU+gpdES1UjSyAksj6oHVgeLkbJHY7IQ==
X-Received: by 2002:a05:622a:2a18:b0:4b5:d5ed:e972 with SMTP id d75a77b69052e-4b5f83776e8mr115322091cf.2.1757373464869;
        Mon, 08 Sep 2025 16:17:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfSiCxfgTyUTXZ/I9eRB1KmfreEJp4V1EmRoN294FRRXw==
Received: by 2002:a05:622a:d3:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-4b5ea7fcf7cls63401081cf.0.-pod-prod-02-us; Mon, 08 Sep 2025
 16:17:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4XVRL3X9uorF53dM+fDB8aPKMUyffCZWgDkM+Zop3R35+r0dZNXtWAeGLMxd8oke1esdJ/sxTUsY=@googlegroups.com
X-Received: by 2002:a05:622a:8c8:b0:4b5:8c8:11a3 with SMTP id d75a77b69052e-4b5f843c0c0mr120110591cf.50.1757373463912;
        Mon, 08 Sep 2025 16:17:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757373463; cv=none;
        d=google.com; s=arc-20240605;
        b=DTEOhe9snW6oajlAMzTVza8/FDgV6Lmgomal/PnHi3GeeROUMgLJ0tRUeU39lBvHwP
         Py30nEILX2L4e1kfELXLEp5jA6IxgaQKrKh3IPAyEMuGQczfuj1+W2SmSMYEp7yFK0WR
         NdnqEfg8fSs5Y8hOjYqICjFDL0huOi7FypmcR0vl8PDvRLD1u1hnlR7IPKCpamj5/Vt0
         uI+mRJmSrfayqmS2vFMOIOtTw9bryfEfPXrgAJeuLoXwJOPyBbclyjIu6d0GY41RWLf1
         LC5nMYu8DqTsSeYDN6zmJ9c0syiBwllMbcr6Bt6ncSehBSF2wmLmU5kSGKTJQ/8kW/Lg
         ydrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=CMlqYlKj+ILUokIqP1ABAMFD7Ot5oBLbcsJFMFm2zE0=;
        fh=vE//gYcdDTzwUu6ZacqbisgC57IFOdOoISwcuapz7x4=;
        b=f3bZFZVBHSxP/NZRChzDn2DXbij5C6XswPjPVs0oRUtj3JHyt1ObhL7Yj8Q3/INCJQ
         +LBcY6OAbkG5562w0XEjOVRCTi66KaOp4LbHmLyCnISDbBC/DaPGQSJ0NoeMNdjemEwr
         hwqWkWl2FlAGtYw6WfmhByBc0iKr79pYVikCAQQm8aVd2iZ83Pb5KFsSp55al/E7//2p
         uOW1P9AJ3f8Tta6UTO+uxcIAIAp86pLhylA/j7s6fI+vBnm020KNNpOm9+HU952mTTTs
         rqiKSsfJJMVdFedmsvEsZ4TbxxZ1PSJzm86mimJ2gAePIh/VMG3H80zao5Uh9Lrjd0O5
         wLgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="o/yhZAT6";
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b61b92f953si199751cf.0.2025.09.08.16.17.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 16:17:43 -0700 (PDT)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.25.54] (helo=[192.168.254.17])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uvl6s-00000002unf-1xHe;
	Mon, 08 Sep 2025 23:17:18 +0000
Message-ID: <c0d7df5f-ac43-4e15-8400-155bf87d5e77@infradead.org>
Date: Mon, 8 Sep 2025 16:17:16 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 07/16] doc: update porting, vfs documentation for
 mmap_[complete, abort]
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>,
 Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>, David Hildenbrand <david@redhat.com>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com,
 Jason Gunthorpe <jgg@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <1ceb56fec97f891df5070b24344bf2009aca6655.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <1ceb56fec97f891df5070b24344bf2009aca6655.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b="o/yhZAT6";
       spf=none (google.com: rdunlap@infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
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

Hi--

On 9/8/25 4:10 AM, Lorenzo Stoakes wrote:
> We have introduced the mmap_complete() and mmap_abort() callbacks, which
> work in conjunction with mmap_prepare(), so describe what they used for.
> 
> We update both the VFS documentation and the porting guide.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>  Documentation/filesystems/porting.rst |  9 +++++++
>  Documentation/filesystems/vfs.rst     | 35 +++++++++++++++++++++++++++
>  2 files changed, 44 insertions(+)
> 

> diff --git a/Documentation/filesystems/vfs.rst b/Documentation/filesystems/vfs.rst
> index 486a91633474..172d36a13e13 100644
> --- a/Documentation/filesystems/vfs.rst
> +++ b/Documentation/filesystems/vfs.rst

> @@ -1236,6 +1240,37 @@ otherwise noted.
>  	file-backed memory mapping, most notably establishing relevant
>  	private state and VMA callbacks.
>  
> +``mmap_complete``
> +	If mmap_prepare is provided, will be invoked after the mapping is fully

s/mmap_prepare/mmap_complete/ ??

> +	established, with the mmap and VMA write locks held.
> +
> +	It is useful for prepopulating VMAs before they may be accessed by
> +	users.
> +
> +	The hook MUST NOT release either the VMA or mmap write locks. This is

You could also do **bold** above:

	The hook **MUST NOT** release ...


> +	asserted by the mmap logic.
> +
> +	If an error is returned by the hook, the VMA is unmapped and the
> +	mmap() operation fails with that error.
> +
> +	It is not valid to specify this hook if mmap_prepare is not also
> +	specified, doing so will result in an error upon mapping.

-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c0d7df5f-ac43-4e15-8400-155bf87d5e77%40infradead.org.
