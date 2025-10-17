Return-Path: <kasan-dev+bncBCT4XGV33UIBBFXOZLDQMGQE4BF5EOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb138.google.com (mail-yx1-xb138.google.com [IPv6:2607:f8b0:4864:20::b138])
	by mail.lfdr.de (Postfix) with ESMTPS id 475E9BEBD21
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 23:37:28 +0200 (CEST)
Received: by mail-yx1-xb138.google.com with SMTP id 956f58d0204a3-63e08ae023csf4223543d50.1
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 14:37:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760737047; cv=pass;
        d=google.com; s=arc-20240605;
        b=XZvp9A83FdrFeEeuI7rpDFJj6DztStqjDbgJkTAyMIW5mi1RCdHGik03TQyGZt/e7K
         To8sU8TUEO3Hdq1VlfQYlreoZQlGJ9zw2M0vGnH8rh4Cr45TYI2Q1dtQn2dXDqAO9h3V
         unMG+ig19OqQ3tJ0X3UIe+hZJyTUrkdBOA02sO/caCfDNLojrZo8AEuUtckpQptE4Sby
         DARTAF5nTA4XdpXAIFZr3eFAb09Slu3F70rnpgX/wZnHoBJNTn6zRcidjCSyuvhCkHGG
         JIHfssAphfy6JX0MlyhZC9rqk3eoSDBu25JilXhbiPkXEZ7fcXmgmykMAQicwDppE/O1
         l9fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=sFp2C9+Oo19s2mBhJlaKLtIURtHFn9d7KqHnJS2/7mY=;
        fh=Ggn/RgiRVLLyuI/i65C7jGAPz7ADJymrqW8yQLmRANc=;
        b=C+V9UKGo/CzzivBzFreUOk6LLg6xfJ1iylEEAyQtehqCzVq6coPyqeSXbEvebV+ptG
         mpLi12yQBhKKpr61xf8cjJnv73qZfKriRiEvFlxFeIloXRkGPPo4mm4ZmEG4MnhGjkPw
         +RwgNvb2GWJ3YYYJyHNAukJEPu1m21V72DM7XDUj8OwJp+oHDsfyu/zKWFRpVEDwJ0by
         g1gxC6lZsOUjmwwR8/vLezyG87p5z9INup5SWQuikLq9o32YqYaF6BAIySvB16bwQGka
         525q8f7EpyLGDh/WFmvc7o4C8YSEKY9Sdaft6dp24blryRDW/bfrNT+2aChnPTssx9eU
         H5RQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FE1dBvUV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760737047; x=1761341847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sFp2C9+Oo19s2mBhJlaKLtIURtHFn9d7KqHnJS2/7mY=;
        b=qVP2rzCjL4rL9lQnCIOJ7ASQGr92QCd0QOeEsDebUl7ZJs5jZDTrNMhf9W9oFhqjZx
         cPLvpam/JS6OGhGJwR5HUtWzfkb7VLfqHurLtAQVUwBlqzegs8XZmm4O4HE1L6gFgX+1
         sdR9q1cj8SPAMr3CFdHZ92FaT94oKEX6YqYEtWZyd3Q77W1R68nMfLoTMjMQaHoUYKZP
         n9Gctokf/rrrHzQ7NG+RsogP0nzlaUk2IFn1oLmnFGD7EBxRFxBhrHDf7Ap51BaeHIFO
         3XhqSoJEWOKzsZTNSe0j6W5y2qioG8iRWWsgmy+0qFxWJZAB2Dwib2fq13/vtOeQ+46w
         CJUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760737047; x=1761341847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sFp2C9+Oo19s2mBhJlaKLtIURtHFn9d7KqHnJS2/7mY=;
        b=dOuYEwrmGWOAAPPTHzWF6daz/lWgXBF4MMeogw36jw4YV+h1HWJ9rSJNOolcTKr/Et
         HRe6rxeTNMR9qCvTr2Gor62bhrrGLQAQgCQA259YTj17hZlP86QEMi+vREueVg6z4CfM
         AX+pvCaMYpHpzpcvwDhmwGqFZXjz28L92JlkfJKfEuZ3BN6ICaAzCR7p2CUNPqjOTazK
         BtlFq6YW6Cq+7fTiPthJOTgiVBBsr/mltwI47ngoCPjZEYCNiiWa9dNQapR3hxLkPS0N
         PkTpWPXXQ5FSqBEGqt3wtHxkbU0YTSfnSfLte4gMMXxEfXCV0dIOzThgf3Yw9Grc8IhH
         VjAQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXCcW5sg9iVZQmnu2xAvcXkkdSR/RDNX568qfUwht4brodo9FFUzRUYpNn7wWeA8Vildo9uXg==@lfdr.de
X-Gm-Message-State: AOJu0YwSgxbpl1MNwpCsy0mbIbGxRpLZ8A6wjvbHywBvrv6erAzW7bu4
	kWuskRHWZ9eaVoIEetFGvNRo56KfBkJ1oOapa1pUCJCQnnn19dxutqtY
X-Google-Smtp-Source: AGHT+IG2o2SDtPQcblNkfLX9Z+x1yg98+xpBlqn6gQfR+ee2v17ZAjOMGmZ+g2c57uKadbISN0SHmw==
X-Received: by 2002:a05:690e:1248:b0:63e:1e1b:d6fa with SMTP id 956f58d0204a3-63e1e1bf8cemr2254565d50.30.1760737046846;
        Fri, 17 Oct 2025 14:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5MsyfbNeqsd2YhPJrJHd+mrGQDynL2F/eVF1G3YiPTSQ=="
Received: by 2002:a53:c053:0:10b0:63e:195f:cff0 with SMTP id
 956f58d0204a3-63e195fd21als569406d50.0.-pod-prod-00-us-canary; Fri, 17 Oct
 2025 14:37:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTPuMtsyz3oSDMEp9b6ho3WazKIVcQE3/OVbVq3xOz1HlFO8CMT+8dp64NED6zn7OOnk1/DixvpYU=@googlegroups.com
X-Received: by 2002:a05:690c:6288:b0:738:a712:6972 with SMTP id 00721157ae682-7836ccb874amr53865657b3.12.1760737045906;
        Fri, 17 Oct 2025 14:37:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760737045; cv=none;
        d=google.com; s=arc-20240605;
        b=j8zmisUDAWn0N07asbDtvj4IiZmhXwTchx559iCOwstspmmKb3xvq5/T7ohMbJfS/F
         bU1O3Tj6mMJK3YZ1hEFl8IK5l2VxfeocOQyRU2kvC8v1SPWT2FNWhKt6vSAFrQ0r8tAx
         G4p5U5/w7wPqjQ/Iv3zt4JkDNeYvDUwZ/h1UrWcEYAZykQVwFS2vLOYrYVZOiSFQyvWR
         Nc9NrG3tOKjaS0X23PwqF1qBxSFs2NhzQ1KTuA+ZiIUYUCa4b4bQ3nCd3KXleWh0G8+s
         wh0Cl1MdKK1WlAJ0tUQlzQYaZorFmhWt7F+kf/TXNJ6KHPrfkZTIqMt9ETc1hGV04Rpn
         CHLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=S9EkNhymVLMKxTXl4lXZBEsZGNtUn/k0HTojV8R9ID0=;
        fh=FEOUSDLUpbUwMbKAw4qZAkpK8Tofk8rF8+Nt26NCdsQ=;
        b=MNOaUwYnImWBF5CStB+B3uZaN9823GBriVODSwHeRy34RXzRSNH8zBI1Lwe8mvHM58
         n0Bl9ffQ8I6Y8TyGZ3FkLQ1x0jrQ1wSEuYk2gwIml9yBZE8xFsdIyW61DbUqqK2TWFNh
         prBkze0gkCxCarBSEdChm8sO56kV8v9kT/Yn87dsqRfJXXENtjMtIIVlJ7aaANj8dRtD
         ILxMlq/5kal0vVvjYJWnLx8xDSoEuhasqd4e/9+kH+c9WB1EN8buGDj2hVTNtVEmqNzN
         nh2C/OyiWSx4xeXgtZBWG/OHaXMEqj3WPP+5oNrUhnfV2QYrBjeZ0Rpc0nTDu++QIYGv
         WRUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FE1dBvUV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-784673cb452si331997b3.2.2025.10.17.14.37.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Oct 2025 14:37:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D2A714B5CB;
	Fri, 17 Oct 2025 21:37:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C7221C4CEE7;
	Fri, 17 Oct 2025 21:37:22 +0000 (UTC)
Date: Fri, 17 Oct 2025 14:37:22 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Sumanth Korikkar <sumanthk@linux.ibm.com>, Jonathan Corbet
 <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>, Guo Ren
 <guoren@kernel.org>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Heiko
 Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, Alexander
 Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger
 <borntraeger@linux.ibm.com>, Sven Schnelle <svens@linux.ibm.com>,
 "David S . Miller" <davem@davemloft.net>, Andreas Larsson
 <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman
 <gregkh@linuxfoundation.org>, Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>, David Hildenbrand <david@redhat.com>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>, Baoquan He
 <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>, Dave Young
 <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>, Reinette Chatre
 <reinette.chatre@intel.com>, Dave Martin <Dave.Martin@arm.com>, James Morse
 <james.morse@arm.com>, Alexander Viro <viro@zeniv.linux.org.uk>, Christian
 Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, "Liam R . Howlett"
 <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport
 <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
 <mhocko@suse.com>, Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>, Pedro Falcato
 <pfalcato@suse.de>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
 nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
 ntfs3@lists.linux.dev, kexec@lists.infradead.org,
 kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
 iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>, Will Deacon
 <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 11/14] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-Id: <20251017143722.d045a2cd9d1839803da3f28a@linux-foundation.org>
In-Reply-To: <c64e017a-5219-4382-bba9-d24310ad2c21@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
	<e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
	<aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
	<20250923141704.90fba5bdf8c790e0496e6ac1@linux-foundation.org>
	<aPI2SZ5rFgZVT-I8@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
	<c64e017a-5219-4382-bba9-d24310ad2c21@lucifer.local>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=FE1dBvUV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 17 Oct 2025 13:46:20 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:

> > The issue is reproducible again in linux-next with the following commit:
> > 5fdb155933fa ("mm/hugetlbfs: update hugetlbfs to use mmap_prepare")
> 
> Andrew - I see this series in mm-unstable, not sure what it's doing there
> as I need to rework this (when I get a chance, back from a 2 week vacation
> and this week has been - difficult :)
> 
> Can we please drop this until I have a chance to respin?

No probs, gone.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251017143722.d045a2cd9d1839803da3f28a%40linux-foundation.org.
