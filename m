Return-Path: <kasan-dev+bncBCJNVUGE34MBBGODWHDAMGQEMZE4IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 70DDAB86BFE
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 21:46:35 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-893658a9acesf143823539f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 12:46:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758224794; cv=pass;
        d=google.com; s=arc-20240605;
        b=jqJeaOAGNAL9EmH2odUqlEctgnmq2AAZxnjS4NvVe47LHXc6UAaQi5CUtHPJ6OAkqA
         ASJfKqgt8m9Gnkrw7wFpedJJtqvsiXiQ6WHFPmP3WDmA8ZejyXbUzmkwnmVW85Bi6JnN
         xrglbHWuuH3MdRrNHCCdm6sTI0YqT6BLeYgpKJ7g50pfg1frNVjXSISNVMkG2U9VKCsA
         ZgmjNIrVitCfXDrpCrlUAWX2bdLYMl/AkBJBCaPwGmYIoJUv8i7/Y/RRJQZxIxxGRFyx
         9rvOmE4nGP8WljonUhpzjIE81Tw8p06WT8dxjc/0Cjit7jNWvcNcvRblFXQ7gvxgxF0z
         5QpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fcglzz0aAwKpdZjQwdZkk5DnohKfC0qBN63kNZgmU7o=;
        fh=Z4T4t/JUR3CguI8Z7Xwa0KjTz+QiYMW0hpz5qEuSrDU=;
        b=jqKQCeczH1l+nJeFlHiew4BnTTV9zMpdiC9NtiLRQsBCt7v2YjVyoiAF94S2FuNHVw
         QuhpFg/67YoetScIEgHXz+DGM7Ez59c+J793cSC/9QyG1jROwoo4JwDZpOQNEt4PZSEo
         cyOfTLoFMW57FDXEayUgTrxovkPmq9HE6Zvz0cwdzNrTp7hZQe9AIaAz5HRztnuN/NO+
         zXxoF6hhs+W6DQVlO8fJPlwVz7LQU76Y2NKtjUHyL7ZOf7y8sodzQhCVoVqV3vPjAiK7
         BbuszO1YLCPceM0fQw3uAuXmBVuA7hwfl5cKhsl2y9ojYM7dshkjHYrwWTu3GeN6DBkf
         TGHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=oUvgxHX4;
       spf=pass (google.com: domain of prvs=5356f0da48=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=5356f0da48=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758224794; x=1758829594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fcglzz0aAwKpdZjQwdZkk5DnohKfC0qBN63kNZgmU7o=;
        b=jNSY8BVdBWAel44m5AdpZ69F1qnpZ/qTG7dmgvqPWQ9v7/IT8izfRo1Chbb0+DF8n9
         5s+2a5dW1M4fMjBDj9guXdpFw/v15Ya+ucaHHAXYmMZ7jRcTFEkEn98j1+WNxyFacztt
         BOEsKdB5YtcvlM5QLYZ/Ho+lMD5ohBRnb3LYnln3UmngbRftkEFFuyCHcLWP0axtXxsH
         GrIOOo8uq8tzGZTjAt6RULfOnIK7DxeiAomxB5AWZgjlDFB6wQFlpp+HdBeyvpeROiRl
         4jWAdnLhKR4nRSGZpjRcHLH8SuzPvUNvckLqI2s6SLoaHWfk1Js2JpjqdvdUjqd14eqX
         Dj6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758224794; x=1758829594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fcglzz0aAwKpdZjQwdZkk5DnohKfC0qBN63kNZgmU7o=;
        b=eV5QudsNCaHNJnnC5qREpYcr98cG+n+exKjfV0aafA6KXQF+NGPhK4EOSYutyM/ygY
         qGzgCSg15RELk2mn4GYqmyttOrck5UD14eiMqB47wLiReU6Dngovrf6h4g7pu09umt8D
         L5xVul4btJtEWHHmYtGSDl1NoGBa9Fr6u0+KFERN5Il/0j3JP4c3+zP25xuBdpFDqPhW
         NO0VMSqWvIu3Aq+Yh1ta0S186ADbNPL5T35/hr4UFT22c8HSpiD9j8JWaTbw4a8kpOEc
         9qa+6a3Rf/XmbSyVOnIQLFIZHqyWLAONR1I06dcXImtSFiIZgcA7QNhRTQpdpxxJZiug
         R0Dw==
X-Forwarded-Encrypted: i=2; AJvYcCWbvCsMbi7Kifm+HW48szJwdXAApQENV4URuSU70zZhSzDZWy/BCQf4lQ/dlg72EtYFxP6LWg==@lfdr.de
X-Gm-Message-State: AOJu0YyVlV0vIxOM2jc+IZGI2spKldX2hQtRPdc3vhEEo7SbGp2bqhOO
	63TQ8Xuj+W3UQ1GsQa3RBBGKPJg+2KLj7cL88A+BWTP0gR1zhgKsxHgv
X-Google-Smtp-Source: AGHT+IFw9bXon9rcK5wOdInOqF0wrVGZfJcW7qsW97JaSl+BHOa926QuIXnNVSxSnmFQ0VaTdaMHaw==
X-Received: by 2002:a05:6e02:1a8d:b0:3f2:a7ef:bd88 with SMTP id e9e14a558f8ab-42481911aadmr11853635ab.5.1758224793489;
        Thu, 18 Sep 2025 12:46:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7MiwHAkrx1bY/3IyXO+jpzQnJDUcsqHHetWsHsmjdIcA==
Received: by 2002:a05:6e02:df3:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-4244da2edfcls9433175ab.2.-pod-prod-06-us; Thu, 18 Sep 2025
 12:46:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVs3fmsDzRWVkHKCHO0jhSpUV11dmcW4YRr2o0kya4kZSDSmNUOPw45Vf3+TVXHM6ojAkyBc0nGaEA=@googlegroups.com
X-Received: by 2002:a05:6e02:1a08:b0:424:7e36:f863 with SMTP id e9e14a558f8ab-424819ab873mr12055435ab.30.1758224792351;
        Thu, 18 Sep 2025 12:46:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758224792; cv=none;
        d=google.com; s=arc-20240605;
        b=ebslR05azJbKFN2DiYosOaxMmB8vnb74DP6k+NT+RMAVQA3WZ6lBTyeJXHGEHBCdcC
         d5jcb8Xhy80+WCh99opu19LGAodD16nDJ9+20uUD9OPlTsM1UpgWD6jrDb+7zDUjXJkW
         wokdcvXZlELfqbgIg68kk72g/Tkt390DmTu0f1apoopZANYdkzJ/qniTfJxBR2TDUb6g
         FgwtvocGJf+HWct3zqw8YTY7TAm+DcJWrEB/PRQauwf3qnSaAuF1JeNTR8irnQcA9LlC
         gyUNFHs58VGvWHM+pEpk0IWmy4ZZGyFK24kf9ff9AJE4fX2472h1GtCsB1BiEfxomheX
         Er1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BNnQo0sMp5meQ8eMdhpYCpDIuJZVf4B2s9e5frOewII=;
        fh=TbPVaglT1XXw1caSS86THbeGwBaPNlarBYV8UySgShw=;
        b=OiPKKUcPBBo7cBmqYnoKNHBa9GeQc/tTRrwkhpRfZ6KF/+qOu1ZqrGKp3MxY2X6JT+
         xLC/DOpEfrHAozSDfGbaiXktjOvWcHhMACPXpAeTXFPvf9+uOZqfl216eB90002RqOET
         IQK9o3RUHuqI75yQiqRwJ/QOEcemyfPM3yYhW2/QFe/Fw0c+3JN4qlknqtzD1OD9pm2h
         OaYySjQE32fB+D3iNVSuo1nK//NjhoEJj3i2pIIIhXIkdvvbHoUCUjxASKR376ftT09u
         poQYDFrYMRDIFnLlzWbFiS1uSXSbxRxjoQWMB5zc8BkzeYBLO09Hzn2VfPhcoZ9vK1S0
         8w5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=oUvgxHX4;
       spf=pass (google.com: domain of prvs=5356f0da48=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=5356f0da48=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244a36a70dsi1264905ab.2.2025.09.18.12.46.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Sep 2025 12:46:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=5356f0da48=clm@meta.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0109333.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 58IEpiMR2943542;
	Thu, 18 Sep 2025 12:46:16 -0700
Received: from maileast.thefacebook.com ([163.114.135.16])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 498m7fjkq1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Thu, 18 Sep 2025 12:46:16 -0700 (PDT)
Received: from devbig091.ldc1.facebook.com (2620:10d:c0a8:1b::30) by
 mail.thefacebook.com (2620:10d:c0a9:6f::8fd4) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.2562.20; Thu, 18 Sep 2025 19:46:14 +0000
From: "'Chris Mason' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
CC: Chris Mason <clm@meta.com>, Andrew Morton <akpm@linux-foundation.org>,
        Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
        "Thomas
 Bogendoerfer" <tsbogend@alpha.franken.de>,
        Heiko Carstens
	<hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev
	<agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller"
	<davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann
	<arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        "Dan
 Williams" <dan.j.williams@intel.com>,
        Vishal Verma
	<vishal.l.verma@intel.com>,
        Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre
	<nico@fluxnic.net>,
        "Muchun Song" <muchun.song@linux.dev>,
        Oscar Salvador
	<osalvador@suse.de>,
        "David Hildenbrand" <david@redhat.com>,
        Konstantin
 Komarov <almaz.alexandrovich@paragon-software.com>,
        Baoquan He
	<bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
        Dave Young
	<dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
        Reinette Chatre
	<reinette.chatre@intel.com>,
        "Dave Martin" <Dave.Martin@arm.com>,
        James Morse
	<james.morse@arm.com>,
        "Alexander Viro" <viro@zeniv.linux.org.uk>,
        Christian
 Brauner <brauner@kernel.org>, "Jan Kara" <jack@suse.cz>,
        "Liam R . Howlett"
	<Liam.Howlett@oracle.com>,
        "Vlastimil Babka" <vbabka@suse.cz>, Mike Rapoport
	<rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>,
        Michal Hocko
	<mhocko@suse.com>, Hugh Dickins <hughd@google.com>,
        Baolin Wang
	<baolin.wang@linux.alibaba.com>,
        "Uladzislau Rezki" <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        "Andrey Konovalov"
	<andreyknvl@gmail.com>,
        Jann Horn <jannh@google.com>, Pedro Falcato
	<pfalcato@suse.de>,
        <linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
        <linux-fsdevel@vger.kernel.org>, <linux-csky@vger.kernel.org>,
        <linux-mips@vger.kernel.org>, <linux-s390@vger.kernel.org>,
        <sparclinux@vger.kernel.org>, <nvdimm@lists.linux.dev>,
        <linux-cxl@vger.kernel.org>, <linux-mm@kvack.org>,
        <ntfs3@lists.linux.dev>, <kexec@lists.infradead.org>,
        <kasan-dev@googlegroups.com>, Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH v2 16/16] kcov: update kcov to use mmap_prepare
Date: Thu, 18 Sep 2025 12:45:38 -0700
Message-ID: <20250918194556.3814405-1-clm@meta.com>
X-Mailer: git-send-email 2.47.3
In-Reply-To: <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [2620:10d:c0a8:1b::30]
X-Proofpoint-ORIG-GUID: -nb3wVnAtqomihwZ5BzjAk2px7ex6dUi
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE4MDE3NiBTYWx0ZWRfX4Y8q+OJtcR0W
 +oYOau8ot7ilGTzu5PMGr/c3x1bedT9B3gqOZHC7hM/Xi6+uaY0+lHxn/Ka9lE213kL68CII/7K
 z3B5d+3wpbiSc/ygeHsIhiWDxHAwN+fGFwFsRE7UhGTUUvWkFkY05ELfd3kxwScqvazqt9rbonW
 bOXl1lczG5Z9G+teTpxDti5TNxhuajRiwYF0JOVA2rBw9NRviqGPh4HP+n9iXtIIMtm1GoToIaT
 Hu39ICr9dMFPAjamuD3EgvUaHLFY/4+APB4u9SBfeGw7HWZlMuLwY/AgydoBSK6opKQCrvQOWH5
 3JASKIaygraugixdHv8cWWJX9wRaKGzhstUShrgPXa9rw8BJZv52JiSljT0Adk=
X-Authority-Analysis: v=2.4 cv=G6AcE8k5 c=1 sm=1 tr=0 ts=68cc6188 cx=c_pps
 a=MfjaFnPeirRr97d5FC5oHw==:117 a=MfjaFnPeirRr97d5FC5oHw==:17
 a=yJojWOMRYYMA:10 a=yPCof4ZbAAAA:8 a=auZRGODfdbgPxNsHCnAA:9
X-Proofpoint-GUID: -nb3wVnAtqomihwZ5BzjAk2px7ex6dUi
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-18_02,2025-09-18_02,2025-03-28_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=oUvgxHX4;       spf=pass
 (google.com: domain of prvs=5356f0da48=clm@meta.com designates 67.231.145.42
 as permitted sender) smtp.mailfrom="prvs=5356f0da48=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
X-Original-From: Chris Mason <clm@meta.com>
Reply-To: Chris Mason <clm@meta.com>
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

On Wed, 10 Sep 2025 21:22:11 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:

> We can use the mmap insert pages functionality provided for use in
> mmap_prepare to insert the kcov pages as required.
> 
> This does necessitate an allocation, but since it's in the mmap path this
> doesn't seem egregious. The allocation/freeing of the pages array is
> handled automatically by vma_desc_set_mixedmap_pages() and the mapping
> logic.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>  kernel/kcov.c | 42 ++++++++++++++++++++++++++----------------
>  1 file changed, 26 insertions(+), 16 deletions(-)
> 
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 1d85597057e1..2bcf403e5f6f 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -484,31 +484,41 @@ void kcov_task_exit(struct task_struct *t)
>  	kcov_put(kcov);
>  }
>  
> -static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
> +static int kcov_mmap_error(int err)
> +{
> +	pr_warn_once("kcov: vm_insert_page() failed\n");
> +	return err;
> +}
> +
> +static int kcov_mmap_prepare(struct vm_area_desc *desc)
>  {
>  	int res = 0;
> -	struct kcov *kcov = vma->vm_file->private_data;
> -	unsigned long size, off;
> -	struct page *page;
> +	struct kcov *kcov = desc->file->private_data;
> +	unsigned long size, nr_pages, i;
> +	struct page **pages;
>  	unsigned long flags;
>  
>  	spin_lock_irqsave(&kcov->lock, flags);
>  	size = kcov->size * sizeof(unsigned long);
> -	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
> -	    vma->vm_end - vma->vm_start != size) {
> +	if (kcov->area == NULL || desc->pgoff != 0 ||
> +	    vma_desc_size(desc) != size) {
>  		res = -EINVAL;
>  		goto exit;
>  	}
>  	spin_unlock_irqrestore(&kcov->lock, flags);
> -	vm_flags_set(vma, VM_DONTEXPAND);
> -	for (off = 0; off < size; off += PAGE_SIZE) {
> -		page = vmalloc_to_page(kcov->area + off);
> -		res = vm_insert_page(vma, vma->vm_start + off, page);
> -		if (res) {
> -			pr_warn_once("kcov: vm_insert_page() failed\n");
> -			return res;
> -		}
> -	}
> +
> +	desc->vm_flags |= VM_DONTEXPAND;
> +	nr_pages = size >> PAGE_SHIFT;
> +
> +	pages = mmap_action_mixedmap_pages(&desc->action, desc->start,
> +					   nr_pages);

Hi Lorenzo,

Not sure if it belongs here before the EINVAL tests, but it looks like
kcov->size doesn't have any page alignment.  I think size could be
4000 bytes other unaligned values, so nr_pages should round up.

-chris

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918194556.3814405-1-clm%40meta.com.
