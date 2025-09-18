Return-Path: <kasan-dev+bncBCJNVUGE34MBBAVTWHDAMGQEG5CVTJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 4973BB86A14
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 21:12:04 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b3415ddb6asf55511811cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 12:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758222723; cv=pass;
        d=google.com; s=arc-20240605;
        b=H678Jsft3Py6KOdLwjp64BYgVcyrufirCJ7Jyq+0q5FsPS9WJPxlzUxHRP4IUHbt16
         uEqoPRURulFlRi77A7aD0JYaFVd6uRGMV2NcJh83U2OkXf/DCXDKlKDCGRav3c7RxA6p
         GPLXKbyuMRl8BIQw3ejeZwJcG0/zwml9U2zWXqe3O75LTgY361iClf3LKV+AwFwzP7b6
         AXmcq4QUQZZEoif3UW7RX25Wjx4pl134Zm+H62Q1Vm449QM+RoWQbXeBh5iFs6xkvyoV
         szsi6BvboMitJuWFhdUce7F9rvqwmOtL5t3lk6b3AnRcSjd46edO1phtdC8BSbrcek6+
         GmIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kHUxHUrgzdlq5IgKyPZUu1vmQoWa1ccL4cAWwxoKKjI=;
        fh=TwnJO0yfKxmNQAOfzovgt41yW2hM070Y86+S3e+wsTU=;
        b=bDIZvBdNn2fZEGI4/lmbwQ+c+qbMaBTCkmcfvagEOpIiAyoOB/CQgahqWHxBysLg/5
         KkpIfb6EaLsNl+itlCmPb0Y/q5y8J4O2j7FzVaLdTnl8oVDnXq7vVMDh6Ik8Qntmc1xU
         l/k8JL3RNI4tCydCLQ6/Bjou0U6E7A60gLvM9CfmrTH8I/59zlRHsFLPfv5PdY10BGzh
         Y5Mg3aMEMlTBjKNXogOToP3RRKTWOPMN6z/TkEKoSsJuhnGJEStDzmKGwwz/JhljjW/6
         biVld5sOjoN1loiI3Wa9nZwGSvIz1WNfVr8147AGnN2MrlT+4KEp7csqBiKThnKvpW7a
         LciA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=e1PjzYEw;
       spf=pass (google.com: domain of prvs=5356f0da48=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=5356f0da48=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758222723; x=1758827523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kHUxHUrgzdlq5IgKyPZUu1vmQoWa1ccL4cAWwxoKKjI=;
        b=hauzRP+4X1BZqA9KFJoC+FN5yRU618QvH7SzARLtpVOtTM/62zV+TzkLUGqi0FQ0nS
         AZe/ke2HIUH0zSYCsdpkr3IIi/tgSSu2/ybbjcGd+FRBqe5W/3IXiOnbqWOC2xPrlS9D
         TThh4r45k32cNyznGiIn4x4NAkZUOdku6KGwzQl54wn2Gyx+H5TUwLM5+By1KIfURCo7
         ZOC32O1pLjhOImJQfPVdM834sKCLRdVA/qqMI4QK+FOI51ty4qUA+vhs+F3dTEnAzn6d
         c4eqzvlTXe7T7+9GCvrgopjQ6+HoDJUEWAJ1fDuWsTLpQA2lvdVMxY8/ocyKPfkgfdgB
         RHiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758222723; x=1758827523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kHUxHUrgzdlq5IgKyPZUu1vmQoWa1ccL4cAWwxoKKjI=;
        b=wtuEa4BZw3EVAVVYlaiZMtA2HGTJ/lugyeT2ivYcZ55V8BuZjaNr2LYJuKEKOaKUQN
         RNg1uDWaBdre8XJLeFF8+2VXHbmIIWwe4zJeC8c7PeG6UIbGA/z3fpkmI5OukiMQwhs5
         q5G4265JHoOf2ZVaM4sTVX7QCz1DxVFwU6u/57sPLSW/ziSSqSnfzQ/UnFWDcD3mS1AB
         hPmFU1xL1mon4Z9eTu6SnnqCqmphVlzrNxJT2lyFU6nczDOO/hjafojiN1RdW7pxkDvU
         lQtPGluyUQSevCn9HKtSdnzRIQd9Vvw6jVjoIFOMFEMLO1B8rt1cRsddL72y8TcrB6lH
         1Bmw==
X-Forwarded-Encrypted: i=2; AJvYcCW7YzhmSyNQ5bQlcYHVQudmWqlMDzfF7TL2FGsHeuaS3VHUiMH70H18MdQXQr86kpJEc/2QtA==@lfdr.de
X-Gm-Message-State: AOJu0Yx/zVIN+QqWhARHZh98kuEm6iSIQ7xBNau91coNFMTisqjMsgTp
	vSP5YHmmOu4Py56nGJPeyib6u7i4csfJFDw3cVyPduA31nZp2D4xkrSk
X-Google-Smtp-Source: AGHT+IES2dDv0PFQqJKcCsn07UqTL/aNcjCzG2U/GimErIX5kJxvKAQ1vL+cmNnjHdc18nAFcIX0Iw==
X-Received: by 2002:a05:620a:4404:b0:826:53a6:85a0 with SMTP id af79cd13be357-83634d2e12cmr524035585a.19.1758222722710;
        Thu, 18 Sep 2025 12:12:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4+utuWVcYt8VCgsUn/0I0xkFNfakbPtqAPX3FA6pZYSA==
Received: by 2002:a05:6214:14b2:b0:76d:ac47:1aa2 with SMTP id
 6a1803df08f44-78e67e9459fls15986996d6.1.-pod-prod-00-us-canary; Thu, 18 Sep
 2025 12:12:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBGbuqHvqbT8hSu6w7k8SbAnK3Dco67zMiXkUvhxNYy8R+0YWHdUvdlTEambBvkgECZXKtS+zp/6E=@googlegroups.com
X-Received: by 2002:a05:6122:181e:b0:545:dc3c:a291 with SMTP id 71dfb90a1353d-54a838d3f86mr375302e0c.6.1758222721692;
        Thu, 18 Sep 2025 12:12:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758222721; cv=none;
        d=google.com; s=arc-20240605;
        b=S+VlEKjxmyZBFBg1lhif2GUsDyaVdoM1hE7pI8I6h09SDn9Ft3KVb2RDsfyn5nDnF/
         CMwVZC4Lgiy5fidf3wLfA8YfKAQ6gUPV/tRn+fmyaQ0cuS5ZRrgnn+/OvftUZDcXl+ys
         r7x0QA/oOO3Pa3rLFs5pA3brwMBGy2r+sHJQhHgu4SF1oc3VYVm5zWwYYWOSbec3eeHI
         9KcXfbzX5SeGp/mI1yuKInNprxA4o5l3LclzOwYEVKlPXnyU0Nkp0bDtb7ziTsWLOwxY
         bYKFUmEiUHw3JGncnjgbXiFImw8ngjRI8Cjafksonkuiwe9kM5XzI4Z7lVZyQ3dnoKB1
         tveg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=n7WMUyT5L/wA654bmEoUeQzuO+YeNxS6ichaQfAm4K0=;
        fh=TbPVaglT1XXw1caSS86THbeGwBaPNlarBYV8UySgShw=;
        b=Gl7VRamxdddoy6MhDVgBhcoDj+EcBxKMxwIR3Wz6XX4yePpH9ZB00VKV7TURtwpuCM
         b/+07jDV/4HPfXHOyTMeu1+T24qkz1p2Py2smZZNGrVVcRq5+Yu38m1kqrf1tlAU9bcE
         /ULamLBQ1ONjfrq4AxbdgeN8z9sbVgqwnq/EtjS+Qg9k/iZSF7bbIwYOKW1BUlE2Rtcq
         JJ751kOznAmAet2rMQbhFMucUBMmyO/Hw1Bzz8U8xCRxw7kXYaNt4In3JoDvHlvPfcbt
         6UGtR8hKSYncVe1P3wPQ0BJJdbv8Q+iBAeTUAX9qROUrkfkl+njjXu+zPaIrmQJ8o2Y5
         gc9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=e1PjzYEw;
       spf=pass (google.com: domain of prvs=5356f0da48=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=5356f0da48=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54a72320195si142518e0c.0.2025.09.18.12.12.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Sep 2025 12:12:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=5356f0da48=clm@meta.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0148461.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 58IHFrYs3277934;
	Thu, 18 Sep 2025 12:11:42 -0700
Received: from mail.thefacebook.com ([163.114.134.16])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 498f7yccgs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Thu, 18 Sep 2025 12:11:41 -0700 (PDT)
Received: from devbig091.ldc1.facebook.com (2620:10d:c085:108::150d) by
 mail.thefacebook.com (2620:10d:c08b:78::c78f) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.2562.20; Thu, 18 Sep 2025 19:11:36 +0000
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
Subject: Re: [PATCH v2 11/16] mm: update mem char driver to use mmap_prepare
Date: Thu, 18 Sep 2025 12:11:05 -0700
Message-ID: <20250918191119.3622358-1-clm@meta.com>
X-Mailer: git-send-email 2.47.3
In-Reply-To: <aeee6a4896304d6dc7515e79d74f8bc5ec424415.1757534913.git.lorenzo.stoakes@oracle.com>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [2620:10d:c085:108::150d]
X-Authority-Analysis: v=2.4 cv=Wr8rMcfv c=1 sm=1 tr=0 ts=68cc596e cx=c_pps
 a=CB4LiSf2rd0gKozIdrpkBw==:117 a=CB4LiSf2rd0gKozIdrpkBw==:17
 a=yJojWOMRYYMA:10 a=yPCof4ZbAAAA:8 a=QLIaiyCFZkuJlwHvl48A:9
X-Proofpoint-ORIG-GUID: yzU4eNHLhAUfSh4h33V6r2BXOldJckJZ
X-Proofpoint-GUID: yzU4eNHLhAUfSh4h33V6r2BXOldJckJZ
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE4MDE3MCBTYWx0ZWRfX+OH6/CZXfYF1
 ZQZSd3MY5d1+huXM92tmUuaixGbvXh9eslNEM1bRcbWXduWBJkY9hM7pAwYK1UmVGB6+KtMLK3+
 5xu0OvXnTYTE5X3/j7r0YUT9jTEQIyg7vs2wzGv7et2oYHzPIQqFSONTUbrUfKZtQGE+5Ql2G/m
 FB+fFTcxSnJqueTYbtn/kFdO7ZXWcwZvUvPEHQAajQYNZXBbU5RIDDKbQMkKIDQGqkR8eZiO5xs
 q0uwGSCKiMwePOEm2hD3yphFf7LSfGFQnTUqyn0uufzwKaznKzrNA1c2BW91Ht07S88ASQbLxJd
 y3Z61QWwzOnbaToH1kdrhAuNayIEpInurTQIzwra/DJzb/lInqX9Bhz50sofEw=
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-18_02,2025-09-18_02,2025-03-28_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=e1PjzYEw;       spf=pass
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

On Wed, 10 Sep 2025 21:22:06 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:

> Update the mem char driver (backing /dev/mem and /dev/zero) to use
> f_op->mmap_prepare hook rather than the deprecated f_op->mmap.
> 
> The /dev/zero implementation has a very unique and rather concerning
> characteristic in that it converts MAP_PRIVATE mmap() mappings anonymous
> when they are, in fact, not.
> 
> The new f_op->mmap_prepare() can support this, but rather than introducing
> a helper function to perform this hack (and risk introducing other users),
> simply set desc->vm_op to NULL here and add a comment describing what's
> going on.
> 
> We also introduce shmem_zero_setup_desc() to allow for the shared mapping
> case via an f_op->mmap_prepare() hook, and generalise the code between this
> and shmem_zero_setup().
> 
> We also use the desc->action_error_hook to filter the remap error to
> -EAGAIN to keep behaviour consistent.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>  drivers/char/mem.c       | 75 ++++++++++++++++++++++------------------
>  include/linux/shmem_fs.h |  3 +-
>  mm/shmem.c               | 40 ++++++++++++++++-----
>  3 files changed, 76 insertions(+), 42 deletions(-)
> 

[ ... ]

> diff --git a/mm/shmem.c b/mm/shmem.c
> index 990e33c6a776..cb6ff00eb4cb 100644
> --- a/mm/shmem.c
> +++ b/mm/shmem.c

[ ... ]

> @@ -5920,6 +5925,25 @@ int shmem_zero_setup(struct vm_area_struct *vma)
>  	return 0;
>  }
>  
> +/**
> + * shmem_zero_setup_desc - same as shmem_zero_setup, but determined by VMA
> + * descriptor for convenience.
> + * @desc: Describes VMA
> + * Returns: 0 on success, or error
> + */
> +int shmem_zero_setup_desc(struct vm_area_desc *desc)
> +{
> +	struct file *file = __shmem_zero_setup(desc->start, desc->end, desc->vm_flags);
> +
> +	if (IS_ERR(file))
> +		return PTR_ERR(file);
> +
> +	desc->vm_file = file;
> +	desc->vm_ops = &shmem_anon_vm_ops;
> +
> +	return 0;
> +}
> +

Hi Lorenzo,

shmem_zero_setup() does a if (vma->vm_file) fput(vma->vm_file) dance.

It looks like we need one here too?

-chris

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918191119.3622358-1-clm%40meta.com.
