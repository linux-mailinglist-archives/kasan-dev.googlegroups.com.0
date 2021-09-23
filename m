Return-Path: <kasan-dev+bncBDE5LFWXQAIRBD6ZWGFAMGQEH4YNBGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 12B24415D72
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 14:01:20 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id p23-20020a05620a22f700b003d5ac11ac5csf18555659qki.15
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 05:01:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632398479; cv=pass;
        d=google.com; s=arc-20160816;
        b=caVKGXDIGxz1N3VtFkd1w0bUYTRiaw6JPx+VDmPLYuC3ssGLFXHTNFuqp2JAxyER79
         5ktM3xjvqFUO261oUUskylivrEuKg7+2sGy2i+l0iyc2ZZZ0anjABBAh4EkCM6iAyWO6
         IVkLqZiKD9cjU3cxATv7X6GfNic1VfNGjZLcrSzkOtFy1nyohbo3YUa6JR2CuIoBr9QT
         b3qYX8lBBf1d+dkYthoVq7Sts9ToMkFYQu+V2fEd0fTjxk5Bw7NgEx641gOfcDtKqZ79
         sVQKBOIZW0ICaIYmO2MdZKrOI6G1/NZ7S6xDSh5+HcfYhCkjmFhSCuFY33TWXoJm/LHg
         tDkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=421CCv77k0tJIuBYH8jn4Ne1IcHhB3IZzuz6Qeb/q18=;
        b=PVa6v5c1ItvBHddoTWRg1S2fb94hT/jzmQKQSbI6qUOXyusAvccsKhUEQC3PriHrFf
         j2JPWQ/ZTHfImpXg+cpksEoch6bMp+GUcOPiL6qtv+jmPgBqIolQpsvgN7Zu+z40nNt1
         ZLdHeUOkOMFSeAhJ5fBA5XoMMoANc7lFkq7dvqwB8u7/AZLXrGOeI/sj9qYiJifrbxeI
         hFJuLeuNCbSPbSHptFSwrh6p/hiUncMG0u9sD4huS+x9TGeSBxv6/YsohrNBuQ3DuhFL
         Erb25XLqmbfNJbMwFvVr4tzeYwZY+8ZJVzC87Uw9HFuk0WoSu6wBbzKT+GGyC3zIvXrj
         pzDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ZCv5VVg5;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=421CCv77k0tJIuBYH8jn4Ne1IcHhB3IZzuz6Qeb/q18=;
        b=AveH51UsOdylteCQgLwpi7kjN8jr8qZMlKJUMU7cYOEmIVe5wzToRZwvfAhJQBGNVM
         2WvTT1Y7l+m5D3zgIcyCaQR+9foNJ22Yi1rari8ZELLUi36Z2sZdxRqwdOc+pt1mMSuM
         sjcZnPY6HIs0/q1SiP8lsVJIgoUwsjb69S1OhWw7ea7wousra+dE9XgtwV2oTBpSrCZg
         JK+AwbtRKTMJBfnrCJdUHiZzyywVAcnMcgakutaByFnvC60pYCDFvGB7uaNnxfQ+KFS9
         9kKnbdMGwWWvz6AaRrcN2mg57VIdbaWMCb5D3l7l6z0klvJEQNtAfOq/9nB17vTW525g
         IFeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=421CCv77k0tJIuBYH8jn4Ne1IcHhB3IZzuz6Qeb/q18=;
        b=dMWNGkW5peznGNr4ivDikhsh+SrbcmJ+QjHLGigc/a4I1HfMokD+Ta+MmrGrUJaqQd
         vHkkVtnEZMjtIJXPK2KNepCEW/uoCkB27rHAv6dKD7QrvRf1XGIvjJbqPYPqtSgMD1kA
         NJt/9VDj1apCWjEu08hu4AcV8s+Y2sq5TMXpkIw1IpWLAfyWAwVCjEt0CZYh2cWJTK+l
         MmxpWga+neObC86JjD6hag99jo00GQzgm+LmfXT0MXFWSm5rhbKUA0wOlI3dkDoujIam
         DB8fFmvQuL4+8xqrW8Lh0iy9GyK1drrvM0wzeu8w2W6uii3EUR3r9iG2wAV0i0uhAjhC
         EKjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OeSFPr9fI68kWKWYhr4OOWqL6XXXTWa6FqyZu/chMUDiQdUkn
	ZAtw2/NXSXDm7MmIMXkmE3I=
X-Google-Smtp-Source: ABdhPJx6wMv5Q1Et2tbXptFNip9nWSoheHDLMjQ4c2Mu6OJ+SQYbZV0Gk4FRUyn3YNBjdu8FUQJRLg==
X-Received: by 2002:a25:adc6:: with SMTP id d6mr5223883ybe.463.1632398479172;
        Thu, 23 Sep 2021 05:01:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:37ce:: with SMTP id e197ls2792184yba.10.gmail; Thu, 23
 Sep 2021 05:01:18 -0700 (PDT)
X-Received: by 2002:a25:50c7:: with SMTP id e190mr5056915ybb.439.1632398478710;
        Thu, 23 Sep 2021 05:01:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632398478; cv=none;
        d=google.com; s=arc-20160816;
        b=dI3tQBpK8H39yTVRYEQ4y7gPWPo/uBZXR/DzKtbotXCQUh/667WpKyv7cGzc7gG2TH
         mwnJsfLEVLMm2PEtvdU6YFDNq5HLA7RQQMADADXhsSb1CtWFARi2vSKiJ92UKUEYOi0T
         HwMWn+IFBFDBz7kPRxO1mUogctEF5Jt7JVvVji18ylsdF0xhZJoQIv+8u1SxM82QsMNb
         3SCMjIm/8X7AkKg6s/ZVb7CsxITadqRl9trQzmFY2SO4XLfgEgSQ6QWVy20YBATJHjR8
         y5P2jASzLkR4N3/DagnFmAil2c/4rC4O4jUTkZQa8xyXvh6FXtfuTZnBUTCNSoGR82HU
         xEKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=pXzEf65A4Oe5+XzfRr8terVnfyIyuO6PQs0+F8aXgGc=;
        b=h3QSiq3xGXl7IQg6At4CwMm937AymJNZm05F1z1VNRzTsOQe2zNEKJMX5LtQdEzJBb
         1Sk6ohqoFymwNTwFwlKp6exYlXXBKLWecQGbPmJ0wPdxQiX9YPhS+9SH7zd5z+ZmokXR
         QOV3xCI4tOP3wE+hYuxfu9FZfrQ5qnhKuD4hvQyB5aeFfL64M7w1zcQrc/Zc3VOPciPQ
         7IJJZzdz4+H6z4YA+hYB3BfzcyrvaUbLeLnhUX//+hv7s6T4lOJT9cnYQEZAutRXqCLs
         0BieaOVyftp0e+qyTwVq78iKBFfmD9jz7hLbjyjJbJ7JkUZg3gbOE9f9F86RUOXRVMgG
         Nf4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ZCv5VVg5;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id x6si258528ybn.3.2021.09.23.05.01.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 05:01:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098410.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 18NAdUcU003364;
	Thu, 23 Sep 2021 08:01:15 -0400
Received: from ppma06fra.de.ibm.com (48.49.7a9f.ip4.static.sl-reverse.com [159.122.73.72])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3b8p4dcmbn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 23 Sep 2021 08:01:14 -0400
Received: from pps.filterd (ppma06fra.de.ibm.com [127.0.0.1])
	by ppma06fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 18NBvwov029624;
	Thu, 23 Sep 2021 12:01:11 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma06fra.de.ibm.com with ESMTP id 3b7q6ps42c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 23 Sep 2021 12:01:11 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 18NC18Jk56885734
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 23 Sep 2021 12:01:08 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 810B04C08B;
	Thu, 23 Sep 2021 12:01:08 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 64DD54C089;
	Thu, 23 Sep 2021 12:01:06 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.159.121])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 23 Sep 2021 12:01:06 +0000 (GMT)
Date: Thu, 23 Sep 2021 15:01:04 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Mike Rapoport <rppt@kernel.org>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        devicetree@vger.kernel.org, linux-efi@vger.kernel.org,
        kvm@vger.kernel.org, linux-s390@vger.kernel.org,
        linux-sh@vger.kernel.org, linux-um@lists.infradead.org,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-mips@vger.kernel.org, linux-mm@kvack.org,
        iommu@lists.linux-foundation.org, linux-usb@vger.kernel.org,
        linux-alpha@vger.kernel.org, sparclinux@vger.kernel.org,
        xen-devel@lists.xenproject.org,
        Andrew Morton <akpm@linux-foundation.org>,
        linux-snps-arc@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
        linux-riscv@lists.infradead.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH 3/3] memblock: cleanup memblock_free interface
Message-ID: <YUxsgN/uolhn1Ok+@linux.ibm.com>
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-4-rppt@kernel.org>
 <1101e3c7-fcb7-a632-8e22-47f4a01ea02e@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1101e3c7-fcb7-a632-8e22-47f4a01ea02e@csgroup.eu>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: fe2SFaLdoxw706nrVmE8bleSLkHdGrzC
X-Proofpoint-ORIG-GUID: fe2SFaLdoxw706nrVmE8bleSLkHdGrzC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.182.1,Aquarius:18.0.790,Hydra:6.0.391,FMLib:17.0.607.475
 definitions=2021-09-23_04,2021-09-23_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 clxscore=1011 bulkscore=0 spamscore=0
 mlxlogscore=613 impostorscore=0 priorityscore=1501 malwarescore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2109200000 definitions=main-2109230076
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ZCv5VVg5;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Sep 23, 2021 at 11:47:48AM +0200, Christophe Leroy wrote:
>=20
>=20
> Le 23/09/2021 =C3=A0 09:43, Mike Rapoport a =C3=A9crit=C2=A0:
> > From: Mike Rapoport <rppt@linux.ibm.com>
> >=20
> > For ages memblock_free() interface dealt with physical addresses even
> > despite the existence of memblock_alloc_xx() functions that return a
> > virtual pointer.
> >=20
> > Introduce memblock_phys_free() for freeing physical ranges and repurpos=
e
> > memblock_free() to free virtual pointers to make the following pairing
> > abundantly clear:
> >=20
> > 	int memblock_phys_free(phys_addr_t base, phys_addr_t size);
> > 	phys_addr_t memblock_phys_alloc(phys_addr_t base, phys_addr_t size);
> >=20
> > 	void *memblock_alloc(phys_addr_t size, phys_addr_t align);
> > 	void memblock_free(void *ptr, size_t size);
> >=20
> > Replace intermediate memblock_free_ptr() with memblock_free() and drop
> > unnecessary aliases memblock_free_early() and memblock_free_early_nid()=
.
> >=20
> > Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> > Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
> > ---
>=20
> > diff --git a/arch/s390/kernel/smp.c b/arch/s390/kernel/smp.c
> > index 1a04e5bdf655..37826d8c4f74 100644
> > --- a/arch/s390/kernel/smp.c
> > +++ b/arch/s390/kernel/smp.c
> > @@ -723,7 +723,7 @@ void __init smp_save_dump_cpus(void)
> >   			/* Get the CPU registers */
> >   			smp_save_cpu_regs(sa, addr, is_boot_cpu, page);
> >   	}
> > -	memblock_free(page, PAGE_SIZE);
> > +	memblock_phys_free(page, PAGE_SIZE);
> >   	diag_amode31_ops.diag308_reset();
> >   	pcpu_set_smt(0);
> >   }
> > @@ -880,7 +880,7 @@ void __init smp_detect_cpus(void)
> >   	/* Add CPUs present at boot */
> >   	__smp_rescan_cpus(info, true);
> > -	memblock_free_early((unsigned long)info, sizeof(*info));
> > +	memblock_free(info, sizeof(*info));
> >   }
> >   /*
>=20
> I'm a bit lost. IIUC memblock_free_early() and memblock_free() where
> identical.

Yes, they were, but all calls to memblock_free_early() were using
__pa(vaddr) because they had a virtual address at hand.

> In the first hunk memblock_free() gets replaced by memblock_phys_free()
> In the second hunk memblock_free_early() gets replaced by memblock_free()

In the first hunk the memory is allocated with memblock_phys_alloc() and we
have a physical range to free. In the second hunk the memory is allocated
with memblock_alloc() and we are freeing a virtual pointer.
=20
> I think it would be easier to follow if you could split it in several
> patches:

It was an explicit request from Linus to make it a single commit:

  but the actual commit can and should be just a single commit that just
  fixes 'memblock_free()' to have sane interfaces.

I don't feel strongly about splitting it (except my laziness really
objects), but I don't think doing the conversion in several steps worth the
churn.

> - First patch: Create memblock_phys_free() and change all relevant
> memblock_free() to memblock_phys_free() - Or change memblock_free() to
> memblock_phys_free() and make memblock_free() an alias of it.
> - Second patch: Make memblock_free_ptr() become memblock_free() and chang=
e
> all remaining callers to the new semantics (IIUC memblock_free(__pa(ptr))
> becomes memblock_free(ptr) and make memblock_free_ptr() an alias of
> memblock_free()
> - Fourth patch: Replace and drop memblock_free_ptr()
> - Fifth patch: Drop memblock_free_early() and memblock_free_early_nid() (=
All
> users should have been upgraded to memblock_free_phys() in patch 1 or
> memblock_free() in patch 2)
>=20
> Christophe

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YUxsgN/uolhn1Ok%2B%40linux.ibm.com.
