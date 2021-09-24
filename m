Return-Path: <kasan-dev+bncBDE5LFWXQAIRB4OFWWFAMGQEOCKEUTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 10FF9416B33
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 07:32:35 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id 66-20020a1f1145000000b0029bf15e8828sf977573vkr.7
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 22:32:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632461554; cv=pass;
        d=google.com; s=arc-20160816;
        b=CLkz6fyk1LvblVMaJpikVLnD/CpapwGjxuzP3k2JiWYi5kz2he/0hS/9vMKjmrZXtx
         dbIG6hONFYkGHFqsdSYGazM2rjzOU1ci01lsC3Zd3ailxUX3my6m1XT+HamQSL8h9mFT
         JNggsS5ji3wL3q/Nk8zxL40Lt1ohkvEsYFS4A+NFnYg7Nl7SyaDTGNSVR0+tNwFmieZe
         jHbuHXMKsCMzvKb0+t1S8Jn7ri/aFzRLhWqdaMuG+BEeCHTx5aPNO12N1hlzbqw0I99L
         0dlfmLKFgw+cj0lrAnoVhCoOHi5/WObN9l56rDukNjOqlXoMiqfzibcbEPw/Od7xrxte
         /Tiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YgQIBGQ5ZB013ZAMKX/slQ6EURb72Mn7ZTFaepCuUuo=;
        b=iDnpHtbE6CtXZqg71rNbN41Q6uya8GGrFTF9ZcwWQpeTMTBtkoNQCN3QRZrwHShh3k
         dWmvY6A7AomvTj+k7YY6zF0BHiu018rKY88OTe38qebNqYr7MJXVq+uZLH10kZaD1fbk
         iz1yLhNEGCe4fjBE3JSpQ4ozvPzdz7jtiU7zgpO8VUHLXNy8CqeeHu3c9y4NsSh/PIQP
         vxLv75BnubMg9SZCJLudpbHB+C2CfzrsC8nuvSM1tELO00mSJ1KxxCiIUI97wk/+OOzp
         0CE8OHb/G8Wwu1mwUAxr1f6l2SncSuVkQWSu31m+6m/irK9sQABbih4nGEYnr9uHNR30
         bEVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fM5r0pOd;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YgQIBGQ5ZB013ZAMKX/slQ6EURb72Mn7ZTFaepCuUuo=;
        b=qWU9G192RiOo0d+AaN9rHNizg1a6YSJ48CtosN9EaqxKMCQLMWPwDaOZM/WsSp37qk
         ob61EOokzsHDy6behZ+ZfrQL2KW+exx5Ak9JZkvzDSLlf+ZQKKxZiTLdS9aDORRt1vmB
         GFXF3Pn852SAG5XVO8eMllUelGlC/D9Z9QpsowsBHTXXjux3QKbupmEp31S1FoK7Wfc0
         SH7Uk3NlIU6EeoU3XHUmKl/35azMbe2nCkVCgKE3vc/oMPOdqdgj8kZPnU7dMAaA9107
         sqwFZGarHgr3Hm661y+FmyqTW/yZQXUOSTypy4PEkwkkrjA7l/IstGhEPAaNRzvrHmI1
         xDsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YgQIBGQ5ZB013ZAMKX/slQ6EURb72Mn7ZTFaepCuUuo=;
        b=u91QeZDFBRpkTlGvGKxNsXqZYhaKJFunxVdW9hMdqtlXjYeda/kGjTP5x3gGGbnil5
         sbbcWS5eqpmZKo+oJq7DoC8IWCfXeJIBMyrprUQXH0CvBqpfT16ivM1MBouNBs2SNLdy
         mNMu60t3MEUPZSkYxsSAIlcY7yaq6RvhL0ZhjHfFvFKLzP9AD5iIr4F9Q/nieRSNGQTt
         RgQ3G4pFxlmdisbu1OtUDDSxyDqvMrbbr3V+FLq2KFriCcf1sL7ZPxg3va1uOLVDDYh1
         PVqn8cTZ1X4pZoAurxo9F6KZgegTFxeF2i3wZp4FjxdEayNGs2k0W58x78kgrjjugkn0
         1PSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532b4KMwR/auwdfajleyBaWemYQJBEbMkb0WsV8rxlAb7ImNLwmx
	lq6rShTXVcdzAtfLfiz877c=
X-Google-Smtp-Source: ABdhPJzcQDlykMyBB9dkkA+DWVjih+4CfZYyCFR84EnpQZ2JUQ+O9npqz5A3Mabes3l5W72F/4eeXg==
X-Received: by 2002:a67:eb43:: with SMTP id x3mr8072465vso.29.1632461553848;
        Thu, 23 Sep 2021 22:32:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d18e:: with SMTP id w14ls2052700vsi.7.gmail; Thu, 23 Sep
 2021 22:32:33 -0700 (PDT)
X-Received: by 2002:a67:f147:: with SMTP id t7mr7926048vsm.57.1632461553376;
        Thu, 23 Sep 2021 22:32:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632461553; cv=none;
        d=google.com; s=arc-20160816;
        b=i7cJzTCGw/fEl267PC2MLy39R+5kdm/MP9aT2inYBN4ebYeVwL6mkR6NvpXonny6bB
         v4yhtoeoOu1Z6zFKOClAGFnYnhx405YwnQ/y4VA9cGT1PLjrklKvYQdc+MLp0tAM9SSE
         QAc8GV4CU7trdBlJf0v6WXsG8GfGkX0Kj6TRoe703qtYWCmRhmGRUHTZYwcwor2Q5ERM
         kxNtO/PLuLtOLrf8nlgYeYRF74eoqB4MPyCEqL40VkO7Jw9UTmEpzJI9pU9rMUVy5QhU
         cD9C8cEo2APDCINkcyQjwT0wgZtghWc5HbuIlxz+6MGE5IhvfEbOVwVYL9eKBnGqBT7I
         IfYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=LcclFexTC3W4CGWQ05F30N7TENmKQs3CWJF8lIJhAyA=;
        b=sYIe+uorZatNVSJyep8qhxKAx+Y81FBhXHg80wAshA8ixH66ecmRr9A3eL3DF1ATkZ
         yjMrxh73jis0E0ct6sYtMbyfqTXINHLBO0mhcc4WCf5eJqI+nmK5ni2u16svMWf2F8Uo
         WBfKAiGAry44hshxs2kENL8SCKMHYDcjBNwF2sRsRJhvzU9+GZRN0ZBY2USwLGNQ36Tp
         Zs1k0PTQpMguc69m/YVVLEGLt0VTvJzzR+VnudQxeKwhKLjCdhQk07Gu1+vaZlaX2hOR
         eoW/pxRNdPNep+ITNDp9J7MeVIQuHXytJf/shNFfYXY+4Ht0v3LifeU2ETfrHi4LnvIV
         2Daw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fM5r0pOd;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id a18si247374vsi.1.2021.09.23.22.32.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 22:32:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098419.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 18O4TxLE003727;
	Fri, 24 Sep 2021 01:32:30 -0400
Received: from ppma03ams.nl.ibm.com (62.31.33a9.ip4.static.sl-reverse.com [169.51.49.98])
	by mx0b-001b2d01.pphosted.com with ESMTP id 3b97px199p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 24 Sep 2021 01:32:30 -0400
Received: from pps.filterd (ppma03ams.nl.ibm.com [127.0.0.1])
	by ppma03ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 18O5WBU3010032;
	Fri, 24 Sep 2021 05:32:28 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma03ams.nl.ibm.com with ESMTP id 3b93gb1yvs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 24 Sep 2021 05:32:28 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 18O5RWr150528586
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 24 Sep 2021 05:27:32 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A77234C04E;
	Fri, 24 Sep 2021 05:32:25 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 26CB04C050;
	Fri, 24 Sep 2021 05:32:23 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.159.121])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Fri, 24 Sep 2021 05:32:23 +0000 (GMT)
Date: Fri, 24 Sep 2021 08:32:21 +0300
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
Message-ID: <YU1i5YyldfS1HH0j@linux.ibm.com>
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-4-rppt@kernel.org>
 <1101e3c7-fcb7-a632-8e22-47f4a01ea02e@csgroup.eu>
 <YUxsgN/uolhn1Ok+@linux.ibm.com>
 <96e3da9f-70ff-e5c0-ef2e-cf0b636e5695@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <96e3da9f-70ff-e5c0-ef2e-cf0b636e5695@csgroup.eu>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: EYYWPQtbK60SNKLXoEtnrAemGAQvCJn5
X-Proofpoint-GUID: EYYWPQtbK60SNKLXoEtnrAemGAQvCJn5
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.182.1,Aquarius:18.0.790,Hydra:6.0.391,FMLib:17.0.607.475
 definitions=2021-09-24_01,2021-09-23_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0
 impostorscore=0 mlxscore=0 lowpriorityscore=0 bulkscore=0 spamscore=0
 clxscore=1015 mlxlogscore=856 adultscore=0 phishscore=0 suspectscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2109230001 definitions=main-2109240031
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fM5r0pOd;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender)
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

On Thu, Sep 23, 2021 at 03:54:46PM +0200, Christophe Leroy wrote:
>=20
> Le 23/09/2021 =C3=A0 14:01, Mike Rapoport a =C3=A9crit=C2=A0:
> > On Thu, Sep 23, 2021 at 11:47:48AM +0200, Christophe Leroy wrote:
> > >=20
> > >=20
> > > Le 23/09/2021 =C3=A0 09:43, Mike Rapoport a =C3=A9crit=C2=A0:
> > > > From: Mike Rapoport <rppt@linux.ibm.com>
> > > >=20
> > > > For ages memblock_free() interface dealt with physical addresses ev=
en
> > > > despite the existence of memblock_alloc_xx() functions that return =
a
> > > > virtual pointer.
> > > >=20
> > > > Introduce memblock_phys_free() for freeing physical ranges and repu=
rpose
> > > > memblock_free() to free virtual pointers to make the following pair=
ing
> > > > abundantly clear:
> > > >=20
> > > > 	int memblock_phys_free(phys_addr_t base, phys_addr_t size);
> > > > 	phys_addr_t memblock_phys_alloc(phys_addr_t base, phys_addr_t size=
);
> > > >=20
> > > > 	void *memblock_alloc(phys_addr_t size, phys_addr_t align);
> > > > 	void memblock_free(void *ptr, size_t size);
> > > >=20
> > > > Replace intermediate memblock_free_ptr() with memblock_free() and d=
rop
> > > > unnecessary aliases memblock_free_early() and memblock_free_early_n=
id().
> > > >=20
> > > > Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> > > > Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
> > > > ---
> > >=20
> > > > diff --git a/arch/s390/kernel/smp.c b/arch/s390/kernel/smp.c
> > > > index 1a04e5bdf655..37826d8c4f74 100644
> > > > --- a/arch/s390/kernel/smp.c
> > > > +++ b/arch/s390/kernel/smp.c
> > > > @@ -723,7 +723,7 @@ void __init smp_save_dump_cpus(void)
> > > >    			/* Get the CPU registers */
> > > >    			smp_save_cpu_regs(sa, addr, is_boot_cpu, page);
> > > >    	}
> > > > -	memblock_free(page, PAGE_SIZE);
> > > > +	memblock_phys_free(page, PAGE_SIZE);
> > > >    	diag_amode31_ops.diag308_reset();
> > > >    	pcpu_set_smt(0);
> > > >    }
> > > > @@ -880,7 +880,7 @@ void __init smp_detect_cpus(void)
> > > >    	/* Add CPUs present at boot */
> > > >    	__smp_rescan_cpus(info, true);
> > > > -	memblock_free_early((unsigned long)info, sizeof(*info));
> > > > +	memblock_free(info, sizeof(*info));
> > > >    }
> > > >    /*
> > >=20
> > > I'm a bit lost. IIUC memblock_free_early() and memblock_free() where
> > > identical.
> >=20
> > Yes, they were, but all calls to memblock_free_early() were using
> > __pa(vaddr) because they had a virtual address at hand.
>=20
> I'm still not following. In the above memblock_free_early() was taking
> (unsigned long)info . Was it a bug ?=20

Not really because s390 has pa =3D=3D va:

https://elixir.bootlin.com/linux/latest/source/arch/s390/include/asm/page.h=
#L169


--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YU1i5YyldfS1HH0j%40linux.ibm.com.
