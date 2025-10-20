Return-Path: <kasan-dev+bncBDBPXNMCXABBBBPX3DDQMGQE3DTC5NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B9EBBF191C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 15:39:19 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-290b13c5877sf88735575ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 06:39:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760967558; cv=pass;
        d=google.com; s=arc-20240605;
        b=e3EYsFxdwQSObkEvJ8p9V/KYRQ0Mb8XFoOr8zaN8c7HQ17LN55cdx7W6Ni8MJCjUvn
         xS4oCmWoJiIsT/Suuues/u6XvSNySysCl4juAQWtOqHW2rwnsib1Q2rapkbdQMCZdvGK
         jDwYo7dp7se4lsij9Fw9GMugcZ40X165QDUKz++EjG0XPK57mk5IJv5/3UK7C3kiHmqM
         mG3/V2KvVbdvpUtBV72AlgqviNS5AAAWLZfM/FiRgUvkG8RnOWnLlqtICTIqZ3fu7rgE
         WLkyVLqPMQQdQavKy1Jbi6BsoAAlImr/o4fFsP5rfVnR2rLrMbZ/FTbA3yiQ9E2qZiXF
         9+mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/zndCDiOYrMYYd/u/PW3CX3dsItWMVCvPqT0kU+a7KE=;
        fh=+CeDoUVTtoP/gbJlIesMLy0OyO73LvcuYWBMvsPEemw=;
        b=eweOyht0ICvfRPo84olnEWFP2ZWmhnnoVLeXer8L08fQmmzhl1zgd7uieVf2iOmFvq
         kjUg2ELZazVFs9A8K+VYbpp1gCzM+bfR8XtkN1ZNd4WG0OjadtYvpkLsopJOSNUmQO35
         +6ZwlgEISjpb8sfHv4WjpawErsuwAwDigChkRsXcF8Vp+9WhMu8tnykqndaMM7eFHemK
         svBMG4UpaEDnlkYZfrLdgotJa7fxD+J62/fjQmgpA47qLU9o1EdjWlWIJtDIzazp/IRa
         X68GgIf88fMI5sWsd698y4rPzElXDc7NlQMJQdbQMPi8Z3hGAdlDHHRKcMiYgnLXEVmq
         OvNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Ptjzv4kB;
       spf=pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sumanthk@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760967558; x=1761572358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/zndCDiOYrMYYd/u/PW3CX3dsItWMVCvPqT0kU+a7KE=;
        b=UNJoTec8VSYsSLfJHXjEjbHk/r1Qyar/Zl+16Ey6I+W8TWrGnYcU+vEEreWYG9MkUr
         M4SLP8Nk8PUjckb3HmCWmHPa4Nn0Y7j7Ts7oUNyyoW+PUHIkceItHNGM0tgWYjr/aqBe
         awplCvh4bmtNcyufnkh/2LpvKdAM9mia10a8ajRo8g3l7hsT1mHWUW50JdeRzKyN66fs
         aCelMPXPfAtIPuyB8yitOgtGx5Kq+bqRa3VSmTd837Axr0gKPYcPS4vYiNPcb4tq/Bel
         21fAkwO5IJ7k5ZpV+ugk0v/1UExGZSwRv6TSrLbAzV01byu7ax8UaP7odovUjUJI0kms
         WQDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760967558; x=1761572358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/zndCDiOYrMYYd/u/PW3CX3dsItWMVCvPqT0kU+a7KE=;
        b=HleHU0zIbTdQzAcilWrt1ZEUYbP2nO8ymtu0JHPIdiMvHOO92B8usym26/lzcWyZQO
         VZxdrh+XbfpPYW09mYhImRn8zgycBd/8WOd5hwM81l8fAT1iyTR/7mpU8pLrKJXC52fs
         164FcUXhC40BieKMgc9goa2R0XtccdnhsHYzmh+GU1E5fcipX63yWeTabjhg84az4TdJ
         VoCxeyUbcBMPpdGSsmv3xK/czO1l0r4f+jtDjiRchDshTeljGPW2QeGlUDu4kblK98Jo
         uEQ2g5UCw4c4gc9/tieIDRhQ6AWhYpaOw6yaeZ/NguzlDzwKj3lznfo6dNVWNpUzfy4V
         kVaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVE05uqISsD4Vdep5n1KVoPzgLy5qbdgJA94HOcyBvr+iHdCEeJw6OHtfWxqiYeFksmldx8Fw==@lfdr.de
X-Gm-Message-State: AOJu0YzO79j+F2rtyaHdvHdYGQYPtBZg624fQyqkq9tuigBC+rdEvcZH
	kDzBbBu5Q5SJSyH+8AruQqEaB8WPWhDRqIWqW3zCcgG6Y+jEyIlUtVjv
X-Google-Smtp-Source: AGHT+IHY6lj+h94xU5zHV911XJOcPdggb2rMcjKKLVfmxeRDHIUTW8D/Cs5IEps/nxO39gDHiV4L0g==
X-Received: by 2002:a17:902:d50b:b0:24e:3cf2:2453 with SMTP id d9443c01a7336-290cbc3f1b3mr171421055ad.61.1760967557822;
        Mon, 20 Oct 2025 06:39:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7F19umhJQSTToAJbrjbS6JrH3ZB4MfySLGYPdK3eSYSA=="
Received: by 2002:a17:903:17c8:b0:269:63c2:108a with SMTP id
 d9443c01a7336-290aaa5001als45548895ad.1.-pod-prod-06-us; Mon, 20 Oct 2025
 06:39:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUklWLZ3ld/v8+qFgCVepcb4z2gUkPnNgutVa9yxl1EWVJdjs+foN1rHS6p0UqtvzElQ9nvhTCm5Eg=@googlegroups.com
X-Received: by 2002:a17:902:e5c8:b0:290:c5c8:941d with SMTP id d9443c01a7336-290caf851a8mr200891785ad.39.1760967556481;
        Mon, 20 Oct 2025 06:39:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760967556; cv=none;
        d=google.com; s=arc-20240605;
        b=H4JomsrmnKGGmwjEfKO5jZw0hvtGepS/La3eyDAep8G0m4grHl4Wx2TwaFnw1Mi9mk
         NaNrjQjfOti8xFUDf76K09QKyD+QKOnKTFqa+sHVyGmXGzwLLRjBZC1If8bBFyqzvvZu
         99jfqZ7CYXJrzn0uJL7FjWOHmQjfb9gZa0g5dhxn5pNTgsSJOtOuAyKpN23oEuCF4Hbg
         d4XKHmb1awcjFdWkVRbHx3cPftBKwOldcztKufXPFqpsmbXS+lYrvtGDlGyhBGKsvg3J
         JwvhS1iE3lzfms94A7whv6YWiYqky83Z3CvPeBXSEz8zNs3KFfSUXQQxSwHOiBbIiNwf
         SxnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ViQ89gOu19UDAiRynbx1fqy0JdIKiOkaAlpGFEg0jmo=;
        fh=EyueO3/KsOf1nuzzflXHAbZMueY1tbGxAHLRS9wb6ys=;
        b=XIyFPyFxh6GXKey8sExda0DJFE5HbxC9VhTzYFF+3NZkoXsCcGswgbKeEuwaN3xtZJ
         OUT56iWIZMYjOoTr/Pe5St+1FsRoHeInJEyVddLG4OB4y6tCnDvAa13ZtlONxpJ/ZjsU
         pmx+O9EStrVCwNjIkb3N35ipnJ1Omnn9sWKFedh15oEvvYqpZYAEz1UmFMabK0mclLZN
         JYaymaoPkCkhDOB+iowtvZQkQcN0FgKdsjOWObFrPZWBZq5kL71UQBqIbbBQSEqQKXEW
         Gwo7ITatg+J1J1mY5USPi2AYewX43WM93Snklp1k/Z24t4zIPz6uurpsNSZsei0xd7Sz
         tYDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Ptjzv4kB;
       spf=pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sumanthk@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-292470a6808si5117405ad.3.2025.10.20.06.39.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 06:39:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59KCRbo4023459;
	Mon, 20 Oct 2025 13:39:15 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49v31rsqg6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 20 Oct 2025 13:39:15 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 59KDSrHp023351;
	Mon, 20 Oct 2025 13:39:14 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49v31rsqg3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 20 Oct 2025 13:39:14 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 59KC35wv002281;
	Mon, 20 Oct 2025 13:39:13 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 49vqej5p7v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 20 Oct 2025 13:39:12 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 59KDd98t29557158
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 13:39:09 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1465F20040;
	Mon, 20 Oct 2025 13:39:09 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0AE432004B;
	Mon, 20 Oct 2025 13:39:07 +0000 (GMT)
Received: from li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com (unknown [9.111.85.12])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 20 Oct 2025 13:39:06 +0000 (GMT)
Date: Mon, 20 Oct 2025 15:39:05 +0200
From: Sumanth Korikkar <sumanthk@linux.ibm.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Dan Williams <dan.j.williams@intel.com>,
        Vishal Verma <vishal.l.verma@intel.com>,
        Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
        Muchun Song <muchun.song@linux.dev>,
        Oscar Salvador <osalvador@suse.de>,
        David Hildenbrand <david@redhat.com>,
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
        Hugh Dickins <hughd@google.com>,
        Baolin Wang <baolin.wang@linux.alibaba.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
        nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
        ntfs3@lists.linux.dev, kexec@lists.infradead.org,
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
        iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>,
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v5 12/15] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-ID: <aPY7eQec0bB9847x@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
 <b1afa16d3cfa585a03df9ae215ae9f905b3f0ed7.1760959442.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b1afa16d3cfa585a03df9ae215ae9f905b3f0ed7.1760959442.git.lorenzo.stoakes@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: ZSoy0DnAVX45duhi1_mDLkuJQ3da5vFy
X-Proofpoint-GUID: 2FFr9MxsKTbmfu7DnP8tGWY4DhBVRDkg
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMiBTYWx0ZWRfXy3CVS9OyeYuF
 3+tWa5wjvP+gkbv9wIuR2qBo2tCYgmgyTdm2zAqfL8UFStMulHvbtnTG5sqtSbNbGC7YvcprEqv
 0d6/694Ay5/WaywfyIa71bzqVpJ+YelsfaR6Fgo2F6IMpwfoqzJiZIDNnA7xw0K40cEjnFnUiYM
 oDKF5qlhz607Hjx7bxgydKT4VgnEhOta0jia3+WHEGk61414+0Z9tjdEL7VpIj44M5+o7Y1fW82
 OVInIKfzXUDHTrkjx3GSeH/Sqxwna+Wi9hKxe9JcxyPadb1pe+SyjdPgcUFpynbyWFiFEpi45GP
 4FvlBMRbqmC01KgzuyyJ/fw2hjq8Pgqs/7uGjoyGcoquemDY7UnpDzBM6gZj/b+AHFmqBo6ZfMD
 TihvVeJSVrOZw0tNC7yiCSCnr0sABw==
X-Authority-Analysis: v=2.4 cv=IJYPywvG c=1 sm=1 tr=0 ts=68f63b83 cx=c_pps
 a=AfN7/Ok6k8XGzOShvHwTGQ==:117 a=AfN7/Ok6k8XGzOShvHwTGQ==:17
 a=kj9zAlcOel0A:10 a=x6icFKpwvdMA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=Ikd4Dj_1AAAA:8 a=VnNF1IyMAAAA:8 a=7mAFR29It3qcuHcA-EIA:9
 a=CjuIK1q_8ugA:10 a=UhEZJTgQB8St2RibIkdl:22 a=Z5ABNNGmrOfJ6cZ5bIyy:22
 a=QOGEsqRv6VhmHaoFNykA:22
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_04,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 phishscore=0 lowpriorityscore=0 clxscore=1015 suspectscore=0 spamscore=0
 bulkscore=0 adultscore=0 impostorscore=0 malwarescore=0 priorityscore=1501
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2510020000 definitions=main-2510180022
X-Original-Sender: sumanthk@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Ptjzv4kB;       spf=pass (google.com:
 domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=sumanthk@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Oct 20, 2025 at 01:11:29PM +0100, Lorenzo Stoakes wrote:
> Since we can now perform actions after the VMA is established via
> mmap_prepare, use desc->action_success_hook to set up the hugetlb lock
> once the VMA is setup.
> 
> We also make changes throughout hugetlbfs to make this possible.
> 
> Note that we must hide newly established hugetlb VMAs from the rmap until
> the operation is entirely complete as we establish a hugetlb lock during
> VMA setup that can be raced by rmap users.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Hi Lorenzo,

Tested this patch with libhugetlbfs tests. No locking issues anymore.

Tested-by: Sumanth Korikkar <sumanthk@linux.ibm.com>

Thank you

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aPY7eQec0bB9847x%40li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com.
