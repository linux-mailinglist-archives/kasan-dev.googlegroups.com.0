Return-Path: <kasan-dev+bncBCVZXJXP4MDBB3GL77CQMGQEOFICHCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C3B03B4A548
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 10:31:42 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7725c995dd0sf5416957b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 01:31:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757406701; cv=pass;
        d=google.com; s=arc-20240605;
        b=YeWGnYznHBkbryf25eEh6MoGSGG4BzQbbHv/tuAbEU3o+S6cwQlnu0MAMl0IxiNIXz
         XfNQABb5WDVWowoK3RswpmQOhF9+DF9KCJDC6waQutGd7s5iJHbBw6Us+KutgtQnluc7
         jwk9O4Sedh5QXeYVkJvWJUlz/7EiiUYA2v2eBHUasXVR4tGfBfPK/9kQlLmS6KlWriTG
         QEdniOCLA22hWMZi80nLADKri3X0vCOU0nStbRsGcRb2+TzBjYyqPxBGseT1UUZi8GqP
         5vtqukzLgfkxrs+yDOog7sWBJW5THPKQI6mWxmRcpX7M1WVi1H/bbnRH8Z3Y/4CJMeBD
         Sbzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=36VseVrP62pq3bLwPrrsE6eH6yczJ7n3xFjlDLnqxGE=;
        fh=JHLk0ja9v2Ii0EqThx/FsPuw0LMNkTkh3sqm1qoWRzw=;
        b=X5+Syox4KVAQN87PRdxCJoultQ/Nlm2EJIf1wv8lL6b2kyTuxOdyNgUrT6isFK/cEt
         jjTSAILyk/+DJT5xgQvsfyv3sFZI1t/7Sira7RDyiIfJkF4qokGY5oAqg2mCzu+UiCn6
         QEfIkteZxuTI5ZxZEPpMY9Czyo3fDaj0xMAurGGrUlJk81bMDh03JFBfuj7QPdN0073Z
         23HA0iPyEcTNJIyPYjVQpLXN80s7DJly7moXiurbY5vk/gdAl9TtwcFfPu8iP9voAY3f
         dRCiF+nnbbiWQEhGzyeLC3S8cT33aw6sATG1Mv5f1eVqmG+41u+K3RfAGLhNYMy5sn+K
         tAUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MyRChXSO;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757406701; x=1758011501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=36VseVrP62pq3bLwPrrsE6eH6yczJ7n3xFjlDLnqxGE=;
        b=m2gc0nvoxEQGG9Lhl77VBq+F3+n2WWAjf4AkyrqC3XXJQ3aWkQuafMyIeLuValUR+U
         SJl7Nrwh+juF28NUQWms1NjJyV0Cvm6rS1PRQH9pZAPkZAkZpMSRUu8hYY++NrBwWQp1
         D1fh74wb0W3b1uwG0DMTjHzRTBzCN232Ler2xFWN/IhbGr3zKqzxudueU3+5VfIliabZ
         HUu4dukToC7vXKRspEj7Uw8tGSP2hTwf7/7ZwwNhhlVTxSX6CLsGX6qYPwlOgkZ7U0kM
         zHbs6huXDNgu3mFjzMGTh5CQGlVPUeNdHj1Xr+yDOHWYtdI559OgFCkuAlILlJSrW+Xs
         6FLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757406701; x=1758011501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=36VseVrP62pq3bLwPrrsE6eH6yczJ7n3xFjlDLnqxGE=;
        b=bK4ctsdl0LLBJoLkguj61CbL2acHso79BN7EmfzKUqNm7wUfiXcGTE12yrfzC3f3Ms
         81x6rVMNumQi4P/Przur++lQv0ULeZ+ZOqvDy4OATJtPQpLGHjeRSwtb9aF+kEN8aYN2
         7N9ievf9JLfLcgUIf0MnLQa7EOPKZ1Pi2XIlESJuQh5SLaIvfEjW5HfUzRKhob4b5VM3
         OzV2VS0SVe5ZTos1eD6Zjb+AbrV6q3ei2HUrhWSnPPzten9JLsvNVwx5nRPcTRxKdmtU
         Jcp4zD+G62M2Orh+OvQqVOIF+Enh5eH3AKbIEnBNSztusaIiMCyw38m/Q6FXV4I30coj
         x8gA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2X79L/Kfdkj4MxYNdMilBa+1IHNnaNs4Z4x9knrl9lcbX/YqZoVrwtAix/PkxjhJk7KKRfA==@lfdr.de
X-Gm-Message-State: AOJu0Ywc8169lnEco0xjL3U9aRUBSKEODyx/u/WSqyPIQDvOgPESwCf3
	cQhl5KxlZHyNySsf3Ij6mH5YJhbGFAGCs0c9Oc0+CNRJaMeDFWr8xRT9
X-Google-Smtp-Source: AGHT+IE6W40z4BS5iclWL3PjCg2Udn5pWu+5TRkuivIs2ffJRRwJez37nCNUbw2QB+HJHcHGIEjHlQ==
X-Received: by 2002:a05:6a00:c8c:b0:772:5487:c35a with SMTP id d2e1a72fcca58-7742dcd7050mr14720577b3a.14.1757406701064;
        Tue, 09 Sep 2025 01:31:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdIqUh6vQzab9DvTPN03MjhRyzTCeggdbCrMOH6Fyztqg==
Received: by 2002:a05:6a00:f86:b0:772:437d:60ca with SMTP id
 d2e1a72fcca58-7741eeff3e0ls4007178b3a.0.-pod-prod-01-us; Tue, 09 Sep 2025
 01:31:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7SrfmoNA/L2J4U7RDYAXYs/Nph0QWh3/CzcJsY5EDlOEzFuD+Q7C3xvgCc6J+q2YmTNZAgKm3Q2I=@googlegroups.com
X-Received: by 2002:a05:6a21:339b:b0:250:6e0:ab3d with SMTP id adf61e73a8af0-2533e18c848mr16856439637.8.1757406699298;
        Tue, 09 Sep 2025 01:31:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757406699; cv=none;
        d=google.com; s=arc-20240605;
        b=C/VsGeroZoYwYiKAFoxl8j+lXKJhN28MMODssELy4HvP4vpCvoLVycx3nkTQ6ZrzMC
         gmIGj+O9VZ+r9gJbUdazOG1tA1K/iyF2MOym3UYHrrMmaCQP+25Tw/kTgYu4ix3JNic3
         lsEmPIgEq2BfcuvFhoa+o9wNmnwHqvt4wmyDorz4mNxAE7vkWrg4qi/yzmCSrnFsthtf
         MNTyaqC+6FfZh5IarRDv9HpY0LTmuoSxs1+6Mhos63ulvrN84Y7YW+3uM5rTH89d18Or
         eVpS7lsS507kLdj2GjE7QS7xQuOPwfhnidSI5AWq0NkW9hnewN7WzXGlwggHh/upIqWr
         Iltg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XRGYRp9IpXgOlM6YrJRhvNTKdkbZq/NQnIfckf3EQjs=;
        fh=Ij5oADESTW4IVY1YwadtFENfJwkg4a2jmN+e8QXfrDc=;
        b=cd/xwMcR8IPaK9g6YoQ4APIPc1F62hVbgh/MYupidVEJKAXz4Gzq/FskUgtb1zp+O0
         BipMKaiMCZ2JbncuX6CGvb0v4SEvIHFIVE5OBL6VbEo1ZT44CHrbr2982M7/+eNM/lz0
         Cb/nSIrdlQAEJmSass8uovxd5LHWrk4V8gT1jUEJ8wag8c0fWZu1W4rpk3X9T2tNnRU/
         Pq7Wj6n7r+LNh+D34E7n8OhfSOxyIqBT/AQMvyUK3e/C3b4Ki7EtHBMgi31hVBn3EMcX
         Kyde+WAN/N0+MzalLSTywGUsDv/zEemDCH14BpyjgRJ5FbxpQ99zaKmddMwovt0tIGrw
         6HjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MyRChXSO;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4faa1812aasi605890a12.3.2025.09.09.01.31.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Sep 2025 01:31:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588JcNWG009190;
	Tue, 9 Sep 2025 08:31:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 490acqxe1c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 09 Sep 2025 08:31:33 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5898Qk8A011618;
	Tue, 9 Sep 2025 08:31:32 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 490acqxe14-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 09 Sep 2025 08:31:32 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5895lhMj011435;
	Tue, 9 Sep 2025 08:31:31 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 490y9uacnj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 09 Sep 2025 08:31:31 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5898VSmY44564752
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 9 Sep 2025 08:31:28 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EA9D020043;
	Tue,  9 Sep 2025 08:31:27 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8E9C720040;
	Tue,  9 Sep 2025 08:31:25 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.87.149.210])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  9 Sep 2025 08:31:25 +0000 (GMT)
Date: Tue, 9 Sep 2025 10:31:24 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH 00/16] expand mmap_prepare functionality, port more users
Message-ID: <4fbe6c51-69f4-455e-922f-acdc613108cb-agordeev@linux.ibm.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 3deOkNqrfHdLIv9wcUPHlUetDtdvUQWz
X-Authority-Analysis: v=2.4 cv=Mp1S63ae c=1 sm=1 tr=0 ts=68bfe5e5 cx=c_pps
 a=bLidbwmWQ0KltjZqbj+ezA==:117 a=bLidbwmWQ0KltjZqbj+ezA==:17
 a=kj9zAlcOel0A:10 a=yJojWOMRYYMA:10 a=rCdDL0ybDgsdDLvqgG0A:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: qA00adzFc2mr4mwvlzTl3c7SVFuwc24W
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA2MDAwMCBTYWx0ZWRfX9DH4SXGK5Ef2
 wejG4c7pX++RhbA1qSy6joL4Dc2oCsCOSPIhrBxt/QLkDiM3oF5S3fnf0a8rvaceAzUOg6WA1gQ
 Ir8I+yPvEyV1Im2S29dkEFwOqpdtLAPsWf2TTp0eyOgmPS+IVsDGdHQRHBjWiZ05r0xpu4su3dr
 m16Ho7NogpEOVcd3h6JEtyn5UfreBb3jlkItkjRqhI4JeeAIMcTnphkaB4l7pHKWbZxIqItt4g7
 VpspaOMhadlzbq6FrrwE54z2UGMx4eYQuRZiUQE2/EtFUQMQbKGs7KhlROQVEQLcoAhtD28WCFQ
 L6pd7Sw8hzkZH/lMoqL2zPGcZXWdwKNG36NITE6JE5TGdgh01ojrh+qdwWmxBmCjCCl7ztPlKTn
 wVjj1P8/
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_06,2025-09-08_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 impostorscore=0 malwarescore=0 clxscore=1011 phishscore=0 spamscore=0
 adultscore=0 priorityscore=1501 bulkscore=0 suspectscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2507300000 definitions=main-2509060000
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=MyRChXSO;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
Content-Transfer-Encoding: quoted-printable
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

On Mon, Sep 08, 2025 at 12:10:31PM +0100, Lorenzo Stoakes wrote:

Hi Lorenzo,

I am getting this warning with this series applied:

[Tue Sep  9 10:25:34 2025] ------------[ cut here ]------------
[Tue Sep  9 10:25:34 2025] WARNING: CPU: 0 PID: 563 at mm/memory.c:2942 rem=
ap_pfn_range_internal+0x36e/0x420
[Tue Sep  9 10:25:34 2025] Modules linked in: diag288_wdt(E) watchdog(E) gh=
ash_s390(E) des_generic(E) prng(E) aes_s390(E) des_s390(E) libdes(E) sha3_5=
12_s390(E) sha3_256_s390(E) sha_common(E) vfio_ccw(E) mdev(E) vfio_iommu_ty=
pe1(E) vfio(E) pkey(E) autofs4(E) overlay(E) squashfs(E) loop(E)
[Tue Sep  9 10:25:34 2025] Unloaded tainted modules: hmac_s390(E):1
[Tue Sep  9 10:25:34 2025] CPU: 0 UID: 0 PID: 563 Comm: makedumpfile Tainte=
d: G            E       6.17.0-rc4-gcc-mmap-00410-g87e982e900f0 #288 PREEMP=
T=20
[Tue Sep  9 10:25:34 2025] Tainted: [E]=3DUNSIGNED_MODULE
[Tue Sep  9 10:25:34 2025] Hardware name: IBM 8561 T01 703 (LPAR)
[Tue Sep  9 10:25:34 2025] Krnl PSW : 0704d00180000000 00007fffe07f5ef2 (re=
map_pfn_range_internal+0x372/0x420)
[Tue Sep  9 10:25:34 2025]            R:0 T:1 IO:1 EX:1 Key:0 M:1 W:0 P:0 A=
S:3 CC:1 PM:0 RI:0 EA:3
[Tue Sep  9 10:25:34 2025] Krnl GPRS: 0000000004044400 001c0f000188b024 000=
0000000000000 001c0f000188b022
[Tue Sep  9 10:25:34 2025]            000078000c458120 000078000a0ca800 000=
00f000188b022 0000000000000711
[Tue Sep  9 10:25:34 2025]            000003ffa6e05000 00000f000188b024 000=
003ffa6a05000 0000000004044400
[Tue Sep  9 10:25:34 2025]            000003ffa7aadfa8 00007fffe2c35ea0 001=
c000000000000 00007f7fe0faf000
[Tue Sep  9 10:25:34 2025] Krnl Code: 00007fffe07f5ee6: 47000700           =
     bc      0,1792
                                      00007fffe07f5eea: af000000           =
     mc      0,0
                                     #00007fffe07f5eee: af000000           =
     mc      0,0
                                     >00007fffe07f5ef2: a7f4ff11           =
     brc     15,00007fffe07f5d14
                                      00007fffe07f5ef6: b904002b           =
     lgr     %r2,%r11
                                      00007fffe07f5efa: c0e5000918bb    bra=
sl   %r14,00007fffe0919070
                                      00007fffe07f5f00: a7f4ff39           =
     brc     15,00007fffe07f5d72
                                      00007fffe07f5f04: e320f0c80004    lg =
     %r2,200(%r15)
[Tue Sep  9 10:25:34 2025] Call Trace:
[Tue Sep  9 10:25:34 2025]  [<00007fffe07f5ef2>] remap_pfn_range_internal+0=
x372/0x420=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe07f5fd4>] remap_pfn_range_complete+0=
x34/0x70=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe019879e>] remap_oldmem_pfn_range+0x1=
3e/0x1a0=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe0bd3550>] mmap_complete_vmcore+0x520=
/0x7b0=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe077b05a>] __compat_vma_mmap_prepare+=
0x3ea/0x550=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe0ba27f0>] pde_mmap+0x160/0x1a0=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe0ba3750>] proc_reg_mmap+0xd0/0x180=
=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe0859904>] __mmap_new_vma+0x444/0x129=
0=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe085b0b4>] __mmap_region+0x964/0x1090=
=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe085dc7e>] mmap_region+0xde/0x250=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe08065fc>] do_mmap+0x80c/0xc30=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe077c708>] vm_mmap_pgoff+0x218/0x370=
=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe080467e>] ksys_mmap_pgoff+0x2ee/0x40=
0=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe0804a3a>] __s390x_sys_old_mmap+0x15a=
/0x1d0=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe29f1cd6>] __do_syscall+0x146/0x410=
=20
[Tue Sep  9 10:25:34 2025]  [<00007fffe2a17e1e>] system_call+0x6e/0x90=20
[Tue Sep  9 10:25:34 2025] 2 locks held by makedumpfile/563:
[Tue Sep  9 10:25:34 2025]  #0: 000078000a0caab0 (&mm->mmap_lock){++++}-{3:=
3}, at: vm_mmap_pgoff+0x16e/0x370
[Tue Sep  9 10:25:34 2025]  #1: 00007fffe3864f50 (vmcore_cb_srcu){.+.+}-{0:=
0}, at: mmap_complete_vmcore+0x20c/0x7b0
[Tue Sep  9 10:25:34 2025] Last Breaking-Event-Address:
[Tue Sep  9 10:25:34 2025]  [<00007fffe07f5d0e>] remap_pfn_range_internal+0=
x18e/0x420
[Tue Sep  9 10:25:34 2025] irq event stamp: 19113
[Tue Sep  9 10:25:34 2025] hardirqs last  enabled at (19121): [<00007fffe03=
91910>] __up_console_sem+0xe0/0x120
[Tue Sep  9 10:25:34 2025] hardirqs last disabled at (19128): [<00007fffe03=
918f2>] __up_console_sem+0xc2/0x120
[Tue Sep  9 10:25:34 2025] softirqs last  enabled at (4934): [<00007fffe021=
cb8e>] handle_softirqs+0x70e/0xed0
[Tue Sep  9 10:25:34 2025] softirqs last disabled at (3919): [<00007fffe021=
b670>] __irq_exit_rcu+0x2e0/0x380
[Tue Sep  9 10:25:34 2025] ---[ end trace 0000000000000000 ]---

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
fbe6c51-69f4-455e-922f-acdc613108cb-agordeev%40linux.ibm.com.
