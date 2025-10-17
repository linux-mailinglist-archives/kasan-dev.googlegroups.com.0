Return-Path: <kasan-dev+bncBDBPXNMCXABBBV7MZDDQMGQEDOWMM7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 16EBFBE8954
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 14:28:10 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-3c984a64bfasf2483192fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 05:28:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760704088; cv=pass;
        d=google.com; s=arc-20240605;
        b=dxhf/eTXPqI3X9JrAVSH3NEFgsU5iFuBV/urwT6B3bf/TZXaoESuiDe+HjPS4433Zu
         ZDaAT736VhvUcoB4p0zxs8SMGFRdKHeDml4W6757MeKfYdJhcWhCXkcZRz8wHY9O7OBH
         Uxj7BMhLnBVtcEfzQgZoUu4WTEqy2P9AejNCLEZftss5hmUTKavbNyevOBG8hH27sDZn
         sXBpRXP31ngihAu3bfe/PeIohaxORH1yUX64Jzp0aCwuVdK+9ZxvlrG5zk7wJkB3apIY
         IH3iY5wWCGEzVtqwCbxbl4ow0cCmDL3ejfTRM+qZ2yWpK8xiPTBqMgkCLIJI0drYx14C
         2Czw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=G7X5T2H1WKHhphIZtf67EgdR2cJEJpQn3ThC8HSiuBU=;
        fh=Y957kpqSDeAp84ET1zyfA0xV8i2klA8HkIgKc46yC/4=;
        b=A+CsiEFNfZg/nZb8WZKFMR2MHb2Wi5BQZr2xBtCxCQcQyJYzF6YXP0e03ES28xTDb+
         Hlsa3btcwy8UH3SLmxlfFPdVlAaM6YQ0rW4WIZwQOzuuZ8rTbUtn59xEx+6DVHo1+/e/
         ql7BVIKCCjQv2TV9dZWEXlbpPP5oX+EbntE7HKcDP/Fs4xOrZpCTcXZRcMkDT5Q5GAoo
         HV9wMJktjfldTDYMq4AHNbN5yf+HsRj+XArHl0H01tLCcoGAaXG5wIC3mEUq3XSvfQqD
         zSXUkwW201R3RD4XNiZ5v89Rot4RtrVY3p590Ac56/laiTOwObZDZMElTRazBOAFBDkU
         rglw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=eE5W0N9n;
       spf=pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sumanthk@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760704088; x=1761308888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G7X5T2H1WKHhphIZtf67EgdR2cJEJpQn3ThC8HSiuBU=;
        b=H3W2MSOX6e/jCaA8tKKKOOLDFYQlM/LsJki1JSVLsFAtJayaRdxoQtJa7DFOy8h8FT
         eKlgJDTSNXuUBOaZtyTXqWYM3s5nTyh0PjyY4Jss9foVpT842o7Q+NauuFqAfVEUM2/W
         olCm7mh3ah4Z012jPbDF0PMV+T3mPj0iURiJigPFriGM/7AAhx9qcN0+NGrPJI3vvCvh
         328P0mAcDBIyA631c3elbiY/1TK0jvArPOgsGPi7E8FsrfixEJNiaCaOn6YaZL1xh78a
         wppD8+zLgw6Qa7DW4MRqPmPQ2RqQhR23ygHuL3HPAvkiTEKzMq156hl8S1iSWuaHcK9K
         ALvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760704088; x=1761308888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G7X5T2H1WKHhphIZtf67EgdR2cJEJpQn3ThC8HSiuBU=;
        b=QVrOpgg/Ts51FXv5+VP2S3yb1bbGjcvUZLAes2eVvjmCGVXb9ueF9EwKkReqDXex17
         0cyVI319LSY64KABwEWWTBCoXwogyiKr49UBG0ldstQxAnPSWDayEyLe4biro2VHDqQU
         g4VBnfVdXruQChXpDgyfdI744OU99Ka9qaiLZ4TKdQa8JI0kb589JqwaH/j+isfOuqK6
         0FWHgPd8/8v7CQ8oGWYAHIfQC/ICkSWSdRBPXLxuJOG5AcWt5gUaG0U3CVp5QWQ89qy9
         iMTv+FuD3vZgKscKQyWOJaze8V+UFrN1HX0tpmIiTytOLjoU5MG4KoIPNP7t13KGlajO
         I8BQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWd8lY5mlcj8rQ7CO3TftKrX7/L2oDnI9pN0kw6hC0wikHBhkwka1hJZEGB4RXIylKEVXXB6Q==@lfdr.de
X-Gm-Message-State: AOJu0YwmpFQz6ASyjO2EawNFjKv8YH/ohkHoAeTrRyze7OicVZ7CBoUk
	/Am62Zumg/w9dqbtKKuMwdeYa+luhRf4qWn6CltpErzv4rx6mpV76uDg
X-Google-Smtp-Source: AGHT+IG4JFaeN7xB7jrDqSvnrhixIkvOfaSo0lyDt6PbEykT9aro+KX0Cb03Pk5NWEFOQU1+U963/g==
X-Received: by 2002:a05:6871:7421:b0:321:8f88:a39c with SMTP id 586e51a60fabf-3c98d1424afmr1421175fac.47.1760704088374;
        Fri, 17 Oct 2025 05:28:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd57xXcIcfWGMAF/URhs3/2QjEKhK2777BAxjW0FurpT+w=="
Received: by 2002:a05:6871:7c0c:b0:3a9:7d42:2984 with SMTP id
 586e51a60fabf-3c975220d77ls1716577fac.1.-pod-prod-05-us; Fri, 17 Oct 2025
 05:28:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVHPk9qgBAlijdn5HQXjxWzOJftiMnoglIY5HhS12+IhpDIAg4k/3ik3RYOtb5SoccEK3kxYRQCtaA=@googlegroups.com
X-Received: by 2002:a05:6871:5211:b0:3c9:7b0c:8b60 with SMTP id 586e51a60fabf-3c98cef4cb0mr1623044fac.2.1760704084570;
        Fri, 17 Oct 2025 05:28:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760704084; cv=none;
        d=google.com; s=arc-20240605;
        b=MqBgMFXC8BPY4HVsIopCT4cbLHLIAvVkaATVzlfTkFIMfUfvZftwUkGytfb9LuOx17
         BtltUXpWuOwJ2OWSgOdg7Ep/DlUll1dbYx2LjmnZx0d5chAiSkhHxKnXdG4izzIGgFVE
         72BsYX3IeNpgAbhl+AOGwGYHGX+eVT+Jndy7B3+eqKH8mISwCAbAtbbuKexRBYHIqZui
         NB6WlOdVAOzK86OmQbjuj7lJ+JvOecEUpfMlLfaEFsyUV+eTNqgler612+64uCtMeEYp
         JeO7h8FDSjIxZUOy5IltJ4PiGLlpmipNkyrU7ueg09/0dj3phVu0xdkSlvf9ef0058cQ
         oqkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zcD/4uYFsGN+ddlc5XN7jrlEbZPy90Q3VYii2jxgM9Y=;
        fh=U8TtT34EoG38Adv4STInzKJIgZ45rKwkAvQEav943y8=;
        b=B/eN8Z93sFhkAAwb9NRfiRlpl8Mr6/1q5AaiO2cuNVmVsrLRNv1H4BixyJNOmsGgCz
         zQ5nNCoD/onFZkYV5CjAPZ3Q4yiyipQu2aFB3TZf1VhkNx8Gek4p6QZnXrqjwA8pP1BY
         37W3V8EJBEz+oiEjQo0NPrZNzbsziTwLEM8Z2owwy2YJ3qrJF3fHXsGV2NABks2yIeGB
         w306D0pIcIolOZk8m2nx0Vx62RUjQTaTxtC6faWCNOH0JzvHlQ3mE5p7wAuJcvI7DVN0
         ++ByHDQSopQYgoEeCmRlbr0L+QXzIK/m4/P+o/mTfXYrLBcDAwTdKtQGVtviOF2W6oBx
         eI0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=eE5W0N9n;
       spf=pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sumanthk@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3c98402511dsi324029fac.3.2025.10.17.05.28.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Oct 2025 05:28:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59HAarsL010294;
	Fri, 17 Oct 2025 12:28:03 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49qewujm35-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Oct 2025 12:28:03 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 59HCS2e4011949;
	Fri, 17 Oct 2025 12:28:02 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49qewujm2x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Oct 2025 12:28:02 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 59H9Ms3A015041;
	Fri, 17 Oct 2025 12:28:01 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 49r3sjvxxw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Oct 2025 12:28:01 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 59HCRviL24904158
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 17 Oct 2025 12:27:57 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 80522200F0;
	Fri, 17 Oct 2025 12:27:57 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DE081200ED;
	Fri, 17 Oct 2025 12:27:54 +0000 (GMT)
Received: from li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com (unknown [9.111.68.179])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 17 Oct 2025 12:27:54 +0000 (GMT)
Date: Fri, 17 Oct 2025 14:27:53 +0200
From: Sumanth Korikkar <sumanthk@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: Re: [PATCH v4 11/14] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-ID: <aPI2SZ5rFgZVT-I8@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
 <aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
 <20250923141704.90fba5bdf8c790e0496e6ac1@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250923141704.90fba5bdf8c790e0496e6ac1@linux-foundation.org>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: oq4BBwfqQ48M4fFrJYto5eFg6cOrIUo4
X-Authority-Analysis: v=2.4 cv=Kr1AGGWN c=1 sm=1 tr=0 ts=68f23653 cx=c_pps
 a=AfN7/Ok6k8XGzOShvHwTGQ==:117 a=AfN7/Ok6k8XGzOShvHwTGQ==:17
 a=kj9zAlcOel0A:10 a=x6icFKpwvdMA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VnNF1IyMAAAA:8 a=Q64uQKxdJJvBSAPQG9IA:9 a=CjuIK1q_8ugA:10
 a=UhEZJTgQB8St2RibIkdl:22 a=Z5ABNNGmrOfJ6cZ5bIyy:22 a=QOGEsqRv6VhmHaoFNykA:22
X-Proofpoint-ORIG-GUID: 6VusDNc5IkEdh68Kaj2ZTeyqGB4LSNCy
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDExMDAxNCBTYWx0ZWRfXxloq0CHfoAPH
 XWVL1aBHdkm9/xfBCuiQ3NRDkHBHHJBzuRDZONYMy2fb9zEbQIvnfmYJ/id2eywCKro3ajwNeBN
 4kh50+Ptwe9WC/jgv6TvlSU3BjTjj8J4e8Q28WaUW15+fWE4+obYIhdatSNa8pR7s7K3qc9B/vz
 /NrDUP9sclcVLmwCaUq8/8kitasnnMGBQ+06iNPPJ2JLfYTXft3CE9tZA6j7MvZnByxSm0WG2L9
 6HJF8v/KHOyke08jKmTMex92BViTc6nNAZ8Mf08l0p8tEVPKsDoeg+/woBR1eJnDItXypZ8WKoi
 4hmgIRXSm+rnxVDlrmJgusCv4UyparD/Ec+dlPRV+dFyojmExkE6m1pDYvzlIJcGkJRfebaDxiR
 gMuyJhCR/K7vXVkZsF8tcUl7kIfexg==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-17_04,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 spamscore=0 priorityscore=1501 lowpriorityscore=0 bulkscore=0 adultscore=0
 phishscore=0 suspectscore=0 malwarescore=0 clxscore=1015 impostorscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2510020000 definitions=main-2510110014
X-Original-Sender: sumanthk@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=eE5W0N9n;       spf=pass (google.com:
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

On Tue, Sep 23, 2025 at 02:17:04PM -0700, Andrew Morton wrote:
> On Tue, 23 Sep 2025 13:52:09 +0200 Sumanth Korikkar <sumanthk@linux.ibm.com> wrote:
> 
> > > --- a/fs/hugetlbfs/inode.c
> > > +++ b/fs/hugetlbfs/inode.c
> > > @@ -96,8 +96,15 @@ static const struct fs_parameter_spec hugetlb_fs_parameters[] = {
> > >  #define PGOFF_LOFFT_MAX \
> > >  	(((1UL << (PAGE_SHIFT + 1)) - 1) <<  (BITS_PER_LONG - (PAGE_SHIFT + 1)))
> > >  
> > > -static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
> > > +static int hugetlb_file_mmap_prepare_success(const struct vm_area_struct *vma)
> > >  {
> > > +	/* Unfortunate we have to reassign vma->vm_private_data. */
> > > +	return hugetlb_vma_lock_alloc((struct vm_area_struct *)vma);
> > > +}
> > 
> > Hi Lorenzo,
> > 
> > The following tests causes the kernel to enter a blocked state,
> > suggesting an issue related to locking order. I was able to reproduce
> > this behavior in certain test runs.
> 
> Thanks.  I pulled this series out of mm.git's mm-stable branch, put it
> back into mm-unstable.

Hi all,

The issue is reproducible again in linux-next with the following commit:
5fdb155933fa ("mm/hugetlbfs: update hugetlbfs to use mmap_prepare")

Thanks,
Sumanth

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aPI2SZ5rFgZVT-I8%40li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com.
