Return-Path: <kasan-dev+bncBDBPXNMCXABBB5MTZLDAMGQEKVMOWII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id A048BB95BD9
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 13:52:23 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-eaa41510d98sf5103955276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 04:52:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758628342; cv=pass;
        d=google.com; s=arc-20240605;
        b=CQBwoCBF7iMbim3MBJbr8uT30TyrOjp2jJUmxO61ZL4s7fHKyGXys0y56j+iSQzsvd
         EDIrBWkQMD6SIB5snE0pyWIZDNz6GSFnsFDqlWUDHxJKcMoEPjNrFCQ1mnI14HWluuaD
         K3NuSYiBR0WEQpm+kZOZvX2IFuCxTnFXl4k/Cp7i2HmUSoq5Wdp3t6pMNz10W7pVZBAp
         d6QvM0T+W5Rg6+hfR4FUc3PCj/mNj7tJbFNpLNdfdQ9CIMFEeJ2N2n0ERVLSmtLKer95
         OridUrBdXf1UrSR0a88ox7wh21aUI53RXxRBeGvqZPA0ofsYRMSDwr2GavOT2PQRCm5z
         VAiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UDHgFFunltdvjN7KKzZkuCUm3Rc6yzmic0cVXG1yWWM=;
        fh=pLWZq5Gy6D/YsAkrgdev0lxbrSgjIvbKR+Qm0ZzB72E=;
        b=fq4Yw0UT1zHBkWn01nV79+G3/HottRYJ3LBSkSjU2+sb7VvYuY+wnKNYaAzHlFTi1b
         gWqqm/jpLAMRLGfgGrVl5uCSat58Zwx8CADPViNIibk0p2bEAfJ9pPftoVs0wiZbfKbR
         bjn++aspQnzVG7OMM8PngVadD4Q2Z+kF5C4ktoNeaYvVJ4Y6GpIa850rnc+chdZWRsE8
         qSctLEkomivvbnFUxSmCWVZEtfNDMwneebKlqin4Q9LhbvDEVXoXZZDDc7LFqK+fLdCU
         CaipWAbpUuS3PkhE/tSEO94bI7sAMkRuEut8/UInAew/PbZEbwLxFrxqtUPmjAeKUdIk
         RfJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EFGvr8Qy;
       spf=pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sumanthk@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758628342; x=1759233142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UDHgFFunltdvjN7KKzZkuCUm3Rc6yzmic0cVXG1yWWM=;
        b=BVmGstgAMN8L/WECA1hvgXCpyfTa4+xJim00IBDKK0mrlVZNwrYUoOmVpVYnA5m717
         Zxe1FULYnDPKnBv4OfVuP3H/ammnI/6VgvSVtZZqcsOV/B5Jik7VboirYnWWHD61tL99
         GQ2p6xV/uR3exWluLEjXpih6qs3VgMtxuV0S+PvnsDcPb1IUPft8BbQNwhFQPPctl4L3
         0JwNeDD4ROLC31Q3B62LM4tnOqYB+PzZMFkA/9OtzHDjoMhph8nah5BYTjhkT26lMynC
         0PIqhoDtIXRoOH1NYifhjml/J+CV9OSXFSId2Q/DNTaVxcm/HKW0K+Vn9R9iQF2e/ME5
         xERQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758628342; x=1759233142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UDHgFFunltdvjN7KKzZkuCUm3Rc6yzmic0cVXG1yWWM=;
        b=hKk6jYbE4BhRR7ikLNvkwN6qZZpY1p+u3+7PN0vR1l3qimyTJqTkTrORbLRN6wV+d3
         kppuZezfLcloen9ErLiNAoRSTH/LYIBDTZVXOA/fb7eZiCsK/+IZVp9hi6GrGFehYCBF
         ef+SNoySu2w+HAiErjRxMHlzaUVsGuKDLO6Ymcp7kM2jJ5BbLUsESAGG7cYwjrFFfo2p
         dIjFRde00994WXlC1z9fC5pslW4qB8rPbadtPwOhMdJsKFT2pSpy4+E9zz/y3N1DTtMK
         m9UEXjxwRp4vkXDFtn+gOc0k+B2rSDF7UxT/qA9gEfvSdrtjnKwHNWLVQrt/L4ovs07x
         xe5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVEIZfsyIXNXc32YCCkRgi7gELXwBtOvxsacsb+RqK54VzstuMqKrAtTDw7kWrMgCG2TnuzhA==@lfdr.de
X-Gm-Message-State: AOJu0Yzx7NMvtV/rMTBwigtNznIoSR5jc57oJm4uo6fPO6yse9gSSgvA
	gZF82HPuj08dfpH3MoGvyzkoDldJ4yVNWerxFdhDmpkY0C11mgiE47/T
X-Google-Smtp-Source: AGHT+IHjw7m2kV2zQc5HIne57CGoS/e7/6ZuWAc/9pcj4+x0Jx0Vs7UbtZJ28OwHNHiGEnFuu8gTdg==
X-Received: by 2002:a05:6902:1206:b0:ea5:b757:9641 with SMTP id 3f1490d57ef6-eb33838097cmr1441764276.1.1758628341782;
        Tue, 23 Sep 2025 04:52:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5AU9os9xpCArOdK9dxem8fJ+A5gzUxZ+K+LTJPYQw57g==
Received: by 2002:a25:b292:0:b0:ea5:b227:2f5f with SMTP id 3f1490d57ef6-ea5bc2d102cls2113527276.1.-pod-prod-00-us-canary;
 Tue, 23 Sep 2025 04:52:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWp5ZdLw1CTMInhadRT/W2BuiP881rUJveNgnV/cBCXQlqa806dDX31kAHzevXD0XRTwaJNRBMrsSo=@googlegroups.com
X-Received: by 2002:a05:690c:6d91:b0:74f:c3d4:1b51 with SMTP id 00721157ae682-758a1e95788mr16366057b3.22.1758628340709;
        Tue, 23 Sep 2025 04:52:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758628340; cv=none;
        d=google.com; s=arc-20240605;
        b=FXHaf8Gl85jebhY9mRdDlJMo2F05Sm31+8KCIZVUd2iFfIH0a4N71vpx9e4I3OQ2K/
         7SDeCZ3feVCA4ExC7gpDSEez+NLgYqydygdorefF3t4IgsH8T9R9uREWV0zMA8q8YurS
         QqIHlxW3lggk1WhPNS+qJZQiTNlM76bGpXyw4oPLMFn1YQ/36c35rEt29JOyGTG1SMq1
         OSy7+6HYJrXCpZZ+XoOPR5RSH0LGk6KTNTQvWGMkHrU00kB2KTWJ/6h+6GQglyX+45gD
         1PRukx22ozRMlaeRwvxTmG/ceJGHhniSQrVr519LSYDiGPjt5NnCyFYfHzTLBEYWrrBJ
         /ZKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FZaoT1QNSR93wIPtHts3CPzp0ctIk0vYDNbzffEOi0c=;
        fh=EyueO3/KsOf1nuzzflXHAbZMueY1tbGxAHLRS9wb6ys=;
        b=JrNsk4uCkFADHy6HeTbgenMTC8Wm5Qg2FQr4R7NQcM67gBhxjG53JaZbOLTU+qa1px
         2I6z4ZhfyqU3pPIwSUTUP3TNLv/fylD+B0YicXmW3xFAO8Xt0OKIQAq0NzCD0AUyHJvV
         hKwtkofP8z41ZwfPqraLoBRVZA0H9ZIcPEEHh7+zeh2KrAU9CCTmo5goam6Ibh+s7hek
         hithKHEuMG3wbc9CBIthOUyCmkXtBZOBzeKCstZ5V8zVwP/f1pISEe1rVakBPJUC8vBb
         q9N2Qzn2aEI61UTHyuY/8eIVUGayuOE3LYlmFzWKJ0FMJtBjKmSosjLw8q7mAg+A3Fhl
         opEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EFGvr8Qy;
       spf=pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sumanthk@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-635380b3cf4si320297d50.1.2025.09.23.04.52.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Sep 2025 04:52:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of sumanthk@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58N8Y12b008695;
	Tue, 23 Sep 2025 11:52:19 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 499n0jgm9c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Sep 2025 11:52:19 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 58NBn9Dd005820;
	Tue, 23 Sep 2025 11:52:18 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 499n0jgm96-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Sep 2025 11:52:18 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 58N9Tk1U019675;
	Tue, 23 Sep 2025 11:52:17 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 49a83k31qr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Sep 2025 11:52:17 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 58NBqDIE43516160
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Sep 2025 11:52:13 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F401A20043;
	Tue, 23 Sep 2025 11:52:12 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A61F420040;
	Tue, 23 Sep 2025 11:52:10 +0000 (GMT)
Received: from li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com (unknown [9.87.150.243])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue, 23 Sep 2025 11:52:10 +0000 (GMT)
Date: Tue, 23 Sep 2025 13:52:09 +0200
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
Subject: Re: [PATCH v4 11/14] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-ID: <aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTIwMDAzMyBTYWx0ZWRfX1/CT4ehdu5F7
 6VnJC5JZb/TGq0GTxXqzwutGBpnh5zvXhqXxihnE0ZIBeLxavZe5A1rzKbuxO1bDNyuFhUEM+Rk
 4I1KMXyeBzNEU/g4Tedu1h1rULa5Sn/p0/UqkELdAnxrKDhWjf96WssSMg0ltTS+aMBZqn2U8bf
 Mm6V030K3rfmUmm6+2tKL/Lil9yhk2vaa1ilZs3936p1XOaPfvsu3tSuBabaOBW+S4p6UJCCS7o
 UssKxq/W9pewKawoXgWRMXrenvRD0Q+OeFvs8GRRauXhjlsHet/L1r4+QnnsJQ0kVijCVo4qQhY
 p/3nafFZQN3AWkhiFthvrI3hfInHVuTDSlQN3xLdzE/r0zMDPQuTX7WW9M8m8X+BWNkt+j6HOZU
 bcmWMt/c
X-Authority-Analysis: v=2.4 cv=TOlFS0la c=1 sm=1 tr=0 ts=68d289f3 cx=c_pps
 a=3Bg1Hr4SwmMryq2xdFQyZA==:117 a=3Bg1Hr4SwmMryq2xdFQyZA==:17
 a=kj9zAlcOel0A:10 a=yJojWOMRYYMA:10 a=NEAV23lmAAAA:8 a=yPCof4ZbAAAA:8
 a=Ikd4Dj_1AAAA:8 a=P7Dlay8f7KcL8MNlhToA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: F6nP2Q8ol4BSxLNz15joz3bImrmTREZ1
X-Proofpoint-GUID: 5HR21TLQQZuGh5ctB-qo8M6ErsQDpoDW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-23_02,2025-09-22_05,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 clxscore=1011 priorityscore=1501 phishscore=0 impostorscore=0 adultscore=0
 suspectscore=0 spamscore=0 bulkscore=0 malwarescore=0 classifier=typeunknown
 authscore=0 authtc= authcc= route=outbound adjust=0 reason=mlx scancount=1
 engine=8.19.0-2507300000 definitions=main-2509200033
X-Original-Sender: sumanthk@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=EFGvr8Qy;       spf=pass (google.com:
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

On Wed, Sep 17, 2025 at 08:11:13PM +0100, Lorenzo Stoakes wrote:
> Since we can now perform actions after the VMA is established via
> mmap_prepare, use desc->action_success_hook to set up the hugetlb lock
> once the VMA is setup.
> 
> We also make changes throughout hugetlbfs to make this possible.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
> ---
>  fs/hugetlbfs/inode.c           | 36 ++++++++++------
>  include/linux/hugetlb.h        |  9 +++-
>  include/linux/hugetlb_inline.h | 15 ++++---
>  mm/hugetlb.c                   | 77 ++++++++++++++++++++--------------
>  4 files changed, 85 insertions(+), 52 deletions(-)
> 
> diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
> index f42548ee9083..9e0625167517 100644
> --- a/fs/hugetlbfs/inode.c
> +++ b/fs/hugetlbfs/inode.c
> @@ -96,8 +96,15 @@ static const struct fs_parameter_spec hugetlb_fs_parameters[] = {
>  #define PGOFF_LOFFT_MAX \
>  	(((1UL << (PAGE_SHIFT + 1)) - 1) <<  (BITS_PER_LONG - (PAGE_SHIFT + 1)))
>  
> -static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
> +static int hugetlb_file_mmap_prepare_success(const struct vm_area_struct *vma)
>  {
> +	/* Unfortunate we have to reassign vma->vm_private_data. */
> +	return hugetlb_vma_lock_alloc((struct vm_area_struct *)vma);
> +}

Hi Lorenzo,

The following tests causes the kernel to enter a blocked state,
suggesting an issue related to locking order. I was able to reproduce
this behavior in certain test runs.

Test case:
git clone https://github.com/libhugetlbfs/libhugetlbfs.git
cd libhugetlbfs ; ./configure
make -j32
cd tests
echo 100 > /proc/sys/vm/nr_hugepages
mkdir -p /test-hugepages && mount -t hugetlbfs nodev /test-hugepages
./run_tests.py <in a loop>
...
shm-fork 10 100 (1024K: 64):    PASS
set shmmax limit to 104857600
shm-getraw 100 /dev/full (1024K: 32):
shm-getraw 100 /dev/full (1024K: 64):   PASS
fallocate_stress.sh (1024K: 64):  <blocked>

Blocked task state below:

task:fallocate_stres state:D stack:0     pid:5106  tgid:5106  ppid:5103
task_flags:0x400000 flags:0x00000001
Call Trace:
 [<00000255adc646f0>] __schedule+0x370/0x7f0
 [<00000255adc64bb0>] schedule+0x40/0xc0
 [<00000255adc64d32>] schedule_preempt_disabled+0x22/0x30
 [<00000255adc68492>] rwsem_down_write_slowpath+0x232/0x610
 [<00000255adc68922>] down_write_killable+0x52/0x80
 [<00000255ad12c980>] vm_mmap_pgoff+0xc0/0x1f0
 [<00000255ad164bbe>] ksys_mmap_pgoff+0x17e/0x220
 [<00000255ad164d3c>] __s390x_sys_old_mmap+0x7c/0xa0
 [<00000255adc60e4e>] __do_syscall+0x12e/0x350
 [<00000255adc6cfee>] system_call+0x6e/0x90
task:fallocate_stres state:D stack:0     pid:5109  tgid:5106  ppid:5103
task_flags:0x400040 flags:0x00000001
Call Trace:
 [<00000255adc646f0>] __schedule+0x370/0x7f0
 [<00000255adc64bb0>] schedule+0x40/0xc0
 [<00000255adc64d32>] schedule_preempt_disabled+0x22/0x30
 [<00000255adc68492>] rwsem_down_write_slowpath+0x232/0x610
 [<00000255adc688be>] down_write+0x4e/0x60
 [<00000255ad1c11ec>] __hugetlb_zap_begin+0x3c/0x70
 [<00000255ad158b9c>] unmap_vmas+0x10c/0x1a0
 [<00000255ad180844>] vms_complete_munmap_vmas+0x134/0x2e0
 [<00000255ad1811be>] do_vmi_align_munmap+0x13e/0x170
 [<00000255ad1812ae>] do_vmi_munmap+0xbe/0x140
 [<00000255ad183f86>] __vm_munmap+0xe6/0x190
 [<00000255ad166832>] __s390x_sys_munmap+0x32/0x40
 [<00000255adc60e4e>] __do_syscall+0x12e/0x350
 [<00000255adc6cfee>] system_call+0x6e/0x90


Thanks,
Sumanth

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNKJ6b7kmT_u0A4c%40li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com.
