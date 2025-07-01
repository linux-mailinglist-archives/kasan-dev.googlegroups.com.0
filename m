Return-Path: <kasan-dev+bncBCYL7PHBVABBB6XKR3BQMGQEAILGQEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id E2622AEF4C9
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jul 2025 12:16:31 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2363bb41664sf41532425ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jul 2025 03:16:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751364987; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zq1+LoummQQxcIRQlfrbA84AmXGm0v4FE7MOn324zWyrKkYX2rnO6vJCwOEeQ+1AZ+
         NXkjN1hGr2OkieMr+fhcQ/puw/izp75wXPOUOLhlt+FUxvfi9FtWMYnLDl6KORTKgu2N
         9eu8knILWaj9U+PU+7QFxoO4rYEJcizrZ7ndZsWIqOznm71MNsOHe1osX2L4OHs6Ikvd
         OZ7nB+ZpRwqd+q/TGGqV9BAVKp9I2a2doGFO1xkMlRITFwkg8XGYvD4KelrV+yoJuRCU
         wW930hW4E9VbnkjiWPpBojC9C1pltgh+emKWts4Ztkov0bV7gF0alEz7SD5/VKf/80gs
         coFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=BkeI4UJ8r5046XgKA4N/qWA4jIDMSMD5hGregVG/NVE=;
        fh=FDQ9dHU3jOuyef7MngaK5oVDoZaYS9cpw+wDtgvdMEo=;
        b=SRa8+8uPUOQ9tBYYaUhCNxfguRN6t6DYxzNGyzEojAzQVNQ5IT2CVHPV2OrL2NQk+4
         GkjBP0aR8Li/hdwYFYnfqJfsjY8ObowgbfaYwsxRXWtTSuQoBgdo8H3CdYim1B0uSn+K
         BM8TwyKUv0PFsYMijRl66CmOGjaQvOwqxilhswxrrU61c2IjZJ/PhlJtw9jwbJFFY8Gn
         qajgunTPCPr4zNjdchxAxYmixabuDub9Pgprl+ytnt8TriZlXqzcVxP9WwhHDQynymVQ
         DNUKJXLsnlhiSWbeOio7QQsxxmomdhhMGzlEZAoxXpVAhSj+BXuKkYjMR/mRjMw+qRVl
         kBtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PjDoYwjt;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751364987; x=1751969787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BkeI4UJ8r5046XgKA4N/qWA4jIDMSMD5hGregVG/NVE=;
        b=pxdC2r9NuSy6LLnoSbNKuhSWrizBeWUJElHxIqYPYzkdh02kbX0GsEt8JDEFfJhtF4
         YziKeoLz8fapnWg0dBqvK4GXfx/EkjpNnfIYZPfrU6gUmgE+7ese7HifqTR2gy6ljOkA
         SgQIzdo1K1P31+gdcvCLv/yT2bgN1bwX/u/BT1gqttxUT2c+b6o7ebqORSBom1AlOaAH
         BcXZ03QHHOoZ/qZJ+3oaWSaabTaP8HsGCRjWWrl6QCzKN+MX9FYXunljK5bypvIL452g
         Uc28YfGGfBU5TbWXmEMPCgL+7H3blMAIK5w6+ePRipt4GIV2EszmdVu91bNc3JF9CMI1
         ucdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751364987; x=1751969787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BkeI4UJ8r5046XgKA4N/qWA4jIDMSMD5hGregVG/NVE=;
        b=pQ75ygR2gZMJEFcRnX4m+ML8SHOXA/Y5mUhf1LddouUv2gklIpzcq0iGEE/fkCbpUE
         btS/jLPhqCxAkCV9st9iGnq8MCISsxgI3pEhS0GJr/MWKkf+jbP88eeFF1+CrYB6RU4J
         1J12mo/1VA8hnqyBt/WzKQu23Ad24pUFf1rvhpe6thGSq93U+6qBM+FBuVoNNMP1tuod
         2Y98drNzi9LWO7z31x/gGri4U8BiPsaZUlT2aTVQcvzm6B0WI7VQBpt0UyNGNa4Wd++m
         PgVSVCo4vKF+wqQ6mvpLn/ZZAw/gx/oTyA1m5Nhi1f1temWddRP9L36w/SfQ7gkguzLp
         bd/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+PdLYUPb7Yq6BcCtu6/7o52Fa81WzUddyasSRtNaqIq9BEpDX9bmSiEyY+WmaYUnQiH5BRA==@lfdr.de
X-Gm-Message-State: AOJu0Yy9PxDEnCmHYv2qUQ05XgCR5j8d4uj+88A8r0ZMjGfNujc3EzdV
	VoqFTzTwGIlKGaN3y5OyfAE2Ik96S2RXTS7m8wE0x80QNMG3ypqD07n8
X-Google-Smtp-Source: AGHT+IHQPR+zyCjpWTLwTsRfD76944m09GPkyaVLH9maBUSpKdle6g32ehMSO8EiVIhyI5GGaVLR4g==
X-Received: by 2002:a17:902:ec85:b0:234:adce:3eb8 with SMTP id d9443c01a7336-23b354ccbd2mr50009235ad.12.1751364986811;
        Tue, 01 Jul 2025 03:16:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZ23t6fDIL5JpXUaA18fNUj07qsf1LBNQ4JlUXZcBeXw==
Received: by 2002:a17:903:2806:b0:234:ae27:bf40 with SMTP id
 d9443c01a7336-238e9e13976ls28497285ad.1.-pod-prod-00-us; Tue, 01 Jul 2025
 03:16:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbsd0YkrZ1+sLyFlaTePoqxjAXvetwsX32st7fc3fcVeU528YovlNz9lP0wMOnBWJY9RZIDROd4lU=@googlegroups.com
X-Received: by 2002:a17:903:3c4e:b0:234:325:500b with SMTP id d9443c01a7336-23b3550a283mr49414885ad.22.1751364985436;
        Tue, 01 Jul 2025 03:16:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751364985; cv=none;
        d=google.com; s=arc-20240605;
        b=OkAs53f1VuHOc/R/59sD3xCAwFV9KxQNovmLRv3azshnM96k8NGBS72QcEyGTWatrT
         288WSu0y+szNBPePSPXqLCMrx6Pdr8MxtVATNHE6LFyi0Rv4Vwn7qi7N97ShNLezVvoN
         DTX6q7oxLuhMs81skQrqrApaGQNwpuWec0Mrh++87YhkDst08ROA5Rnq7Ag8k+7zKgao
         hB3Bq2OqBSOsFCqP2q0mtgFEmZrfgAKSVCCUQ5IxjDMTNvsDa34mQ8E2byNPAHg9HEYM
         q3lePFeMvy1dZC9tqYCCEjf8gBqgTKrEtJfF9ybJYQmKhp9LWWikFUuYBq3Tx+ELYBR3
         eUCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bI5gCubobaT76ILZ7nxLCeAprDNwZM108vGmis92vfw=;
        fh=zjm47Xfua9dOpEl1hojw/3j9s0j9uDx2CfL8cpSA8x0=;
        b=hT5xcWSMmOjZyN2wdYXTCgzxtfiLB4uq0Q4ifYqNBuYpdCoQXj/CPBG/v9AUg1YGgz
         YZ0pgbbGWSt4DXtx6XjC6jt3viTXDVcnAtm14yteP6sjEG8WviOtvw1h0mT2uFvthTEj
         R5lKmr2O6A7Or80G+/0XbCina5WK4N7lulQXllRo6Hk+ZQPFIJTYwpXl4JjLVFyFZ2JI
         b8B/thclODGi+eiMdYn8Dx9hSir6ug979h8Bq2qajL7ldLyRpZ2y9OeYTf9Hy/pZsm+M
         QnyduRSLCtRdWT9fUU8XReWYD4U9Pmx4ntrrh6l+8yLQyV73HA16ij38S8B9UiF+2gMo
         JiYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PjDoYwjt;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23acb2fa636si4440615ad.5.2025.07.01.03.16.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Jul 2025 03:16:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5616feQ9015295;
	Tue, 1 Jul 2025 10:15:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j830pmab-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jul 2025 10:15:48 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 561A93Md010712;
	Tue, 1 Jul 2025 10:15:47 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j830pma6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jul 2025 10:15:47 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 56173CoY032320;
	Tue, 1 Jul 2025 10:15:45 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 47ju40j8xb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jul 2025 10:15:45 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 561AFfZk21365030
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 1 Jul 2025 10:15:41 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4405320040;
	Tue,  1 Jul 2025 10:15:41 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 32B5D20075;
	Tue,  1 Jul 2025 10:15:39 +0000 (GMT)
Received: from osiris (unknown [9.111.81.242])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  1 Jul 2025 10:15:39 +0000 (GMT)
Date: Tue, 1 Jul 2025 12:15:37 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
        glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        linux@armlinux.org.uk, catalin.marinas@arm.com, will@kernel.org,
        chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
        mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
        paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
        alex@ghiti.fr, gor@linux.ibm.com, agordeev@linux.ibm.com,
        borntraeger@linux.ibm.com, svens@linux.ibm.com, richard@nod.at,
        anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
        dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
        tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
        hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
        akpm@linux-foundation.org, nathan@kernel.org,
        nick.desaulniers+lkml@gmail.com, morbo@google.com,
        justinstitt@google.com, arnd@arndb.de, rppt@kernel.org,
        geert@linux-m68k.org, mcgrof@kernel.org, guoweikang.kernel@gmail.com,
        tiwei.btw@antgroup.com, kevin.brodsky@arm.com, benjamin.berg@intel.com,
        kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
        linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
        linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
        linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
        linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with
 kasan_enabled
Message-ID: <20250701101537.10162Aa0-hca@linux.ibm.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
 <CA+fCnZfAtKWx=+to=XQBREhou=Snb0Yms4D8GNGaxE+BQUYm4A@mail.gmail.com>
 <CACzwLxgsVkn98VDPpmm7pKcbvu87UBwPgYJmLfKixu4-x+yjSA@mail.gmail.com>
 <CA+fCnZcGyTECP15VMSPh+duLmxNe=ApHfOnbAY3NqtFHZvceZw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcGyTECP15VMSPh+duLmxNe=ApHfOnbAY3NqtFHZvceZw@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: qu16htFmviN0JHs_Lk2UXggpRHKamSL3
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNzAxMDA1OCBTYWx0ZWRfX1+8afvt373Lc kWdnunbPz6C9f/GOHjl4ZrQKHABgOATpMhlNHzlwXmovxD7qpB0NHRzjO1rBP3TCrzWp9aDgeMZ BRGyDtucaQptfKRiB1Ir1UEiA/DnvvId+/noIpRKGxbqodALAZAM/OouyWSCdZn9Br55SUFY1mF
 /QElD3fMWDED/2Up/bE3bdkQFp0y4l0tbOgz/r1X+BYJtzifCAp1d8Rjiv1rqAaxBvj1uWPWfAv gRsEeOrKai0th89ONMoXzLZtwQ+ZFabmyQx6rICdTSFHm+Cjr3wa4WzluId4DM526gzf4NqEHxp T9u38OW/UmDyf8gxdR/KVtrZKshh0EQP4/y/BFKLU+IB3+JEAkKDZdFyiBgBhMsxkkHSKm2H012
 aLNkwLyaNoCYreQzuUSpD2tKUqxrMT5HjvgLBKo4Yoqu8W0zpbow/WbwFXvshhrHRfN8RYzo
X-Authority-Analysis: v=2.4 cv=MOlgmNZl c=1 sm=1 tr=0 ts=6863b554 cx=c_pps a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17 a=IkcTkHD0fZMA:10 a=Wb1JkmetP80A:10 a=jBQngTtrd59FM_Ge02gA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10
X-Proofpoint-GUID: HLwv3VLvA_zkneOazGXOaA6Q1nuISU0B
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.7,FMLib:17.12.80.40
 definitions=2025-07-01_02,2025-06-27_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 mlxscore=0
 adultscore=0 suspectscore=0 bulkscore=0 clxscore=1015 impostorscore=0
 priorityscore=1501 mlxlogscore=906 spamscore=0 malwarescore=0
 lowpriorityscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505280000
 definitions=main-2507010058
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PjDoYwjt;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

> > > Another thing that needs careful consideration is whether it's
> > > possible to combine kasan_arch_is_ready() and kasan_enabled() into th=
e
> > > same check logically at all. There's one issue mentioned in [1]:
> >
> > Hello,
> > I've removed kasan_arch_is_ready() at all in this series:
> > [PATCH v2 11/11] kasan: replace kasan_arch_is_ready with kasan_enabled
> >
> > Is it not what's expected by unification?
>=20
> I guess the issue description diverged a bit from what needs to be
> done, sorry about that.
>=20
> The core 2 things I wanted to address with the unification are:
>=20
> 1. Avoid spraying kasan_arch_is_ready() throughout the KASAN
> implementation and move these checks into include/linux/kasan.h (and
> add __wrappers when required).
>=20
> 2. Avoid architectures redefining the same kasan_enabled global
> variable/static key.
>=20
> Initially, I thought that s/kasan_arch_is_ready/kasan_enabled + simply
> moving the calls into affected include/linux/kasan.h functions would
> be enough. But then, based on [1], turns out it's not that simple.
>=20
> So now, I think we likely still need two separate checks/flags:
> kasan_enabled() that controls whether KASAN is enabled at all and
> kasan_arch_is_ready() that gets turned on by kasan_init() when shadow
> is initialized (should we rename it to kasan_shadow_initialized()?).
> But then we can still move kasan_arch_is_ready() into
> include/linux/kasan.h and use the proper combination of checks for
> each affected function before calling __wrappers. And we can still
> remove the duplicated flags/keys code from the arch code.

FWIW, as Alexander Gordeev already mentioned: this series breaks s390,
since the static_branch_enable() call in kasan_init_generic() is now
called way too early, and it isn't necessary at all. Which, as far as
I understand, may be the case for other architectures as well. s390
sets up the required KASAN mappings in the decompressor and can start
with KASAN enabled nearly from the beginning.

So something like below on top of this series would address
that. Given that this series is about to be reworked this is just for
illustration :)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 0c16dc443e2f..c2f51ac39a91 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -172,6 +172,7 @@ config S390
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_EARLY
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
 	select HAVE_ARCH_KMSAN
diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 2436eb45cfee..049270a2269f 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -10,7 +10,11 @@
  * Global runtime flag. Starts =E2=80=98false=E2=80=99; switched to =E2=80=
=98true=E2=80=99 by
  * the appropriate kasan_init_*() once KASAN is fully initialized.
  */
+#ifdef CONFIG_HAVE_ARCH_KASAN_EARLY
+DECLARE_STATIC_KEY_TRUE(kasan_flag_enabled);
+#else
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+#endif
=20
 static __always_inline bool kasan_enabled(void)
 {
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..1407374e83b9 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -4,6 +4,13 @@
 config HAVE_ARCH_KASAN
 	bool
=20
+config HAVE_ARCH_KASAN_EARLY
+	bool
+	help
+	  Architectures should select this if KASAN mappings are setup in
+	  the decompressor and when the kernel can run very early with
+	  KASAN enabled.
+
 config HAVE_ARCH_KASAN_SW_TAGS
 	bool
=20
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 0f3648335a6b..2aae0ce659b4 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -36,7 +36,11 @@
  * Definition of the unified static key declared in kasan-enabled.h.
  * This provides consistent runtime enable/disable across all KASAN modes.
  */
+#ifdef CONFIG_HAVE_ARCH_KASAN_EARLY
+DEFINE_STATIC_KEY_TRUE(kasan_flag_enabled);
+#else
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+#endif
 EXPORT_SYMBOL(kasan_flag_enabled);
=20
 struct slab *kasan_addr_to_slab(const void *addr)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index a3b112868be7..455376d5f1c3 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -42,7 +42,8 @@
  */
 void __init kasan_init_generic(void)
 {
-	static_branch_enable(&kasan_flag_enabled);
+	if (!IS_ENABLED(CONFIG_HAVE_ARCH_KASAN_EARLY))
+		static_branch_enable(&kasan_flag_enabled);
=20
 	pr_info("KernelAddressSanitizer initialized (generic)\n");
 }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250701101537.10162Aa0-hca%40linux.ibm.com.
