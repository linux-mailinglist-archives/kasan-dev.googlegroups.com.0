Return-Path: <kasan-dev+bncBCVZXJXP4MDBBB6YRLBQMGQEGCJBUSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EA67AEE246
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 17:23:56 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-311d670ad35sf1864030a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 08:23:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751297032; cv=pass;
        d=google.com; s=arc-20240605;
        b=NtBgY1WbzAYVpFJbsebOkw6M4uzM1DrF6Pz9fPLZFjhlIekJtjyeJy8CexpheGqj2c
         yjpswJq7VecXpzW5D1JRKKKfraiVpSH8GzGjvtof4UBzUuQ80rZcSLYQepk2JKepQtAB
         lsn/sBg4cSbK7FmTHjoGwJOWAU7tTAAdQX/mRpKqwNheQWz+h7vpf7zwPMjaVwjt7VZi
         0W36Ag+BB0z1ZizfVTUseHHdxJ7jKh9BTJyKyOBS5TJc6Jzg7DiVP78VRQvKCqR/BiTR
         8n/Oe0ksYW28PVruzkhN+tP1x+FPtxyUey8TffDfu8UOrjDpSAhVmqB7nQ5T2uGR2aox
         kVJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5ljxVYueP5Q/Xl1rGwK/Ev3YKPYhm3FHe0fB/ocYcfU=;
        fh=+gNjEuKaxTkVBg1d91d1Ikc91zBZjRlYm1liobTeqII=;
        b=guWiXCtSUnZb3lx2MBivtJAc6sH2GTOlGabFWQjJx2+AoSGV4oONK8Tg2+L1JfLIGK
         wGhUVR5XKWOlPlzK1JO7Z0EPqMTnxN5x+oKrhuOKkY6sIkq0F2Riye8sVK4PzGrPsJtI
         pl0bZg55ga0epjc1TnUwq9po0J0SuPfPg3MmifkgVB0saDfYGInfG7uy1hXKEW0qIqtG
         C1t0ntxL407S9D98MptMJthRavwT0UABB6ZBRA7Wb+bX0TtbDxReUu0YeVyqsQJNTWiB
         yULp6oDYFGBaeGhqy9E2NVFo4behqq/TBt9DP9FgBlGTWY7MV/VvH3J/dl7iQCXNemcx
         km7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Ab5IZRmw;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751297032; x=1751901832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5ljxVYueP5Q/Xl1rGwK/Ev3YKPYhm3FHe0fB/ocYcfU=;
        b=ejcMJ+gyxSG2Tr3ZBx+67Q9SLqZlzg6Wk4mB5GLMm5oOSjIIyr8io4qSD/hOBipGEg
         kxS7qrxLWOnTVOkXmPnmgxVTW4/U4OjUIpaiNXDGqP4X2JjOUEIVpT0mv6suu+4UMrVS
         GJ1DwJE4Cp1qj9D93RVn32zXga/SE2aQQebqYKFRZmkyTvwpTylVRtoiEWvU4qED61Qk
         GZNf6LkOe2cOaapN9H/fdMDgTQZPMEbo5TmY1GxAUOHFG5A7GPnVFKT3DPEGFvcYokZW
         scz8wY810z1MGTKgxmzHwwmQvfhwDQlvJzPotleDtdwP5rG0sGqLY8FcrfiCGMH4jLqV
         SZIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751297032; x=1751901832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5ljxVYueP5Q/Xl1rGwK/Ev3YKPYhm3FHe0fB/ocYcfU=;
        b=WrSSu/HoHekd1aIOtvUsPi1qsAGKfxv6KWRxTStSPLnJ7bqHWqLKnkD2Bmck85y9EQ
         9yUb0axZzG7gWHE8Mzyi9z9x/EnkBjdF57WGP5zdExQo1QSDnpdKeZGqbEdVBxlUQ1RQ
         C4SbpfYREISSzwnOk8pdU1sioJ5z1pVXo3PLDrsGIdKRh6NfDXLHlDJ2eyfsEOiAy8tP
         3r5+LAboQ+Te7Y2hgPP8U0/QN+CMBS0ztU/BJsJ8P13cOhzdMM370MgD0UTFs5bfEKF4
         MQfNkGswBp+HFvRAhUviKY9xM0XXZIFHmNc1QPQkRwkN+MWPypVkwNBUiWbyeYLBo1c2
         dD5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXNo1Om8PAIgEbqksqeyPkkOiqR8O0xlutsCuPcn6XTqI2MLkLfs6hDglq43ZUvHloC5W69/g==@lfdr.de
X-Gm-Message-State: AOJu0Ywbglujd/lc2CZZaIOLHVQeKVs1jjMXaF7oW1n0+4TobADVcSVZ
	unY79JMrZS8qKx2nq2mL6jYy1OuA6Czb7Ncxf0Q6QEciyDHGYgtQrjZJ
X-Google-Smtp-Source: AGHT+IEcTVFoDWnm0jHT/xw21PW98ZFq4tKKpB7G5OlvvwYqS3e9YHLMbK0fVdBsnTyouFSHDwtzdA==
X-Received: by 2002:a17:90b:2dcc:b0:313:14b5:2538 with SMTP id 98e67ed59e1d1-318c93131damr18929621a91.35.1751297031602;
        Mon, 30 Jun 2025 08:23:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/p3h19A4RLn/VlZplfr6TzS7/qAyCIZSr+PLMdDJhgg==
Received: by 2002:a17:90b:498d:b0:311:df4b:4b8d with SMTP id
 98e67ed59e1d1-3169dc5fe52ls4214562a91.1.-pod-prod-07-us; Mon, 30 Jun 2025
 08:23:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVorESvRgkYp3vBPc6V/o2MmV+guxvqREvmSFxYgr+yrNoob4ZpPHmxS00LWdcAubi8YdTWvPiFkdk=@googlegroups.com
X-Received: by 2002:a17:90b:5345:b0:311:b3e7:fb31 with SMTP id 98e67ed59e1d1-318c8d2ba92mr21669284a91.0.1751297029786;
        Mon, 30 Jun 2025 08:23:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751297029; cv=none;
        d=google.com; s=arc-20240605;
        b=iqqnTYKDXGbhB7F6w/3QksawiTxYdGHNWZb71fTArqMnNGncgyTUn6KeRdvAzCMAhN
         AhlrNSLyIp+0O8pcWH88rXVZF/kk+D3w0ehb2dka7i9VE1IV0TNqCnZgaiWb+wO8m2s6
         3ys0ZbEPzMm1VpYE3zeL6DhsN6nxXzSMl8VkqshpqYf1mE2kfmZPimuQoV1hA//lRjsF
         vNgclUoUWwjIzAcyboaZzycxzMqPn9+f7ZBRzLT9S545arAZETCRCfkMEOI5es8PAdkl
         /DeYnBSD+Rsi8e8hzInYZVTWNCsY+jPK7SWUftXtZDw+kIwIQTyrIDEmT6Qx5b27Zx8d
         S5qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6FceECBbuO6Z4x2Rp39hcL1hfD2xOI56xCXiWcKK9WA=;
        fh=/ULJ/0QzlVmsRiNxYIpinK78DeAvVUJr9smzFOdF9wQ=;
        b=Y8hAYzdyP8El+EdU9lIEfRskCglRgKo7CLnVUWJqYabMq0yFQVS2YC7B++jjxc2ecE
         B5WgSz3AA0DbZgl+NRzb2No1XR2ZJnljeib3FjYS37LYfVQE3yda81BTyrtj6oRCXg2+
         2ZxoV+ZP5DN0cifxNKCEu0yANr9e4ClJWsrYdETbCCi+9mJM9s0ioRniiz4kWYS65nWV
         wVv4FPHn2Y1Am/DlVIMOwkXhAOxBoe2D3PCO7uTiUfjLPBzKLcOku+pPrkCRDx1HW0VC
         FdSSsGaiNII9AAvnPpOKbsEheyhgTrTS6F4q3uex9VRqrXU57YM/JHMmPrreSBDRTY2V
         Ogjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Ab5IZRmw;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-315edd125f8si212203a91.1.2025.06.30.08.23.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Jun 2025 08:23:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 55U8V2Ia000758;
	Mon, 30 Jun 2025 15:23:22 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j5tt2hv1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 15:23:21 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 55UFKkJT001633;
	Mon, 30 Jun 2025 15:23:20 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j5tt2hut-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 15:23:20 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 55UF6Jrx006928;
	Mon, 30 Jun 2025 15:23:19 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 47jvxm687n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 15:23:19 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 55UFNFi141091496
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 30 Jun 2025 15:23:15 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9E3012004E;
	Mon, 30 Jun 2025 15:23:15 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4EF2520043;
	Mon, 30 Jun 2025 15:23:14 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 30 Jun 2025 15:23:14 +0000 (GMT)
Date: Mon, 30 Jun 2025 17:23:12 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Heiko Carstens <hca@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>,
        Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
        glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
        vincenzo.frascino@arm.com, linux@armlinux.org.uk,
        catalin.marinas@arm.com, will@kernel.org, chenhuacai@kernel.org,
        kernel@xen0n.name, maddy@linux.ibm.com, mpe@ellerman.id.au,
        npiggin@gmail.com, christophe.leroy@csgroup.eu,
        paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
        alex@ghiti.fr, borntraeger@linux.ibm.com, svens@linux.ibm.com,
        richard@nod.at, anton.ivanov@cambridgegreys.com,
        johannes@sipsolutions.net, dave.hansen@linux.intel.com,
        luto@kernel.org, peterz@infradead.org, tglx@linutronix.de,
        mingo@redhat.com, bp@alien8.de, x86@kernel.org, hpa@zytor.com,
        chris@zankel.net, jcmvbkbc@gmail.com, akpm@linux-foundation.org,
        nathan@kernel.org, nick.desaulniers+lkml@gmail.com, morbo@google.com,
        justinstitt@google.com, arnd@arndb.de, rppt@kernel.org,
        geert@linux-m68k.org, mcgrof@kernel.org, guoweikang.kernel@gmail.com,
        tiwei.btw@antgroup.com, kevin.brodsky@arm.com, benjamin.berg@intel.com,
        kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
        linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
        linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
        linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
        linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2 01/11] kasan: unify static kasan_flag_enabled across
 modes
Message-ID: <aGKr4DgJ4w3TfJm1@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
 <20250626153147.145312-2-snovitoll@gmail.com>
 <aGKDhPBgDv2JjJZr@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
 <20250630143934.15284Caf-hca@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250630143934.15284Caf-hca@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: z4_YQR3yiIx6CG78lyz9FOWfFKu_sVzX
X-Authority-Analysis: v=2.4 cv=UtNjN/wB c=1 sm=1 tr=0 ts=6862abe9 cx=c_pps a=AfN7/Ok6k8XGzOShvHwTGQ==:117 a=AfN7/Ok6k8XGzOShvHwTGQ==:17 a=kj9zAlcOel0A:10 a=6IFa9wvqVegA:10 a=DoNX2vE5F4BLjyZpJB8A:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: tSMJYZyFhxN0ELYUCpeHLTTc07NMO3uI
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNjMwMDEyNiBTYWx0ZWRfX8gNfFxZTXHKZ dZ80+g69PboCFvZ7mBnOUfK0bCwcv0dSYRqbRWUQ19q/nN1wI6TuhuYqwHy593nbcEA7jlbJwZD 77dnrz9oUStk3kQiVeqmPXKGtKxsdBJ2rMDUHOTQC4GBaAbPZwrp6WqFZf9dFe5sx5xhOKbWCy/
 NwZq+dxl31GEeh7qeRCnnHi4Qxd16CxChbxAbT7vyTZGkfYmt2gzAZsQ9WVivWWtyFljm9LUYUu /A210g10AJ2Cdlfpn7GA0E0mvRxrp+tSiKfaUfSUuPHgdjtBlrSqzSrHD/D2Xsqd7rUwWfMIZjW fInaitcISkEwByhpED+nxsY2XtLUIBynWgUbXHjHc6nBJWSN0rrJzyr4x5ElJH4AxMuQUcAIOs7
 1rhZuhkKthJv/kG2udE/dGMrx+Msfn4q3zQeVCOUgtPKntnHQoMJd3LZcLGKdzNOHbuQfZDm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.7,FMLib:17.12.80.40
 definitions=2025-06-30_04,2025-06-27_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0
 priorityscore=1501 phishscore=0 mlxscore=0 spamscore=0 mlxlogscore=999
 adultscore=0 clxscore=1015 lowpriorityscore=0 bulkscore=0 impostorscore=0
 malwarescore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505280000
 definitions=main-2506300126
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Ab5IZRmw;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
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

On Mon, Jun 30, 2025 at 04:39:34PM +0200, Heiko Carstens wrote:
> > > +/*
> > > + * Initialize Generic KASAN and enable runtime checks.
> > > + * This should be called from arch kasan_init() once shadow memory is ready.
> > > + */
> > > +void __init kasan_init_generic(void)
> > > +{
> > > +	static_branch_enable(&kasan_flag_enabled);
> > 
> > s390 crashes at this line, when the whole series is applied.
> > 
> > FWIW, it looks like kasan is called while its state is not yet finalized.
> > E.g. whether calling __asan_report_store4_noabort() before kasan_init_generic()
> > is expected?
> 
> It crashes because with this conversion a call to static_branch_enable() is
> introduced. This one get's called way before jump_label_init() init has been
> called. Therefore the STATIC_KEY_CHECK_USE() in static_key_enable_cpuslocked()
> triggers.
> 
> This again tries to emit a warning. Due to lack of console support that early
> the kernel crashes.
> 
> One possible solution would be to move the kasan init function to
> arch/s390/kernel/setup.c, after jump_label_init() has been called.
> If we want this, is a different question.
> 
> It seems to work, so I see no reason for not doing that.

IIRC, we wanted to have kasan coverage as early as possible.
Delaying it past jump_label_init() leaves out pretty big chunk of code?

> Vasily, since you did nearly all of the KASAN work for s390, do you have any
> opinion about this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGKr4DgJ4w3TfJm1%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
