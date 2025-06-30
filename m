Return-Path: <kasan-dev+bncBCYL7PHBVABBBT6DRLBQMGQERS6J4HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id EB737AEE111
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 16:40:19 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id 5614622812f47-40b23c71b40sf400754b6e.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 07:40:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751294416; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cam0UcQTXsqw6eset5/9S0mhsVyE8PTEeaouad2c7C6wjscM0JPn0ouZEc6KAoof05
         V2rURjVEL17XqgkCbesojQRouuDgo/NkREODJTv75uAVd5s08+eYz+Arl+r8fmORijMJ
         EbPhvoz/K6qR7cBYBoh/6/ISwpypE5Jt0+E+zYbUmhfO4ZWMA83Vbo2FPaYbMrfb20EF
         FM7QfJmH4a11e1Xqh5u9hYLZmOY/4TGuijnz3L+5NNiIts2TCtD+PEdwhz7rENxUDlBI
         9aTj6qI/v/ThvbNFtTQuvz9fhE8VucT6OB4GAuT40coL7/SucLUCQYDi/9yUVxWZO4ii
         G1NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tYXAfaR3gBK6ZopKSji4qpOyEvkodt0oUrMipVPTSRQ=;
        fh=Us+B4d/tZa7RuRbn+Aziope392i4K0z8mWygvrHRe5g=;
        b=Vp8mkt6CNTuQR2ySg3pDdRMC0zTUxgh+Y9tojvzdfJSxgKudNQQAsA2FPMGb1NZYC7
         feUr/Cxez89w/uBLAl/G8TsI9d0p0qEVRKobOF2qJHk8uDAI3XfbljvlEeLITL0OnwUz
         Gi4hxuVDY9Bc+/mAPz7mYRONXcbiwDmEHQfvjzB9JWfAj6yjsqbvULKfNlRqY8C0oA3s
         j7W9iGFijAmKKd9g+wtiNJE+gc7dM5Y2+Nx4g3G1oxYhQ9kD7leTpevoCQpVpRggn6AQ
         b5zbwbA9JqNVDHiu6hk8r38NxxTlHgtW9ZxWgunEYd2Qf8DUTGRZtNrI9DS9x69Oz+9k
         Y11A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LvjN75Dc;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751294416; x=1751899216; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tYXAfaR3gBK6ZopKSji4qpOyEvkodt0oUrMipVPTSRQ=;
        b=mNC/5Taejd3iaapdD6ZbF0OfLfTayMhtVt76cSsYksgpLxLyk+lknj0n9+PSodfPAS
         +EuTUDTTNQY+C8XLZX5PsPIkbNB4B6giPtCp2vyyQj0NQMnR5jMRKJqTIzwJ+lhwf+Ow
         6QNGTPxknPLo6KlRA0E1OKmWjIaBDWuh4DclRHUtHt/UMEJxymlWJ8QVUc7AnZp0Gw29
         L9wBWLXdaMM7qZ/yQGlVeO07HSkyZ/PHDk/edaDYbyjgNfUYvGbYrtnzhBAshOarwr3H
         KlCIdbfi/RxAdkU1CxvbgyzD0Vz7+D+0E7Y05nnuLDY8kr9FzEjfhCaNuaeL8z8qM9t7
         WpLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751294416; x=1751899216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tYXAfaR3gBK6ZopKSji4qpOyEvkodt0oUrMipVPTSRQ=;
        b=RJwikzEF/e8TzITjFbCCgAa655jukNVtvUN003xwUT7k8ZfeP1zdWM1B8fD7gnzXNA
         ADzvziLj0OSk8EOs+pMhhct6Cj8DddlCFZv46i1bqqQmDeJG8OQmuLYAsHvEKut+Gc6i
         VeHZPCI1eSG86nsUc8X6T4ueczK1/8q65g2mqKKE4ZW/yU+hwUE4pfWbIHKs1HHStdmN
         9yB/Lc3LjM1B9+bFalgaPqSQ6L8Xb6gQ5PHvjA2dFpaB4WBbJgLcFjoMcT2yLzQXJi4y
         b//US4CijYPIaWFOXvrVGI5OYNJPSZAXM+xzA5f0C4ytcoxhlZld6mOMgGN03XNo2pwT
         JyUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJkDyaBn6yYweJoeWv0+OXwzilDCiO/fEaSanDWSdy8DLHg1b+CDO+6utUQclbKrk1TEmQCA==@lfdr.de
X-Gm-Message-State: AOJu0Yw05P81kTV//llq72CqHHodJbty/ElQw6zSDydpqxobIulvFfvo
	yo/cD88wNgJn40HomFzZu0LyRe1UoOHUAYuCG+1MYJywETcQJBABkZuh
X-Google-Smtp-Source: AGHT+IEnpGFbVadITNilRIY2DI9VSPsE4ds92o+ztPxjwqMN+udbGE3ojXetJk0Ak5OpBlJmve73cA==
X-Received: by 2002:a05:6808:2e43:b0:406:7a21:1ae9 with SMTP id 5614622812f47-40b33e72646mr11757227b6e.37.1751294415699;
        Mon, 30 Jun 2025 07:40:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfJR3AF3enuQprY1W4QvbNCe5DodRZmYu+9NyTfOa4qHQ==
Received: by 2002:a05:6820:2e88:b0:611:78ba:54b7 with SMTP id
 006d021491bc7-611ab016a47ls585760eaf.0.-pod-prod-06-us; Mon, 30 Jun 2025
 07:40:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFmJ02fX04mj0Mlw1+9GCHBSP6PCgnpfVr4hftLxoHbraX/gYxoU4CFEbGrwWs87pMmy/sWI8Trd8=@googlegroups.com
X-Received: by 2002:a05:6830:7101:b0:72b:9724:6a82 with SMTP id 46e09a7af769-73afc67c11amr10070702a34.17.1751294414171;
        Mon, 30 Jun 2025 07:40:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751294414; cv=none;
        d=google.com; s=arc-20240605;
        b=C2esIPRqFxTHXPktQ9EIB9zVISCxQCde+n0AQ0tCJNQHDFmlywuFLSBg/pxyFDhziJ
         hN8oxaq2MNkjIiXlUXDDgATwTq9aXHeaZ99+FfFspG28BgMzciBiO1SyQ8GSuvPkKMLD
         9Cu7+qC6hc6/TOj9MlEwGYLISJpVnIyyKRMVySQbwgqn9qB7MRL9B362oBnObLtGPHQa
         WZjzrWkyk5aSy1ldx3E3Ig7BcDkiQaq8NUw46XmuYy51Sc1xGn3EznqO1RrpW4f8KwwI
         WaT+4IWb85FVttfPstBVeOPDMeOQZ8qQRrsdkqJCNZhub7iUYABxhSn/zUmSmAo6XiI0
         j4SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dZVMGl4ViErQo4fFQ8VUnT+LNcHK9FWrYiT4XPKoVoU=;
        fh=OlzghnpJ+AfNj1SPJbIae8CQ5M9ZcF67EnRuRteUfdc=;
        b=NdLAF7K061/1J8RHNodKIq4tNBmdcufbQnXDb7W6PYssEfEUmeckH+W4Wyl0JaHlZE
         6QyUcbZWeFgtuAANIAC5fhtai/9D35JuSq9+hgfiGa83x6iuiPvxokQUmAfw0BzoV52/
         kveiNUcGL/eo1exqkt+jBqAx/7J/L9kqUTx623+tbH2K9xwOI10KxxTLzQojABlcafox
         3WFMktbBUNfp2N91gOlSKO6yS/XERihaOACMcfJMKUb8T2ejgHy1tANzykeby45dxw1R
         mUDVDGhouc12iyEofKAZxH4MqGoBPbZQCtFjQ7Jn1MMBPH1JDRHkASnz4sH1Kv3DmZdK
         nDkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LvjN75Dc;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73afaff6828si389521a34.1.2025.06.30.07.40.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Jun 2025 07:40:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 55U8xoVD015498;
	Mon, 30 Jun 2025 14:39:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j7wra0bv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 14:39:45 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 55UEX7fk002972;
	Mon, 30 Jun 2025 14:39:44 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j7wra0br-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 14:39:44 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 55UE1gX6021934;
	Mon, 30 Jun 2025 14:39:43 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 47juqpe8ck-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 14:39:42 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 55UEdc3544761382
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 30 Jun 2025 14:39:38 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7DE0A20043;
	Mon, 30 Jun 2025 14:39:38 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8161D20040;
	Mon, 30 Jun 2025 14:39:35 +0000 (GMT)
Received: from osiris (unknown [9.111.82.77])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 30 Jun 2025 14:39:35 +0000 (GMT)
Date: Mon, 30 Jun 2025 16:39:34 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Vasily Gorbik <gor@linux.ibm.com>
Cc: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
        glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
        vincenzo.frascino@arm.com, linux@armlinux.org.uk,
        catalin.marinas@arm.com, will@kernel.org, chenhuacai@kernel.org,
        kernel@xen0n.name, maddy@linux.ibm.com, mpe@ellerman.id.au,
        npiggin@gmail.com, christophe.leroy@csgroup.eu,
        paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
        alex@ghiti.fr, gor@linux.ibm.com, borntraeger@linux.ibm.com,
        svens@linux.ibm.com, richard@nod.at, anton.ivanov@cambridgegreys.com,
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
Message-ID: <20250630143934.15284Caf-hca@linux.ibm.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
 <20250626153147.145312-2-snovitoll@gmail.com>
 <aGKDhPBgDv2JjJZr@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aGKDhPBgDv2JjJZr@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=E/PNpbdl c=1 sm=1 tr=0 ts=6862a1b1 cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=kj9zAlcOel0A:10 a=6IFa9wvqVegA:10 a=AeL96baZ9YmIqE4yH0MA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: 2hwphgPZI837FabFeudLVjFicIoSmhXG
X-Proofpoint-ORIG-GUID: FiHtpeYVQCPMFgF1X9Rek_sDm6f0w0qN
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNjMwMDExNyBTYWx0ZWRfXydsoblXBR0ze E9HvMeQ14kc+Woe5xd/SFPBcu0vlwEb2rfyIotIQPVlF4ubkEgP5011gPNTSWqTF2yHh0XA+4Ys YtUR6UrKRuqNmHUZHfVrDRMN52XXJ8jmaoDUHFwngVMl/S0kuPwOX0KnQ08i7W5uZum6/pQlsxH
 PSRM68qtAJ+io/RlKpS8hVyp8JhMgoeN7tOOZYNJa4YzA3PSVAQzl1PZ5jjF5v+hYU4evHZAXNO 9IYq4VHNT7cT81dC5A7Z/s9IYQVPzNtDhaXj0Dc9jHPz9/phE/B/idozZZjcYiqY6iFL3AYGZq0 UJK05i7AMCYmP5WJn4xDjjygHxdSbNqoEBEmoYZebnEX4uBv0r9o5LI1Se2/L8pc7bQ8CW0e8qY
 COnK5bFnlwiVLGEKcvd+kJLxqLtFo59nsnoiQfRh0QLr6h7E4OxTno1X7/1yF98bvPZMX5sU
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.7,FMLib:17.12.80.40
 definitions=2025-06-30_03,2025-06-27_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 spamscore=0
 bulkscore=0 priorityscore=1501 phishscore=0 suspectscore=0 mlxlogscore=999
 lowpriorityscore=0 mlxscore=0 clxscore=1011 adultscore=0 impostorscore=0
 classifier=spam authscore=0 authtc=n/a authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2505280000
 definitions=main-2506300117
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=LvjN75Dc;       spf=pass (google.com:
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

On Mon, Jun 30, 2025 at 02:31:00PM +0200, Alexander Gordeev wrote:
> On Thu, Jun 26, 2025 at 08:31:37PM +0500, Sabyrzhan Tasbolatov wrote:
> 
> Hi Sabyrzhan,
> 
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index d54e89f8c3e..32c432df24a 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -36,6 +36,17 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >  
> > +/*
> > + * Initialize Generic KASAN and enable runtime checks.
> > + * This should be called from arch kasan_init() once shadow memory is ready.
> > + */
> > +void __init kasan_init_generic(void)
> > +{
> > +	static_branch_enable(&kasan_flag_enabled);
> 
> s390 crashes at this line, when the whole series is applied.
> 
> FWIW, it looks like kasan is called while its state is not yet finalized.
> E.g. whether calling __asan_report_store4_noabort() before kasan_init_generic()
> is expected?

It crashes because with this conversion a call to static_branch_enable() is
introduced. This one get's called way before jump_label_init() init has been
called. Therefore the STATIC_KEY_CHECK_USE() in static_key_enable_cpuslocked()
triggers.

This again tries to emit a warning. Due to lack of console support that early
the kernel crashes.

One possible solution would be to move the kasan init function to
arch/s390/kernel/setup.c, after jump_label_init() has been called.
If we want this, is a different question.

It seems to work, so I see no reason for not doing that.

Vasily, since you did nearly all of the KASAN work for s390, do you have any
opinion about this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250630143934.15284Caf-hca%40linux.ibm.com.
