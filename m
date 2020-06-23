Return-Path: <kasan-dev+bncBCJJPO575UBBBYMDY73QKGQE4UHNU3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 101E0204CDF
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 10:48:35 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id s7sf11468637pgm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 01:48:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592902113; cv=pass;
        d=google.com; s=arc-20160816;
        b=m6EEe04CuwXHY+2mcirjK1IknAjEpWZgiMU7ORE1dBbzX0V8wn4Fr3vbIJWTBpXLaO
         uTy5aoo0iPa4JOK5FbQIbmqhRtjvBrfTBIxYeRGzl/amNAkL5WLuVXQm1FWh3Xt3p2C1
         iAgRufqimZfHvBIGYm3F+6Bvv10Ns7yjrqwOU2tC2L1H+gL0iy7/5hk0M4PoXOz8rqmd
         18rcOh8FJB1x7RkEy5D1MHRhfwnEzPjshGTyzscmFf3HJka49B+51uDh6FvHRoliRlGh
         MqpdqWRuOuVR/8w0bwb5UmvSjCNypDv8Cfd2vWNtabTApBHtkneAjZwHRS0/Ki3vojwS
         Krkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=umGsqQ8GIAx9gZAOf13sB1uiX4RxldYWYIllylWTZxA=;
        b=pygFbjZY3al8at9Lt4SeRXbP+SZ5g6/NqtytzMWwokk8A7i0xtqC4Q6PtRjRsW6i1L
         h9fuDLsyOGKw3fnNx9r+mtk/dZEL6KpEEutztkM1o5/PxwxcBtu7kmhheF2JkDDlT+4Y
         3lkRduJCrD/QUE1Erbvb6c+HruLDHtUS/go1hShruJDoTR74/LKIM/nmRD3wVNlx/KJw
         +/fFt/SEFYLD023KILh0nP3M0Qby5uVyusb42vGK22QL50hScL2OXdd5hz+S4UyPTgJg
         70kvNtiA5RNLFakBIM2AJQVfv+Cl01KZSmx706WoWyv6sQC4HQDXZlk25r4MrXWS/PBS
         fRvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of heiko.carstens@de.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=heiko.carstens@de.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=umGsqQ8GIAx9gZAOf13sB1uiX4RxldYWYIllylWTZxA=;
        b=cGFqlhnPoOnUzZMS/I/vDrnXk84UdKOUhGI85iJls1jMg8Nj+UxHt9EiPt+ngEGPAi
         S9z241L/El6vy+4FPalqXXPEIRPgNafNwRmHCaPkvbc1i9AihrZKWnKWr+IA0ZFVuJ1g
         uANtVx9STTjD9+OduxebfX8zIB7beI5xDDVj0CJqMPNVzHL8nIyjUh6sg7WB9Geh/ev5
         50XVMTC0stKYEjkEB/1wRuQAPXood4pHMESu+9zJTYZ3rGEWu66k5vR3YfD1n/9wPk5L
         VQXvTJXKD/WL8NHd8R2wuUjjmA/tSkKhsIwRgTqQB6HVAAt1CMY9dHjuETA99NEbJ8ZB
         iFVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=umGsqQ8GIAx9gZAOf13sB1uiX4RxldYWYIllylWTZxA=;
        b=Jc4RqMPtQx7ty2keR1Bbsp3Bwuzt/ApSEo98RC8n/+8MbRjn9gFnAq9nJKIVLVEjG7
         cJYB3hJWfxp5He1g1Z3Tsox6BqBGCqiIE84hql6F/eZr7Hl5NSU+kMeLSdsc0lGb0KxO
         zpwsGX4gDz6ysehtP1a3rKWWA+f9WdiDIoZ6PeYdiaD2dn2ZtComHDauyNcnBn7FZVN4
         cgnkIaiz4GXnmbvznHu5TT2Uait7gJhF86M6f3cX+TAsRgewQkUmbInfz+rev8HNqZQK
         a3xCgJIsMEDZNc8YVED0gAixde/vB8YR0vx4sPVvMDoGTlcYUvrdKAC7C+fqnYhHMGaS
         35kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318smxcIc8oS6+39rC+vYYU06QZ/yRqd2CRGlv8Z0Fdw9Yw3J5U
	4rJGkIEYGowCnVe0dvOBoiE=
X-Google-Smtp-Source: ABdhPJzxdn66bOfrfc4Ef0I3NOFryrQTyXHS0308RJry/gLqWG0z4W3/OfQJh4YoQKrVhZyCaLFChw==
X-Received: by 2002:a63:29c8:: with SMTP id p191mr16983370pgp.333.1592902113532;
        Tue, 23 Jun 2020 01:48:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7143:: with SMTP id g3ls1074899pjs.1.gmail; Tue, 23
 Jun 2020 01:48:33 -0700 (PDT)
X-Received: by 2002:a17:90b:809:: with SMTP id bk9mr22773559pjb.53.1592902113148;
        Tue, 23 Jun 2020 01:48:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592902113; cv=none;
        d=google.com; s=arc-20160816;
        b=ncixypm1dVa5Us4t+GkYSZktUCP+3evDP8mtxUreguhy87cAGIXdKlrRyiWW0ZyHUo
         UOKgzYdzsIuKOj6fiSK0Zvi5Ev5UTg+sRdViDL+GshNG0GofuynPeh7fjiTUdyDVFsQG
         IPn62KXGK6IUQi6IV+wQLNIcsLpZkzGQMNqPjENKWnnlMf0zFkf3r1nDYfyvWFW9cFxt
         3eLw2Sg78PK5BaegoVmPC6RJSwCk7++BUokd0nccGwxtm7Wu7a49zXB8lkqBpxtjX/56
         yywZTfGJNeAFG9YQ6u1D5lJjh2cyp4N5eix4uRo2YUzRGakDRRBrxPiTThrlR7FMD6vq
         9kpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=hOFZROz1GcB3XE2yENNgVWLQ2R7fqOJ30/qeOXf9AQQ=;
        b=Oge7q+Hp1V2EQBTaKgr0gxAzyd/eNJglPEbUOgPRBDv9zTce90dG6t+Y4IQcHpe50r
         p8sk6AuSWqFtnIebJYMobCWoxYQlOOSxtamLNcw6Qy4OmWUWrSc0vVm0z1pNG+xvlM9u
         TRpaoGeM1mM/FMNeAzU1KVLR3iVtj1t4YOapLatuVmOvAhjzgb1qK6ZEQk8ZXGYe5z1f
         mOU6yR2TGPks0qU3Yl1Ja77KE1aZLNamxYgobD7vsMZrP1hme+RyklpzRGec+uA72PVP
         sBRs0W/i2ljHNl/P8A+BmunV06fz2YwbFROm/hf8rqV3NTFJSyiVB/SHbzSkodqwIVoB
         VcrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of heiko.carstens@de.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=heiko.carstens@de.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id t23si709419plr.4.2020.06.23.01.48.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 01:48:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of heiko.carstens@de.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098420.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 05N8XEsU052824;
	Tue, 23 Jun 2020 04:48:32 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com with ESMTP id 31ud982nqh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Jun 2020 04:48:31 -0400
Received: from m0098420.ppops.net (m0098420.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 05N8XeG7055496;
	Tue, 23 Jun 2020 04:48:31 -0400
Received: from ppma04fra.de.ibm.com (6a.4a.5195.ip4.static.sl-reverse.com [149.81.74.106])
	by mx0b-001b2d01.pphosted.com with ESMTP id 31ud982npp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Jun 2020 04:48:31 -0400
Received: from pps.filterd (ppma04fra.de.ibm.com [127.0.0.1])
	by ppma04fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 05N8fdtL029890;
	Tue, 23 Jun 2020 08:48:29 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma04fra.de.ibm.com with ESMTP id 31sa381w8u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Jun 2020 08:48:29 +0000
Received: from d06av24.portsmouth.uk.ibm.com (mk.ibm.com [9.149.105.60])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 05N8mQG562390426
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Jun 2020 08:48:26 GMT
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 96D684204B;
	Tue, 23 Jun 2020 08:48:26 +0000 (GMT)
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 25E7642041;
	Tue, 23 Jun 2020 08:48:26 +0000 (GMT)
Received: from osiris (unknown [9.171.83.193])
	by d06av24.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 23 Jun 2020 08:48:26 +0000 (GMT)
Date: Tue, 23 Jun 2020 10:48:24 +0200
From: Heiko Carstens <heiko.carstens@de.ibm.com>
To: Qian Cai <cai@lca.pw>
Cc: Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Kees Cook <keescook@chromium.org>,
        kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
        linux-s390 <linux-s390@vger.kernel.org>,
        LKML <linux-kernel@vger.kernel.org>, Vasily Gorbik <gor@linux.ibm.com>
Subject: Re: [PATCH] mm/page_alloc: silence a KASAN false positive
Message-ID: <20200623084824.GB5665@osiris>
References: <20200610052154.5180-1-cai@lca.pw>
 <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
 <20200610122600.GB954@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200610122600.GB954@lca.pw>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.216,18.0.687
 definitions=2020-06-23_04:2020-06-22,2020-06-23 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 mlxscore=0
 malwarescore=0 spamscore=0 cotscore=-2147483648 mlxlogscore=851
 lowpriorityscore=0 impostorscore=0 clxscore=1011 priorityscore=1501
 bulkscore=0 adultscore=0 suspectscore=84 classifier=spam adjust=0
 reason=mlx scancount=1 engine=8.12.0-2004280000
 definitions=main-2006230064
X-Original-Sender: heiko.carstens@de.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of heiko.carstens@de.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=heiko.carstens@de.ibm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Wed, Jun 10, 2020 at 08:26:00AM -0400, Qian Cai wrote:
> On Wed, Jun 10, 2020 at 07:54:50AM +0200, Dmitry Vyukov wrote:
> > On Wed, Jun 10, 2020 at 7:22 AM Qian Cai <cai@lca.pw> wrote:
> > >
> > > kernel_init_free_pages() will use memset() on s390 to clear all pages
> > > from kmalloc_order() which will override KASAN redzones because a
> > > redzone was setup from the end of the allocation size to the end of the
> > > last page. Silence it by not reporting it there. An example of the
> > > report is,
> > 
> > Interesting. The reason why we did not hit it on x86_64 is because
> > clear_page is implemented in asm (arch/x86/lib/clear_page_64.S) and
> > thus is not instrumented. Arm64 probably does the same. However, on
> > s390 clear_page is defined to memset.
> > clear_[high]page are pretty extensively used in the kernel.
> > We can either do this, or make clear_page non instrumented on s390 as
> > well to match the existing implicit assumption. The benefit of the
> > current approach is that we can find some real use-after-free's and
> > maybe out-of-bounds on clear_page. The downside is that we may need
> > more of these annotations. Thoughts?
> 
> Since we had already done the same thing in poison_page(), I suppose we
> could do the same here. Also, clear_page() has been used in many places
> on s390, and it is not clear to me if those are all safe like this.
> 
> There might be more annotations required, so it probably up to s390
> maintainers (CC'ed) if they prefer not instrumenting clear_page() like
> other arches.

Vasily will look into this and come up with a proper solution for s390.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623084824.GB5665%40osiris.
