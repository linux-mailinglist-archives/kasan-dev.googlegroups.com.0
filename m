Return-Path: <kasan-dev+bncBAABBLGDWPWAKGQE6XWA2DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DB80BF663
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 18:05:01 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id l84sf2020638ybc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 09:05:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569513900; cv=pass;
        d=google.com; s=arc-20160816;
        b=c0Wqa2CKE0Lh6hY2TDCZXwTE9H8MMlPcMvgrKy58v8ry7P3dLPwiYq3BF6556E3hTv
         4nvcREq7lGyhXdj7mbTlR47Z2DZIS67ze32vF88C1fnp4p39FaAZiClilU4oGuwMrqAV
         yRaf+2bVGLGrPBKq2TndZk5L2lZ61w8vF8L291h58d9909+1Iif53d/qFANWQZAzxSc/
         G0UqHsiKN6qcfCU76aDNi6/SnXbSYt02+dsh1ftw0yvYJZrpQsFzye2jpG+zYzmK/h3p
         Nt7HPEo5vKQI2kiauMaiZoxG+FhPGIF5HEbjmD0xxvd4s5APaurzOchUCaWMWDGQ2iQC
         eo2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:user-agent:in-reply-to
         :content-disposition:mime-version:references:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=/sQut6uG2ic9BQfa/UiAnKzAiSu8DdtsuNXzc5m+4o4=;
        b=hDPB0/KE1McCmEU0S0pqcr0JXIB21C+RW7N6s9aZnwEQDpVSFVtOcg+A9I75mrB+J4
         b+XrnoKePV2AeFvjmiaV5aZmRezOwuEU7YiLLUSmTkEPTGwFf3lPuZ/Dw+R1YIsv7shw
         QYznk+cP/BqSGkXxkmEiQ2CPVVi/2o4koDa11hoJzbCm2JIoKJIWZzEmF6++JdoT6gnA
         sgr8CPt+3xZEUYdqsmAhAo0rJA40NqcJJL5dc4w39ChUYMyVBLFnGCFhLgrekevpotRz
         6QW6o3sCGm0sTRVr8smew40iFXLS5n4ngkmYbtjyXKyPzeLgnzMkag4WYwgs8OqJG3M+
         Ir+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:references:mime-version
         :content-disposition:in-reply-to:user-agent:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/sQut6uG2ic9BQfa/UiAnKzAiSu8DdtsuNXzc5m+4o4=;
        b=ZPJtM1CggTiSfB0CIMM9TMypVMg1ZhUHuWrlmwQV52Gvgu2DrvoHYqlzm4/SqoNk4+
         WgjNcNJADxMBO07JWgU5sEe5y95ddUEWC+SDfvnVA9D0UsE9ZH8wMJZLwTVunTjsrnbP
         +IEs29GOT0l6Lp6T0wB2wNteRAugDjsK/4tQvm0J4GWGAH5p6mY32dW4W3ghdj4uTRls
         4aCTXJ7OLGsKIr0CDZEYQF14X/3tC2VM+wfCnmo8fAHHyw5ygwRP31ygGUFNmL+4Yp6A
         pYs93UyuyLzQgGOkgGziRT20Aqr3qYh0fVhOw6xsDHIcCkNQoRcDtVTgSNWWh0xSG1RM
         oAPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:references
         :mime-version:content-disposition:in-reply-to:user-agent:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/sQut6uG2ic9BQfa/UiAnKzAiSu8DdtsuNXzc5m+4o4=;
        b=lELrT626G5jI2b8gx9UpU/QgMKtXxMDaGLASAPL3vMDHo4fVVejNFM8Z1RnoZLB1n/
         Cwy+B1zdzCeQT00dVVXdWiWo6QAXshCohVyqsplYRV6q4yfQx9Sc656icv5Ztep0RZSu
         RY+7ggyS4Xsmmu7BUDT1XHXMTDYCKKq3bh2i6DvR4cpyyRwHUyzHv0IYzu5JYu17RDDz
         VAHY7ync7+03HLx/ctSR9Re6bAwuSaPTxnCE34l9aoZxGVBJVEnI0GHAYs9uq+MQd4+H
         xSLwKjEN00ljbI/YlMogcs8oOKJCFCTFfdsoenaPXS1KGcte6rxouKjXGQJLI4JPHiIV
         ql8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUlGcTghjWqnWx7ig1xaCmIAMmtXTNqRlbr1Z1gVJRWGCvV1MOp
	eBfu9MVOGq6S6ySzRBYe184=
X-Google-Smtp-Source: APXvYqyzKziuzGltZRdn0hyodNnS8GMaJrO7MWPSAPBA/0xyZjVGtdM7uCD9YTFr0he0CKplq4cfSg==
X-Received: by 2002:a81:2e0e:: with SMTP id u14mr3022220ywu.271.1569513900163;
        Thu, 26 Sep 2019 09:05:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:30d2:: with SMTP id w201ls436874yww.14.gmail; Thu, 26
 Sep 2019 09:04:59 -0700 (PDT)
X-Received: by 2002:a81:103:: with SMTP id 3mr3343974ywb.471.1569513899813;
        Thu, 26 Sep 2019 09:04:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569513899; cv=none;
        d=google.com; s=arc-20160816;
        b=oTcaEA78JEo7KP2KRWIUoExfqE5L2JDAhVCcqM+vb7fXuEG6Xj0BXxySchvt743Bwb
         gfjZx+Q73RV/lx+mQ3EybDaVZAcYmurwkCOgxWhlA0b0ssYQmiHGGcg8sEbBowqiWPx9
         YYBBTtw5xVvrwost3kC8LgOcf0cyLsaqtO0fedjwDRjHnuX7EVVIfA0Htunog6GYk/zR
         nYqTGEGTq31QRFabiFe19NfHmeSzE37XVLJuG3NabIYrq8uPY5Mv5ipxDob4VSZSUu0r
         WhC/pcsjGCOGmQNa0pjR19hXKLy9DKpwMJJpW4/YQlTXyNFdwtEMhtBHmZFTaseymaDs
         8V8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:user-agent:in-reply-to:content-disposition:mime-version
         :references:subject:cc:to:from:date;
        bh=5/TzZd+4AoBIVzYUZzSvKF0fCAKB1pdBRXiTKzuaTQg=;
        b=bD3mCGSfayxmDMzE5hI4uCO6CYa3ysKHmr8WfOS992rcdGs4qJ29cbBvI0z7wCTiPD
         JS6tPJ8HIaEKezMpsp9Tw+NZzO6T7eETX0P3oKntqCbcCK+4UzcnsxZ+w9Z05zfIO89J
         KDCkgeLmk7jBwhICU3cZ9eP9FiOBFzRLHrSBeJa102h4TAFNwnybU3fk7dXXON33t9VS
         +0hxumnFaJzcFdrZknqAQVbDTs7NT46o/Yni99oPk8CpMrOD+ekL1gtGZ1maG+MBK60W
         dLxPbRCNUKhZ+QBP/PKy4iVTPsiuFHKpOaOvfwbGwlc8uCadh78vwpa9TDjA/2ew7niW
         u3jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id r70si201185ybc.1.2019.09.26.09.04.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Sep 2019 09:04:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098410.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.27/8.16.0.27) with SMTP id x8QFrZCY009464
	for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2019 12:04:58 -0400
Received: from e06smtp04.uk.ibm.com (e06smtp04.uk.ibm.com [195.75.94.100])
	by mx0a-001b2d01.pphosted.com with ESMTP id 2v904c98s8-1
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NOT)
	for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2019 12:04:57 -0400
Received: from localhost
	by e06smtp04.uk.ibm.com with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted
	for <kasan-dev@googlegroups.com> from <rppt@linux.ibm.com>;
	Thu, 26 Sep 2019 17:04:53 +0100
Received: from b06cxnps4074.portsmouth.uk.ibm.com (9.149.109.196)
	by e06smtp04.uk.ibm.com (192.168.101.134) with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted;
	(version=TLSv1/SSLv3 cipher=AES256-GCM-SHA384 bits=256/256)
	Thu, 26 Sep 2019 17:04:41 +0100
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (b06wcsmtp001.portsmouth.uk.ibm.com [9.149.105.160])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id x8QG4eJ744761120
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 26 Sep 2019 16:04:40 GMT
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C49C4A4054;
	Thu, 26 Sep 2019 16:04:40 +0000 (GMT)
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9A5B1A405C;
	Thu, 26 Sep 2019 16:04:36 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.148.8.153])
	by b06wcsmtp001.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 26 Sep 2019 16:04:36 +0000 (GMT)
Date: Thu, 26 Sep 2019 19:04:34 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Adam Ford <aford173@gmail.com>
Cc: Fabio Estevam <festevam@gmail.com>, Rich Felker <dalias@libc.org>,
        linux-ia64@vger.kernel.org, Petr Mladek <pmladek@suse.com>,
        linux-sh@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
        Heiko Carstens <heiko.carstens@de.ibm.com>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        Max Filippov <jcmvbkbc@gmail.com>, Guo Ren <guoren@kernel.org>,
        Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org,
        Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org,
        linux-c6x-dev@linux-c6x.org,
        Yoshinori Sato <ysato@users.sourceforge.jp>,
        Richard Weinberger <richard@nod.at>, x86@kernel.org,
        Russell King <linux@armlinux.org.uk>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Geert Uytterhoeven <geert@linux-m68k.org>,
        Mark Salter <msalter@redhat.com>, Dennis Zhou <dennis@kernel.org>,
        Matt Turner <mattst88@gmail.com>, linux-snps-arc@lists.infradead.org,
        uclinux-h8-devel@lists.sourceforge.jp,
        devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org,
        linux-um@lists.infradead.org,
        The etnaviv authors <etnaviv@lists.freedesktop.org>,
        linux-m68k@lists.linux-m68k.org, Rob Herring <robh+dt@kernel.org>,
        Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org,
        Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>,
        arm-soc <linux-arm-kernel@lists.infradead.org>,
        Michal Simek <monstr@monstr.eu>, Tony Luck <tony.luck@intel.com>,
        Linux Memory Management List <linux-mm@kvack.org>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        USB list <linux-usb@vger.kernel.org>, linux-mips@vger.kernel.org,
        Paul Burton <paul.burton@mips.com>, Vineet Gupta <vgupta@synopsys.com>,
        linux-alpha@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
        linuxppc-dev@lists.ozlabs.org, "David S. Miller" <davem@davemloft.net>,
        openrisc@lists.librecores.org, Chris Healy <cphealy@gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com>
 <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
 <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
 <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
 <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-TM-AS-GCONF: 00
x-cbid: 19092616-0016-0000-0000-000002B10922
X-IBM-AV-DETECTION: SAVI=unused REMOTE=unused XFE=unused
x-cbparentid: 19092616-0017-0000-0000-00003311D734
Message-Id: <20190926160433.GD32311@linux.ibm.com>
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:,, definitions=2019-09-26_07:,,
 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0
 clxscore=1011 lowpriorityscore=0 mlxscore=0 impostorscore=0
 mlxlogscore=999 adultscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.0.1-1908290000 definitions=main-1909260142
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE
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

Hi,

On Thu, Sep 26, 2019 at 08:09:52AM -0500, Adam Ford wrote:
> On Wed, Sep 25, 2019 at 10:17 AM Fabio Estevam <festevam@gmail.com> wrote:
> >
> > On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:
> >
> > > I tried cma=256M and noticed the cma dump at the beginning didn't
> > > change.  Do we need to setup a reserved-memory node like
> > > imx6ul-ccimx6ulsom.dtsi did?
> >
> > I don't think so.
> >
> > Were you able to identify what was the exact commit that caused such regression?
> 
> I was able to narrow it down the 92d12f9544b7 ("memblock: refactor
> internal allocation functions") that caused the regression with
> Etnaviv.


Can you please test with this change:

diff --git a/mm/memblock.c b/mm/memblock.c
index 7d4f61a..1f5a0eb 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
 		align = SMP_CACHE_BYTES;
 	}
 
-	if (end > memblock.current_limit)
-		end = memblock.current_limit;
-
 again:
 	found = memblock_find_in_range_node(size, align, start, end, nid,
 					    flags);
 
> I also noticed that if I create a reserved memory node as was done one
> imx6ul-ccimx6ulsom.dtsi the 3D seems to work again, but without it, I
> was getting errors regardless of the 'cma=256M' or not.
> I don't have a problem using the reserved memory, but I guess I am not
> sure what the amount should be.  I know for the video decoding 1080p,
> I have historically used cma=128M, but with the 3D also needing some
> memory allocation, is that enough or should I use 256M?
> 
> adam

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190926160433.GD32311%40linux.ibm.com.
