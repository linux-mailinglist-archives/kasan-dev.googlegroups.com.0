Return-Path: <kasan-dev+bncBCYL7PHBVABBBP54RKEAMGQEYV3F2YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 294FB3DA30A
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 14:25:36 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id v71-20020a252f4a0000b029055b51419c7dsf6492125ybv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 05:25:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627561535; cv=pass;
        d=google.com; s=arc-20160816;
        b=R5ib1FTAt/P6ToSoefcOqK3KfRJ35FDZc5/1wSps3oSqxNFzp2kIBKgdWHO6dTrQdI
         aSSA7Di3kFXyCgVWsWaDbzATFGxZe6uOBVW6HEXxBmoVLkbJ5WLEI54AUWLhnmjcRWUx
         A35f+pmIWjS472GupNs9Qc/7N9s1lB5RwJjddR03qx6ndODmE9v8Mr2OUuBmiWiuuhmr
         UBMijofhd2WONvODf9NooTAq0AFbPZGey3MwVCZeevoSwY+e4FvtmWHZog/Ujdd/sgck
         9SD1nWtYFlRZlfa56YjVTe+FRBOCoU41+iCMfWrKpZdmZ+yE9hrEfoIhPsuQ1VsW4Okx
         9EGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SOCYLh3X7PIiapXb5QpZFtJLWpB8p1tCaiRPy95PED4=;
        b=nUHDUrAtYu8p101hn4RGT8xTlQebhw46u67P/sD05fCkyszZ5wxwwlUR+23AfKAatt
         p7Y4nxTzTNMFSJJckRkB0Cs+gEmTdGUGK5dS9aKSbAQo5pizmui8SDhGs/tdrRUnkWv8
         L3K6h1tifcO/xSH+zA0OtkpmxDVsh8uFotHYmFXI9tzisM0lOy3LT/ZPwETyjg4291DS
         PLdcVEFr9jt3kgJqEkPZoucy4my2COJ198J2tKgtglNGQ71pGjfRxtMDfx+VhCjivPYr
         l0zw4jH94KzZmxuqzz0cTLUFHSUWgT21+oytHsfYltHwqftcgIiPNJbPkJH/OaaMdDvg
         BZvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oE83htfQ;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SOCYLh3X7PIiapXb5QpZFtJLWpB8p1tCaiRPy95PED4=;
        b=fLGOOEazMeIhSuxwMK9ANLStilCu6U44Y7Qnk0dxLe+i4JnSH4c9mEEXMBk6rlwwEc
         f4HnrN3cl0yDdHhahAx3ar6qZOTNf32Sp5cq9oGhiKHMkH+I83MDSXC+CRCk2KEC1jdH
         PRRp0hDhKXaJ6YPsNRMYgNr8yiU/GWjbrUzr2FDQVKXmUEx6JIebOHumT0lIswZdO7HQ
         HCcczBLdqy/POV+yShcswxHx+WH6j+8p4WcrkD3pcPlzFpaa1Ijq18jlspG56mARruMY
         20fouLbnKVhKilg4Ix0o65/zpf5vNeBw1RJUhKajm1mQV9MGdYEOXNkgnOHaPwvqdIsM
         XeOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SOCYLh3X7PIiapXb5QpZFtJLWpB8p1tCaiRPy95PED4=;
        b=Cw+ULXcmE0LK0CgmnapHhmEwIp+fLGIOGNAqs3EMatrpQP24Rt/iQmlK6JGAHSyfjL
         sYnNvPrHSIezphJqfxpjr6U24xYSKL8KxMxAOEjSWKUGwvRJtpL3m+SBe9C1bv4S65LW
         ZrssLLGY7qB0FyB7cdCVz/nby8Fp+BjRiWb5PbDou9UuAkfSEhdZ6CF/R47zTJUlMTP+
         hEEXz6fryi/y1qqwIqYrvidIOIZLH6RZHN6QcHPWOceiJ1Acn4kRcsMx8wjFYtAEDpzF
         A+a0lNNuimIbbI4KbFvL/t0P465tSEIDQqlYyAEpOdmCkF54MbVFvaWmcCwD+7LCZtNz
         zpHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ln6gSeZnNPuvaKyXY2KywVgaY4W09U90TJWVy7hfhH3c9nvzb
	MHOGWGn/ickdnHBNalJDvzE=
X-Google-Smtp-Source: ABdhPJyQ3WGZ/mm0zqKatv4AePsd4k1IorxB59r+0yypnP13IjNF3ceBAV2FTQKnMcfAYTiS4tR4og==
X-Received: by 2002:a5b:783:: with SMTP id b3mr6666155ybq.328.1627561535280;
        Thu, 29 Jul 2021 05:25:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7bc7:: with SMTP id w190ls3048677ybc.2.gmail; Thu, 29
 Jul 2021 05:25:34 -0700 (PDT)
X-Received: by 2002:a5b:f43:: with SMTP id y3mr6217971ybr.45.1627561534771;
        Thu, 29 Jul 2021 05:25:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627561534; cv=none;
        d=google.com; s=arc-20160816;
        b=ohgEv/tkt994kKLf6shn27jhaJxo+jKNr7bXyyPAp+d3kHi5Ghe5xYGtrEzFCZEamP
         gwVG0BL9tl/xFud9YZIjkqZpKDBvRLjZuIzaU9zxvGHGU+xzmrR7+1cg+Tc7ZV4Hvvtd
         b24HGWCQGB2u2oWXO+0Ulc2NTCxeHew8e8BPJhj74un/TWcAnBtmkkvefhg+c2J6873K
         bNs1wWPcJShKWXLYtLuNv07nysz4OccENUt7ExTAD+/lZ04qir8UEif0kMmwgopDcm8S
         H492PKsUp3ilradWokm9zItZumpEoT3y86UoBq0Fb9CnIDEcVt45Z88cDVBRUozHTS1z
         TtQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GkmeYWDizMKTMJM7MmskuLB3P8agtCV0s0RJcAVmDWY=;
        b=uvjApOkHneawl9JxaUPPlYAEkLyZWfzbxPhzYddhYy0GP0Iq9NY8IfTzc7EvD/OJgO
         zTp6YwU2ARSE0mDW5KDlt++pEmYGNXRFo4KrNQ/Td9tEEdHjg737VZcV5xHQhhA6yqZo
         O+AlBlxDR6m/N8TXYL1aYwJ0IxcvndfMaP0R98lXBKd82JxDRkRTPrJcGr6J2bOv2UgC
         xcTqj4liLFV1fMbWZr5JjCQvCZ0oXusCN9Lh5fQqKkYi+rbwQM2MJYsD4eDRmMadWDU/
         r+gn9lNV6tV7o9+ykT8QgutCOXAVYRccOig1fOUV1ohTr1Ld62chynj/ESOLFxKO4k2A
         sWmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oE83htfQ;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id z205si348811ybb.0.2021.07.29.05.25.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jul 2021 05:25:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098404.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16TCEURP161610;
	Thu, 29 Jul 2021 08:25:33 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3v5n0e8y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 08:25:33 -0400
Received: from m0098404.ppops.net (m0098404.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16TCEe69162548;
	Thu, 29 Jul 2021 08:25:33 -0400
Received: from ppma03ams.nl.ibm.com (62.31.33a9.ip4.static.sl-reverse.com [169.51.49.98])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3v5n0e88-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 08:25:32 -0400
Received: from pps.filterd (ppma03ams.nl.ibm.com [127.0.0.1])
	by ppma03ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16TCDbWX009633;
	Thu, 29 Jul 2021 12:25:30 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma03ams.nl.ibm.com with ESMTP id 3a235yhpx3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 12:25:30 +0000
Received: from d06av24.portsmouth.uk.ibm.com (d06av24.portsmouth.uk.ibm.com [9.149.105.60])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16TCPRun23068986
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jul 2021 12:25:27 GMT
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 09D554204F;
	Thu, 29 Jul 2021 12:25:27 +0000 (GMT)
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A665742052;
	Thu, 29 Jul 2021 12:25:26 +0000 (GMT)
Received: from osiris (unknown [9.145.0.186])
	by d06av24.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 29 Jul 2021 12:25:26 +0000 (GMT)
Date: Thu, 29 Jul 2021 14:25:25 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
        Sven Schnelle <svens@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: Re: [PATCH 2/4] kfence: add function to mask address bits
Message-ID: <YQKeNbU4HJhFP8kn@osiris>
References: <20210728190254.3921642-1-hca@linux.ibm.com>
 <20210728190254.3921642-3-hca@linux.ibm.com>
 <YQJdarx6XSUQ1tFZ@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YQJdarx6XSUQ1tFZ@elver.google.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 9tRoZkGVyNh16-45AhbIjXuuDbx5xc_h
X-Proofpoint-ORIG-GUID: MAwPuY-TnMuaoJ-rs9aFpx9-iJqftGxF
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-29_10:2021-07-29,2021-07-29 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 spamscore=0
 impostorscore=0 lowpriorityscore=0 malwarescore=0 priorityscore=1501
 phishscore=0 clxscore=1015 suspectscore=0 mlxlogscore=980 bulkscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107290078
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oE83htfQ;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Jul 29, 2021 at 09:48:58AM +0200, Marco Elver wrote:
> On Wed, Jul 28, 2021 at 09:02PM +0200, Heiko Carstens wrote:
> > From: Sven Schnelle <svens@linux.ibm.com>
> > 
> > s390 only reports the page address during a translation fault.
> > To make the kfence unit tests pass, add a function that might
> > be implemented by architectures to mask out address bits.
> > 
> > Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
> > Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
> 
> I noticed this breaks on x86 if CONFIG_KFENCE_KUNIT_TEST=m, because x86
> conditionally declares some asm functions if !MODULE.
> 
> I think the below is the simplest to fix, and if you agree, please carry
> it as a patch in this series before this patch.

Will do.

> With the below, you can add to this patch:
> 
> 	Reviewed-by: Marco Elver <elver@google.com>

Done - Thank you! I silently assume this means also you have no
objections if we carry this via the s390 tree for upstreaming.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YQKeNbU4HJhFP8kn%40osiris.
