Return-Path: <kasan-dev+bncBAABBZF5WXVAKGQEFT6Y2FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C472B8790F
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 13:54:14 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id x19sf59625093pgx.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 04:54:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565351653; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lfi4cJ04Zv7vg7Flv6srPIYROBc1BIPAPLnsdBVrEaDJcEXVpnOLTrOVBtYeeggHQ3
         t5hUrdA4EkB0Lhu6kWmAwjz+JdBbRit8VJDBde+Hm4xYQrX1drmjT6qne1uUFrzgKHyR
         D+6l86zy9qEz9sbwlCIOUlb7WLGSl/6nN6FO0pfuZnC3wXMwq1uqkzX2NXJvPdF045ra
         p+so+lR6Lz+MlQ+8pj6HWyoTmyz5c+f+guHInXsCRDMoJ7hmZ7FOMAAZJExDxZEtJQeT
         r122T4vpRrY/JfnJIxWMl/xDzXBz3t+WjiwmfvePwHhW4EsQbhJ8UvJIMa2sPTTEBQmr
         1F6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:in-reply-to
         :content-disposition:mime-version:references:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=qQPS2BZgjjPmBnESLVgNw/RxN6D1do55YHYIuKcuGsY=;
        b=BYDN4qvaCJx3muFypaVVnzBhVoZDKHE2pNLyMzXvfL+lWjpXKhB3HOQHAb0+qW66p+
         rBgQkED6Nh7iyM4aEvw9J8eDz42M8atzoHCvfcz7O0w5NCb/gn6/8rw7buK3jYPqIfcp
         szR1RDX3xbMsCBKMkXmNG1U6rFtQDjhzEdJ2rAvCL7b/2gRmTA0WP5lyan5sOSxrnHuG
         0PQyZg+zoa/Y12TNwPNGWLBoHlOvQZaC1T3fvHPJ+Vfg8vpKgKLMRO9sHliBppy6IlxG
         GwzxydpZKxjOLEMW8Q9w4cVTjh9nEQxFNEbwIVz9jOMPvtBgFBAGYSjOTxlvVau4hQKJ
         QiWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:references:mime-version
         :content-disposition:in-reply-to:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qQPS2BZgjjPmBnESLVgNw/RxN6D1do55YHYIuKcuGsY=;
        b=Na+2mmDBxPHjtt4kx6Nh4aJWptgT+Qt2sI6qT9Do6O707Ba268Gp0W4KqZKrM503uP
         b7/ij3jHbsMFf5I7MJTnteHjHlzw5/MoGWSSHb2aClNg1kzDLqnWTSqDk1/sNU1ZlSJL
         mJcOpx/6JHsNmM8yz+C2zPZBvdtN9s3QxuzgB5hQ3Vn7UIYVyiWFpcee9ne2moZ/lQvb
         i/LYuHdDs1OnoUSrRazGnxjbaz0Ft4Ib8/K/vC8tAvGYKth7RIjS54c7llfpZLrpcqCv
         e4KltQEsEFSGLdH5XXyAmhrDzh38IhZkkpyK+oupekIbcxJCjwKz/92S6I5muoMMJTwp
         ze2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:references
         :mime-version:content-disposition:in-reply-to:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qQPS2BZgjjPmBnESLVgNw/RxN6D1do55YHYIuKcuGsY=;
        b=O4i8kUnxU3jqAG+8E+c1GxUQCeAYcRsQz79Kxikit5xK8771x5dCN4S4OAJG7MzH0O
         Oc8R2oMYYPhArTKAyP9jqdShtu8xUVVH48TCmbK5CAGL/VJGvXdxamxkJzy599vuyPlg
         eRDIJnJta8QYWSnGMx8x8JwMaBUs6Och1t8ix9XAuMWfxPhKRMHucqPj8UnoSpr9vOHT
         /hf1OI3diU77SxNuM/0guL4bfQfqVSO5EdaD1QCwk8nxtyp0BERhUd6V/hmaXFJQ18lu
         uFYa3eNJc15besyBwF7yqLZS1TGpW6sxlWyn0iZXWyAd0CrjFXFen67PFqxHhohp9hgR
         E84g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVBEUby4Y/jR0oHQx3L0r3QoqsLy4Gf9kqzOirk1UJbUqf/g4OS
	p7Mdbz6vs6w0CPEwjd/0Pkc=
X-Google-Smtp-Source: APXvYqwQ5dVLXMYLb3Me3ypJT9wmUYpmO/USmwxwwDbYXUi1921ufMCPqsxKtusYGTce+BTyaOTB8g==
X-Received: by 2002:a65:4304:: with SMTP id j4mr17624195pgq.419.1565351653080;
        Fri, 09 Aug 2019 04:54:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7689:: with SMTP id m9ls1543543pll.1.gmail; Fri, 09
 Aug 2019 04:54:12 -0700 (PDT)
X-Received: by 2002:a17:902:e202:: with SMTP id ce2mr17937136plb.272.1565351652816;
        Fri, 09 Aug 2019 04:54:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565351652; cv=none;
        d=google.com; s=arc-20160816;
        b=ZfRU7ExIlZz8qCIzPEEL3pRUJG4nUisbEtLiG/fODZcnijkhz2ZiiP734BsvjecyTg
         phkoricS5ZYpEb6d0AydydMtQa/aNybwcLg5RIK4HPo8x1Og+k00Y6yH2dSVqxVoQONt
         4iWcJoyrD9JpPwZuJtIZV0YoUMzqaMRCzQHv9Cwby7DxcOhRE3B5K90EGiajnloiA8Tl
         9Whn4PgtM1TiXA2uNXBV8iaOqfa/7GIUHa5jJkJX0RXbsiRpAYPbtbD5oijcryipthgR
         Hsqn28NgfwsbbQwMQmue7rCu2h+q3eBwTiqJtOQ+8Stmion4jCEgz4Hmj7iMF7ac787u
         blaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:in-reply-to:content-disposition:mime-version:references
         :subject:cc:to:from:date;
        bh=XYzo8ta1SQfPXc3PL52prdzNrsiUCZYQyCVossBJwZ4=;
        b=exZk6FSAUzNhFM0i2cOxMqSKrKyM0r/v86pInEsc1958bV1DfFvtXzmlLIhOa3QZUx
         ouKqHydxOlpUmdSmyNackLNa2uXIWuR+o37R8kusLdMobw0kBTDRIcETc/1z4Mfw4Y5/
         tWuvFOGUWOSpmcedPWsaEhs1lUVZu5Z22VKH+cRoD0tAntjG0hSWJGtQOVKLEIp8/4+/
         uXG2ZfiPLf/9tCeAeiGdctiKxFIY/6ChMsV41WlBkuJe8R73eHIPX019RcuHb/fp6qvp
         pZWwwOIsA9LeRGDrxnCMrg7FhBv/7i9UYAWM5HOdj0ckLBwFt3EfEc2Dc0TkB3AwamDm
         csDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id w72si4208987pfd.2.2019.08.09.04.54.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 04:54:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.27/8.16.0.27) with SMTP id x79Br7nh002141
	for <kasan-dev@googlegroups.com>; Fri, 9 Aug 2019 07:54:12 -0400
Received: from e06smtp07.uk.ibm.com (e06smtp07.uk.ibm.com [195.75.94.103])
	by mx0a-001b2d01.pphosted.com with ESMTP id 2u94vqqtq2-1
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NOT)
	for <kasan-dev@googlegroups.com>; Fri, 09 Aug 2019 07:54:11 -0400
Received: from localhost
	by e06smtp07.uk.ibm.com with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted
	for <kasan-dev@googlegroups.com> from <gor@linux.ibm.com>;
	Fri, 9 Aug 2019 12:54:08 +0100
Received: from b06cxnps3074.portsmouth.uk.ibm.com (9.149.109.194)
	by e06smtp07.uk.ibm.com (192.168.101.137) with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted;
	(version=TLSv1/SSLv3 cipher=AES256-GCM-SHA384 bits=256/256)
	Fri, 9 Aug 2019 12:54:05 +0100
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06cxnps3074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id x79Bs4oh50659394
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 9 Aug 2019 11:54:04 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BDF844C046;
	Fri,  9 Aug 2019 11:54:04 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6CA394C059;
	Fri,  9 Aug 2019 11:54:04 +0000 (GMT)
Received: from localhost (unknown [9.152.212.24])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Fri,  9 Aug 2019 11:54:04 +0000 (GMT)
Date: Fri, 9 Aug 2019 13:54:03 +0200
From: Vasily Gorbik <gor@linux.ibm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
        aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
        linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com
Subject: Re: [PATCH v3 1/3] kasan: support backing vmalloc space with real
 shadow memory
References: <20190731071550.31814-1-dja@axtens.net>
 <20190731071550.31814-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190731071550.31814-2-dja@axtens.net>
X-TM-AS-GCONF: 00
x-cbid: 19080911-0028-0000-0000-0000038DB433
X-IBM-AV-DETECTION: SAVI=unused REMOTE=unused XFE=unused
x-cbparentid: 19080911-0029-0000-0000-0000244FB9F1
Message-Id: <your-ad-here.call-01565351643-ext-1834@work.hours>
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:,, definitions=2019-08-09_03:,,
 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0
 clxscore=1011 lowpriorityscore=0 mlxscore=0 impostorscore=0
 mlxlogscore=999 adultscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.0.1-1906280000 definitions=main-1908090124
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=gor@linux.ibm.com;       dmarc=pass (p=NONE
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

On Wed, Jul 31, 2019 at 05:15:48PM +1000, Daniel Axtens wrote:
> Hook into vmalloc and vmap, and dynamically allocate real shadow
> memory to back the mappings.
> 
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> 
> Instead, share backing space across multiple mappings. Allocate
> a backing page the first time a mapping in vmalloc space uses a
> particular page of the shadow region. Keep this page around
> regardless of whether the mapping is later freed - in the mean time
> the page could have become shared by another vmalloc mapping.
> 
> This can in theory lead to unbounded memory growth, but the vmalloc
> allocator is pretty good at reusing addresses, so the practical memory
> usage grows at first but then stays fairly stable.
> 
> This requires architecture support to actually use: arches must stop
> mapping the read-only zero page over portion of the shadow region that
> covers the vmalloc space and instead leave it unmapped.
> 
> This allows KASAN with VMAP_STACK, and will be needed for architectures
> that do not have a separate module space (e.g. powerpc64, which I am
> currently working on). It also allows relaxing the module alignment
> back to PAGE_SIZE.
> 
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> 
> ---
Acked-by: Vasily Gorbik <gor@linux.ibm.com>

I've added s390 specific kasan init part and the whole thing looks good!
Unfortunately I also had to make additional changes in s390 code, so
s390 part would go later through s390 tree. But looking forward seeing
your patch series upstream.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01565351643-ext-1834%40work.hours.
