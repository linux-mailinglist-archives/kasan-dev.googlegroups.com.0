Return-Path: <kasan-dev+bncBAABBG7C5T3QKGQEPS37NFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EB8320F4AC
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 14:33:33 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id x2sf13025698iof.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 05:33:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593520412; cv=pass;
        d=google.com; s=arc-20160816;
        b=vAtLVGXGMSpQnKFIXS0mPwBanPGcMocl7buNbrgHlRwRDy+kBgF9KK/yMBgjGUrjAg
         RYJTUKu8JQJ2wkbvqx6b1o0J8OStVKSVTGA5ILQxOywFq8a7c+Iz98QtnnoS72GIc1FG
         /CfLwJK9S+KyolcgVOEo0slu0Dwy57tQaRfGrr9t48jByruslKytBwihkPAffHwjZgFp
         tSKpc7nunDJwvzLhFY0VcvGHEG4kUUD2Owz+egnfUNh2Vd6zHHWDhPwVJN24sHcBgA3/
         0rfbuD94Nh8Pcdzg6/nc3D2LW4a0mYZOcVoCTdYvoIiQqF9zrS7Ca4aYrqj9v4PQjT4d
         hnuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ECnjzevWPeMZwHLnbw97VocAOlMLlhS0VzSdoh29KZ8=;
        b=H1UpitNYbIXxdLURVVneVwFWnUntbLo/6242bItaU6IYIbDcRu0UjNUDYF4YU5Lp2q
         FSMcIzcCuBw2T435wxxj1m7FS3QJBANADig30T/pWfNkHKB3mwK05OmupzEU8TgxYANJ
         fT+FT6yD1DByilFpEoZkgmEXsIo79KVd5uUI+hr/BA108Ii2CKv9CGfo7TzhMZjwlDrH
         R8IEsBOy/24xXww5d9wudP0pdqpB4UtFd4aY1t2y1jx/X1zlrj5vEIvSDNd2seKCmgKi
         NZpZAon6GjYaP2fsOhH/wmKlaNt9e2jbzq8X7MfBOhSIkJcj2rRLClIkPI/FiNoED/Iv
         DqMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ECnjzevWPeMZwHLnbw97VocAOlMLlhS0VzSdoh29KZ8=;
        b=EbD6uTzTV9Hc2qKmIMO6wcyugegYE9O8N+IJqVXJ0JyZUMCQ4x9pnfzC7eLAUL+wk6
         0d6aDaWLL863/KUHsAd7+1H4A43oQjGHIHyFGcBeLTiN0En2yru3XxxA+ey+Nv00tL4t
         s/cXE5RCKZemO2p+zRjXIO/K7cr4d8s3t8oy4n4j6F8fh9ca3tAOL70U5C+0oQ2aHOD5
         FjAFMbZb7gXJQZ4QRc2dNdfBNi/HJ+ulJ51QN9mdj91Zpr7crv5CuXLCGGN6EwQGTm1B
         OYeyGe1XgzgG5SfJ1g3DUJl6vakoldcuCMiQsCfToP53VnV/dekdn/n3d5bj9ln6y/oq
         h2Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ECnjzevWPeMZwHLnbw97VocAOlMLlhS0VzSdoh29KZ8=;
        b=HZOeS1BsJbkLBpCH9wxqcpm6wIidFjI4tjddHVWi7y4gB49bK5qinHz6ByjmduhYEk
         9B2rPHEmG2f5NYNe+Enp6S2iPblXxEbHV+duJUOCq2+Mbop9/rRIrwNWAFUjqHlYBDJZ
         ENFlBhA/sqHJXc72vj98l/h09OAJ206DXpfEHmtX2ulFO8Js6n8mxaw7KUf71ZplC66h
         myQYxRemPLT9eiIusbbqsGhvDVFcyDNqCZEDmBKntRlSCwQhAXSF1+EKDFQyTSlgTse+
         cLZZ36duCQR3We2fodRP2dIlrWcwreto2Wk1EPLo1otJkj8LoTz07GBzVt7S+p4GqWAp
         Lbcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532h9xFu8LtIcmuUtRQ3vK5OHqJHjRbCanBtWN+AZ8Lrw1lyzIh/
	PHjH5O9WIRel0HXNWCH181o=
X-Google-Smtp-Source: ABdhPJwnILpGy+oB0Jh0Dyttui6cVM0zHizrSdnqANi5SM4Lbgttcuyvs4bUp70qCDXNhJQc9n5wtQ==
X-Received: by 2002:a05:6638:1014:: with SMTP id r20mr22872721jab.44.1593520411927;
        Tue, 30 Jun 2020 05:33:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:da02:: with SMTP id x2ls573589ioj.3.gmail; Tue, 30 Jun
 2020 05:33:31 -0700 (PDT)
X-Received: by 2002:a5d:8744:: with SMTP id k4mr21114619iol.149.1593520411587;
        Tue, 30 Jun 2020 05:33:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593520411; cv=none;
        d=google.com; s=arc-20160816;
        b=az9CLSzujBFQb17RVlnoYczhunaIdjyyIRyft8OjhamFrs3Hj4ZI6xo0XQlzj2PI/C
         kFqsDwQtLdIkCIBuRdmNqZ0RBuTbUb9TJIxAv5QV1wgQfgC0piFGXcGW5GZz73Sv52In
         2udFEDa50YzVh3SEEgXinnn+l5LQixRFO/4nobMEHTmrBt0YwrBNnSPJ0BBK9LhPD50J
         TjF4376suZaEVbNtWgH0ibbmwT6lr+aIyM7Zuo/jRoN2BAOvya9vF5LqBcpNvyLAcDmt
         08cWidTKrMPGRhRpR9qO26rm2eunIavIf3HaWzX7ZSe2erG6tub+N102Jw6g7DSLD/+u
         37sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=akLEJn2Ifji040HzwKTgCB3VF5CFlNxc/hUo4Z95EII=;
        b=gZxUqEHIHCYN4BXvrhatZsxaWLrcArrWoFfuSwqnGeogxpJtt/aAABy8vE6TSaMJCG
         /rLPXYE29y1V5MdM074iLA9Occg8czyx8q0lIvNEXkJEF9vj/kAEzo4ZH2pu2JCR3vVn
         uizj2tKd/0qpeiTGHFm7eTZu5SAAdoKHFTsQ6CjlvYW6B/q4FARMVdy60fLI9NkMcV+n
         zD2NLKZDtuAbGu8Nd9nJ4efsXtPUgtgbabDuuaok3xgdaRfUpjPBlJqzIWv1vJqL63gq
         lLsnkHgtsgKb4d+7rxVQyV26fDm1D2yV5/A4/U6Uy2W0OtKo8IeQsW3W5/ijNvntukpZ
         1NfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id f15si166930ilr.0.2020.06.30.05.33.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jun 2020 05:33:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098420.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 05UCWcBc034487;
	Tue, 30 Jun 2020 08:33:30 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com with ESMTP id 3204yvh57b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Jun 2020 08:33:30 -0400
Received: from m0098420.ppops.net (m0098420.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 05UCX8r6039165;
	Tue, 30 Jun 2020 08:33:29 -0400
Received: from ppma06fra.de.ibm.com (48.49.7a9f.ip4.static.sl-reverse.com [159.122.73.72])
	by mx0b-001b2d01.pphosted.com with ESMTP id 3204yvh553-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Jun 2020 08:33:29 -0400
Received: from pps.filterd (ppma06fra.de.ibm.com [127.0.0.1])
	by ppma06fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 05UCGQOu007689;
	Tue, 30 Jun 2020 12:33:27 GMT
Received: from b06cxnps4075.portsmouth.uk.ibm.com (d06relay12.portsmouth.uk.ibm.com [9.149.109.197])
	by ppma06fra.de.ibm.com with ESMTP id 31wwcgsq0s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Jun 2020 12:33:27 +0000
Received: from d06av25.portsmouth.uk.ibm.com (d06av25.portsmouth.uk.ibm.com [9.149.105.61])
	by b06cxnps4075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 05UCXOV365077476
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 30 Jun 2020 12:33:24 GMT
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4FA0311C04C;
	Tue, 30 Jun 2020 12:33:24 +0000 (GMT)
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8310A11C05B;
	Tue, 30 Jun 2020 12:33:23 +0000 (GMT)
Received: from localhost (unknown [9.145.78.150])
	by d06av25.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 30 Jun 2020 12:33:23 +0000 (GMT)
Date: Tue, 30 Jun 2020 14:33:20 +0200
From: Vasily Gorbik <gor@linux.ibm.com>
To: Qian Cai <cai@lca.pw>
Cc: Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Kees Cook <keescook@chromium.org>,
        kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
        linux-s390 <linux-s390@vger.kernel.org>,
        LKML <linux-kernel@vger.kernel.org>,
        Heiko Carstens <heiko.carstens@de.ibm.com>
Subject: Re: [PATCH] mm/page_alloc: silence a KASAN false positive
Message-ID: <your-ad-here.call-01593520400-ext-3384@work.hours>
References: <20200610052154.5180-1-cai@lca.pw>
 <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
 <20200610122600.GB954@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200610122600.GB954@lca.pw>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.235,18.0.687
 definitions=2020-06-30_06:2020-06-30,2020-06-30 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 spamscore=0
 lowpriorityscore=0 mlxlogscore=999 priorityscore=1501 suspectscore=21
 clxscore=1011 malwarescore=0 phishscore=0 adultscore=0 bulkscore=0
 impostorscore=0 cotscore=-2147483648 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2004280000 definitions=main-2006300090
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as
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
> 

Sorry for delay. I assume you tested it without CONFIG_JUMP_LABEL.
I had to fix couple of things before I was able to use init_on_alloc=1
and init_on_free=1 boot options on s390 to reproduce KASAN problem:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=v5.8-rc3&id=998f5bbe3dbdab81c1cfb1aef7c3892f5d24f6c7
https://git.kernel.org/pub/scm/linux/kernel/git/s390/linux.git/commit/?h=fixes&id=95e61b1b5d6394b53d147c0fcbe2ae70fbe09446
https://git.kernel.org/pub/scm/linux/kernel/git/s390/linux.git/commit/?h=fixes&id=d6df52e9996dcc2062c3d9c9123288468bb95b52

Back to clear_page - we could certainly make it non-instrumented. But
it didn't cause any problems so far. And as Dmitry pointed out we
could potentially find additional bugs with it. So, I'm leaning
towards original solution proposed. For that you have my

Acked-by: Vasily Gorbik <gor@linux.ibm.com>
Tested-by: Vasily Gorbik <gor@linux.ibm.com>

Thank you for looking into this!

Andrew, would you pick this change up?
Thank you

Vasily

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01593520400-ext-3384%40work.hours.
