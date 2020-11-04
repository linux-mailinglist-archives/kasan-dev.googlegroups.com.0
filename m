Return-Path: <kasan-dev+bncBAABB5MCRT6QKGQEXATSPAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B7FD72A6DDE
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 20:31:02 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 29sf9151776oot.11
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 11:31:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604518261; cv=pass;
        d=google.com; s=arc-20160816;
        b=1IalmUjovP62W1D+Dp/TzLG2PPOM1nrNpYUWIfz00p6y48W6P6Z2FXp9mmwTLtStAT
         AC/3e9RB3j64KUeVZP6LivTpq91xF7sLG8ipMsS87pn8tsjVjh7StkENIhanQIGyrMs5
         9STEJrUufgQ12+QZme8PCdPuSs9s2hVOg/MOa+pPHreqU/znYTH12EVwx13GmPYonuiZ
         ZnYFKCuATO3QnV4CIN33vr7xcA54f7bBDiuK/MnRiAeeb+3kEs68WwMNY2bA7EM2incM
         9Lo2P3QMbLUdvObbSd8o6Zzpl6Kw1xZ4N2Nu5SzCaxE3UKr0IgDCJspNfyr+E6Sh/27a
         xd5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DCRr9ByWjSH2CsYPz0AmhTG45Ax2rOvHzKW43iZ/71M=;
        b=ZvLK4t5yjKmnebrs7BLVYQxvTLkwnrD6RYLDS7JMu2mZvi8N7zO60brCFB9QMAeD86
         FFUc7PEFy08OPqqN42LmksJKoYLgrC95DOZUZmmEhpV3Gh5r12c/SiKfrUU0mQAKnWRQ
         iuTtTOGgF9mNb3CB1Kom7CXIj2Gaxp/6/7HdQcXkqAlEV8dNsZEr9zLIsxL0zWSjSW9J
         WZljmTXO9rmjpqcdTIazjQEZ6nkxnClt43BMDOOaoGUSA0zHhPzyJGaDWP6VVMeBd0Gv
         IcfoobpPvbX1M9hU42K56tnPeik5/cpXbqJkVb2e+7zZgutBo4aBSYPNUuOhYpqlNOKe
         pAiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=axlsn2DR;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DCRr9ByWjSH2CsYPz0AmhTG45Ax2rOvHzKW43iZ/71M=;
        b=QTRtaH1cFKBHDyvVg1cHMz3SNSFrRF31Sv6tCohiJj75XSRLpYWxAUaG5y4IQ9aASE
         m8ye9W4VXdWQyQ+blzXNC0HfXat1HoGXrOvZA0XMvysIo0ex6qGSAIO4//G6I7sn0lE+
         g5u3hAjTteWikkr2PecYkPk21ypVW/fsnFmcHoyUQKFGqzvH0uvOMLn/9b6/JAVBZHW6
         bzxyriZZehrmy1gFaQgy78ySzvKROqN1rYcmDZpC/Qam4UQVp4XlN9uALEmekkmAbSo5
         LjE6W8kHYUG8ZLkqtiZhJPiBttArMeFh+cReB52q/Ybnr10gGdFw8NRlsGYQk17BwQ4K
         PpQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DCRr9ByWjSH2CsYPz0AmhTG45Ax2rOvHzKW43iZ/71M=;
        b=jfe0tCcK/9NHxfViXI9pir704151Xo4OnybYtAYnlkSJsiPICzF+s+/j/oGCRYtKJW
         rdsqsnU/qs15WhQ49WYfAEAupX5PEHYj0FFS2ntp7vfpVKeGOHeQPg0Dbnpfn9CKI5Ga
         jzALbBZ/tTHuqphGg0+lc5Lq6OfJeI5mHL+hDz6TICEVMINTe/tCkoiTMB9y60+Fkke7
         xOXZs7VBpIWR8LZFNkpvUlXAnyw6c5AGaMgsiUsADFL89Xv4krKjyEsQjIFesVWnHWxQ
         zGswPPq+O9TXiKZGxnqv7+Fzq8FqkhOycgPDdsfdBsBOSob3pfw4KMVXhc6NdSq70m7c
         A/qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zXCInxaouWK/4BsEnSeLQLE2y1t/W5XK8Ke1Ae1e7V67D14/L
	LOKZpjHbE9yFg7hzbJoxNlY=
X-Google-Smtp-Source: ABdhPJyDCSPWPu7nbkB6NQN6IElO0kK6mzKNim9QPwB+rjFbffF4a73yjliy0ZjE11nEifjI3qw1fQ==
X-Received: by 2002:a9d:2283:: with SMTP id y3mr18897000ota.164.1604518261447;
        Wed, 04 Nov 2020 11:31:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:bb2:: with SMTP id 47ls763720oth.9.gmail; Wed, 04 Nov
 2020 11:31:01 -0800 (PST)
X-Received: by 2002:a05:6830:154d:: with SMTP id l13mr21173142otp.61.1604518260998;
        Wed, 04 Nov 2020 11:31:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604518260; cv=none;
        d=google.com; s=arc-20160816;
        b=kvsd8WtjpDijcGF1ucM+LNZMuLiiRyo0gws6CNXQglqYonHpmzJGhaidwWF661l9oQ
         2sS0K6nz3CbowMGmO97ZYXa5j+Lgm/texAA74xRQUyl9Tfp/agXB6gkibLAlilXKtDHA
         SWO6Qzq2SBedUA5gqXObJv0995e8b8MerW0D1sdJsMk0wWp0DXiYZN77e3cSfGw51K6t
         vNdV1RONFLSwlcvMXLYkTFUv78Uk3O0eRqLyQwSTb1BWeaa2EKKUJemM5ZMjEBwmHE2l
         PkmFj1FiD/XUr/cBQ/9npvUlXnCWhTqPlmw+r8EYuLPYPzXU6AwUTa2vicn47K6RQPNR
         CxKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kqKl/Fy8OlJQj/Gv88agH7/I5WU7KGmVdKg9ghw1xjE=;
        b=cOd/4E470PH2CuNgdMZm7eQaqceYQIfXY2tnJef/1+ne+bjeIJppTUX8pXO71sz0/n
         PEE/Zz+ZRhu0qEgm86KPB6zm+r6tBB7GKAOVEF86vcDvG70EXEx6JHj92tSlZAglDuhS
         2ft6L8UnKY/PZkcJryHCK5ksw1MABcHji0AVZHHuGEyLO0yhmH6voJ9zGZ05DWSYZJMR
         yImbTsJN1OjA7jRA1sfdWeH1zC5vEHNwoYLO/soic701uuGjPkfv3OsNqIThlBJy4HGC
         arPtZuD6yDzKkLydEr//qnW86iswPVPZAJ76Sx9Roj/HMD/LnsIf2u7nCC2unNx/7CZD
         8I8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=axlsn2DR;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id m127si300717oig.2.2020.11.04.11.31.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Nov 2020 11:31:00 -0800 (PST)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0187473.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 0A4J38xR010691;
	Wed, 4 Nov 2020 14:30:54 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34m0qck9gv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:30:54 -0500
Received: from m0187473.ppops.net (m0187473.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 0A4J3INU011124;
	Wed, 4 Nov 2020 14:30:53 -0500
Received: from ppma03fra.de.ibm.com (6b.4a.5195.ip4.static.sl-reverse.com [149.81.74.107])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34m0qck9ea-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:30:53 -0500
Received: from pps.filterd (ppma03fra.de.ibm.com [127.0.0.1])
	by ppma03fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 0A4JRnj4026068;
	Wed, 4 Nov 2020 19:30:48 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma03fra.de.ibm.com with ESMTP id 34j8rh9jk6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 19:30:47 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 0A4JUjQb60424536
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 4 Nov 2020 19:30:45 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 544FF4C04A;
	Wed,  4 Nov 2020 19:30:45 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4925A4C044;
	Wed,  4 Nov 2020 19:30:44 +0000 (GMT)
Received: from localhost (unknown [9.145.163.252])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Wed,  4 Nov 2020 19:30:44 +0000 (GMT)
Date: Wed, 4 Nov 2020 20:30:42 +0100
From: Vasily Gorbik <gor@linux.ibm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will.deacon@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
        Elena Petrova <lenaptr@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v7 16/41] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
Message-ID: <your-ad-here.call-01604518242-ext-7611@work.hours>
References: <cover.1604333009.git.andreyknvl@google.com>
 <4dee872cf377e011290bbe2e90c7e7fd24e789dd.1604333009.git.andreyknvl@google.com>
 <your-ad-here.call-01604517065-ext-2603@work.hours>
 <CAAeHK+wuJ5HuGgyor903VcBJSx8sUewJqmhA_nsbVbw0h2UFXg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+wuJ5HuGgyor903VcBJSx8sUewJqmhA_nsbVbw0h2UFXg@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.312,18.0.737
 definitions=2020-11-04_12:2020-11-04,2020-11-04 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 bulkscore=0
 phishscore=0 lowpriorityscore=0 adultscore=0 priorityscore=1501 mlxscore=0
 spamscore=0 clxscore=1015 mlxlogscore=999 impostorscore=0 suspectscore=1
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2011040138
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=axlsn2DR;       spf=pass (google.com:
 domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=gor@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Wed, Nov 04, 2020 at 08:22:07PM +0100, Andrey Konovalov wrote:
> On Wed, Nov 4, 2020 at 8:11 PM Vasily Gorbik <gor@linux.ibm.com> wrote:
> >
> > On Mon, Nov 02, 2020 at 05:03:56PM +0100, Andrey Konovalov wrote:
> > > This is a preparatory commit for the upcoming addition of a new hardware
> > > tag-based (MTE-based) KASAN mode.
> > >
> > > The new mode won't be using shadow memory, but will still use the concept
> > > of memory granules. Each memory granule maps to a single metadata entry:
> > > 8 bytes per one shadow byte for generic mode, 16 bytes per one shadow byte
> > > for software tag-based mode, and 16 bytes per one allocation tag for
> > > hardware tag-based mode.
> > >
> > > Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE, and KASAN_SHADOW_MASK
> > > to KASAN_GRANULE_MASK.
> > >
> > > Also use MASK when used as a mask, otherwise use SIZE.
> > >
> > > No functional changes.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > > Reviewed-by: Marco Elver <elver@google.com>
> > > ---
> > > Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
> > > ---
> > >  Documentation/dev-tools/kasan.rst |  2 +-
> > >  lib/test_kasan.c                  |  2 +-
> > >  mm/kasan/common.c                 | 39 ++++++++++++++++---------------
> > >  mm/kasan/generic.c                | 14 +++++------
> > >  mm/kasan/generic_report.c         |  8 +++----
> > >  mm/kasan/init.c                   |  8 +++----
> > >  mm/kasan/kasan.h                  |  4 ++--
> > >  mm/kasan/report.c                 | 10 ++++----
> > >  mm/kasan/tags_report.c            |  2 +-
> > >  9 files changed, 45 insertions(+), 44 deletions(-)
> >
> > hm, this one got escaped somehow
> >
> > lib/test_kasan_module.c:
> > 18 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
> 
> You mean it's not on the patch? It is, almost at the very top.

lib/test_kasan_module.c != lib/test_kasan.c

I fetched your branch. And I had to fix it up to build old good kasan
test module CONFIG_TEST_KASAN_MODULE=m

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01604518242-ext-7611%40work.hours.
