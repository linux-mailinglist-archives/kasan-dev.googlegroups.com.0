Return-Path: <kasan-dev+bncBCM3H26GVIOBBSWVYOXQMGQERQHPFSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E357D879FDF
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 00:52:43 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3662dbb587esf47649295ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 16:52:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710287563; cv=pass;
        d=google.com; s=arc-20160816;
        b=ej+Wz/biA2wWjFjUhJRamjLqhOCxS3XS2a1EX9l1tJsal4P5QWaxLI/k9rKIlBea0e
         2CLd2lbgSvAWL3WXLcygWwNeksyMq3e2SD+nDkTMk7L2IhwN1EktoZO6zOOLeKp6oPMq
         OkO3Ewf8yNL2JXma3YUHzeQGw3rDu2AODZJ2xxrtzW9V6wiMoelaCV3EBqWkjjze4y6j
         pZl5ECH7OP6/OC5ZJH4DzIl5FtVNHls+FXU0mmvf/V3mIkIY97p5hAG73SpfLOMmgDOs
         ilxpNOzQqwqYUWp0b3q3CkcayQF3cms4x1anT/HhDSfZkgmzdiX4gkHpofKAPEK6zhy9
         0oJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=+qTAlsDTT/LDNT+35BTNuw5sys48F2N8lH3KPI9otEI=;
        fh=MtaPrW1g+S2QSEsTbHaAfeu36Xib/W2nMGUp9QSJ4r0=;
        b=Jv08mb3Ad8OkLJqrxdbWVHaR5Zf5jbcgWzvNqxd8DmytvR7Pedg3mwcpcclqnpy/yS
         UX9jBOT/9iN2YlT3vcP7yBeKo1JgZ7JuNJB9Oo/DDxCqSirW1Eg5cGxGWseqXaz9GOa0
         EVc4AEL87a0weKCZDXcuNM8kDnj0OS5qnqCkwzdFTP9UDHnSJeUwQD97cz4zDzX7lbzy
         GoW1fqxl4a2Twc1cuARwYi9mDxB9dZPEmR2A6h9ojhtDj3n8SOG47feHOCxApb7LsgxX
         BwshXBQwMQIFZQytI1FiKwfPiuTPp0LkdB1xdswEPrmWDKKlskzJxaY2iCXynsOnMiHH
         pflg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TfT7iGv9;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710287562; x=1710892362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+qTAlsDTT/LDNT+35BTNuw5sys48F2N8lH3KPI9otEI=;
        b=MvYXGr/TF1DR9JayT5CH9OwjpLnuhBT05oIjlSV9gdgQtDpS9588NBh9U5o/zX+Y0c
         ZYyrrF05iM9R3LMBYsyKNNDw4lkMNFrRr8V8LKxq/qh7+6KLZntQTmdXG6cjccwV46/g
         yudsGhZjyLS+Grzzape9Ddp1oJc4BLRllJ2TMUATrb3GWbGg/A0Jtq9lFqcFxnVVLEOF
         1D4AB33zyamhKCEohotHe2FaT6hHfFymcN6Qe/05LjmShp9RaDXwUn3ZqwCgKD+Tx6Xk
         iDTqgq9V2ev3qJanMsgsLIfdS7el7CV3jA0KLQN989C/kymS0Fz5Dbb7YkZXmUK+EpU1
         aDUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710287563; x=1710892363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+qTAlsDTT/LDNT+35BTNuw5sys48F2N8lH3KPI9otEI=;
        b=OB6kJ8XPunVtFxsQhvtXSbVoU2aWAQfzw3XjnGQGWUxgUSnM109lWvtj7CCsc66N0L
         PaoAY8dPouY3yjET9U14+BxQphTiQug/zCx9n76xjOYFLF8xKGia73wn9oJ9GwX3o6+I
         RPaMZ67qgei3WaBBEz61dIz+89564RGxU4s6OGza1S8AhNfYg+rYabU8moKypAx3VNds
         CWSpOhwtg0uEdcInmgZX+UaxQ0z1F9nKBl//FS6PQZUEgZERBb/ZFR416mwpshpKaiKN
         Xd96oHtiQdzh2+ykIqeNk6QRna72xENMXHAAQRyRSEacAuHy6LRRE+5QcNJeNbkbEw+p
         ofWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUXhOMRIiqxQfK8t1WbD9qZby9B9Wgv3+ZlBYBEIX1X95jUFRke531k5EzfdeGRkuoMFUXi8infVj58dmxQ8azgTcEGekjZBQ==
X-Gm-Message-State: AOJu0YydeonBDV39rQ80ov5z3pDMDBE1E1pKVlEWDY9Rk41CUghPjyzP
	oGI/gmroFy/bOvYh4q1/k9/soPxV63DlxcfLKa0Wd5fF+n78xgIt
X-Google-Smtp-Source: AGHT+IFcrDjfDmHOTD8m1SR7oYWZWfrrK7Xc+sAn5MH/scRQ22fDBqoLO3LD4fudwgn3qdSst8gpXQ==
X-Received: by 2002:a05:6e02:1a86:b0:365:d2cf:a46e with SMTP id k6-20020a056e021a8600b00365d2cfa46emr3062491ilv.30.1710287562562;
        Tue, 12 Mar 2024 16:52:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:216f:b0:364:f4f8:1f07 with SMTP id
 s15-20020a056e02216f00b00364f4f81f07ls1571153ilv.1.-pod-prod-09-us; Tue, 12
 Mar 2024 16:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSrO3RTu1GE+K8BcXJrUcqo9QKFkAoMK/U1q1g3fceZVYaYdUadXl/VoRij/bEuYL/n0cWw2TcRiYCy5TBmKAy0RpQEi07BJws2w==
X-Received: by 2002:a05:6e02:148c:b0:365:1a2f:8271 with SMTP id n12-20020a056e02148c00b003651a2f8271mr3740039ilk.3.1710287561529;
        Tue, 12 Mar 2024 16:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710287561; cv=none;
        d=google.com; s=arc-20160816;
        b=ZUUaVIc4h8FTEEkgMIQzJ+GiomGEMAv/FlmpaICcYljj8FVfLFmMZccWvuUWZRlDUn
         s6xhCKiOeJtNNps9BbIpAo5VHCEUumpPQJsQ3Gsfoseoh8Kb21j/69sKOStEIGeEURay
         gmswtupIAY7s+SeCUjZnKs9JtPNoL8Vr7cFE671+CUujINCXMvQx4Qh3kAXm2c90R28E
         hr1O11N+iNlzFykI5nqy80yc9yKM+42q1VuLNCKBFD5Z5XV7hsECysOF8oWPzOAZNXSf
         cAflNUSqpx6EyCIQ9OyGAEJlFwXAgfqCe8aDf8MF6Vc+A6+uoJFuuins6wjTMpxHmBT1
         atGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fxzUnZ0nbYPzD6mGgMCor9l0aAH74e99rvLKk3Y5RPM=;
        fh=fWljgm9+YqbXExLhhjJaMZHjcBG6kfUvxRsg8DaaN3o=;
        b=HYfrye7gHJwE1Ve4MEZgk5SxefxiV7wfe6r2YTl0sttHfHc6111etOZYRgsMVHESJL
         BEAD/27DIxAeWLjvLfAU1KsDU3mTqTZ1ey+twGVB9CFWWznQ3rVHeDeiHQTbVMURPIvr
         BzrSIS3bLhv1XLw7waKnDSzLGZAHgvtg2nzzoBO7DqS9Ogti767BYTomI/myurLUpHB4
         abqLq5cl6sufJaL0Mus0XQKpOwbMicC2goqSstIJZr3pKCG1uE7LqPGIySWQ+4dZridN
         4xQWXXzD8CiCw4Qhdzzz0DfqanHGbVQZi18ghtob1zFB2quWY0yTBi+pMqMxcS8hFJsh
         sXeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TfT7iGv9;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id c4-20020a92cf04000000b00365843633c1si668983ilo.0.2024.03.12.16.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Mar 2024 16:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 42CNPnsf029449;
	Tue, 12 Mar 2024 23:52:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3wtyv3rxev-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 12 Mar 2024 23:52:40 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 42CNnhtU017491;
	Tue, 12 Mar 2024 23:52:39 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3wtyv3rxes-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 12 Mar 2024 23:52:39 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 42CLYt81020446;
	Tue, 12 Mar 2024 23:52:39 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ws3km28r2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 12 Mar 2024 23:52:39 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 42CNqZiH12779868
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Mar 2024 23:52:37 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1CBBF2004D;
	Tue, 12 Mar 2024 23:52:35 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BAC8420040;
	Tue, 12 Mar 2024 23:52:34 +0000 (GMT)
Received: from heavy (unknown [9.171.20.188])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue, 12 Mar 2024 23:52:34 +0000 (GMT)
Date: Wed, 13 Mar 2024 00:52:33 +0100
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Changbin Du <changbin.du@huawei.com>, elver@google.com
Cc: Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [BUG] kmsan: instrumentation recursion problems
Message-ID: <ndf5znadjpm4mcscns66bhcgvvykmcou3kjkqy54fcvgtvu7th@vpaomrytk4af>
References: <20240308043448.masllzeqwht45d4j@M910t>
 <CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA@mail.gmail.com>
 <20240311093036.44txy57hvhevybsu@M910t>
 <20240311110223.nzsplk6a6lzxmzqi@M910t>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240311110223.nzsplk6a6lzxmzqi@M910t>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: XMoEI2_KLVggDytKVnGT_gt9PRMt-t9n
X-Proofpoint-ORIG-GUID: nFuB370a9GDq1Q2xV0HTmVpkEjO3Y1ND
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-03-12_14,2024-03-12_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 spamscore=0
 suspectscore=0 adultscore=0 priorityscore=1501 lowpriorityscore=0
 bulkscore=0 clxscore=1011 impostorscore=0 phishscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2403120183
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=TfT7iGv9;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Mar 11, 2024 at 07:02:23PM +0800, Changbin Du wrote:
> On Mon, Mar 11, 2024 at 05:30:36PM +0800, Changbin Du wrote:
> > On Fri, Mar 08, 2024 at 10:39:15AM +0100, Marco Elver wrote:
> > > On Fri, 8 Mar 2024 at 05:36, 'Changbin Du' via kasan-dev
> > > <kasan-dev@googlegroups.com> wrote:
> > > >
> > > > Hey, folks,
> > > > I found two instrumentation recursion issues on mainline kernel.
> > > >
> > > > 1. recur on preempt count.
> > > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> preempt_disable() -> __msan_metadata_ptr_for_load_4()
> > > >
> > > > 2. recur in lockdep and rcu
> > > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> pfn_valid() -> rcu_read_lock_sched() -> lock_acquire() -> rcu_is_watching() -> __msan_metadata_ptr_for_load_8()
> > > >
> > > >
> > > > Here is an unofficial fix, I don't know if it will generate false reports.
> > > >
> > > > $ git show
> > > > commit 7f0120b621c1cbb667822b0f7eb89f3c25868509 (HEAD -> master)
> > > > Author: Changbin Du <changbin.du@huawei.com>
> > > > Date:   Fri Mar 8 20:21:48 2024 +0800
> > > >
> > > >     kmsan: fix instrumentation recursions
> > > >
> > > >     Signed-off-by: Changbin Du <changbin.du@huawei.com>
> > > >
> > > > diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> > > > index 0db4093d17b8..ea925731fa40 100644
> > > > --- a/kernel/locking/Makefile
> > > > +++ b/kernel/locking/Makefile
> > > > @@ -7,6 +7,7 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
> > > >
> > > >  # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> > > >  KCSAN_SANITIZE_lockdep.o := n
> > > > +KMSAN_SANITIZE_lockdep.o := n
> > > 
> > > This does not result in false positives?
> > >
> This does result lots of false positives.
> 
> > I saw a lot of reports but seems not related to this.
> > 
> > [    2.742743][    T0] BUG: KMSAN: uninit-value in unwind_next_frame+0x3729/0x48a0
> > [    2.744404][    T0]  unwind_next_frame+0x3729/0x48a0
> > [    2.745623][    T0]  arch_stack_walk+0x1d9/0x2a0
> > [    2.746838][    T0]  stack_trace_save+0xb8/0x100
> > [    2.747928][    T0]  set_track_prepare+0x88/0x120
> > [    2.749095][    T0]  __alloc_object+0x602/0xbe0
> > [    2.750200][    T0]  __create_object+0x3f/0x4e0
> > [    2.751332][    T0]  pcpu_alloc+0x1e18/0x2b00
> > [    2.752401][    T0]  mm_init+0x688/0xb20
> > [    2.753436][    T0]  mm_alloc+0xf4/0x180
> > [    2.754510][    T0]  poking_init+0x50/0x500
> > [    2.755594][    T0]  start_kernel+0x3b0/0xbf0
> > [    2.756724][    T0]  __pfx_reserve_bios_regions+0x0/0x10
> > [    2.758073][    T0]  x86_64_start_kernel+0x92/0xa0
> > [    2.759320][    T0]  secondary_startup_64_no_verify+0x176/0x17b
> > 
> Above reports are triggered by KMEMLEAK and KFENCE.
> 
> Now with below fix, I was able to run kmsan kernel with:
>   CONFIG_DEBUG_KMEMLEAK=n
>   CONFIG_KFENCE=n
>   CONFIG_LOCKDEP=n
> 
> KMEMLEAK and KFENCE generate too many false positives in unwinding code.
> LOCKDEP still introduces instrumenting recursions.

FWIW I see the same issue on s390, and the best I could come up with so
far was also disabling lockdep.

For KFENCE I have the following [1] though, maybe this will be helpful
to you as well?

[1] https://patchwork.kernel.org/project/linux-mm/patch/20231213233605.661251-17-iii@linux.ibm.com/

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ndf5znadjpm4mcscns66bhcgvvykmcou3kjkqy54fcvgtvu7th%40vpaomrytk4af.
