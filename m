Return-Path: <kasan-dev+bncBCM3H26GVIOBBXMLYSXQMGQEZMILPXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F60B87A0EF
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 02:48:15 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3666d914ce3sf13089125ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 18:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710294494; cv=pass;
        d=google.com; s=arc-20160816;
        b=z9gVYHG3vHE+KI1Tcqfjn5tXDL/BzB1yUEyFDX4rTl0Cg+ttInLL2biulzCaWrzvFm
         YCMX3sHX2Dtnz7P/pSMFCWFUukalTPaZz6pJlUw40ApFUB+gy1eoNz9K/UiwGSHgoOMR
         d3J8vomlySM42BMstwi05QhMPrygrsa+gCxVzF4+JTuAti25rZ2KMJmCvQsWgNaD1ngY
         ljZXO1Y30bTmAJaJk2jMtxvIhixo8kiIozYUfDz/aBkPpmJ7zoQSGgRsMURTEePX6Mp3
         CC9Xw568dNSydPV/BUEs4DL/ecnS1gZr4cOTp7/s9/W3wR5RY3I1IDfjycYG/MLwZHi1
         r36g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=+sTX2768JFZwa/nheYBex/yCzZCIlWdwfHF4Fstvuhs=;
        fh=v3LF1F/WFtn+N8NuhxtD35IOKyzIsP1s+fCRBKbrLUU=;
        b=QL2u2TJBWNySOpw7sDwFArL/hOauGdZNDr5ERtWiDWaWArPzgDq8aEjVW0F4rCzzZm
         ugbb2WxDf4G1YxsJsjME/U1RL/cJTfANczzsy0zWIrN+eC7Lov/hy33rr9RCc8dj5LjR
         kW3airA52kBHCvYS2h7Wx/4OZ356nazX9hEPMmTBAyDqq3Pro+u4xAm3ouDrUOEx//Ux
         AMCmFX1ceJufCYZTnTwXy6wj4Nj8T9dkJ/mtVfjeuWthaK4zTDVRSWITxSwRn/0Gp8V5
         2fSKRT+bFr1yhJqE5VUF2ZfDvcstsq2JffuT2cvu96kh7T0uO3R2jruI0tncxfU4Au82
         isMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YOBNuMQW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710294494; x=1710899294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+sTX2768JFZwa/nheYBex/yCzZCIlWdwfHF4Fstvuhs=;
        b=TATH6xEfNPcJH6MqZ5mOCkDE6gl+RrzEqNT4syInV5JxpS5/7nW9//WGLrg60P4tGw
         2b3VZs2beetowLn6IF1rV7ooE0lw3ts54+NMaWbuVZJN7la4b3xqMB0i2rq4Yvc1P+gO
         OSR0dxieeqHpPbknvtzgw6H4Z1vKj9AJnXsxcVDm+/juztfb328HfQdjH2QmrN5UviYn
         Ff8W8x5NXafqAAe8FLFW8N///KoTxlHK1VCOv/kjJJDqmNQhe/gFRP9CnznCczg5JtNQ
         1d32D1vTpnWg+XJ22ystxEQp6YBVAFwBnfKR1ZIQn2D9VpsAXKzTZ/Whp7uJ7VzMoKA1
         JHMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710294494; x=1710899294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+sTX2768JFZwa/nheYBex/yCzZCIlWdwfHF4Fstvuhs=;
        b=m69ISsCwSTA/typ+M7id5TV1EZw6oA8DarJdVBsPFWWSwOYaDv2mDJ6f3iCZnIG8c9
         Yoel1KleIm0YXFuqZkbg1Oa67cNJ0XJA+E/W4RNGu29KAKEl+AyOBx7wRkBNM7Ej4O/7
         jaDTtsELveWMK2DevQF/kMMQXGqSq63+0K+jiMSkePQyVClpJkYVtTgzkERhwNnWXPNi
         AzeIcYLo6/OAgiT+cCt7M4GR9msd0JMin73/u1ZqF/6xd2Ye90mwkrWIc/ofMVYLyFh7
         IR57SJHVrLtv/Jr6jrewIZpyDiaGOIg+z6pBpkXbftUYJYwudb8Q/IAyH2J1O0C/1NBj
         DM7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXspaIKJBrlaJ95UkMk0/5+Y5rrRLjUO6A6/SORmqP1IN3gJktXNxiheW/BFJGK8Mr7r7y6e7Hm/byAkYtGwovoHJfXE+PnjQ==
X-Gm-Message-State: AOJu0YyGKMlYbff399VcsHGpF0ktVEwe3a0Ea3x407KH1i3etxm7ZObH
	rb7XKaxOBBAPV60SWnoQAW90bckaAHArEZFZPETrB+aMroZfUMaW
X-Google-Smtp-Source: AGHT+IHcVFiZWxK9+fo6/gRc8+DDQ6jScPF55MgQDe94BE8ORAtdOS9w5aRdlkb2+4PxMgY2xs3IgA==
X-Received: by 2002:a05:6e02:216b:b0:366:2e34:a3f5 with SMTP id s11-20020a056e02216b00b003662e34a3f5mr13972659ilv.15.1710294493666;
        Tue, 12 Mar 2024 18:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:dcd:b0:366:592a:fb2f with SMTP id
 l13-20020a056e020dcd00b00366592afb2fls1386757ilj.1.-pod-prod-08-us; Tue, 12
 Mar 2024 18:48:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9k0bKnzdQjgsFt1Q8It/JTh9zf/wvH4ZfooG6sKMP44SpYYKnjsoWAhpkgqOKPuEqt8Nuia6LHamR8auOeSHOhCC1Zo+Bpkz+yw==
X-Received: by 2002:a5d:9ac5:0:b0:7c8:ae3b:acc9 with SMTP id x5-20020a5d9ac5000000b007c8ae3bacc9mr9726955ion.6.1710294492641;
        Tue, 12 Mar 2024 18:48:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710294492; cv=none;
        d=google.com; s=arc-20160816;
        b=B5o9gVAHMhuHcbNeIpj7Pstk385XkdGeaURP5oBWUVqwBGZWLFB2pmKhJ7IxcS9cJs
         5mccW0zU+QPpK/xCbn+Jiz+J9VvvqrZjKm/wmeF/x8kkh51skX4RnntoIaShsenZqhHS
         Q0saSA7MSctNu5faW5T2JgcLOjzy8plOGAeKx2AxLdwlG0m2ejWiGX9iHBt4mVvHE1S7
         +tdxnbSckWzb8/MEhhI4MP4SW1ZR9BquCVlhVXDVRFu3RrUA0X97Y40pfpFIFWHJYLx1
         6PQ15Ar1ORe7B0pmpnW9E3WrUmaGcmooz4C+NZuUVA8E4IbGvyxMuLk9fEBNwrNMlbbr
         K7yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lvDevJgXzZHK+XAuqd2R8EtdQOr26ZP2QO5Xtddz0KA=;
        fh=fWljgm9+YqbXExLhhjJaMZHjcBG6kfUvxRsg8DaaN3o=;
        b=wi+NVy7g6sGGS0T0iCo4i5mdSxN8c6yMjbjJJC4FPKgO9jviOiPqT6Hyy3/9eAenuo
         kofLSf5zEf9FjdVdTbGYcvSUMxfSf6PQAOelzoTrZV+eockbGUEcW8Dtno//sxsn23XE
         uVjfLIOEuxUPsj8w6Kgo6LflukDKyq6sGaX3yewpej8yOuSYJJvYIbhwK2rsgslvQw34
         sz03M0qxDaNFAFh5nRSVLCEX0gIZeZAj7RQUNmjPFNOuZt4FqrvPnLIWD7aI7GwHcnZs
         xfrKOvVbs4gDQpKBWnd1BUKMuHQvtNxGKqFwQLWEf2WS8kP0d3ZOjszkN8KcNtMNVMNE
         eFOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YOBNuMQW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id o22-20020a056638269600b004770c2e6beesi146580jat.5.2024.03.12.18.48.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Mar 2024 18:48:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 42D16FLe009969;
	Wed, 13 Mar 2024 01:48:11 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3wu1au127q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Mar 2024 01:48:11 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 42D1j7Tw030279;
	Wed, 13 Mar 2024 01:48:11 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3wu1au1267-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Mar 2024 01:48:10 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 42CN67Yx018134;
	Wed, 13 Mar 2024 01:41:27 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ws23tb3uj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Mar 2024 01:41:27 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 42D1fN1O30867824
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Mar 2024 01:41:25 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7395520043;
	Wed, 13 Mar 2024 01:41:23 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E069920040;
	Wed, 13 Mar 2024 01:41:22 +0000 (GMT)
Received: from heavy (unknown [9.171.20.188])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Wed, 13 Mar 2024 01:41:22 +0000 (GMT)
Date: Wed, 13 Mar 2024 02:41:21 +0100
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Changbin Du <changbin.du@huawei.com>, elver@google.com
Cc: Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [BUG] kmsan: instrumentation recursion problems
Message-ID: <czcb6tjpfu3ry5j6blzkhw5hg2thfkir7xkxholzqqpnv5pj4f@jtdhzoif5m2q>
References: <20240308043448.masllzeqwht45d4j@M910t>
 <CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA@mail.gmail.com>
 <20240311093036.44txy57hvhevybsu@M910t>
 <20240311110223.nzsplk6a6lzxmzqi@M910t>
 <ndf5znadjpm4mcscns66bhcgvvykmcou3kjkqy54fcvgtvu7th@vpaomrytk4af>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ndf5znadjpm4mcscns66bhcgvvykmcou3kjkqy54fcvgtvu7th@vpaomrytk4af>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: Rn6Ph5G0Y3Tx4t5XLA2Vl-9bR-jX3YyW
X-Proofpoint-GUID: iF5gmBX_HbtGdM5hh3iUteh4JaUI99NA
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-03-12_14,2024-03-12_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 spamscore=0 lowpriorityscore=0 malwarescore=0 adultscore=0 clxscore=1015
 bulkscore=0 mlxscore=0 impostorscore=0 mlxlogscore=999 phishscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2403130012
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YOBNuMQW;       spf=pass (google.com:
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

On Wed, Mar 13, 2024 at 12:52:33AM +0100, Ilya Leoshkevich wrote:
> On Mon, Mar 11, 2024 at 07:02:23PM +0800, Changbin Du wrote:
> > On Mon, Mar 11, 2024 at 05:30:36PM +0800, Changbin Du wrote:
> > > On Fri, Mar 08, 2024 at 10:39:15AM +0100, Marco Elver wrote:
> > > > On Fri, 8 Mar 2024 at 05:36, 'Changbin Du' via kasan-dev
> > > > <kasan-dev@googlegroups.com> wrote:
> > > > >
> > > > > Hey, folks,
> > > > > I found two instrumentation recursion issues on mainline kernel.
> > > > >
> > > > > 1. recur on preempt count.
> > > > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> preempt_disable() -> __msan_metadata_ptr_for_load_4()
> > > > >
> > > > > 2. recur in lockdep and rcu
> > > > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> pfn_valid() -> rcu_read_lock_sched() -> lock_acquire() -> rcu_is_watching() -> __msan_metadata_ptr_for_load_8()
> > > > >
> > > > >
> > > > > Here is an unofficial fix, I don't know if it will generate false reports.
> > > > >
> > > > > $ git show
> > > > > commit 7f0120b621c1cbb667822b0f7eb89f3c25868509 (HEAD -> master)
> > > > > Author: Changbin Du <changbin.du@huawei.com>
> > > > > Date:   Fri Mar 8 20:21:48 2024 +0800
> > > > >
> > > > >     kmsan: fix instrumentation recursions
> > > > >
> > > > >     Signed-off-by: Changbin Du <changbin.du@huawei.com>
> > > > >
> > > > > diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> > > > > index 0db4093d17b8..ea925731fa40 100644
> > > > > --- a/kernel/locking/Makefile
> > > > > +++ b/kernel/locking/Makefile
> > > > > @@ -7,6 +7,7 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
> > > > >
> > > > >  # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> > > > >  KCSAN_SANITIZE_lockdep.o := n
> > > > > +KMSAN_SANITIZE_lockdep.o := n
> > > > 
> > > > This does not result in false positives?
> > > >
> > This does result lots of false positives.
> > 
> > > I saw a lot of reports but seems not related to this.
> > > 
> > > [    2.742743][    T0] BUG: KMSAN: uninit-value in unwind_next_frame+0x3729/0x48a0
> > > [    2.744404][    T0]  unwind_next_frame+0x3729/0x48a0
> > > [    2.745623][    T0]  arch_stack_walk+0x1d9/0x2a0
> > > [    2.746838][    T0]  stack_trace_save+0xb8/0x100
> > > [    2.747928][    T0]  set_track_prepare+0x88/0x120
> > > [    2.749095][    T0]  __alloc_object+0x602/0xbe0
> > > [    2.750200][    T0]  __create_object+0x3f/0x4e0
> > > [    2.751332][    T0]  pcpu_alloc+0x1e18/0x2b00
> > > [    2.752401][    T0]  mm_init+0x688/0xb20
> > > [    2.753436][    T0]  mm_alloc+0xf4/0x180
> > > [    2.754510][    T0]  poking_init+0x50/0x500
> > > [    2.755594][    T0]  start_kernel+0x3b0/0xbf0
> > > [    2.756724][    T0]  __pfx_reserve_bios_regions+0x0/0x10
> > > [    2.758073][    T0]  x86_64_start_kernel+0x92/0xa0
> > > [    2.759320][    T0]  secondary_startup_64_no_verify+0x176/0x17b
> > > 
> > Above reports are triggered by KMEMLEAK and KFENCE.
> > 
> > Now with below fix, I was able to run kmsan kernel with:
> >   CONFIG_DEBUG_KMEMLEAK=n
> >   CONFIG_KFENCE=n
> >   CONFIG_LOCKDEP=n
> > 
> > KMEMLEAK and KFENCE generate too many false positives in unwinding code.
> > LOCKDEP still introduces instrumenting recursions.
> 
> FWIW I see the same issue on s390, and the best I could come up with so
> far was also disabling lockdep.
> 
> For KFENCE I have the following [1] though, maybe this will be helpful
> to you as well?
> 
> [1] https://patchwork.kernel.org/project/linux-mm/patch/20231213233605.661251-17-iii@linux.ibm.com/
> 
> [...]

So, I tried to brute force the issue and came up with the following.
The goal was to minimize the usage of __no_sanitize_memory in order to
avoid false positives. I don't propose to commit this, I'm posting this
to highlight the intermediate problems that need to be solved.



From e3834f4e4ebe2596542a7464f8cc487e2c8e37c9 Mon Sep 17 00:00:00 2001
From: Ilya Leoshkevich <iii@linux.ibm.com>
Date: Wed, 13 Mar 2024 01:18:22 +0100
Subject: [PATCH] s390/kmsan: Fix lockdep recursion

After commit 5ec8e8ea8b77 ("mm/sparsemem: fix race in accessing
memory_section->usage"), an infinite mutual recursion between
kmsan_get_metadata() and lock_acquire() arose.

Teach lockdep recursion detection to handle it. The goal is to make
lock_acquire() survive until lockdep_recursion_inc(). This requires
solving a number of intermediate problems:

0. Disable KMSAN checks in lock_acquire().

1. lock_acquire() calls instrumented trace_lock_acquire().
   Force inlining.

2. trace_lock_acquire() calls instrumented cpu_online().
   Force inlining.

3: trace_lock_acquire() calls instrumented rcu_is_watching(), which in
   turn calls instrumented __preempt_count_add().
   Disable instrumentation in rcu_is_watching().
   Disabling checks is not enough, because __preempt_count_add() would
   call __msan_instrument_asm_store().
   Force inlinining of __preempt_count_add().

4: lock_acquire() inlines lockdep_enabled(), which inlines
   __preempt_count_add(), which calls __msan_instrument_asm_store().
   Don't inline lockdep_enabled() and disable KMSAN instrumentation in it.

5: lock_acquire() calls check_flags(), which calls the instrumented
   preempt_count().
   Always inline preempt_count().

6: lock_acquire() inlines lockdep_recursion_inc(), which needs to
   update KMSAN metadata.
   Do not inline lockdep_recursion_inc(), disable KMSAN instrumentation
   in it.

7: lock_acquire() calls instrumented lockdep_nmi().
   Force inlining.

With that, the KMSAN+lockdep kernel boots again, but unfortunately it
is very slow.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/preempt.h | 12 ++++++------
 include/linux/cpumask.h         |  2 +-
 include/linux/tracepoint.h      |  2 +-
 kernel/locking/lockdep.c        | 10 +++++++---
 kernel/rcu/tree.c               |  1 +
 5 files changed, 16 insertions(+), 11 deletions(-)

diff --git a/arch/s390/include/asm/preempt.h b/arch/s390/include/asm/preempt.h
index bf15da0fedbc..225ce14bb0d6 100644
--- a/arch/s390/include/asm/preempt.h
+++ b/arch/s390/include/asm/preempt.h
@@ -12,7 +12,7 @@
 #define PREEMPT_NEED_RESCHED	0x80000000
 #define PREEMPT_ENABLED	(0 + PREEMPT_NEED_RESCHED)
 
-static inline int preempt_count(void)
+static __always_inline int preempt_count(void)
 {
 	return READ_ONCE(S390_lowcore.preempt_count) & ~PREEMPT_NEED_RESCHED;
 }
@@ -44,7 +44,7 @@ static inline bool test_preempt_need_resched(void)
 	return !(READ_ONCE(S390_lowcore.preempt_count) & PREEMPT_NEED_RESCHED);
 }
 
-static inline void __preempt_count_add(int val)
+static __always_inline void __preempt_count_add(int val)
 {
 	/*
 	 * With some obscure config options and CONFIG_PROFILE_ALL_BRANCHES
@@ -59,7 +59,7 @@ static inline void __preempt_count_add(int val)
 	__atomic_add(val, &S390_lowcore.preempt_count);
 }
 
-static inline void __preempt_count_sub(int val)
+static __always_inline void __preempt_count_sub(int val)
 {
 	__preempt_count_add(-val);
 }
@@ -79,7 +79,7 @@ static inline bool should_resched(int preempt_offset)
 
 #define PREEMPT_ENABLED	(0)
 
-static inline int preempt_count(void)
+static __always_inline int preempt_count(void)
 {
 	return READ_ONCE(S390_lowcore.preempt_count);
 }
@@ -102,12 +102,12 @@ static inline bool test_preempt_need_resched(void)
 	return false;
 }
 
-static inline void __preempt_count_add(int val)
+static __always_inline void __preempt_count_add(int val)
 {
 	S390_lowcore.preempt_count += val;
 }
 
-static inline void __preempt_count_sub(int val)
+static __always_inline void __preempt_count_sub(int val)
 {
 	S390_lowcore.preempt_count -= val;
 }
diff --git a/include/linux/cpumask.h b/include/linux/cpumask.h
index cfb545841a2c..af6515e5def8 100644
--- a/include/linux/cpumask.h
+++ b/include/linux/cpumask.h
@@ -1099,7 +1099,7 @@ static __always_inline unsigned int num_online_cpus(void)
 #define num_present_cpus()	cpumask_weight(cpu_present_mask)
 #define num_active_cpus()	cpumask_weight(cpu_active_mask)
 
-static inline bool cpu_online(unsigned int cpu)
+static __always_inline bool cpu_online(unsigned int cpu)
 {
 	return cpumask_test_cpu(cpu, cpu_online_mask);
 }
diff --git a/include/linux/tracepoint.h b/include/linux/tracepoint.h
index 88c0ba623ee6..34bc35aa2f4b 100644
--- a/include/linux/tracepoint.h
+++ b/include/linux/tracepoint.h
@@ -252,7 +252,7 @@ static inline struct tracepoint *tracepoint_ptr_deref(tracepoint_ptr_t *p)
 	extern int __traceiter_##name(data_proto);			\
 	DECLARE_STATIC_CALL(tp_func_##name, __traceiter_##name);	\
 	extern struct tracepoint __tracepoint_##name;			\
-	static inline void trace_##name(proto)				\
+	static __always_inline void trace_##name(proto)			\
 	{								\
 		if (static_key_false(&__tracepoint_##name.key))		\
 			__DO_TRACE(name,				\
diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 151bd3de5936..86244a7e8533 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -111,7 +111,8 @@ late_initcall(kernel_lockdep_sysctls_init);
 DEFINE_PER_CPU(unsigned int, lockdep_recursion);
 EXPORT_PER_CPU_SYMBOL_GPL(lockdep_recursion);
 
-static __always_inline bool lockdep_enabled(void)
+__no_sanitize_memory
+static noinline bool lockdep_enabled(void)
 {
 	if (!debug_locks)
 		return false;
@@ -457,7 +458,8 @@ void lockdep_init_task(struct task_struct *task)
 	task->lockdep_recursion = 0;
 }
 
-static __always_inline void lockdep_recursion_inc(void)
+__no_sanitize_memory
+static noinline void lockdep_recursion_inc(void)
 {
 	__this_cpu_inc(lockdep_recursion);
 }
@@ -5687,7 +5689,7 @@ static void verify_lock_unused(struct lockdep_map *lock, struct held_lock *hlock
 #endif
 }
 
-static bool lockdep_nmi(void)
+static __always_inline bool lockdep_nmi(void)
 {
 	if (raw_cpu_read(lockdep_recursion))
 		return false;
@@ -5716,6 +5718,7 @@ EXPORT_SYMBOL_GPL(read_lock_is_recursive);
  * We are not always called with irqs disabled - do that here,
  * and also avoid lockdep recursion:
  */
+__no_kmsan_checks
 void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
 			  int trylock, int read, int check,
 			  struct lockdep_map *nest_lock, unsigned long ip)
@@ -5758,6 +5761,7 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
 }
 EXPORT_SYMBOL_GPL(lock_acquire);
 
+__no_kmsan_checks
 void lock_release(struct lockdep_map *lock, unsigned long ip)
 {
 	unsigned long flags;
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index d9642dd06c25..8c587627618e 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -692,6 +692,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
  * Make notrace because it can be called by the internal functions of
  * ftrace, and making this notrace removes unnecessary recursion calls.
  */
+__no_sanitize_memory
 notrace bool rcu_is_watching(void)
 {
 	bool ret;
-- 
2.44.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/czcb6tjpfu3ry5j6blzkhw5hg2thfkir7xkxholzqqpnv5pj4f%40jtdhzoif5m2q.
