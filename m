Return-Path: <kasan-dev+bncBCVZXJXP4MDBBH4M5DAAMGQEC5SROZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B434AAC49F
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 14:52:49 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4769a1db721sf146382131cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 06 May 2025 05:52:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746535968; cv=pass;
        d=google.com; s=arc-20240605;
        b=h5LawWib4n4+2RAxiLjroI2t4kQoVq9qUPHs5E44853y5X+BJ3Lve9FuwPEIfjhbKX
         zPgZwswEndBvwr19sJpAGqfdSwamc2AH+6iC6/uYe1xp1c3Bx3LZ95ptzPOCGkT/U78X
         eSfgUMdM9hUnu+AkBB6wvXYYYUr2FX5ZjHHpVNiQiO/Vl3YwjJECBRl84CvjZ/SJUg6q
         5/WbKdc+GMUrb0ggGMkq12UZW9+a238O1ia7hC4sm8bBz21fj5pgL3TMM2br8ziTadAz
         pWB5B4fkGP+eQYGVdOu6eDMGQEbkJbwR3ljv2Lggv/M5FPBCT6tpGZ+TL0sR8j531RYz
         3Xnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TEx43DcPxdjQ+pb94H3IXv61lKbRzMKZ7urHpPnG5KA=;
        fh=+VmJJJrEJDFAfdL4twBYuuO41/bnyHD3zyq+Kb1TNrY=;
        b=A3xhcEq01L8GF+f+AkBHTqiwFE0IKP10o0nGaKqs92mamLML6WHnagyEKV+0rGomKP
         kf9z6bzYTsyGzj3GDIf7+HQ7wcTvzI1pzdV/126/b7y+Xmzk37Yv08cIIfVp4eN87BJQ
         IuM8lrLM+QrAosCm0C6+iSF4+ZZw73iZVBzTmViJqZ2CWZMlhpZni8eNuMx5uTV5one9
         T62iq5zoZWIt1XYfGoY+Jasqj9A9uicB9AGnTrbi4f9gZhEaoJjzOTttHAfDPmpr+/Fs
         esHw11cu8RxX0udn4kKmskB9S4Vtuc7fYDd+pu09GXVi8VqGL4Pd1BbiOfih61eJKe6k
         V+Mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YV75fVWt;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746535968; x=1747140768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TEx43DcPxdjQ+pb94H3IXv61lKbRzMKZ7urHpPnG5KA=;
        b=IAQkUWMcS+tua7uN3MvnvjlHi2Cw/Avl09gzIAemcQald6QuI90+Hi30WKiDezfRpL
         1tyut1NUu6TFO4OLGuoihgE4hdERpTNbdsJBWqNSXsmQdK+mc9RWWKTuHzHzIKwxaIV5
         vVKT/g1zuvXarSQzacoIps2yi9rihJldT+WYXTqSgQFPolyiMjtyiI/32Hn0OWRqQydK
         StKRU2VW6weZe53cq2l2vjpsLM8/3XOylSCQVYMUAmHQSMcUvT/YLBFt4zmlie1yXmxc
         QhgNOw8Q8C72EAlk7/xuhI7IfaiRPXQUnygC09TNUblpwWLm2iRbFbT9FYeCbRPSNNY1
         /Osw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746535968; x=1747140768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TEx43DcPxdjQ+pb94H3IXv61lKbRzMKZ7urHpPnG5KA=;
        b=RxfPsi6MM70vdhpCSXa271ecaLwO/Hf37WBk33MaNY+/qmiL7bt7HlyabPcCI65Ksd
         8Bpzu26n//goC7zq9DGH2e4in+W7XRdaKlDB8Onawk16Hs1/+7L52TqXxMtGJx/MIDw3
         uxqQoRjBxhj/f394RMWxqt/TP+PqdbOw5/HrIQagc2io8+KSFjV485o211KjXnDPvAKx
         3wFpvQU9fCFZ8qmo4PZ3zWaHE9veIwaAIOW8v9CkXqD+RX50sAeWteF0RON9SMsLo0TB
         7RJtd2OuVrHhKCLbtpPwY9R3LCjj8MjEX6BVSj9GkFHpCAokyLRiTP6F5QGNE5JE14lN
         VwLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUB9fs+kAk9T/aB0kBS7USSjGm431ta5ztxwmSPaexXMze/QNHR60y2TyL9iCgWAphFre/7QA==@lfdr.de
X-Gm-Message-State: AOJu0YxhVs4p61Paot1XL+r4jfAZq366kbINfAcXU4QTHok43tGZ8vEK
	MUGgvjmRNu3WHsSrAjrwmwB8FySjImz/Qu1gmy4cgJ74qoBM5tq0
X-Google-Smtp-Source: AGHT+IHNuGRrbTZAT2UXmCozfZdOFvLvuUm/zCvSH9kDCM1ri4/lSL9FGCi0rNZ7yaDx3XWdGBGySA==
X-Received: by 2002:a05:622a:1b07:b0:490:8ffd:8f02 with SMTP id d75a77b69052e-490f2c8b6b0mr61913321cf.37.1746535967782;
        Tue, 06 May 2025 05:52:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH3bCzBJ+m4/N03huM26C2JEzfz45lDmXRRbRxrMmSQwA==
Received: by 2002:a05:622a:4787:b0:47e:c50e:95f6 with SMTP id
 d75a77b69052e-48ad89a123fls76592911cf.1.-pod-prod-06-us; Tue, 06 May 2025
 05:52:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZz5wk6uSe4KC1iMf9iC2nH0xv7Om0iKUC6g527Vsg5S09vLfaBdIXLWWcmbcmNZ0G0u4SlfE4nB0=@googlegroups.com
X-Received: by 2002:a05:622a:288:b0:472:1aed:c8b4 with SMTP id d75a77b69052e-490f2d817d5mr49718981cf.34.1746535966487;
        Tue, 06 May 2025 05:52:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746535966; cv=none;
        d=google.com; s=arc-20240605;
        b=BvxbBf6RwQzCylCt1zPZahCuLgQ+K0wU0r3r90C2FRHh1LeK8BtnoOnmQ+SBVcfdVg
         uk30/Md8JKkysKd9nFBrigK2u2JpAADT8vqQ3fSgKyGHd5MshlHnI5tGRndg4hhkCTEa
         DZChF/zF7dfqje/T1QMbtE69tRa6YJOuJG8yRe90Gtv/76gj0FAe1HlZHA1CvTzkOtjV
         oJThQWmdnRSB1sX9w5LXw3EWrYHWVkcawKY0/O/j7wX87iT2zjoyQS0QOlpGCw5kVPyE
         qWdkc66b6DB9Hm9+NcwepU8t6+s3PTeRHaY7W9QNStzPjouk6KgVl+EtbU0Yh8y2+VIa
         nK4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vf/iktNQ2AmPr6Q+t9oVj3VwPkiNre+eTtQgMcG2xLo=;
        fh=UDdBOzNKXZ7Naie7WIjvPNKc6E4DKPCddYGjM4WKApE=;
        b=cb4JLfUqcIPSc2hQ9VpludXh2ltG8xo4i2W5awG4XcwO2EHZ9WOyKjukhQe0rS+7nW
         ZqmzWnNfSETdUM1L0j0lscB+l20m9lcz7Ukva5inH0iDHzVWnpjNPnZsSwoZWKEBkl5s
         hyXd54TlLtGDmVm7BG4trdUxYgRE/fBV9zd+CG1SV76ttVo1vkoRo8lhnw7EBGbOTY3/
         olFiAir+xr/IXYHW4GUfBDfdkzlDVWv+aIe7TTIIH1ty6j58hln/BSRuxHVl1Cx8IBaW
         F880dJn0zLePFMrAftcM8/MHBHqlYWR82nU+tdZYP6nzYFL51qkEXG9th0hc/BGCbfuL
         7Z2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YV75fVWt;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-48b98a267c2si125421cf.5.2025.05.06.05.52.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 May 2025 05:52:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 546A4LD5010869;
	Tue, 6 May 2025 12:52:44 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fgbj8qtq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 12:52:44 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 546CcINK023452;
	Tue, 6 May 2025 12:52:43 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fgbj8qtm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 12:52:43 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 546Clu3q025798;
	Tue, 6 May 2025 12:52:42 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46dwuyukcb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 12:52:42 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 546CqetV31392038
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 6 May 2025 12:52:40 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 318F520049;
	Tue,  6 May 2025 12:52:40 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F1B9D20040;
	Tue,  6 May 2025 12:52:39 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  6 May 2025 12:52:39 +0000 (GMT)
Date: Tue, 6 May 2025 14:52:38 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aBoGFr5EaHFfxuON@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1745940843.git.agordeev@linux.ibm.com>
 <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
 <aBFbCP9TqNN0bGpB@harry>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aBFbCP9TqNN0bGpB@harry>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 4mfBGix7teZnrAIMT1_J1PZGjukJuupJ
X-Proofpoint-GUID: r_eyKJ4ve2-qsexXr878tGFbuP5SgN2y
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA2MDEyMSBTYWx0ZWRfX1DxlGgzeC0aF JQ/5DcOy3odI/Dd+ROZjOyED+46ICWdau37TqDtYWEofa6iLl3mpgmzHOoYuoNr3WJUq0V02aru gCZ133BgoUazqXZS4HQ51IyN7PxIvUObSwXH5Y5p1I76B5eFNVnyGkLG3x4G/3Kd1i/eGt4IT0Z
 trK35FPPLh2Ao3pEtwq1Ag3GVH/6+bMjXbYgPxjy43BrnXwBSXwYX5irW17UInf6nwnAff/SMue X+PvIPh+YLYQppXVPuLlmy/rinOGUhALTsMPKJne9twXgzH1h1UAoG1XzaJ+KUqDKbcIFTAQCGY c/vifDFNr24bTXfYTqnoNpibUtGYhRi31EuhOhYt3N8wLlsImmMc/cNtDxGLs+/BM260qJ7Jjpd
 oDVx19qIncXAMtAXcoJMvczC+N+1Z7j+KBLP8RVZLK3CM1Dude0tdVlsgKsL4rfRu9OoloD1
X-Authority-Analysis: v=2.4 cv=FJcbx/os c=1 sm=1 tr=0 ts=681a061c cx=c_pps a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=VwQbUJbxAAAA:8 a=7CQSdrXTAAAA:8 a=pGLkceISAAAA:8 a=VnNF1IyMAAAA:8
 a=-ziGmjT95ElobUBgwqYA:9 a=CjuIK1q_8ugA:10 a=a-qgeE7W1pNrGK8U0ZQC:22
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-06_05,2025-05-05_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 mlxlogscore=679 phishscore=0 impostorscore=0 suspectscore=0 mlxscore=0
 malwarescore=0 lowpriorityscore=0 clxscore=1011 bulkscore=0 adultscore=0
 spamscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505060121
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YV75fVWt;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
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

On Wed, Apr 30, 2025 at 08:04:40AM +0900, Harry Yoo wrote:

Hi Harry,

> On Tue, Apr 29, 2025 at 06:08:41PM +0200, Alexander Gordeev wrote:
> > apply_to_pte_range() enters the lazy MMU mode and then invokes
> > kasan_populate_vmalloc_pte() callback on each page table walk
> > iteration. However, the callback can go into sleep when trying
> > to allocate a single page, e.g. if an architecutre disables
> > preemption on lazy MMU mode enter.
> 
> Should we add a comment that pte_fn_t must not sleep in
> apply_to_pte_range()?

See the comment in include/linux/pgtable.h

"In the general case, no lock is guaranteed to be held between entry and exit 
of the lazy mode. So the implementation must assume preemption may be enabled
and cpu migration is possible; it must take steps to be robust against this.
(In practice, for user PTE updates, the appropriate page table lock(s) are   
held, but for kernel PTE updates, no lock is held)."

It is Ryan Roberts who brougth some order [1] here, but I would go further
and make things simple by enforcing the kernel PTE updates should also assume
the preemption is disabled.

But that is a separate topic and could only be done once this patch is in.

> > On s390 if make arch_enter_lazy_mmu_mode() -> preempt_enable()
> > and arch_leave_lazy_mmu_mode() -> preempt_disable(), such crash
> > occurs:
> > 
> >     [  553.332108] preempt_count: 1, expected: 0
> >     [  553.332117] no locks held by multipathd/2116.
> >     [  553.332128] CPU: 24 PID: 2116 Comm: multipathd Kdump: loaded Tainted:
> >     [  553.332139] Hardware name: IBM 3931 A01 701 (LPAR)
> >     [  553.332146] Call Trace:
> >     [  553.332152]  [<00000000158de23a>] dump_stack_lvl+0xfa/0x150
> >     [  553.332167]  [<0000000013e10d12>] __might_resched+0x57a/0x5e8
> >     [  553.332178]  [<00000000144eb6c2>] __alloc_pages+0x2ba/0x7c0
> >     [  553.332189]  [<00000000144d5cdc>] __get_free_pages+0x2c/0x88
> >     [  553.332198]  [<00000000145663f6>] kasan_populate_vmalloc_pte+0x4e/0x110
> >     [  553.332207]  [<000000001447625c>] apply_to_pte_range+0x164/0x3c8
> >     [  553.332218]  [<000000001448125a>] apply_to_pmd_range+0xda/0x318
> >     [  553.332226]  [<000000001448181c>] __apply_to_page_range+0x384/0x768
> >     [  553.332233]  [<0000000014481c28>] apply_to_page_range+0x28/0x38
> >     [  553.332241]  [<00000000145665da>] kasan_populate_vmalloc+0x82/0x98
> >     [  553.332249]  [<00000000144c88d0>] alloc_vmap_area+0x590/0x1c90
> >     [  553.332257]  [<00000000144ca108>] __get_vm_area_node.constprop.0+0x138/0x260
> >     [  553.332265]  [<00000000144d17fc>] __vmalloc_node_range+0x134/0x360
> >     [  553.332274]  [<0000000013d5dbf2>] alloc_thread_stack_node+0x112/0x378
> >     [  553.332284]  [<0000000013d62726>] dup_task_struct+0x66/0x430
> >     [  553.332293]  [<0000000013d63962>] copy_process+0x432/0x4b80
> >     [  553.332302]  [<0000000013d68300>] kernel_clone+0xf0/0x7d0
> >     [  553.332311]  [<0000000013d68bd6>] __do_sys_clone+0xae/0xc8
> >     [  553.332400]  [<0000000013d68dee>] __s390x_sys_clone+0xd6/0x118
> >     [  553.332410]  [<0000000013c9d34c>] do_syscall+0x22c/0x328
> >     [  553.332419]  [<00000000158e7366>] __do_syscall+0xce/0xf0
> >     [  553.332428]  [<0000000015913260>] system_call+0x70/0x98
> > 
> > Instead of allocating single pages per-PTE, bulk-allocate the
> > shadow memory prior to applying kasan_populate_vmalloc_pte()
> > callback on a page range.
> >
> > Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: stable@vger.kernel.org
> > Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> > 
> > Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> > ---
> >  mm/kasan/shadow.c | 65 +++++++++++++++++++++++++++++++++++------------
> >  1 file changed, 49 insertions(+), 16 deletions(-)
> > 
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index 88d1c9dcb507..ea9a06715a81 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -292,30 +292,65 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> >  {
> >  }
> >  
> > +struct vmalloc_populate_data {
> > +	unsigned long start;
> > +	struct page **pages;
> > +};
> > +
> >  static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> > -				      void *unused)
> > +				      void *_data)
> >  {
> > -	unsigned long page;
> > +	struct vmalloc_populate_data *data = _data;
> > +	struct page *page;
> > +	unsigned long pfn;
> >  	pte_t pte;
> >  
> >  	if (likely(!pte_none(ptep_get(ptep))))
> >  		return 0;
> >  
> > -	page = __get_free_page(GFP_KERNEL);
> > -	if (!page)
> > -		return -ENOMEM;
> > -
> > -	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> > -	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> > +	page = data->pages[PFN_DOWN(addr - data->start)];
> > +	pfn = page_to_pfn(page);
> > +	__memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
> > +	pte = pfn_pte(pfn, PAGE_KERNEL);
> >  
> >  	spin_lock(&init_mm.page_table_lock);
> > -	if (likely(pte_none(ptep_get(ptep)))) {
> > +	if (likely(pte_none(ptep_get(ptep))))
> >  		set_pte_at(&init_mm, addr, ptep, pte);
> > -		page = 0;
> 
> With this patch, now if the pte is already set, the page is leaked?

Yes. But currently it is leaked for previously allocated pages anyway,
so no change in behaviour (unless I misread the code).

> Should we set data->pages[PFN_DOWN(addr - data->start)] = NULL 
> and free non-null elements later in __kasan_populate_vmalloc()?

Should the allocation fail on boot, the kernel would not fly anyway.
If for whatever reason we want to free, that should be a follow-up
change, as far as I am concerned.

> > -	}
> >  	spin_unlock(&init_mm.page_table_lock);
> > -	if (page)
> > -		free_page(page);
> > +
> > +	return 0;
> > +}
> > +
> > +static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
> > +{
> > +	unsigned long nr_pages, nr_total = PFN_UP(end - start);
> > +	struct vmalloc_populate_data data;
> > +	int ret;
> > +
> > +	data.pages = (struct page **)__get_free_page(GFP_KERNEL);
> > +	if (!data.pages)
> > +		return -ENOMEM;
> > +
> > +	while (nr_total) {
> > +		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
> > +		__memset(data.pages, 0, nr_pages * sizeof(data.pages[0]));
> > +		if (nr_pages != alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages)) {
> 
> When the return value of alloc_pages_bulk() is less than nr_pages,
> you still need to free pages in the array unless nr_pages is zero.

Same reasoning for not to free as above.

> > +			free_page((unsigned long)data.pages);
> > +			return -ENOMEM;
> > +		}
> > +
> > +		data.start = start;
> > +		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
> > +					  kasan_populate_vmalloc_pte, &data);
> > +		if (ret)
> > +			return ret;
> > +
> > +		start += nr_pages * PAGE_SIZE;
> > +		nr_total -= nr_pages;
> > +	}
> > +
> > +	free_page((unsigned long)data.pages);
> > +
> >  	return 0;
> >  }
> >  
> > @@ -348,9 +383,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> >  	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
> >  	shadow_end = PAGE_ALIGN(shadow_end);
> >  
> > -	ret = apply_to_page_range(&init_mm, shadow_start,
> > -				  shadow_end - shadow_start,
> > -				  kasan_populate_vmalloc_pte, NULL);
> > +	ret = __kasan_populate_vmalloc(shadow_start, shadow_end);
> >  	if (ret)
> >  		return ret;
> >  
> > -- 
> > 2.45.2
> > 
> > 

1. https://lore.kernel.org/all/20250303141542.3371656-2-ryan.roberts@arm.com/#t

> -- 
> Cheers,
> Harry / Hyeonggon

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBoGFr5EaHFfxuON%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
