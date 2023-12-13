Return-Path: <kasan-dev+bncBCM3H26GVIOBB2EO46VQMGQE3N2TUEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 82C4E81157E
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:02:01 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4258d33d5f4sf59794491cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 07:02:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702479720; cv=pass;
        d=google.com; s=arc-20160816;
        b=yjVtGQr7lF68oO0GnWfJMTU2PSznM+xkGZOlJ4CskIpZMBcSe9qHQtN0+WHX1Ql9wd
         g+hZd+aKwt142KllwZsmqNNHSzmzoDrKLEDsqRFjp5HVgqBD/4pTY3tP6hOaZTzVOti6
         WYzCt7OARIGLtz2+tvB6haZkFMhHFEZ0X9afamx4S/PF7dAuVZBoHr5iyOcewBsOFtxk
         B+QozjXI0XhKN+tKXeJSi5LMzo7Rjye4CAi2dP78/kFsxVm0idb1ql9QxHdSuVIQSTW9
         w/VD76DrEpBGx+C/9gZQPTt+blNun0hnKTtsyCiX6lHGP1WTXLG34S3hgF23MYB7EBhE
         v/fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=gXCuWWuU/LH9uFnAh3idehMYpF6qJXPj1pjA2qvOiA8=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=VqWxYbhHEa241fnyAbFg402WdBDi+C8vH2pxbCD9BQc5ZB8XpWGc3teFcLs0x5Jmcz
         SJPfCAGR+J869hU2xu+vdvWAEr3VhR27kh9eUQUpThxQsjr3uQlV1bJtFumKOt9YTtY9
         FPdqmA6D/X2Le7zo4xTA27jdI8J36jVzS13QDVpXt8JYtUNChmjCOveyqt/BB+DmTx0+
         6Dnto0dZ7t9TRLYNLYorZGSSh8OWEtHfexC3oIPwbnUel4HXy/bEzkaVs4+7+w0L7o3h
         DnFd/SYu9Y0Dt6tIRBKvFaNr32ertsTA3p/1F2N7vkTls+aIeuT39oI4lEIJM7i3OhEV
         wneQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aE87hCYr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702479720; x=1703084520; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gXCuWWuU/LH9uFnAh3idehMYpF6qJXPj1pjA2qvOiA8=;
        b=kGvkKk/JgfrFv2phMx4MzHQCStHi6Tec9J5LnJZ5ftgkRH3qzdGyKL80nqFQ4S4XWh
         W6yzlx7BxV4d0hIxQ1PIVl+lrDpqa8XaVUCPxrA+piUFlzU0CDI8qjshy2FS0JS8T4Li
         yuQ6DukwZRn2rDb/TraZUOpYOIYemkYRach79wbezaCieq0ireGelGn7U/Ja6KoexN7/
         0ozOQGGKgSnRwl7xCoMJahqkwXpmx670OX0gih5l+GG4oeZX0KtMro2iBzQHOLs/fg5W
         Tx+3+8ESKUnUhIJkaf2KA/gL0hoojn6OoCJG0VwfVrsSxkAWXHyxJtL7rfP4y0q9wBbQ
         Eegw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702479720; x=1703084520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gXCuWWuU/LH9uFnAh3idehMYpF6qJXPj1pjA2qvOiA8=;
        b=SJpIamgIizyxGyqpjMIzSxJ2T7Zim5fragkZf6M+ca0eFkxoWIRjZxHdz/rCHrooyd
         txhee9Q9mnSZCf1q/lrQh6cQwUwp+Cd6jh27r/M+6/3v3+JoU6rtNHpMr38QuOlLp3+r
         UBWDzo8UcEbt+EqarhbmWWuU2FtruqqrkORpfXwskggtSPMV/J+qkwLhslbr4MBOig2I
         E9Q7ls2DUrBVkCDq0mqxypbmfauGjRagw6gXAPyBWcrZ/xU3Y8ZKNmfC3rH4R9JFzbH+
         CK4VVp4buh4RveRPcoiYumP/JGLwljOc32+ExhFaKzFU8om/KgDrogRJPAM6nfnIVVh3
         MVrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxoJHLfliuznLoJBlHlFoDG9YFAHRpKpObdQ0nU64M/MkVj+GJC
	l7MAT42zMVNgt/gHED1wx/Q=
X-Google-Smtp-Source: AGHT+IGFE1a5i/2uriJO3oybyuFdZoQU2EmcFqn3qcQC5R0SJ3yBTHkSpgOEOdB0SpfEvOGrkRuOkw==
X-Received: by 2002:a05:622a:341:b0:425:4043:8d36 with SMTP id r1-20020a05622a034100b0042540438d36mr6936269qtw.81.1702479720168;
        Wed, 13 Dec 2023 07:02:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1815:b0:423:7e09:4f05 with SMTP id
 t21-20020a05622a181500b004237e094f05ls288261qtc.2.-pod-prod-08-us; Wed, 13
 Dec 2023 07:01:59 -0800 (PST)
X-Received: by 2002:a05:620a:571:b0:77d:bbb7:4690 with SMTP id p17-20020a05620a057100b0077dbbb74690mr4851086qkp.12.1702479719040;
        Wed, 13 Dec 2023 07:01:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702479719; cv=none;
        d=google.com; s=arc-20160816;
        b=KKFXhTBC7Wlb76uBBDS/WeScJQAhRD5A5uGrYtZsVkMW+eyyJpMGYFS3+HaQaV/OP9
         7YZFPEIbcH4escH3ufP4JFEIkNNTIbNc6/WDlO3vyGLQyafWd+sUBcqMoIaoyjDM1j6b
         qwEQnVu7S3bfhKWdTNSlW8YP3SAywFMTHjXWU36DT/RBCFvvRwUcPKVV56PpwJ394TIO
         +hCi7ZVcyssyHDdLBOJDfUylcjBwcpWLnErI7qgL2N5DLvDVtQqdTSZ+s4DZEjgCJVBN
         FvfMh3LLYLRbsdzlGOS3xyt7jKm0He2lR4sUKwVhX2Z2ezCxiyQRHh0/ASyZPdBBTZi8
         Co1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=WUqGMWDQsotOfJsdMdUdUke3R0PN1jxvlT3CqFRehkM=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=JEcmrfBJj1hFttS65Z1/aw4cApGo8R/YSFOI3eK9lGdOcXsqANf4/fE+pSAR10Rdrn
         MmhQUDok2bYWTnj2e8jLaEJy3TUbj5ju7ht56PPLGSHYyMh/O8SbiVsMP2g5LMvQosdq
         IWL4o9xPImV+3W3XB9wp/EJ0tkUNKSat2xRlz0OAnDrTcUXu/huD2YaiwCGvZB/mI4b2
         fpAPD8R1JVZvZxIIpJ3xCrI6lwKDsJtTyuYaTQQYtOuIRcOaPOL2zm58Y7OnHXiyAgsx
         BqJdRlPWtU8i0ZiG+hEFOR1z6C9c/9H+hbDfjL5WnLUwxG+Mx0MyHcM2DcByn9e/grDC
         KASQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aE87hCYr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ss11-20020a05620a3acb00b0077f0dcac143si96150qkn.6.2023.12.13.07.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 07:01:58 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDELKdC022454;
	Wed, 13 Dec 2023 15:01:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyd9qb1rw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 15:01:52 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDELZV8024068;
	Wed, 13 Dec 2023 15:01:51 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyd9qb1qr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 15:01:51 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDEGiPt008450;
	Wed, 13 Dec 2023 15:01:50 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtht35-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 15:01:50 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDF1lpD24052302
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 15:01:47 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 08F3B2004E;
	Wed, 13 Dec 2023 15:01:47 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A027920043;
	Wed, 13 Dec 2023 15:01:45 +0000 (GMT)
Received: from [9.171.70.156] (unknown [9.171.70.156])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 15:01:45 +0000 (GMT)
Message-ID: <0bd0f6f9d0c6ff454739f38d6661fdda662afcca.camel@linux.ibm.com>
Subject: Re: [PATCH v2 12/33] kmsan: Allow disabling KMSAN checks for the
 current task
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Andrew Morton
 <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>,
        David
 Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami
 Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven
 Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil
 Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Wed, 13 Dec 2023 16:01:45 +0100
In-Reply-To: <CAG_fn=VaJtMogdmehJoYmZRNrs5AXYs+ZwBTu3TQQVaSkFNzcw@mail.gmail.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-13-iii@linux.ibm.com>
	 <CAG_fn=VaJtMogdmehJoYmZRNrs5AXYs+ZwBTu3TQQVaSkFNzcw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ahpnbjqfUrHjRu_h2faEroNfAjnwxAiU
X-Proofpoint-ORIG-GUID: DbOOs6ZkGakRHkgEME2dN21fy0MBcb1e
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_08,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0
 impostorscore=0 malwarescore=0 clxscore=1015 phishscore=0 adultscore=0
 spamscore=0 mlxlogscore=553 priorityscore=1501 bulkscore=0
 lowpriorityscore=0 mlxscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312130106
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=aE87hCYr;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

On Mon, 2023-12-11 at 12:50 +0100, Alexander Potapenko wrote:
> On Tue, Nov 21, 2023 at 11:06=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.=
com>
> wrote:
> >=20
> > Like for KASAN, it's useful to temporarily disable KMSAN checks
> > around,
> > e.g., redzone accesses. Introduce kmsan_disable_current() and
> > kmsan_enable_current(), which are similar to their KASAN
> > counterparts.
>=20
> Initially we used to have this disablement counter in KMSAN, but
> adding it uncontrollably can result in KMSAN not functioning
> properly.
> E.g. forgetting to call kmsan_disable_current() or underflowing the
> counter will break reporting.
> We'd better put this API in include/linux/kmsan.h to indicate it
> should be discouraged.
>=20
> > Even though it's not strictly necessary, make them reentrant, in
> > order
> > to match the KASAN behavior.
>=20
> Until this becomes strictly necessary, I think we'd better
> KMSAN_WARN_ON if the counter is re-entered.

I encountered a case when we are freeing memory from an interrupt
handler:

[  149.840553] ------------[ cut here ]------------                  =20
[  149.840649] WARNING: CPU: 1 PID: 181 at mm/kmsan/hooks.c:447
kmsan_disable_current+0x2e/0x40                                      =20
[  149.840790] Modules linked in:                                    =20
[  149.840894] CPU: 1 PID: 181 Comm: (direxec) Tainted: G    B   W   =20
N 6.7.0-rc5-gd34a4b46f382 #13
[  149.841003] Hardware name: IBM 3931 A01 704 (KVM/Linux)    =20
[  149.841094] Krnl PSW : 0404c00180000000 000000000197dbc2
(kmsan_disable_current+0x32/0x40)
[  149.841276]            R:0 T:1 IO:0 EX:0 Key:0 M:1 W:0 P:0 AS:3 CC:0
PM:0 RI:0 EA:3
[  149.841420] Krnl GPRS: 0000000000000040 0000000096914100
0000000000001000 0000000000000001
[  149.841518]            0000036d827daee0 0000000007c97008
0000000080096500 0000000092f4f000
[  149.841617]            0000036d00000000 0000000000000000
0000000000000040 0000000000000000
[  149.841712]            0000000092f4efc0 00000001ff710f60
000000000193acba 0000037f0008f710
[  149.841893] Krnl Code: 000000000197dbb6: eb0018640352        mviy =20
14436(%r1),0
[  149.841893]            000000000197dbbc: 07fe                bcr  =20
15,%r14
[  149.841893]           #000000000197dbbe: af000000            mc   =20
0,0
[  149.841893]           >000000000197dbc2: a7f4fffa            brc  =20
15,000000000197dbb6
[  149.841893]            000000000197dbc6: 0700                bcr  =20
0,%r0
[  149.841893]            000000000197dbc8: 0700                bcr  =20
0,%r0
[  149.841893]            000000000197dbca: 0700                bcr  =20
0,%r0
[  149.841893]            000000000197dbcc: 0700                bcr  =20
0,%r0
[  149.842438] Call Trace:                                           =20
15:37:25 [90/1838]
[  149.842510]  [<000000000197dbc2>] kmsan_disable_current+0x32/0x40=20
[  149.842631] ([<000000000193ac14>] slab_pad_check+0x1d4/0xac0)
[  149.842738]  [<0000000001949222>] free_to_partial_list+0x1d72/0x3b80
[  149.842850]  [<0000000001947066>] __slab_free+0xd86/0x11d0=20
[  149.842956]  [<00000000019111e8>] kmem_cache_free+0x15d8/0x25d0=20
[  149.843062]  [<0000000000229e3a>] __tlb_remove_table+0x20a/0xa50=20
[  149.843174]  [<00000000016c7f98>] tlb_remove_table_rcu+0x98/0x120=20
[  149.843291]  [<000000000083e1c6>] rcu_core+0x15b6/0x54b0=20
[  149.843406]  [<00000000069c3c0e>] __do_softirq+0xa1e/0x2178=20
[  149.843514]  [<00000000003467b4>] irq_exit_rcu+0x2c4/0x630=20
[  149.843623]  [<0000000006949f6e>] do_ext_irq+0x9e/0x120=20
[  149.843736]  [<00000000069c18d4>] ext_int_handler+0xc4/0xf0=20
[  149.843841]  [<000000000197e428>] kmsan_get_metadata+0x68/0x280=20
[  149.843950]  [<000000000197e344>]
kmsan_get_shadow_origin_ptr+0x74/0xf0=20
[  149.844071]  [<000000000197ba3a>]
__msan_metadata_ptr_for_load_8+0x2a/0x40=20
[  149.844192]  [<0000000000184e4a>]
unwind_get_return_address+0xda/0x150=20
[  149.844313]  [<000000000018fd12>] arch_stack_walk+0x172/0x2f0=20
[  149.844417]  [<00000000008f1af0>] stack_trace_save+0x100/0x160=20
[  149.844529]  [<000000000197af22>]
kmsan_internal_chain_origin+0x62/0xe0=20
[  149.844647]  [<000000000197c1f0>] __msan_chain_origin+0xd0/0x160=20
[  149.844763]  [<00000000068b3ba4>] memchr_inv+0x5b4/0xb20=20
[  149.844877]  [<000000000193e730>] check_bytes_and_report+0xa0/0xd30=20
[  149.844986]  [<000000000193b920>] check_object+0x420/0x17d0=20
[  149.845092]  [<000000000194aa8a>] free_to_partial_list+0x35da/0x3b80
[  149.845202]  [<0000000001947066>] __slab_free+0xd86/0x11d0=20
[  149.845308]  [<00000000019111e8>] kmem_cache_free+0x15d8/0x25d0=20
[  149.845414]  [<00000000016bc2fe>] exit_mmap+0x87e/0x1200=20
[  149.845524]  [<00000000002f315c>] mmput+0x13c/0x5b0=20
[  149.845632]  [<0000000001b9d634>] exec_mmap+0xc34/0x1230=20
[  149.845744]  [<0000000001b996c2>] begin_new_exec+0xcf2/0x2520=20
[  149.845857]  [<0000000001f6a084>] load_elf_binary+0x2364/0x67d0=20
[  149.845971]  [<0000000001ba5ba4>] bprm_execve+0x25b4/0x4010=20
[  149.846083]  [<0000000001baa7e6>] do_execveat_common+0x2436/0x2600=20
[  149.846200]  [<0000000001ba78f8>] __s390x_sys_execve+0x108/0x140=20
[  149.846314]  [<000000000011b192>] do_syscall+0x4c2/0x690=20
[  149.846424]  [<0000000006949d78>] __do_syscall+0x98/0xe0=20
[  149.846536]  [<00000000069c1640>] system_call+0x70/0xa0=20
[  149.846638] INFO: lockdep is turned off.
[  149.846846] Last Breaking-Event-Address:
[  149.846916]  [<000000000197dbb2>] kmsan_disable_current+0x22/0x40
[  149.847057] irq event stamp: 0
[  149.847128] hardirqs last  enabled at (0): [<0000000000000000>] 0x0
[  149.847227] hardirqs last disabled at (0): [<00000000002f8f46>]
copy_process+0x21f6/0x8b20
[  149.847344] softirqs last  enabled at (0): [<00000000002f8f80>]
copy_process+0x2230/0x8b20
[  149.847461] softirqs last disabled at (0): [<0000000000000000>] 0x0
[  149.847559] ---[ end trace 0000000000000000 ]---
[  149.865485] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D

Using a counter resolves this issue, but, of course, at the expense of
not reporting valid issues in the interrupt handler.

Unfortunately I don't see another easy way to solve this problem. The
possibilities that come to mind are providing uninstrumented
memchr_inv() or disablement flags for each context, but I'm not sure if
we want to go there, especially since KASAN already has this
limitation.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0bd0f6f9d0c6ff454739f38d6661fdda662afcca.camel%40linux.ibm.com.
