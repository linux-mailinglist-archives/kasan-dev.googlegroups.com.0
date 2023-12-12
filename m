Return-Path: <kasan-dev+bncBCM3H26GVIOBB4H732VQMGQEFREFJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84D1B80E13C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 03:05:37 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-67a940dcd1asf71324196d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 18:05:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702346736; cv=pass;
        d=google.com; s=arc-20160816;
        b=CFY5N0hk8bybqHwpWWy7pojLG6XZ6zPy1Dlms1SeFdch6L4gCNJCfaDu2KDjRjsCv3
         Cu932/pivOIBnt7aMQFhB7L4U7lV0vN/GaxbkDoGUk/9cKmUQA9toI3Yj4+qESTDtkXA
         UiqfMzOhYB140l1OgMlBiIRvTdVtvSxhIIWtIs/mxWlTcGT4Z4/Y1B/qWkcskKNASpqJ
         /P53uZ6iDqyaWLX5axlBYmKlEvWYTKXiOoIS+SdMQZwyBYHyzdi8oQe7JBoMcQa2EGHE
         YwQZOgY/rogDfAf5QHsMEzw97m3+KFpz+4bctN2Qw9IUsoyx5KQh6IZasEFiZuVqS/C3
         1PAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=95TCGwHozwFJesRSb8UL4MR/Kv/sojUwDfxyc/a2riM=;
        fh=unG9oIr1g7sooV4KyypO7SrMPxgK63mSHAjczAEOeKY=;
        b=uWeswUtu9GNmWjXL9jmKfgJx8vtR7L85fChTMa3tan1/zuGJM7PVzAVw7kC0opm/+F
         P4MOIYTb20QcnX6mxKECGTeHa0pdByABpMuIEjTdML15xYtIRaj7VvXG5ENQvCk1de5z
         TuP7eKhYBfz7ET/ZNkVwEJ2+Bd9+1Abu1baCy1EhX0cD3v0UXRCYPP/32ja71hBmO1y/
         Hu/N7yqmstqd4QiNV+mdzRV+9pWpaZzePvR0rlwc8UJq+Vst6G9qQjd/H28mpLHeB0pk
         Pfhk0nrDEbfStod+NvQP0WXYIUlxzY+Dx5kshXOsyVGa8+HH7cDDsLV2bTzz1pXroLj7
         DFIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jA6Nr7J6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702346736; x=1702951536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=95TCGwHozwFJesRSb8UL4MR/Kv/sojUwDfxyc/a2riM=;
        b=FnjI5ItLsmgjVYViHZc5qm1iPH7xCRTaOts1z/OuwdpmpgJ7Ll0MssUASG/8Fbd1gy
         oY2R7n+ab4BsIASEZxHiBZTRBLd3hyiX/FOEDVs9Ainf6EBg4OkvdHUyUyILu5XZ5wBG
         XGfTna85bitDZOz2gZEKv7OZaYAMRffPSzcC8QYFwRtGNgjAILKTb82c5CCGtKmfF0i+
         JPBv/L2rTIl+WcW3FPqEJQuBoPCM3zQQakej5gkURSEqoLfIiFWhlDhETXlAL5XexhO4
         e+d8ikRbWim4B7NjftSFPOShetIyEazmu54RCgcn0Hsaaw0f+y00oTdKc5rsCADlHPf5
         +2cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702346736; x=1702951536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=95TCGwHozwFJesRSb8UL4MR/Kv/sojUwDfxyc/a2riM=;
        b=VfKEGDUcpkwFVXGMP7qOQWVmdtGGLaMZzar2blW8AOC5gdqU67WodeVcn2KXpWrczZ
         p/JyAr8OFcESM9/yqrDf/m2AyQfma7hSXPqJ7kUnzQbZyZB0W6/El42Si69kLhFun5nc
         0qY1dV54VE91VoRknqUo+l3lTFpVm+CVDk31kWpvz8h/6/HjpJBlV5IwA88rFQHlmLbm
         gmR7o4XMyriER+WF48Bnpr69dzb7DNyNcj78HUQvpH0H9ETtsOfEM0f0BrQkMYg3vyzZ
         D8AZCqTwvwu9nUx3omIZfhTi4bUynTWddILTJIFBmWPvD5r/O8fn2PkPDNd3eaNrYnUO
         dJMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw4AK7bmEs7jB3aISlsgHAOBLAlTl8UQUflZXYSAuHAoW6Nycws
	uMH6bKuqfjyFhdzyzQds5C4=
X-Google-Smtp-Source: AGHT+IFzrpLUpoKrDx/2W5DchyhxYWFUgMvUepLOKiIyG1mlf/WNvutH0DDvb6cWhJ2sdiNdU5MM3A==
X-Received: by 2002:a05:6214:c1:b0:67e:c693:9eff with SMTP id f1-20020a05621400c100b0067ec6939effmr4000776qvs.107.1702346736451;
        Mon, 11 Dec 2023 18:05:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1924:b0:67a:1a4b:e43e with SMTP id
 es4-20020a056214192400b0067a1a4be43els1419756qvb.0.-pod-prod-02-us; Mon, 11
 Dec 2023 18:05:35 -0800 (PST)
X-Received: by 2002:a0c:ee45:0:b0:67a:a61e:f1fa with SMTP id m5-20020a0cee45000000b0067aa61ef1famr6027577qvs.52.1702346735686;
        Mon, 11 Dec 2023 18:05:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702346735; cv=none;
        d=google.com; s=arc-20160816;
        b=ksUZ5iFVUXlZsXOrtejqLorzOgGGBG2oCj6kFGCDpUnYxXIPE0t7SNXZMm5+tI1aTw
         NzSFbRVnQXn3reUpHcdOIuWQwr7aWrNNhLdSQc/vQAwfYDo8qvz3MZtR/i35aZxKLKIL
         RQkywLGIRN6d9TONmeuDYfE88RXr/TAJbzN3V2ieSCX0/C0aBYMhsPyvWH0g2PalYgt3
         he0avkJq+951peZRTLCyQiCpgmxS7g9oHCPMMpR4TVAvjYo2XOJyHslAUSq/Iphu5+u8
         t5LrbJrP0DdCIBqK2WrTylfNUzPcYRuurEclahH0lGfdT5dbz9dMnulIIBDT9Awedr0n
         Co+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=Ot8KKoxIBjGSb3I4fQ0uzOZ3rMDzR3TKxD9TleX3+9A=;
        fh=unG9oIr1g7sooV4KyypO7SrMPxgK63mSHAjczAEOeKY=;
        b=dLdjOdkcubOUeDHoBP9ceSUFs7GcWKHTzRX/7zOnrN62stnFE6iG8GX59gBCbvV7Om
         t4iTqY7BhiUv8JiCgAAKxAtUNzASA3kFU2jdCbplUyGP+EmKSmchJuv2avD6GwifDQW7
         gmlF5MfalFbFzMAYmCCu7PLXu1HEdTA6H+vp4/jneOddzrnO3bp7wJ9+fln+wVocZ1cX
         /AaMRp+vwGVne4K9DM0BEmlNEzYZbgJBKyrqycJ6xKpnH1rHDpKkP35FlDr3dJOSBHyf
         7TcBIeiP0Hp4FzRex4fC9J9dEBz0lk3K4vBbypFXtjDijPGrny8Hd7P7OUKitVbSIY94
         iDJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jA6Nr7J6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y8-20020a05620a0e0800b0077f3d2c7a9bsi604322qkm.7.2023.12.11.18.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Dec 2023 18:05:35 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BBNMuXi032321;
	Tue, 12 Dec 2023 02:05:32 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uxc1tjy2r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 12 Dec 2023 02:05:32 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BC1oHKZ006324;
	Tue, 12 Dec 2023 02:05:31 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uxc1tjy27-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 12 Dec 2023 02:05:31 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BBN2wVU013869;
	Tue, 12 Dec 2023 02:05:30 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw591w85a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 12 Dec 2023 02:05:30 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BC25RGr46989760
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Dec 2023 02:05:27 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 601A520043;
	Tue, 12 Dec 2023 02:05:27 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0EA7920040;
	Tue, 12 Dec 2023 02:05:26 +0000 (GMT)
Received: from [9.171.76.38] (unknown [9.171.76.38])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 12 Dec 2023 02:05:25 +0000 (GMT)
Message-ID: <3897a38ef97742f7f51fb4c84c5ddeb4e36dae79.camel@linux.ibm.com>
Subject: Re: [PATCH v2 01/33] ftrace: Unpoison ftrace_regs in
 ftrace_ops_list_func()
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Steven Rostedt <rostedt@goodmis.org>,
        Alexander Potapenko
	 <glider@google.com>
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
        Pekka Enberg <penberg@kernel.org>, Vasily
 Gorbik <gor@linux.ibm.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Christian
 Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov
 <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Tue, 12 Dec 2023 03:05:25 +0100
In-Reply-To: <20231208093133.62aae274@gandalf.local.home>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-2-iii@linux.ibm.com>
	 <CAG_fn=WHf0t=-OJL0031D+X7cX_D25G7TG0TqROsT34QcEnqsw@mail.gmail.com>
	 <20231208093133.62aae274@gandalf.local.home>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: LdRjikzPVMkLwO_P5tClkpAJCESuoSPy
X-Proofpoint-GUID: LtJfjO66RfKFUX7oxZBtF4AB6-D3cx5W
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-11_11,2023-12-07_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=884
 lowpriorityscore=0 adultscore=0 priorityscore=1501 mlxscore=0 bulkscore=0
 impostorscore=0 malwarescore=0 clxscore=1015 phishscore=0 spamscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312120015
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jA6Nr7J6;       spf=pass (google.com:
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

On Fri, 2023-12-08 at 09:31 -0500, Steven Rostedt wrote:
> On Fri, 8 Dec 2023 15:16:10 +0100
> Alexander Potapenko <glider@google.com> wrote:
>=20
> > On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich
> > <iii@linux.ibm.com> wrote:
> > >=20
> > > Architectures use assembly code to initialize ftrace_regs and
> > > call
> > > ftrace_ops_list_func(). Therefore, from the KMSAN's point of
> > > view,
> > > ftrace_regs is poisoned on ftrace_ops_list_func entry(). This
> > > causes
> > > KMSAN warnings when running the ftrace testsuite.=C2=A0=20
> >=20
> > I couldn't reproduce these warnings on x86, hope you really need
> > this
> > change on s390 :)

I just double-checked, and it's still needed. Without it, I get:

[    4.140184] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D =20
[    4.140416] BUG: KMSAN: uninit-value in
arch_ftrace_ops_list_func+0x8e6/0x14b0           =20
[    4.140484]  arch_ftrace_ops_list_func+0x8e6/0x14b0               =20
[    4.140546]  ftrace_graph_caller+0x0/0x34                         =20
[    4.140614]  read_tod_clock+0x6/0x1e0                             =20
[    4.140671]  ktime_get+0x3a4/0x670                                =20
[    4.140727]  clockevents_program_event+0x1c8/0xb10                =20
[    4.140785]  tick_program_event+0x11e/0x230                       =20
[    4.140842]  hrtimer_interrupt+0x118a/0x1d10                      =20
[    4.140898]  do_IRQ+0x108/0x150                                   =20
[    4.140959]  do_irq_async+0xfc/0x270                              =20
[    4.141021]  do_ext_irq+0x98/0x120                                =20
[    4.141080]  ext_int_handler+0xc4/0xf0                            =20
[    4.141141]  _raw_spin_unlock_irqrestore+0xfa/0x190               =20
[    4.141207]  _raw_spin_unlock_irqrestore+0xf6/0x190               =20
[    4.141271]  s390_kernel_write+0x218/0x250                        =20
[    4.141328]  ftrace_make_call+0x362/0x4a0                         =20
[    4.141386]  __ftrace_replace_code+0xb44/0xbd0                    =20
[    4.141442]  ftrace_replace_code+0x1d8/0x440                      =20
[    4.141497]  ftrace_modify_all_code+0xfe/0x510                    =20
[    4.141555]  ftrace_startup+0x4f0/0xcf0                           =20
[    4.141609]  register_ftrace_function+0x1316/0x1440               =20
[    4.141670]  function_trace_init+0x2c0/0x3d0                      =20
[    4.141732]  tracer_init+0x282/0x370                              =20
[    4.141789]  trace_selftest_startup_function+0x104/0x19d0         =20
[    4.141857]  run_tracer_selftest+0x7c8/0xab0                      =20
[    4.141918]  init_trace_selftests+0x200/0x820
[    4.141977]  do_one_initcall+0x35e/0x1090
[    4.142032]  do_initcall_level+0x276/0x660
[    4.142095]  do_initcalls+0x16a/0x2d0
[    4.142153]  kernel_init_freeable+0x632/0x960
[    4.142216]  kernel_init+0x36/0x1810
[    4.142277]  __ret_from_fork+0xc0/0x180
[    4.142333]  ret_from_fork+0xa/0x30
[    4.142431] Local variable agg.tmp.i.i created at:                =20
02:06:55 [30/1836]
[    4.142476]  timekeeping_advance+0x79a/0x2870
[    4.142394]=20
[    4.142431] Local variable agg.tmp.i.i created at:
[    4.142476]  timekeeping_advance+0x79a/0x2870
[    4.142534]=20
[    4.142573] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W     =20
6.7.0-rc4-g7657d31dc545 #4
[    4.142638] Hardware name: IBM 3931 A01 704 (KVM/Linux)
[    4.142686] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
[    4.142734] Kernel panic - not syncing: kmsan.panic set ...
[    4.142734] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D

> On x86, ftrace_regs sits on the stack. And IIUC, s390 doesn't have
> the same
> concept of a "stack" as other architectures. Perhaps that's the
> reason s390
> needs this?

It's not that different on s390x. There is indeed no architecture-
mandated stack pointer and no push/pop, but other than that it's fairly
normal. Linux uses %r15 as a stack pointer.

On s390x ftrace_regs is allocated on stack by mcount.S. From what I can
see, Intel's ftrace_64.S does the same thing, so I don't immediately
see why uninit-value is not detected on Intel, even though I think it
should.

> -- Steve

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3897a38ef97742f7f51fb4c84c5ddeb4e36dae79.camel%40linux.ibm.com.
