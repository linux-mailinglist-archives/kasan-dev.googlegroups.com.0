Return-Path: <kasan-dev+bncBCM3H26GVIOBBSUBU6ZQMGQEZJWPFFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 630AA905714
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 17:37:49 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-6ea9b2ecb63sf753959a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 08:37:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718206667; cv=pass;
        d=google.com; s=arc-20160816;
        b=l1ArfaodEgT8fWhwveZSLuR5cUS4X0zSRjcn1G1GW7yde1IUM86dqSsGqLgzR8YR1v
         1XyelwaDS8PtR9vZR8o3+uqY/wcAGrYyW5ZVv1trX7OAFm8XwOaE1jKJc+rNY9s0HKOk
         UMkvW5wjqWzk7wFPpwAIPTiQCbUZBScWXKIYl5MJ54PWOB131yK8tXDNfur3N2h+jQXC
         17D/6wIKBFIlKceMuOsjJBLYPKtIjZ7EgEkiU1dDqYSkuKsc5AnX7CimPKc3m8cyofbX
         zH07H7bkR2m5sWSPQ6v00wJdy7l0dVa1sR223AXln46mmAmWnd758lQ1hFULDvfx2JQA
         mGHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:user-agent:references:in-reply-to:date:cc
         :to:from:subject:message-id:sender:dkim-signature;
        bh=FgkxP3UGmsKWMHboTlwiy8v8c52nJcnwSNWmLFlUR5U=;
        fh=VnkNt/WXY/wGzL++uMnK4kMzSNbzYc24qy3VS6DlU+E=;
        b=hPp1jyudtu5n/0jz79Vingg83rbl3SqEL7KMzyLTKnL3SYr14d7MAQmXOjvHzCajKJ
         aFC71ErTDsXBS7QYzHWSv9EbIxqxupeafxqnklc+XYSEGup/u2FY0jtOij9X/OXf0ukc
         xYlfFPWHng4bL7tNd3RYr6Tl/ClvvL4RedeEejMcaq9yP42b5mrZS8R1dG44iGE1dWf5
         hSr6VZ7EGjempDQSaPZIyh9LF9zEao8AIagJdSTEXVdIRmPaGe3BmbvoJS9dZ/BIFfeo
         rv00+sbWUCnVEM+LGWUnAhGYeKaYXAKbBmihj5nkEXCiqm0V7w+OqW8t0m7qSJFYKlXZ
         QJ9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=daXsUq4X;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718206667; x=1718811467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:user-agent
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FgkxP3UGmsKWMHboTlwiy8v8c52nJcnwSNWmLFlUR5U=;
        b=D2q9kdc4UgYJMa+2cJXhAZb+gLQUZCxUqS4PjyIwOqVyC5fhB5EmVmzftYh7clivn+
         XbfqTKzpeKq1KlF8o/MEIPWiH0md9Ch3lCS+WzupZ/1iNzdv5Ae/ZOm77/8vqw/Qsu/1
         DQ2Tehr4/pX1WaPOKgWT98TWnrN3gw3yMlvRpLR85KDI0F1Y+8GeJUeupBPlOyiayapP
         hmyiQZnyqlrYXjt4hYMLXreUpksG3fqYPLqaIkB+yDCZd3pNR6sU5dgkQJT3J7TzcEJW
         gQYgvu3ehrji3O1uHHZPYme6kgf7ZEbtah31oeHBt+4ZpoOcWMDVLsr0JAeJZPXAS7QH
         W9yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718206667; x=1718811467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:user-agent:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FgkxP3UGmsKWMHboTlwiy8v8c52nJcnwSNWmLFlUR5U=;
        b=YEbRnxBtXYIpUGQUdSoHCuhY1LEXPRFQ8ZOja634R4N8nEKJlnUzQsgKUsjkNZPgQV
         UWArwJ0RCW1mAHkz5lFEDJW+XUwFX6ehRz6CR5c99qzkfk1TchrTtTmYsgTSwpMTxRUV
         J8Xbhq5LynjXKBnttNj7Xo89nyGuR51+KkzkFFOAYvWYkpoxi/fRRNJ98XqW9gb8AYee
         LBoIQ0kJOyYURTV0sPqExVc+jwggG+5qxU+F+Y4MtifX55/rzX60lDTp6KhWLvNoBFRj
         mdtXLuQodE7HfwVVmOktjhG/fU0bdgqBE9JL++rM0w9dMSaX4etm95lmuX5vlU0KHG37
         0exg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwtuftpa6hiyEI40UzWNxJYrZcXtV1SjKUREP27bJVpahFMfv1F6M8/iXQ8YhNAT4z6cRO9rYHtRqJBiIFnse1Fv647rh6sg==
X-Gm-Message-State: AOJu0YzwlPxYzL5KCbTLRzOEPX9SMB+KhMR7Kzlm4DZrc2/piOs0gP/z
	YnGQvuwf1TD3flZgWFcp7DZZDZXZgvb6lAlSFqBNdue3tjMCoii9
X-Google-Smtp-Source: AGHT+IF2qYo01/yKJcjFs19SaW7PG+MDI+QD8NPVGrbY4DhUSBuCjaFSc/Djv90TYqaPhkgxDEYWUA==
X-Received: by 2002:a17:902:c942:b0:1f6:3580:65c9 with SMTP id d9443c01a7336-1f83b19c26fmr38675125ad.26.1718206667101;
        Wed, 12 Jun 2024 08:37:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2cc:b0:1f7:979:2da7 with SMTP id
 d9443c01a7336-1f84d643786ls144745ad.2.-pod-prod-00-us; Wed, 12 Jun 2024
 08:37:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9X5u7sLucTMNUxXKVJLAsJU6Hxa0f+QApKUHQFEN1NBsTkG+vQaIsL1GSS/g4tiF/7FmZ/vzFbvKMEiQR5vsvB23lHdSLnfFvxw==
X-Received: by 2002:a17:903:2291:b0:1f6:6606:c91e with SMTP id d9443c01a7336-1f7289551dbmr91072785ad.29.1718206665567;
        Wed, 12 Jun 2024 08:37:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718206665; cv=none;
        d=google.com; s=arc-20160816;
        b=RkyvDE+rndOwSb25OxOkKz/ITV758UyB2qKiTEUX+/G+ysK3/Dyd56monbkkRxmbml
         3CO6sL+mVMQhXUUyvzgW6V61+0BwGBVrjzFluI2+wQk4PEQfzxD5iKcLmriVGwq/KZcU
         EOXTtkA+atkdBVmYmaNhc5k4dGOrpc326sGmv3dSletWf43yL/J2Y0ohu5oLe5ktGtgg
         nXSOsGzK87bySkeqFd51uuocUFAHNIyig39dy1+K9zazLsgVF85bYDegXBVi7r1pj2/F
         OnpYkmWgUv4s3de5C5BWrnVB4LkMzYghgHLAzsO1rJM6LofJQMPheoTk9sjON4YkWAW7
         wXxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=sUlVOpLsB7ZgvZM2Yku0ftpL1kxmfJTOLslTgiO7Wc0=;
        fh=WOXJPmrxApa3z0zXI6WlCxsLeH3iapg+yMuEwUqA9W4=;
        b=C1xhYnJd8B7oQ5so5RdPfccwsj+VF32aKVP/QMNarMUbhKcG6A2tAIY9VadSmf4hgS
         hIueKwUigdnstDieDvowP15yrl9xEmaHz+KLVg/atHnhCK3CxpO9NP/BDbjHkj20w/Pb
         5YOrkrt+Rir1TCuczwo4BaJU4sRXiNh+d/9Qp52P/UpUe0dd29TBXZkN6JDmubso6g4m
         ErfSPdc1uHpUEayBp2orP0IYU8K1XaTtLsuxBCxc2LGhIa4vS5Vucz94yFrPjjQVuE6c
         X2gUiVV7EGed4kgS+Kgx+y7pMuEX6J9QM+xrfyKwjJccFAyd3XGVcuShu34EDhV35gXJ
         HZRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=daXsUq4X;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f6fb7681eesi3862645ad.11.2024.06.12.08.37.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Jun 2024 08:37:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45CFTKxU001593;
	Wed, 12 Jun 2024 15:37:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqebx80pn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 12 Jun 2024 15:37:40 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45CFbdDb014086;
	Wed, 12 Jun 2024 15:37:40 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqebx80pj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 12 Jun 2024 15:37:39 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45CFLocC003881;
	Wed, 12 Jun 2024 15:37:39 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn2mpy4ha-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 12 Jun 2024 15:37:39 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45CFbXI411403582
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 12 Jun 2024 15:37:35 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 187342004E;
	Wed, 12 Jun 2024 15:37:33 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B02D720040;
	Wed, 12 Jun 2024 15:37:32 +0000 (GMT)
Received: from [9.155.200.166] (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 12 Jun 2024 15:37:32 +0000 (GMT)
Message-ID: <6403223315eda4e8023a828d6f40353c694d474e.camel@linux.ibm.com>
Subject: Re: [PATCH v3 01/34] ftrace: Unpoison ftrace_regs in
 ftrace_ops_list_func()
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko
 <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph
 Lameter <cl@linux.com>,
        David Rientjes <rientjes@google.com>,
        Heiko
 Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco
 Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka
 Enberg <penberg@kernel.org>, Vasily Gorbik <gor@linux.ibm.com>,
        Vlastimil
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
Date: Wed, 12 Jun 2024 17:37:32 +0200
In-Reply-To: <20240102101712.515e0fe3@gandalf.local.home>
References: <20231213233605.661251-1-iii@linux.ibm.com>
	 <20231213233605.661251-2-iii@linux.ibm.com>
	 <20240102101712.515e0fe3@gandalf.local.home>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: rmQltXYdpFw9fTbDS6VlEHPVsYz_YHE3
X-Proofpoint-GUID: Ivcj_IlvBtvvOQzLTRy84LG3MKhmjE9t
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-12_08,2024-06-12_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0
 priorityscore=1501 phishscore=0 lowpriorityscore=0 adultscore=0
 clxscore=1011 impostorscore=0 mlxscore=0 suspectscore=0 mlxlogscore=999
 spamscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406120110
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=daXsUq4X;       spf=pass (google.com:
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

On Tue, 2024-01-02 at 10:17 -0500, Steven Rostedt wrote:
> On Thu, 14 Dec 2023 00:24:21 +0100
> Ilya Leoshkevich <iii@linux.ibm.com> wrote:
>=20
> > Architectures use assembly code to initialize ftrace_regs and call
> > ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
> > ftrace_regs is poisoned on ftrace_ops_list_func entry(). This
> > causes
> > KMSAN warnings when running the ftrace testsuite.
>=20
> BTW, why is this only a problem for s390 and no other architectures?
>=20
> If it is only a s390 thing, then we should do this instead:
>=20
> in include/linux/ftrace.h:
>=20
> /* Add a comment here to why this is needed */
> #ifndef ftrace_list_func_unpoison
> # define ftrace_list_func_unpoison(fregs) do { } while(0)
> #endif
>=20
> In arch/s390/include/asm/ftrace.h:
>=20
> /* Add a comment to why s390 is special */
> # define ftrace_list_func_unpoison(fregs)
> kmsan_unpoison_memory(fregs, sizeof(*fregs))
>=20
> >=20
> > Fix by trusting the architecture-specific assembly code and always
> > unpoisoning ftrace_regs in ftrace_ops_list_func.
> >=20
> > Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
>=20
> I'm taking my ack away for this change in favor of what I'm
> suggesting now.
>=20
> > Reviewed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> > ---
> > =C2=A0kernel/trace/ftrace.c | 1 +
> > =C2=A01 file changed, 1 insertion(+)
> >=20
> > diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
> > index 8de8bec5f366..dfb8b26966aa 100644
> > --- a/kernel/trace/ftrace.c
> > +++ b/kernel/trace/ftrace.c
> > @@ -7399,6 +7399,7 @@ __ftrace_ops_list_func(unsigned long ip,
> > unsigned long parent_ip,
> > =C2=A0void arch_ftrace_ops_list_func(unsigned long ip, unsigned long
> > parent_ip,
> > =C2=A0			=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct ftrace_ops *op, st=
ruct
> > ftrace_regs *fregs)
> > =C2=A0{
> > +	kmsan_unpoison_memory(fregs, sizeof(*fregs));
>=20
> And here have:
>=20
> 	ftrace_list_func_unpoison(fregs);
>=20
> That way we only do it for archs that really need it, and do not
> affect
> archs that do not.
>=20
>=20
> I want to know why this only affects s390, because if we are just
> doing
> this because "it works", it could be just covering up a symptom of
> something else and not actually doing the "right thing".
>=20
>=20
> -- Steve
>=20
>=20
> > =C2=A0	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
> > =C2=A0}
> > =C2=A0#else
>=20

Ok, it has been a while, but I believe I have a good answer now. KMSAN
shadow for memory above $rsp is essentially random. Here is an example
(you'll need a GDB hack from [1] if you want to try this at home):

(gdb) x/5i do_nanosleep
   0xffffffff843607c0 <do_nanosleep>:   call   0xffffffffc0201000
Thread 3 hit Breakpoint 1, 0xffffffffc0201000 in ?? ()
(gdb) x/64bx kmsan_get_metadata($rsp - 64, 0)
0xffffd1000087bd38:     0x00    0x00    0x00    0x00    0x00    0x00 =20
0x00    0x00
0xffffd1000087bd40:     0x00    0x00    0x00    0x00    0x00    0x00 =20
0x00    0x00
0xffffd1000087bd48:     0x00    0x00    0x00    0x00    0x00    0x00 =20
0x00    0x00
0xffffd1000087bd50:     0x00    0x00    0x00    0x00    0xff    0xff =20
0xff    0xff
0xffffd1000087bd58:     0x00    0x00    0x00    0x00    0x00    0x00 =20
0x00    0x00
0xffffd1000087bd60:     0xff    0xff    0xff    0xff    0xff    0xff =20
0xff    0xff
0xffffd1000087bd68:     0xff    0xff    0xff    0xff    0xff    0xff =20
0xff    0xff
0xffffd1000087bd70:     0xff    0xff    0xff    0xff    0xff    0xff =20
0xff    0xff

So if assembly (in this case ftrace_regs_caller) allocates struct
pt_regs on stack, it may or may not be poisoned depending on what was
called before. So, by accident, on s390x it's poisoned and trips KMSAN,
and on x86_64 it's not. Based on this observation, I'd say we need
an unpoison call in all ftrace handlers (e.g., kprobe_ftrace_handler),
and not just this one.

But why is this the case? Kernel stacks are created by
alloc_thread_stack_node() using __vmalloc_node_range(__GFP_ZERO), so
they are fully unpoisoned. Then functions are called and return, their
locals are poisoned and unpoisoned. Interestingly enough, on return,
they are not poisoned back, even though

commit 37ad4ee8364255c73026a3c343403b5977fa7e79
Author: Alexander Potapenko <glider@google.com>
Date:   Thu Sep 15 17:04:13 2022 +0200

    x86: kmsan: don't instrument stack walking functions

says they do. So what if we introduce that [2]?

# echo "p:nanosleep do_nanosleep %di"
>/sys/kernel/tracing/kprobe_events
# echo 1 >/sys/kernel/debug/tracing/events/kprobes/nanosleep/enable
# sleep 1
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
BUG: KMSAN: uninit-value in kprobe_ftrace_handler+0x5b9/0x790
 kprobe_ftrace_handler+0x5b9/0x790
 0xffffffffc02010de
 do_nanosleep+0x5/0x670
 hrtimer_nanosleep+0x169/0x3b0
 common_nsleep+0xc7/0x100
 __x64_sys_clock_nanosleep+0x4e2/0x650
 do_syscall_64+0x6e/0x120
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

Local variable nd created at:
 do_filp_open+0x3b2/0x5e0

Quite similar to s390. Local variable nd is a random leftover from a
different call stack, which the modified instrumentation poisoned on
return from do_filp_open().

Alexander, what do you think about adding [2] upstream as an option
that can be enabled from the command line? Also, what do you think
about poisoning kernel stacks? Formally they are zeroed out, but I
think valid code has no business reading these zeroes.

[1] https://sourceware.org/bugzilla/show_bug.cgi?id=3D31878
[2]
https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-re=
turning-2024-06-12/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6403223315eda4e8023a828d6f40353c694d474e.camel%40linux.ibm.com.
