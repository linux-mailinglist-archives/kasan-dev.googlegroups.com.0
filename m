Return-Path: <kasan-dev+bncBCM3H26GVIOBBI6S6SVAMGQEYW4XU2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8571F7F38B1
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:16 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-679ceb85c6csf43729226d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604195; cv=pass;
        d=google.com; s=arc-20160816;
        b=JM3efmMiKfERE7SIAnb0prDEgP+Fy9QTBRc5iCGr9ZwHSmws+V/F0Dq12VVuW351MT
         FCydoRQfzN3g6+i7NwJxf8qizU9v7F1kenlQlHMlPtTzMpnghLKUhkB4hgPgNuip4cGg
         zbLxXA5spxQjE2i90ekxd6BbKLpiGI3fE5hU0d88BXtXzCcj56qfkKoa93SenNW/8WIR
         rKf/d/rH7tYkQoGVRDxFxeUY0fv+ko10uBeKTx5pUCrrKpmIpzbuszKp09zbqcmticnH
         vwRk0BHJwAxEPQvsFRaG9VkkAThIk5nv0+9g0P3FbUmGqIzsOqKGfMjCj9ycWosb8tTT
         LIiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ME6zwSHDO9brpLtGbKI6O5Gc3MjI+KVraVBVIJIooj4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=y4GOo6skM+viQqXs/AR5oVvMS5aMjIdLb7Hvklp2BOKd8gxROMJZUudbM4/dlTHaiM
         sBcB2kWMNC59X3ZgcntaiNws09tr+kNrvvhb/X3y7o0vVED7jxzk2Rqt+rrD//GcFyN6
         EU1KfmoVraDk/yDGeVrFNeKLCvhQ6nEjJ6zc/fQK+xSWpp9X0ivYfRmdtgN3gn5cG/gA
         tgWzWdT12DiVH5TO2I1vHlajr2Nt235UTOXHM6eVA7WtTC9VYw4BTcoeWz8DRxWRkzO2
         9RxAmnzSF0g14xcwE3rIhutqfye2xt7j0+DOnvzLlAuDMMfBrmXKHLdAbjvkQKE7Fbtz
         Q3xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IsaFXhrL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604195; x=1701208995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ME6zwSHDO9brpLtGbKI6O5Gc3MjI+KVraVBVIJIooj4=;
        b=UGeTWIjAgU2qkyeiIVazjLoavh+0xH8AmdNmxbOD9VixtZnaLJkfM0J49r6ra6y9us
         JzD6rf4qKBKNSP0i3sGyQCpIlJ6tk3rwJUM+ivL/ozwT1/zLgkryc9GcKRA0Sp51+R7w
         c8/BOvEv/efreFmnhDzCHZU6o5Ni0S+tXSPHcXcnmhBSvJWGNuKnn8S2X088cn7XHfTt
         mB9fqDDMGqTrh8lzH6pQShrn4yChgaTE1MiHiTM1U7XMdl6YH9mOQ03C5Ry4R0Any67m
         FhRBQjCTFUM8tIWW/3Oh82xT2iqV7vpQUi9VXVfU2nbnyOHEB7/3fXDJik7fJCLYwoHO
         ljiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604195; x=1701208995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ME6zwSHDO9brpLtGbKI6O5Gc3MjI+KVraVBVIJIooj4=;
        b=f502sdZALW5ebY7I0oHp15KinlorJ7ao/xL+M3AZ2PHO/AV8t5MVWjoycO1ViZhls3
         A9t31933jkLdvgjafDirWlP9xPx0i5Ahqs+0x3YOp1eIh96RYIUjtZM/4pJHKQlftygW
         R83F+0YN4sv9nUdN06lGPQjBQHfkZNsQ+pA4yEmMTSnm9s7HY7XvnVdtBMJgp+zehqpD
         v8IKOyc3a6wbdDHhIdxx57P3GGSHchcDNqQCS2HOTUbKmGp9yqBugAAgamDMrw7z00rK
         uIQAYwOMa3bG92s8ZMU6xSnzEb4VOy1wfdFOwLwQVvjtxOE4TyzYpWjw4MCaUYOetUfS
         1oaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwwDWI0iWkmEx9aeabwYR7L4ZI89vfpTa7jEZRR5FeBkaY6XrBH
	JW2cDPYMbKO6FiJIu/K3bOg=
X-Google-Smtp-Source: AGHT+IEqU2hA2VVOuDTsXRk7t1pzI/xcH0ZAKs2xd8fxQrCB/AxxHxG8foI9IbSa0OGRvmtzKcdU3w==
X-Received: by 2002:a05:6214:76e:b0:672:549c:15e8 with SMTP id f14-20020a056214076e00b00672549c15e8mr420862qvz.55.1700604195492;
        Tue, 21 Nov 2023 14:03:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5891:0:b0:658:9457:9887 with SMTP id dz17-20020ad45891000000b0065894579887ls751940qvb.1.-pod-prod-09-us;
 Tue, 21 Nov 2023 14:03:15 -0800 (PST)
X-Received: by 2002:a1f:4b02:0:b0:4ac:5a8:f45b with SMTP id y2-20020a1f4b02000000b004ac05a8f45bmr770724vka.5.1700604194775;
        Tue, 21 Nov 2023 14:03:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604194; cv=none;
        d=google.com; s=arc-20160816;
        b=ZmX0GNUkhd6QkW8TxvRM5Ur9vba+FjqKJzlGWzdhlrXAXMeMj8+ngPKxklJ+rPdRmf
         4ElGQlJjBW1CIKYUeET6Dca2j4c74BEYhosnQOjg8YN8fnq/x0hH4wVXVVX8a795N+GB
         1Yezq8jMkJQsTzxDKVrcKEzh4EDZTrEmIQL8DoPXp5zPWeeOHP8LWNBAAU7LJZSQvenY
         3PalmB6WRXzugGdncnaeXrB4RijkW+suHAlPf4JLEfyDQWLQNLHecN6CPZ/bxcvzImDR
         nSAU6TGubakLEbBoAoZ56uBJew0QhMF56da7Ph/uHheMS1+PaAivgUtYz4webLNvhb+P
         8kQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VRISF6fjkFQLGNL8R/C4iEGZtM1pujBZILDlqB1XNVQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=p1D9hudhWJqRVeZ6xw/qDdCvRSm9c9ZbYMHuyvn2vyOfli0VX34kPc+HR57oAcz4y7
         1CQDPxNer+0qbZ1B/ZTGaCTmtzTWxXDtZycYfFZNprmxznQGPpZlpvnMbURv7VLps0cg
         HjpMLD0wkq5KhISkkt0+U8ToIIWqI2Q1wyCyV35hdQZPCzVrDQ1iFtIt7bBQhiVwq5/o
         iIexF3a9/eJF7ACfAi7+PG/W/h2jXDWUmWfxElwn1L6ni3OlYMGBQ4Z0xjBvGPhwaxEy
         JdI8YtpYHYvhpWfX3FlQczaCF/rfFfeRyJr3ASHUF8Nv+Ez4BYayweZf3bMCcsLxXYOh
         J0Ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IsaFXhrL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id n6-20020ac5cd46000000b0049d13f0321fsi934864vkm.0.2023.11.21.14.03.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:14 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLIWBp018448;
	Tue, 21 Nov 2023 22:03:12 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we7gq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:11 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM0mln013908;
	Tue, 21 Nov 2023 22:03:10 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we7g6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:10 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnb8i007091;
	Tue, 21 Nov 2023 22:03:09 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ufaa236na-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:09 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM36eC15991530
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:03:06 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9B54F2005A;
	Tue, 21 Nov 2023 22:03:06 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2C55B20067;
	Tue, 21 Nov 2023 22:03:05 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:03:05 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH v2 33/33] kmsan: Enable on s390
Date: Tue, 21 Nov 2023 23:01:27 +0100
Message-ID: <20231121220155.1217090-34-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Iqksl5PFqplYppxSjWNIWcOBVDkpMksY
X-Proofpoint-ORIG-GUID: mZHNFFkl6l84_fFQmRj-YhaEnX4HgOgV
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 impostorscore=0 suspectscore=0 adultscore=0
 malwarescore=0 priorityscore=1501 phishscore=0 clxscore=1015
 mlxlogscore=766 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IsaFXhrL;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Content-Type: text/plain; charset="UTF-8"
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

Now that everything else is in place, enable KMSAN in Kconfig.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 3bec98d20283..160ad2220c53 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -153,6 +153,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-34-iii%40linux.ibm.com.
