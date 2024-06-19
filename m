Return-Path: <kasan-dev+bncBCM3H26GVIOBBN72ZOZQMGQEI4RFZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9396390F2BC
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:46:00 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-25ca2ebb7b6sf666608fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811959; cv=pass;
        d=google.com; s=arc-20160816;
        b=qYDD0wX+siU4Qzi+MjO5Hztw9sz3QjBrIi3OONkA/svEtB9knOh2RNlDHNvmK2hWZk
         prPAyWmsavmbLD1VkHgOkWPSS02YgtMV8aULg5+Yxk1KtP/gk+64pR0q7fEUANTUFvqb
         LfZkHpyhDm/zM1Daw49mjep1CzhAJBSd18kQHXR+PyGY9PosAKQSImBsA66boLR2btnm
         hUQ5NXn8nf2XO9V/bOhs/W/1JW/U1cp2WrttJ7v9wMZ3Pxk1+coRtfKkDmDDiaGhBihF
         86Srio5RFP1Mz5sEcJeLVsZdBwb2N0u9Ves/CAJtOkUjeCxquOTcWV5k7Kc7e64xAaCf
         l0gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ClxtGgJO06zjTDdBkd26jVO7MVcukG3h+nB/ytnTs4w=;
        fh=lLwy89VqZBHaz9B6YRBxC8mnGraYCg6+V8YtMil/IVU=;
        b=C+c8wmnRzIxzpz47GsA0xpyOJwE72j/sEeVoegXaipun8umOAEbuvW1eXUvZn20H/K
         c+3GqgNQoG6KljDv1ZRTv+ne49erbBTJekOKV28Dt7BIx27nDKU0/qxpauTe7A5bJgyI
         tpedJZ3PSr5QvBa/UQhAhUQFOPFDOKMJaESNd2TG0kV8M0FYEnIVXjf5kKL7WUtIdM12
         pqL3oC0Aj4vWC4t1CU+7qrOblTYtziItGIYmgalrBZH9AFDzGpd5sXH5MDr7dzW5yAru
         tS5UGK+/Sy4tvPGIu219www5vR3CQEuM4OdE49589EUHcV+LvABXF9R8JGKZ0g71/WiR
         msGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=U8GCVwLX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811959; x=1719416759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ClxtGgJO06zjTDdBkd26jVO7MVcukG3h+nB/ytnTs4w=;
        b=TTyIfznNr4xgUCdj1PkbMkM8AfY2fFxUnWQPddw9GjJyR3t3KaN6wbDxe7MN1fnvDD
         7kiQZY6dC4ASdqFhR8XHliQzUozJSyWofydf6zHWBB9gh81lIC+4sYnzZpSV458+uETX
         rl/dE0h4iJ82p2o5sNxlTGRRDHpNFlPr3/95cPQi5Q5xh60B7k+SCaZWIza4U7gProE7
         QFpdIaBL79bA8ghRn2U9oWzYs8CtNrqZw2C1VPkfnbCEOo9Rr7FSYOB100T4oxghnUS1
         vjcHaGNfmQzMuY+dsUcZs4zBtUspmdLxM4f+TTuuMl1TSooCBy/z3z9pMKcNYyDTIz/I
         Eg1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811959; x=1719416759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ClxtGgJO06zjTDdBkd26jVO7MVcukG3h+nB/ytnTs4w=;
        b=INgNNn2xuim8/McklR3k1PgfJ471kACczCgEbxiMMNh3hzic+LViX1JE0HF6K+Yeob
         Y/KGjVTYptYAUCaAfjglPuFpLjIb0qM18zwjYi5C5sUUAdgyS9XMGZeH2DVrUr8Ps4cz
         Th3jU4At1h6S30Ow0NWGSq4MlfW8kUBVeAVqn2hP34DaS/qOSXGCiqIq/9YwCGNG4yGW
         gmXdqUDHO8kOcYZPR6fVNGgA/E/YOLvM4JSQWaBgN4oizk4o35g3+okMUYgjNg2qGPXj
         D9/s0fmaoD5y4+2lBLcAH8D7yC7QON4z9FCSgUSVE3XA8UCCmBdqhkQWoI0m595H+r/1
         My8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQh2lzyYELVb/LRNC2q32vHD0sahsYJ1ZiF0tfHk1Yl9BX77Nsw53lsS/DYyp+P+kBqt7UU/UhEL6XURSMue7X1SwH8CjWlw==
X-Gm-Message-State: AOJu0YwWWcX/dMCpPqt/JufOQAhRbY3IRO9quwQWuwr9VyEPq/0cumTN
	gZceTQ5+atZySoXgEAynvj7RS1i4PO7tx2vxriJDqwYqU4YpkhWc
X-Google-Smtp-Source: AGHT+IHfYeUHTz+WBKLLsCgE5RncmJ90JSU7nwFrlRJ9jL8AbfQlVDoI1p+pH0THA97PYHaBBswpWQ==
X-Received: by 2002:a05:6870:d14c:b0:254:9570:e5aa with SMTP id 586e51a60fabf-25c94d74344mr3382634fac.57.1718811959489;
        Wed, 19 Jun 2024 08:45:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d10b:b0:259:8c55:f25a with SMTP id
 586e51a60fabf-2598c55fb65ls576707fac.0.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbX/jJEfg5tWN2y2Clf3DsrWMNO6HWmbyt3GzmSzw2uNosOvhZi2MsmEQaua+GtfsRANzGAu+IQ0iUP2u5XvmYgNe8x45LlePAaQ==
X-Received: by 2002:a05:6870:63a4:b0:255:c21d:a9db with SMTP id 586e51a60fabf-25c948f4129mr3343913fac.1.1718811958643;
        Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811958; cv=none;
        d=google.com; s=arc-20160816;
        b=pTDodJKaWVfkP8ck4p1Afs0v/ecOLTGuDNzw2WsoKuNJTG1exQjeRb/gIxNPwdUrLO
         sNqz5//0mGUby/T59fH0OdnzzSWrHOrXRm29+Jc8lwBkBeq2cOHPv0U6SZxcIc8yaDmV
         3SpEmCbxO2tI9/tl52q923NW1GN/Y/EuyugJwhFZNCwwv64rxR5y/wYe7e9INa7cxzw9
         T24gAX1JReAabrXfu8K4Hj1ENp9Ov1qJ2q71ksxdaS8xhHYbZLtpKMzKsmegnBPp6W2y
         yYJn7WV/WA0OOprUcCzEV6Swqzsu0pXdo45SkQuhQbxEWAIa4hRil+Uumynq3a92+8Fj
         vTNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IRZnfl5kegw9DdaMeWWbTwWzCErv31wkZ0fJjvxbgdM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=e9ujTd+ZHBh2rtlO1ioOlucIDfUfzPIs6Eu6UI8L2TgjJUcKomhk9sFlzZYwnn8Scu
         tve8HMs9zJClFt/GF7McfE4FnuxuiCLjW8gjc2UDinJmI/rClQxK+w70Lkbefxz/lsB3
         PkQaMbsvJ5fdt6o2Plnq++34fjD/Oq5dC5XAgFypov31xK47Ylj88OQnABvZG6LzGatf
         8SgHyPKnl/h4XQl7bzpRxPyr62Al+Egcy0IJaOzgLHBwXaILycUeF9jGGhbtnYRYo7BG
         QIF3kOHYCFYED+uxn/0boAPJ9+iv2okNhe5Wdb0xzLU5Er9AK7y0eGodsxQLqRAedhG5
         TeRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=U8GCVwLX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2567a98fae0si600341fac.2.2024.06.19.08.45.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JETHMj000657;
	Wed, 19 Jun 2024 15:45:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8cp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:54 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjrsL027940;
	Wed, 19 Jun 2024 15:45:53 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8cg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:53 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFWnRV019495;
	Wed, 19 Jun 2024 15:45:52 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysnp1e4xk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:52 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjkS217891730
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BC86320065;
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6C3D92006A;
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
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
Subject: [PATCH v5 37/37] kmsan: Enable on s390
Date: Wed, 19 Jun 2024 17:44:12 +0200
Message-ID: <20240619154530.163232-38-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: _aFS9VMZNHeI_0QG12mn39Qu-C8A8omj
X-Proofpoint-ORIG-GUID: 2gC1WJMPx7ngoWvphwAauoxDM2L1Po19
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 mlxscore=0 clxscore=1015
 spamscore=0 mlxlogscore=764 impostorscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=U8GCVwLX;       spf=pass (google.com:
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

Acked-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index c59d2b54df49..3cba4993d7c7 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -158,6 +158,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-38-iii%40linux.ibm.com.
