Return-Path: <kasan-dev+bncBCM3H26GVIOBBLH2ZOZQMGQERNYR63I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 615C890F298
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:49 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-44212083709sf20860131cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811948; cv=pass;
        d=google.com; s=arc-20160816;
        b=OfQ88JMmFgy4X6OFJMzQ4S6PXApKx5571YE0IDIscJcfCC3c8TYiD//J1rX2XwV9mk
         mmQhIH/YhAe+F5yYzRy5YqEodf7T3OzNE8hqhJ3JZKRe/7pWDH9VEwj7kvOFdjR3rPvT
         Iq98qzogrM9JYz6d5CNe4yGgpEgsNCO1lS1xNm5v7Ux97EnvnIOHIJ2zLZw5/HzhITOy
         nwQs0RnRXYQcglll0A+S+aERUUPF9mgQ/Z3V9488VOhlvkSz7AEnWOMjn0X3RbN7mYxt
         j4+Pf7WcOTNaig0pBq4YsixjdOt44G2x904SUfE5nxGsV2JQSHr6icBIUJWAWaeZNuuU
         EgHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gJSEeXSuoaOxq1TaC2jYqYGBCDkTQG/l1JSHoQUnYRM=;
        fh=bwqSMoJhzwfPzH9Pb1wre+Wz9th3rHloUGQghV8hBgQ=;
        b=T16Vf0zjYMukcd90sfm4lMA8UwzCyXnCiCt6iN7rOlgjGkbV2r+thhVLPaa3hz7yTu
         OekQ1D+G3ejjaBj336BI31bWc4VP44i04ABtyi2g8Y4T3lcB7CUHwef6K/64oBCtvxOq
         50iJrZIO1jExk+MCo/Mx6OK5G6fnwBA2Kk1S6Xo8/4Kcd+zfuS8G9/hmXCyRl14zPa6v
         QoEdQ4OtF9LWzNKjCcNmB9nzAxbHGdbnaMvTBGn5fSCzpynyIv9XTphG9neiV6hF6qnW
         H2dc9YFMSkNLtX9+yUIlUc+/RVjOUp/QKblXaiRU5SGdAl4roxNqcJrTzvPgS6mZKox6
         pQrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OWZMRIJe;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811948; x=1719416748; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gJSEeXSuoaOxq1TaC2jYqYGBCDkTQG/l1JSHoQUnYRM=;
        b=XThzxf+6l9BqbUe1GyVJtCUT2qAOWYXPZL9fG9ran3kYvVttyXjm1M/ZTrG6kN331K
         41uemSt/2/i+CgXTVGOFisLN0zQADh7uyFf4iUfDXdOq4IhOMsGDqJ/r5qRx6pEGUh72
         0Z7O48Qc9vCQJWKP4YkaIbij2rEccl7DEI6byLpdXvk794yNy8k9+qLGsYI4xqkvjVZw
         tyDq8AyqDq0wnOZsigBMSNlbN/ju9oR7ssB0ZtA+EdZ5mjaqR6dTqV2ATPp1G3NKLNv2
         GThe4rq+QNHfy/vaAJuvoaXglqWhzGbdKc/eGdiHwmPp+b5i/Oo3zHCe4Sx65AMJCzEu
         K+Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811948; x=1719416748;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gJSEeXSuoaOxq1TaC2jYqYGBCDkTQG/l1JSHoQUnYRM=;
        b=aWq3o3d12mqm9yHBSbZ6BgReh146IoVxmXlSzNbaEOsIf86nwqWb9ZiAl8Mw4TSY0V
         KmXjFkktDPpkSmeQo7/QzqQpJRWK6/cMkKYtHM80XwOfq1T55yXJro0PDVu322DltU/O
         Jd0/7j45NRF6Bh5XSo0VILhpzpHu5DDO32/YzsChxEMTCHOpy1UzephEgNxunz13n09k
         2q4kr+bOKE6MYj4TeMZE/KweWJlW7nm2TGJ70bjfhEMaL6qaF/H6eYxDAroxHOwjFd40
         GSBX7sinvBMxZyvLb/WeUNPe7X+4dovTenlyt+l+jVzQehPG2oJCktMa4XV69qkVaWpk
         19PA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWz7fFxj4xIUeNN1VYSK7VJ+JD/lrKLgXht9+9cdznus4KeBwxX01F+KsuImN+9/6eXdAlCVf2GJ1B+N5SFPHU8K5X+i2h93A==
X-Gm-Message-State: AOJu0YyUXrwp6GgbSFGpr3Xl/Z/N770ZTimgh8R07LtgzPU2rldUSgVx
	8gwyH3CM6h1GymjFpjvX2gMZhRKLoBOGUiQycoglOj0ufhMvDDLU
X-Google-Smtp-Source: AGHT+IE0/WPB+1EFFJu8+N0DY3xfNCaOlr0qYnH+F2n1OuNuXazeSU0PpOLOZrDgAHtHqVQeJ2ZGRw==
X-Received: by 2002:a05:622a:1481:b0:43d:dd5a:5d52 with SMTP id d75a77b69052e-444a7846a8fmr59855041cf.2.1718811948214;
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:124c:0:b0:440:f0be:4bd1 with SMTP id d75a77b69052e-4417ac3c289ls127955991cf.1.-pod-prod-00-us;
 Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVl0yZgYFHXFFkkBhK8tVh7OXwZHxvJm5CIgGz2hXhqQmzV1X4N3u0U6Yg3P2MF8DljeLpFCygJdrY/10T3wmwDhRko8uJOT6P/cg==
X-Received: by 2002:a05:620a:4711:b0:795:4e69:5932 with SMTP id af79cd13be357-79ba7737d08mr904792585a.29.1718811947303;
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811947; cv=none;
        d=google.com; s=arc-20160816;
        b=HlDeCFVFMljZIDGELm+uSEoBY0Ty+9kChYtwlnl54RoR9OFWzw+gbe+kVtTQJkovNe
         /7agi9qNj5isBh5q2lV6fmsFuNl0XDkx/PrHV/Tj5aPVsTnfSeWNRRxdgWOdJ4tg8yg/
         6P7XlDHp1rAo6PkIkL9YeuvCev0ffd6+Z3k6fKDxgcuCScY6OgerhEyKwSC/7BPLt4pB
         p3Cc7r6U6ulK5n6Z3EqZxMv5WtlyHv0nO4Onk+EB9LUNo0K8O/+cCQN0FgQck8epqrG3
         mS18Fgde6DR0J07hc/95EMPt2QOa/ZYOVsaK8ILvsqoifmLbS+wtc3e8MNfw319M8h6f
         ViJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v73BMs0EqfMCwxJniJdo3jdaknlggr5A1qJ50X9w6PM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=U5G8okepxnYP9V6+cLUQVyForECj+5hn4bE4eJxE97+w0XGQyoVCEGnFwS7g2c21YQ
         Bgobb36aN5E1Vewt33iKHpr83GP1daXqLgSRZ13DLj2QkdmHokCersb5V8mbWzbnRuca
         A8cn/amiYnOZ6FffnfVdrcUp0cHCjU1FYsCQwKRngbvH/NrJbhhaSpgM2ZCENqeGP8PX
         qzqK/aotsMReF25XdsSideAJ7kJ6AH9Uc+67kUbsoSuKPZzea1uHi2FzM27ODVEI60Wg
         B4HJVS9bxRPVBPg9R69F68Eaxtxp3mz/POr3V+LATQloYgyBjHcOEN0XlEdhY0guJOUl
         ZbPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OWZMRIJe;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798abe4f369si58635485a.3.2024.06.19.08.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFStjf014449;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1fy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjfNR008972;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1ft-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEuVWH009478;
	Wed, 19 Jun 2024 15:45:40 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmkr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:40 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjY6D42205454
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:36 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8AF5E2004E;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3A76020049;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
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
Subject: [PATCH v5 02/37] kmsan: Make the tests compatible with kmsan.panic=1
Date: Wed, 19 Jun 2024 17:43:37 +0200
Message-ID: <20240619154530.163232-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: RWsOexlj7_0iWLLyvnapnr06durS79vv
X-Proofpoint-GUID: gZnZrvku0DfDeUyU90WAlNuPdsXG4CTD
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 bulkscore=0 malwarescore=0 lowpriorityscore=0 adultscore=0
 phishscore=0 suspectscore=0 mlxlogscore=999 priorityscore=1501 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=OWZMRIJe;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

It's useful to have both tests and kmsan.panic=1 during development,
but right now the warnings, that the tests cause, lead to kernel
panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan_test.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 07d3a3a5a9c5..9bfd11674fe3 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -659,9 +659,13 @@ static void test_exit(struct kunit *test)
 {
 }
 
+static int orig_panic_on_kmsan;
+
 static int kmsan_suite_init(struct kunit_suite *suite)
 {
 	register_trace_console(probe_console, NULL);
+	orig_panic_on_kmsan = panic_on_kmsan;
+	panic_on_kmsan = 0;
 	return 0;
 }
 
@@ -669,6 +673,7 @@ static void kmsan_suite_exit(struct kunit_suite *suite)
 {
 	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
+	panic_on_kmsan = orig_panic_on_kmsan;
 }
 
 static struct kunit_suite kmsan_test_suite = {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-3-iii%40linux.ibm.com.
