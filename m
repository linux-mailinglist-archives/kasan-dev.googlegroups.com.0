Return-Path: <kasan-dev+bncBCM3H26GVIOBBTFFVSZQMGQEAQKQVXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 303D49076E4
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:58 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6b0665d2f9csf12598646d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293197; cv=pass;
        d=google.com; s=arc-20160816;
        b=MXxgNg9wAkukLi4AIucKA+BUAjgAnrcoKbV6MhCQ1tG1RDdvKwXKa43EzPytFJ+yuq
         HvjVC9zsilOcWQZ4ctUyPj+fKFdb5za/FcUKutdYi9ZvjefD6XkEX9Sdmc/Q2yN5Jz/k
         gLhbJZLpWKSlCOilnpHLuaI6Cg3pDCg4YezB6Frdd0xB7e8xt5lfnhnsqZYexZ6a09I8
         VogBf2C7Ek0HvibGHdBiMEO8oPhA4b4KG4jgqWcxN9sznsPICcWq4pVYIZ+yqqZTmaoS
         WPL8lzpad+N3TTt3obmtbBpphsHmjbXFE6H3sBhzzSjJYbaRLPmI7pa2oCf6ygODEW7q
         delg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=00oyhkcX2+3peyRlcOa6g+Im7QUKqGrHRVvAs32x/Uo=;
        fh=kHfjapVboxAqoTTMumnuNW09PQVuE6Epj7KH1c5GmMg=;
        b=AWQsCOAeUba9Cpg3Ecpxzay1pggfA98SNGbti/2sJZq1bEvu911dla/igyYFyf+FOr
         X95ufgwKQa6TWG78vwTYebip7hi6zs6FPFhtU0F1v06/4aLA9/yk1w8fCFn1r8SQzeSl
         RQcrYcvnqUW8YH3whaQmF2yI82MHCyuRR61S38mTOUfROiydh42ZVyQmN+wTUWnJH3Er
         BWwposx7GAqs4zi7m4IhwAHLM/cak6lJcb42nyIRTQoaCnl//P/bwAhr6Ht/WuFo2S4L
         9JG5aAImrp5bXn+QFlSbl19w5kb6nnyCu2EJ5zdS4twzmRJ6GRPHvCelLJSXMRLVEn1y
         o1qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BukJUSkj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293197; x=1718897997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=00oyhkcX2+3peyRlcOa6g+Im7QUKqGrHRVvAs32x/Uo=;
        b=g5W8IBIwnBHRGVsYzmFx6pFaYVmae2apOq6MnFCfTUNG0TX5VaEgcbdkGycLeK/b9/
         EihwiTYQh4YrsrX7rsjbu/f7UJFvtYIS8Ps9l/IV6ldxysQFQNUy3RcFsSNgYAxuz+u+
         tnnxpTrN1ZTRfTy23MlF1AmH0wpkCBg+5zMNyhjb5gi+GExxzMvWVCyUQNprqul+z3Zy
         Bgp53JCu+CfmoW4WDqYa3vKXqJmgUxYtBtNMuhUBBr24QIiuGPtxrPibsCP+XxiH2q3N
         VxPFutdg4hLaoR4vMy4iOGRB0/rbF0bnnFIgnefSj8MEL/IM9qndluNZDlorFZC30wJo
         xp4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293197; x=1718897997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=00oyhkcX2+3peyRlcOa6g+Im7QUKqGrHRVvAs32x/Uo=;
        b=umHw4zD1l14uyMTSy8RWSKgrq2rcpm4Uopmyov0tYqFOo2pPcSmSpEIBBNzI3nY2X7
         fibdO9FQD7IEdr5qLLXoQvpnmtyfzepaYp4LzLFmnGsgRIdii57Yw6+3O/6Ys6QAG/AP
         tbRpKne2o+OHu9BOyTiAn8u6mUj1KIyWB4+WButuhyfjmqN/dPey4dgoDlzzsDINBabT
         sHaPDAgFc8KA4b3GBU2quWkIgfz3QhTmZZU3L0NjCzA+k0yJ5kayrIqKmkU0Bf76b1PY
         crE/rvo/EliL6n5ENnZtYcnVLjv/k7v1xzl8mvnDEKo2DSwR069ZXiZ5XKyVXE0fxjzZ
         MJJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhnmCeN9S1XZfGzaSQEedg8+y8aJKBxtJpWKU0rjyS+N3EYVOFykrI5Mh2WMIP6bFkU4mjY3h8hUI5EFYZ1NpmsuUzg13fww==
X-Gm-Message-State: AOJu0YxexMWpk2GGjOL07D1oYehcpGtyTGDBR1wHlRzQVwqfqE0UodsB
	9hRQ7tWtewpGKKj+OgqMKtohYR1EsDwjI4OXGmUEyb1SfDe8FrH0
X-Google-Smtp-Source: AGHT+IGNxvpVwfg8DWatMB5wJ1QtXCNgdU2oNBSp3nJS6A6YGoFVjTzYHEQrVRTtDyOzcBrNIe6a7A==
X-Received: by 2002:a05:6214:4606:b0:6b0:77fb:8f16 with SMTP id 6a1803df08f44-6b191778bdbmr54234096d6.21.1718293197020;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:568c:b0:6a0:7a41:267 with SMTP id
 6a1803df08f44-6b2a351ced9ls15573316d6.2.-pod-prod-06-us; Thu, 13 Jun 2024
 08:39:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUoX5XCEZvVps4F9hHuPGppRvycJRsWHXhXGUJrqSB39m/4Br00k7VuijFehwL/j2q5FY2gMlOAyBY0aPHZqz4vt0xYg6wdTrAKXQ==
X-Received: by 2002:a05:6214:5983:b0:6b0:6897:f250 with SMTP id 6a1803df08f44-6b191684285mr62814446d6.16.1718293196130;
        Thu, 13 Jun 2024 08:39:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293196; cv=none;
        d=google.com; s=arc-20160816;
        b=Ad/pqtYSZDwcN0dMnHk1vNROHqgNWTqzt1Co7TEc4px5649wLmAPe5BkdH11bH0LsD
         sXYLhwyylHK2MSBKkJBVGTiLrfbJwYo2iPOkLL291j5GXoMi4B101qXjNIAALFQM7RBD
         LjLPKkHD/dx9XlsK5O9IMon0EfFy1u/XE3kUcWVLCreoq22Tclf6mawS4+GilyZk99J/
         jv1U6YOJq/3NMdGZQNycxuyYqNXrUw8N0kZp+Pz/plbs4raVMon6rDpJapiUHJPsE27/
         e75o7hPOeq5Et6xEZTJrRuUwE6o9RSTBML+6Ch5bP5rfTRXgBt6DNSCpG5g3d9Ay97UP
         00Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eOJVqKOJuZasA86pPY8j/wtn7XC9Zj2RO1nXjWn3Mgo=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=dz+1ue5TigOM1cwl5LfqjecY1d6Dfbe+hsbapH26/5cjH3Vq5t/2LUexu4+UC6WgYQ
         hfhHmVflhn9OCAjzGhgZlbQ/jmpjxkwFFERHjlBACG/fdZvc7BWBitxJbpFenZJd9WbF
         aqwjKV5Iacwz1BQ9MnSr9LKs+PEY+jVkSPvBtFye/U4CjfTM8nTHXzRUsTJqxg9lVtO+
         oGKetg7W43Zjo/rxLI3S1Pr42/wEtpYaFima0JNPsjHT5tvOaA9QqGShQGzHn1JMUHKg
         wzvh6PKYAA5iLz0WFbXT7dhJKNvojJ3fNObJUJMgYcqI91N1VXouUNNUZZrrUL8p2Mra
         ga/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BukJUSkj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5b70a3fsi1105126d6.7.2024.06.13.08.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DDU5Ym014079;
	Thu, 13 Jun 2024 15:39:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1pa8dky-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdYRq029998;
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1pa8dkv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:50 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEh2w7027209;
	Thu, 13 Jun 2024 15:39:49 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn21197ag-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:49 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdhMV56033720
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 61C6620067;
	Thu, 13 Jun 2024 15:39:43 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E2ADF2004D;
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
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
Subject: [PATCH v4 19/35] kmsan: Accept ranges starting with 0 on s390
Date: Thu, 13 Jun 2024 17:34:21 +0200
Message-ID: <20240613153924.961511-20-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 0eY3MbH0HS6MivN5xeWsj9Ia9OM8Lgw9
X-Proofpoint-ORIG-GUID: cRp1zEfmWI6SKhzVPAlyMPh3l82rIXRt
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 suspectscore=0
 priorityscore=1501 adultscore=0 mlxscore=0 lowpriorityscore=0
 impostorscore=0 mlxlogscore=998 clxscore=1015 malwarescore=0 bulkscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=BukJUSkj;       spf=pass (google.com:
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

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390. There doesn't seem to be a
Kconfig option to describe this situation, so explicitly check for
s390.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 9de76ac7062c..3f8b1bbb9060 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-20-iii%40linux.ibm.com.
