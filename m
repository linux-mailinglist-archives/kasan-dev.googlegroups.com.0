Return-Path: <kasan-dev+bncBCM3H26GVIOBB6WR6SVAMGQE6OJY5OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D4CC7F388D
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:36 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-66d91b47f23sf38092976d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604155; cv=pass;
        d=google.com; s=arc-20160816;
        b=V+iTU9jvQejDiEBLUHdRA8mko7U2941oDAgyXmkMmvtDpa6eLSeG5a1scZ5TtLbi9+
         GgoftNV5v+br6RTmeXJkVyiwcfX5vCjryl3wiMXOdkAuyGRpXz5/q8V9mOez7r17yH8Y
         9yFmhvQZQbgbAhaWFIawqi6X0Y4GLxYItFyMmvUaQkn+C+fI+lgtZIpAs/o3RV0DmggG
         1GDgPUAdwzeKD/aqsTUwHjnL/oBXOYlW37xaQqNaZzyvXBCL3wrU6YYecv2R5XHRRdOm
         YThJ4UdU9ExwWipNKkyzsDxaBjxSaUMpPibizlWmLv/aKa1M6isH6QmZZLx5eOmwlOkw
         JPuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1tdtU6VG/gy7nkdc4qHZjZpGWnDQ59cxAVz3AY9loBk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=f4zkS9x0rbQNCRsANyD19I7oQABlthMYgXOSiJYEMl7BasoSP3mctDB/gUD/rrPMH4
         ydeVFihbZf6Irvag0Y+JkIfGp1FF5ERTaX1k0UUdQ6JADdxsdaafS0+o30zbe50ylf7b
         APxH2D8Y+anq4KMLkUpgSPyJD70EsY9WEpKZDxdZNfLX9hy9+NVED9vcxZu7RbsxX5LO
         Oqs2Mla2CbkU4gPSoN3qLQdkXZqw+wbZ3yhocoMdLyRBzw4peWSPeNmqRL52PRwtKcLJ
         6Ctq4zQgtgrOJE/o6GJeaJ9wylOLbB+kzRRVZuIr07Q3SE81MONjz59Lv36UX4sl2u+o
         gyrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mgSXs3ED;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604155; x=1701208955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1tdtU6VG/gy7nkdc4qHZjZpGWnDQ59cxAVz3AY9loBk=;
        b=Cqvqe1y6OeDqMzX4rSG4e75NqY4ZRXrRJWBTWu6ii9z11swk3SH0pQUJus7XAh58G5
         BimFHcV9iejvNpWF2zC+HRoRqdEJ7fZRHKSkvrioF66vbsR6zmxxSNvVioU7cgh/QQRf
         5Xx3aFj0s3mnC1FsOjOffq5Ave4I/VGEz9DNwZ75ciAtr4kaz5/qzg3iTRF4QjVb5BsX
         5bAEx7nH1Zd2NhNthzZHuIseCec3Js1IIS73po0QyVqIUl4wMnupjzEmkihMnP4ueffb
         wG8Ws6x8xOTt+gMKIrmpFcOYBoK6x76hQMNeDhx4yWee2u0BzKzQqIq46KHcQwexhPTp
         6Ivg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604155; x=1701208955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1tdtU6VG/gy7nkdc4qHZjZpGWnDQ59cxAVz3AY9loBk=;
        b=L0wGv0c2wxAo77BKqzJvYkDNdNzNRZM9KiwfgpmDrvaYfvTtO8mqwzcdKSZr++F2ey
         lb3BB9rKVUftNCqqg/j3jSlw6njZ+J4WucdoAHIefyNu69foN3iAnAW2wfaiRDJi+D3u
         /w3aMZejJkyRhyf6nAjEUj2IHWQsqkZSOr49X5I71EQQEO5afRYDHiJqpg/AysfRfJK2
         krirhv/AaBh8CzJmlskqv7sTYb2t+4vgBUwqEhu4rPxB+8nbvrR8EbC2rfqStHsEVuGB
         OLbLRgEbDjalF/u3/ePOl7AhaQmHp8TkpiZvSBR7ThhkHYN5/M5iwsC0FPYSeoOQXgyk
         N1+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx2HvfW651IbYvsF3jGghI/TH9BEB1eYk2gv5JDKMDE23esISm4
	tha4bd4VFRGDeU3CUbIzGMI=
X-Google-Smtp-Source: AGHT+IG0HIiiGYEAOqLujrfP6NJnbf0UP7qsfK2FFxLgjMLgpNhEijw/IZtWaJ2qMqqMOkMPYD3biw==
X-Received: by 2002:a05:622a:181a:b0:415:1752:1be5 with SMTP id t26-20020a05622a181a00b0041517521be5mr547950qtc.31.1700604154975;
        Tue, 21 Nov 2023 14:02:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4d07:b0:423:72b2:6135 with SMTP id
 fd7-20020a05622a4d0700b0042372b26135ls911167qtb.1.-pod-prod-08-us; Tue, 21
 Nov 2023 14:02:34 -0800 (PST)
X-Received: by 2002:a05:622a:1485:b0:418:1ae2:86e0 with SMTP id t5-20020a05622a148500b004181ae286e0mr538247qtx.54.1700604154218;
        Tue, 21 Nov 2023 14:02:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604154; cv=none;
        d=google.com; s=arc-20160816;
        b=ezQCvDAwkCrKD0Q6dAg0bpZ0jrlVDU618k25ktVlmaQLCCCLvatfk/5K65zoQPII2L
         IblEzXbP1pqYznYW7CGNKf0SgWr+KkjCRQzzh7L7L77KTkPKscg1cok4Ekrj0eZxFmFR
         G6uzNObjXyt4zmxQB3Pc7ffin7LINBZwHBQt8fhXDw1Baz4OZonYTpKY38t+UX0GUqjB
         Cx92jfAvGbhclmB4QBqKNc5upouGrSoJXdLAvpvcBvBnBSeMCGSeomzlbmah8k8G5JVB
         Sr7mzGGViA7Goo59Pv7LbDSxJodY2T6R4vKBFcWVd8Jw0Nb9fqXqWwdss1rzNFBBX82r
         9VAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=f3AHgxo7CJkEcMIYOZw3Qvaw0LNtelk9GucjvrirN9U=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=cEGJgECtTew/6bJUULRgMRlo2/6cQtQnUuEeOEhQLdGwUT162z3LWPEPukS27cospE
         hE3K00hwz5D7ejHCK/Bf2n6LHAuIC4uphsSYmZ5l9FPig/QmcoTbVza5ElZAzK/bKjsM
         Uh1UTBs7xeOOTf0Kvn9g3Cgznh3pm+0iorbZwuxZCwwrDlWvchKH1uQtDGyyExGBIm3B
         oYoa8hWh0oA+mevdj8SEQ55MGE0/RtKYtLU3NANUZvZigMFCClhmuUcJ9qt4gEx27JfI
         97IMlSVo8Dw6CK/33ceGZe8kNykbb7dXObhXuGzYJtnTWZDrP3bydb6DB+3IA8Xu/+Hb
         ykyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mgSXs3ED;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id bv20-20020a05622a0a1400b0041812c64692si1666245qtb.3.2023.11.21.14.02.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:34 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLfG9l025275;
	Tue, 21 Nov 2023 22:02:29 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a1a0f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:29 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLfvNH028432;
	Tue, 21 Nov 2023 22:02:29 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a19y5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:28 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnKcO007619;
	Tue, 21 Nov 2023 22:02:27 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf8knuq22-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:27 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2OkV10814012
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:24 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 19F112005A;
	Tue, 21 Nov 2023 22:02:24 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A203320063;
	Tue, 21 Nov 2023 22:02:22 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:22 +0000 (GMT)
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
Subject: [PATCH v2 11/33] kmsan: Export panic_on_kmsan
Date: Tue, 21 Nov 2023 23:01:05 +0100
Message-ID: <20231121220155.1217090-12-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: xUScG0AM4UlYqELexcF37HUScvwlgRBd
X-Proofpoint-GUID: 8PySRi5MwXxotbKPHBjzYmkONm1nC8Mc
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 impostorscore=0 phishscore=0 priorityscore=1501 bulkscore=0
 adultscore=0 mlxscore=0 spamscore=0 mlxlogscore=999 malwarescore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mgSXs3ED;       spf=pass (google.com:
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

When building the kmsan test as a module, modpost fails with the
following error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for
modules.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/report.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 02736ec757f2..c79d3b0d2d0d 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_lock);
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-12-iii%40linux.ibm.com.
