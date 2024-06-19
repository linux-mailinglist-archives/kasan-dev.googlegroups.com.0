Return-Path: <kasan-dev+bncBCM3H26GVIOBBMX2ZOZQMGQEA4EU7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EA95290F2AC
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:55 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6b4f87eb2e1sf23231356d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811955; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y3FzO91zsyVh7Runx7fuT4XA5LCrO+Osl2JsLWVrQ7TUPGS7AH9nEKtqmo2I8DZxBp
         g2vj2Z9/zRKE8a0A56gu4xCHXroClokGTN1v+l18rc2CdevIE30S3qjXnvzo19Z7xZaw
         j99pXdEkxf6/oCHWCAXZl9zR2cOLA2Mdh+NncJgEsMr9zRA25ZiPji7yWQd3VYStsGjY
         gbttCcDD1rd1pk4I2NOb8wBLRzhORck39JUSAldb+63ZMiQ1M+UEynGFdCh1jQwZdEBc
         AKC5PuWCuaPk6EhVjz1nPCq21iDqJTTKrrrhSfnOAbP1OthrBF1LmtQAmOl1s5+nN1BB
         h1UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GWykYHodYwGkZ8CAa0OKS4xs9FpH0VBg5T2sgoxQ7rw=;
        fh=bzKNCL9KZPhDjYPJO1HQyJ6MY9srYClm2tOVYcgvniE=;
        b=zxxXoCqzORypgnxBfwgaJ6+51CDdq9FXqRGl28ablKbT3xQdRg8N2CXP3NWkVGq1YE
         pZWFsfkbTmMKgEZIBQhEArsXQqJf5jNRhuKqZtxRavBDQezc+FE49wDgz8graPImwMAD
         IFtlBbkgsu0V6sbKAmScweQ+SEvX372bM6SwWGEe1rHsBRo9jCPQbza5VvUbuJxEhhcK
         mM9oqUSk8XoHEuGtEnqD+/zF6pJIXJqTAIuwbBMdZtZ5i3QfARxlZtTNC8DuA8eVjvao
         ZX7/vNHgCxG1XsxlZYC8+J165o5b1qdMESCeM4zMQBOtC4Mcqof8lqaOYEJUplu6HatK
         q+9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="NQ/1vpE3";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811955; x=1719416755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GWykYHodYwGkZ8CAa0OKS4xs9FpH0VBg5T2sgoxQ7rw=;
        b=ZWdSYsx/e5fcvNCwX5/0+TC+cC7WQQ7eXHI3fWgHjtw7CNldt6wmjhj24zsFePCrrN
         jPMwjjw5dhV9wTP+0kM7Ni2fLnXKn2Y+NTyHofnyG1DrXcXYcTxs2RkPRj/t0SrU63S1
         ikz8lCeHMOaTgmUsxt+t5aHGV1dqHd+mZd9ku68Xz2558pK78NGq4VJE61E5A67Q8gh+
         drBg2G2MWf9u+kpUIuvDyuBhEoIJTyTVOmU+0ayexg6hjhp15cBbGPOfol7Mg3Qq1k8R
         fJVeHNXigOZJFSBsvAw0yBlacVFYsVYMv6u3RfhM4eqtX3HinxVBsEmBMfI/08PgdBge
         7Urg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811955; x=1719416755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GWykYHodYwGkZ8CAa0OKS4xs9FpH0VBg5T2sgoxQ7rw=;
        b=P2sxKINx7eHYulS42vXJATjyTvLlveEKhF7nzHlZl+Uv+/eCHFvs5T8K4t/pi9aim5
         eQLQvL6YEJ+idBfP/f5Bx/8KSVfBU6+j23/NQizUVO07DzG8+gQfwUgzdkINgmz49z4w
         tQdsRzfr9QrvC+3yytWRfwmvftmnQFCs0tz4JMuNG/SuBXhVqaKmo/py8MH+kGNRVltX
         7jTUuUbR4zjpYEuigDidsfsA9QsG+zjxWCq+slEBSDSY674BtKLTasDi1JMAZq9CnZYO
         wdcYN9z5B6KEynLKs/T3hcNL6BZblQIlpF6lnJtrcfumOR81H8MyfbDQ4QyHqBlkyaQK
         nBbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeXSagQtg884hp3lYxcj4Z+qNH5IGVnTSXiynLCh1Vn2zxZYHMQqjzv/kesSTOiEyLAG0k1Zg3mWeJb9HbuXnBzmO/Nqxzrw==
X-Gm-Message-State: AOJu0Ywvuirl+YClFj+LVuXiAhEg1+KF53HU87buUC9L6qSavtvPgngT
	X3yAOpUAM9LQRJJNTPRJHKlcYR9N8/UvymSVxMEymID9ZwB26TQB
X-Google-Smtp-Source: AGHT+IHv9mIeTKa6cDXTCuBnJ3dwkUwcZxYz7Nt5GnNwAgtkGGmj8aY6WYefzuRm02Fhc05ZsDWWQA==
X-Received: by 2002:a05:6214:14e7:b0:6b2:d69d:a2d7 with SMTP id 6a1803df08f44-6b501e24638mr27107866d6.19.1718811954830;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:568c:b0:6a0:7a41:267 with SMTP id
 6a1803df08f44-6b2a351ced9ls93958886d6.2.-pod-prod-06-us; Wed, 19 Jun 2024
 08:45:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7ED999OA4nSKWIPqK/gl9Uk04TtcjKxKf7l8s85GZvoRr8hsGb1l282VynSVs1yKghpMv3r4fy6DF10NARAOUAzYdgAXmpsJmmA==
X-Received: by 2002:ad4:5887:0:b0:6b2:af2c:f99c with SMTP id 6a1803df08f44-6b501e45da9mr29438936d6.34.1718811953963;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811953; cv=none;
        d=google.com; s=arc-20160816;
        b=CUJZ1R+K86/8pZgJt6vG9Y3MC2lY6ks5xNV3hOnPcU19C1Pe+LcTwlHIUOlKNBAwZS
         19Ya+YUBSEis9Yz1A3ZoNAOzDqhXDBPSocdutVLTQSuhWHwbRj11od+dcRhULRx493Vf
         kA1eVcgST28iXREkeBw/OZnGxsMsJDzKkLag7zWergxbBqmISxvMKp6PUCRGWGhjQTjt
         c3+lhsa1ADBDgMoMy/iBUO7H1tNOim6AXJQNzTgnfaZ6U/7LUK+UXDiQNidJFAlpAPBM
         FG8lYTezgCdAfly4tfGuLVNZD/imdPaZRXf9Faphcy6Ic7fBalhsBbP04c/lf5z+giTO
         GCaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OuTJsGR9CKQp5KU/moT9q7/MyfMfBzEfOFMR8s/AFMc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=UahmZcJDFqteOjnXVXuJcNT3L6WQm6FVTcDSFD5oWD9ipNmPqjIcdWLDazQy2fs4YN
         hTtDfavyyV2MGaHILFzj5jdl/1mIulq8FdytGM6O1YW86BoNr3kDij6ZhrgqlGXfQXru
         6/l5eq24ulwC0eorxKRObrF60EEyRR5WuXq5cJihzDmhmvcsJvCgrFdHdy1/2N0lop42
         c9rWePlwncSrmMFoHGy9zp7Pf9efAfTT9rF/qcKRIsm/fOgY3O8dXYPOYnnbkI8kh5Fv
         EIPNwABNHuUdGnQsFHvMY7TlMDKGBM7CBQkYHLDyq2rWbJoTI7grK22eACQd4Bd8XDCO
         puLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="NQ/1vpE3";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5b58bcdsi5091626d6.5.2024.06.19.08.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFQhVb017889;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg853u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFhG5m011246;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg853p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEaA8I009941;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmmu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:44 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjdWB34275908
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1D9802005A;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C2EF720065;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
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
Subject: [PATCH v5 15/37] kmsan: Do not round up pg_data_t size
Date: Wed, 19 Jun 2024 17:43:50 +0200
Message-ID: <20240619154530.163232-16-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: qsJ8CmVlMpRqxH0BLyNtNlIww5Y0LD9w
X-Proofpoint-ORIG-GUID: E7I0JiUt6oKSlnECFVkmuHfxn4Vwt2Jz
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=972 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 impostorscore=0 priorityscore=1501 clxscore=1015 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="NQ/1vpE3";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

x86's alloc_node_data() rounds up node data size to PAGE_SIZE. It's not
explained why it's needed, but it's most likely for performance
reasons, since the padding bytes are not used anywhere. Some other
architectures do it as well, e.g., mips rounds it up to the cache line
size.

kmsan_init_shadow() initializes metadata for each node data and assumes
the x86 rounding, which does not match other architectures. This may
cause the range end to overshoot the end of available memory, in turn
causing virt_to_page_or_null() in kmsan_init_alloc_meta_for_range() to
return NULL, which leads to kernel panic shortly after.

Since the padding bytes are not used, drop the rounding.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 3ac3b8921d36..9de76ac7062c 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -72,7 +72,7 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
  */
 void __init kmsan_init_shadow(void)
 {
-	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
+	const size_t nd_size = sizeof(pg_data_t);
 	phys_addr_t p_start, p_end;
 	u64 loop;
 	int nid;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-16-iii%40linux.ibm.com.
