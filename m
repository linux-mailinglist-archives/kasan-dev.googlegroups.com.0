Return-Path: <kasan-dev+bncBCM3H26GVIOBBV4R2OZQMGQEYV4Q56I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id A091A91175C
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:04 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-7ebea0e968esf172023239f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929623; cv=pass;
        d=google.com; s=arc-20160816;
        b=drGAee6fYsgQLBJP+ltvMlnwe52Al74NXnkgEV3PzV/Ct4Px+UgiflAZWlgypxLLRv
         Tz7Pigp4GIvLS5yQsYfDG53JmHjfRsz6+LbKkFwe23lCMjpPfZ1gH0RxBVAb3ghxmYjH
         xUFZyaMXs2wEzvM/COfZGBKXqg75xWSCW+9xhfYb5AyLfLj82HAOFyfQtgnUDMYjmagO
         wQ/JZPkEVUlyiXKSKne7320xC3AgslufzXO9THqB9IDbqlmcpi69uGPEahEYtKG7Qzqo
         tlqVLynZMO3+4r+oJPlcdHzXrJ3+SRL6F6+hNjNz3MBEPGS8ch4OwB+LKVYXgWanEodB
         k1nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/SyLB7f5iNJUNsIxrefaEsTSwn9DknHJml2kZiFKusk=;
        fh=R8X+XfCJK0yYx/BOsxuokITsZhXsoD6vbcEuWcAh158=;
        b=iUnvSNivpEnnU+lLD5m1cZyRPDMCnpg9Ow5ByMh4arE4LmafIgBA2UydGmIW9C1+nO
         T2cCRJjvju1YN+RwYae34+6u5EaJ+TscDiWVubmCHaVj1RsQnAqReF/ISCSIEtwB4BVe
         Joewz4SjiQI0JGNvWLoM/NTAI8x3B4EkcWQTWj507sTUajUTL5E2AzVRf+N9QF7w6Fni
         tt+tSbNQEQLO2YjKOvhmdmG+np6Jvlu49aTEDnagWtmC65MR+PVAAdOD6z94FBkP7rkE
         Chc8352fLQCbXfkV8rUlYJGu4vYsnehvIo4qcwuDh0fUfgbi1gXqbOY5GmOvRnSZ4+ty
         MAcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Hbp62VBZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929623; x=1719534423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/SyLB7f5iNJUNsIxrefaEsTSwn9DknHJml2kZiFKusk=;
        b=Tkjmtsgkl6/Boypm1C7ZgjTFRwz98mkBCP15U7HZVYOWalUGl/PZYxyD21b3AoD1Kw
         F/n12jcQ4pHYBovNNj7Vyc2MbuKaLPwuQ+dSwYNeCZYmSxiNM2AFKzP4UJH2XyMgsUzL
         MhpurODtqfkInPKqp5ZouqgyGkHJilm/79ED9LJYulWTzDMN0jSplFpbpLxV4FC8SRln
         2OGw+oDAKCzMWtCRAATn7B3kve34AqRjc0Z+ttQa5lW6T+hnL7ZQKq8cHLIz8lIm0JH2
         fjzuiGbvK/ePQk/+L7tYuprNap2Iv1GOpTHrDOIss2dhXLSoGPhdBZ4Gp8er+5BYXFIC
         t8Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929623; x=1719534423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/SyLB7f5iNJUNsIxrefaEsTSwn9DknHJml2kZiFKusk=;
        b=PLN1wKuGt4d0BhER1KuE8spfBqkMdy029oUp4cdhm9GDFruH0VoJ/SuO3nFMmGsXCJ
         oNdiu/SuQBS4s/sQsLWgrBMISkCitxX9CN/XzFUF8sX5iJk1Uui1IrCfRI4Wfx+h115e
         vPiHtB5Y+Kr2ps+dtnYTVZHSj+52b1XvNMxF+WDqsQkw90rfsb3WfPlNXXwu7cZUP1mc
         dmUAYVC0utIDZLEooWt2NCKFXS3sbLZpGsGp2mxJGGC+A/JsEJlwZi4QkEi/Xxxi6RJH
         YaSUuYF7WkH+k1jMi0X+Gh9twTVLamMYpjG7gHT67D5jP6pihQJn7dHl3jAg1qNziQpU
         NJbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsJ7bm4I+JvZQKKv0MqUZsV0odVcqpQxvRd+LfCaEMwbJ6ROg2GriHEiKD115D1AHpmDeR7vpoO0HVA4CLluuA4nL3WSA4wA==
X-Gm-Message-State: AOJu0Ywjgd7hA7P1mqGwRY/U0f/mZ9ji59HmChcJczGv7aOYTw7eYN+U
	kvXsxeHr+MFonXRP7m/fp0FrnT/+zL37uWBdgCV/THPcQ+OrfhQr
X-Google-Smtp-Source: AGHT+IHxtBnz6ijPjshVRTU/Or5u+iQbwNiq9GTOk5NUY0+Qg8W2AGNgu4qFnDh9ED3QCcw4a9KZjA==
X-Received: by 2002:a05:6e02:20c4:b0:375:9828:ae0 with SMTP id e9e14a558f8ab-3761d70779emr74607675ab.24.1718929623219;
        Thu, 20 Jun 2024 17:27:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1feb:b0:375:af6a:e6ec with SMTP id
 e9e14a558f8ab-3762693b4f5ls10311445ab.0.-pod-prod-05-us; Thu, 20 Jun 2024
 17:27:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8sLJBFLLzQN2k4aiusLhGB6k88z7OAWWhC+bWSaJ/lx7+xxUKx8FFLmEmFASTaTrkI9USUXO1u0iU1CPaFiGwxWIdyGL63+T/BQ==
X-Received: by 2002:a05:6602:1488:b0:7eb:ae17:c237 with SMTP id ca18e2360f4ac-7f13ee7fd0emr823424439f.17.1718929622526;
        Thu, 20 Jun 2024 17:27:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929622; cv=none;
        d=google.com; s=arc-20160816;
        b=bYMyU0k/BqPMAW874vODLY9Trn5yqYzuONp8uNYJgUriERL4d0UflDy8dfPjaowEN3
         TgRwPAZ8wGXtlaqRBy6+U1S2lzPEn/l4jAM3ZkrVgmMhJQHVxwsSqyOXpJY1N9Gm4PIo
         uTXqzUcon5WoDpA/tX0KCAbqRVrNjdafxGICob/k7QlBqAWQgi7Nq6jd4fSKVPbnY58H
         1h6Sv7QpiSrUkVzZmHwDzF4aziMZrtT0bFuo+Ezchtz4j/v6iAetzfTAkzTsw3F3lNSm
         xO0cUR8VX4hlbmBzjGS//IpDQyYRI02Q0CWu5a3ggT1lWuJk0pEjPZXUg817Hxl447ob
         b/3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WE3ASvt90HWWKhjLUTLn3R+jUtOfzIMMtdYDGL1//DQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=y4XuIThsnEKsWuTXeVopS29e9xdQwrYBZWZgKcSKbhiJ1MrrpfI0BLhmBIh65yk7tJ
         JVwszl+L4De25CsbAf432VLJXElAiVY1d2Y59rWnrP+1uMpFCs1G2XlIuGdFQN2GNtlt
         JR/eOp7MDAkxBDZ85EjLYnEcgLhOzqofoFjA6onXfc8coydK/VFmMMLeSSL7sTQjCnOA
         lDpiA7YTsfDGe+2i6UwhXv70qBhQLtTSl2MiEoyuZvRmR3QKQYsrJsfb2wTW7Fkt41b3
         hx6kNQd5wuUKOaA4BM844d6tTx2+3lpBxljeKNkAigpjEbmnpSWI5jWhYAkZ6+MHi+Uu
         peEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Hbp62VBZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-716bbbc6b2asi13176a12.4.2024.06.20.17.27.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QwX8007942;
	Fri, 21 Jun 2024 00:26:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c8765-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:57 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QvfW007926;
	Fri, 21 Jun 2024 00:26:57 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c8762-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:57 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0LbSD025654;
	Fri, 21 Jun 2024 00:26:56 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv2nnu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:56 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0Qo4749283438
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:52 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9676C20040;
	Fri, 21 Jun 2024 00:26:50 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7319E20043;
	Fri, 21 Jun 2024 00:26:49 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:49 +0000 (GMT)
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
Subject: [PATCH v6 25/39] s390/checksum: Add a KMSAN check
Date: Fri, 21 Jun 2024 02:24:59 +0200
Message-ID: <20240621002616.40684-26-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: v1IZPgxWzopaZuk_kqDc7YIXvTz_GWeO
X-Proofpoint-ORIG-GUID: MSeXoogrFNNvcaxdXykKNNCFHA-AI_pC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 bulkscore=0 suspectscore=0 mlxlogscore=927 malwarescore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Hbp62VBZ;       spf=pass (google.com:
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

Add a KMSAN check to the CKSM inline assembly, similar to how it was
done for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/checksum.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/checksum.h b/arch/s390/include/asm/checksum.h
index b89159591ca0..46f5c9660616 100644
--- a/arch/s390/include/asm/checksum.h
+++ b/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/instrumented.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 static inline __wsum cksm(const void *buff, int len, __wsum sum)
@@ -23,6 +24,7 @@ static inline __wsum cksm(const void *buff, int len, __wsum sum)
 	};
 
 	instrument_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile("\n"
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-26-iii%40linux.ibm.com.
