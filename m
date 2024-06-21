Return-Path: <kasan-dev+bncBCM3H26GVIOBB5GL2WZQMGQELBQO5GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F4559123C6
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:26 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7955a7df54csf23114985a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969845; cv=pass;
        d=google.com; s=arc-20160816;
        b=j1TErvbrj7TYTtUH7mOKtcHoQzHrGdcUVtlV2r/jhUmM33LUtrSvFV4+mCHQAHoI1z
         MMETjqgu4Vl8DVDMJgf1mIDg/Nq7KktvUuLT8U279gRHXjUEoFchEa+VZO1p8bw7CL2D
         JnJ9tNlWlNVh0jkAmzFCcQujGEDQdXsdjG6O6CBkh29/K1q+hs4JLEsf0w2RVxSbYsa7
         nhWKVt0bNlU5zr1phVtUu1N01ofhJo9qQG/uE53sliMZa41c7Kmasg6ReyuVuXl2dCSU
         WHwq9JHNtPpOlO7rZawyf6zQpCUSRhOc2QI+qK1fJrIagYwyZpD/mOG6BuwU4w8ojcSU
         QsoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z9Uff4N3g6vHLB5/aVP5VTt1JmfSr9zqP6NdnRkKkKc=;
        fh=bg+nGY82zRxz+maU47O40nNEs+jKwgJt/50lu8wg6TA=;
        b=DKafxgJFfGrVD6m9zjhkp3/1Uw8OThtDMhX60w0xiWq0lhGgZ3kc6TliLIHsQAYSRh
         GXk4XqBtws9yROvxFeZJ/8ocksMSOJdg/Zj9+481yIdEDs9HNEXJxerK7zbCd+NjpahN
         DM5Rprg2B0X+IO7PmVfqNAi3qdEaGKZbpWiLAqfQ3BNfiLAL/YwVvL/tA0h1llfd2ZyD
         wW5c3ajQBpBi07JOYesc+6VfwpxCJsJb1VlHdnwiDezr9EcthXHndqUuje2CCfllhUQq
         wbn6gy4kZPaRe0JEJ0ndN39tE4dBOCPjNvfHHcuVi4JGNEBdPG35qapAc4p0tUM554wC
         Fbcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kHBtbAMz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969845; x=1719574645; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z9Uff4N3g6vHLB5/aVP5VTt1JmfSr9zqP6NdnRkKkKc=;
        b=OAEhk9XezGjkbByMgGyqdDJiqOR9fswODbMnwmr9xXDZhKNvD/hurLW0N8m/jtWsxm
         P7HDJ+oRydmR3rlysoGYwaBGOWJeXJzRZkIUjo/HcZAHBzCO8hIHLBTQsZXntE9ROvID
         5exAf9GSYASpaI9i8wsd0bB11Xy3Vqrntk5m5CrS3byTX14rRUWMd3vjmSjPtdef+5t3
         C+z2tNAeXGTJi9NJAmb5t5XIFmPWk6PhIKkRjLsP1yTIOvysLA2RBpq4L2suOO5xjmRp
         Ds+DtD/YUAG3ugelWrScut4NpfpZdefvearXsonpm78vnywxxMPRflo53xqR4X9jPCV5
         wM3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969845; x=1719574645;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z9Uff4N3g6vHLB5/aVP5VTt1JmfSr9zqP6NdnRkKkKc=;
        b=rhzfHGI5r/kfXVNok4/858RF4Ik/0A9rX1K4qUyGCY2094Kak8OWf0/bwCGIDckHcX
         J+Cn0ipoAkX3ELh1niYd35rzxG2YC536FN4lFD7MdNpArZ1Jsk/kPmMip0PtEhQmCKZg
         TVNYPeJ7/gfdMiZFkXWJ4s9r0PwdzSB8lJRiM7x2w2f0fFRyo9b++wxKH3FoWnm1wEHL
         Q24rnh34sTnPWUVSIjE6mLwsDO/gAWE6liqBnM67QkrVU0rQVfrxMiWZtuKyD2EHKhIs
         LMKyCqOwQOClw9aBqngGmZBkPqMN8DvOphcuI8FwRn7rAUWhHSQi+guOoqfCFsjl1+KV
         YS1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrKKqftLuMnL+20DyZWiOgeSo+Hxu44jNC6YtQEtOdpqYmr4UdL5CdzzaKGbIb8HVIW888uQKhTAt/1bybEDpHvcwHBVxBgw==
X-Gm-Message-State: AOJu0Yx/6HiXQx1vilaBtPQgHSg1anr6IpjqtCoG+H5kdRFVf7CGUfCv
	GL8OOP0TUVW1slbPsSSTQIvRK/JZI+eE3UbyA+PJO1geNJ1sKge7
X-Google-Smtp-Source: AGHT+IErh89ZKjaevZuLN8rAgcn3GIBwycQypFd9WaAwS8OHiXdK1+BNIlv+yRmINWhBjLfIcZdpMg==
X-Received: by 2002:a05:622a:14cc:b0:440:5eed:8916 with SMTP id d75a77b69052e-444a7ae0ec5mr86593831cf.3.1718969845053;
        Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1821:b0:444:b691:8723 with SMTP id
 d75a77b69052e-444b691884cls22470541cf.1.-pod-prod-09-us; Fri, 21 Jun 2024
 04:37:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJmIrsTlFnLCwG4LaCjDh0BDKm/ZQ8UOQVmlnV47FPjrQp4/j6Peo4tVZfEy6tnmOCiZHi938PSYSegyoDZLItoaOMMa3rXAnrqQ==
X-Received: by 2002:a05:620a:4110:b0:799:2d50:14a2 with SMTP id af79cd13be357-79bb3ee1a9amr874422485a.72.1718969844397;
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969844; cv=none;
        d=google.com; s=arc-20160816;
        b=UykeVBhgw7GcalmC7vpujzZ2kDBmFap2W2KXsSUIimsbtisWMmCExneTTf0yMbGf3b
         1DsI/H7rnSALaeTmuH/j8NkQQPDm5nXxPFrSWXB8+CtAwVZAdWx9N7U8N/7YtCpdt+Op
         F1n0WBjF/AKfHq/vLeOjjxjogndpnlakw/IaesyQ90qQJ/HDp8gsj9+reQ8ljcpymoCf
         VJqWKMt/C7/782P4/Hkq6GvbMOWokW/kFY1YTVVcaviOxitX409V40zvE66pnkQyzjGq
         DWaa93+8V1093DLTOUuVgjSXnO0jv2G0itCOrAjjEvWQO3YnaNdfKQWrhgYU13YQNCc6
         tITw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3hDUyT9rvjh/uqttZeOy24s2Df+NNUjOmmqDaE5+6Vk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=b59kZA9+Wq4c0d1u4xYfrYxLGCYv+vR2ElxrWbv0R68LZ7aMZNOkFE5wt507C7IURT
         BIp8GVaOjv1I7vErhLbjCiGk5UW+wYei/brYUjXaQ2eEDSShOxM2RSrHuH4akWNI1JWQ
         Nzum1dvj8/cdI95W0NxFRkdi9pHQLvVlEOW5tZ3KiNFBdlgJ827MDeGWzW8nwnqPojmg
         AWn9xLJI/DT8eFXx6QuJwAz9BXXVzwMZ5XLmAP3ne2Bqnf5opm+9NwtpWyfvo26TGJTO
         YWk4maT5CGll5sMI1wuXpM+Ka+Y40ro+rRuB8vc61nhSsNGx/+2ip9uAs7rr7LhcNLQF
         OOmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kHBtbAMz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce92af8asi6649985a.7.2024.06.21.04.37.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBSei0031789;
	Fri, 21 Jun 2024 11:37:21 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0hx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbKjP014093;
	Fri, 21 Jun 2024 11:37:20 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0hr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L95u7O030896;
	Fri, 21 Jun 2024 11:37:19 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrssxvb8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:19 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbDV153019072
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:15 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5E0C120043;
	Fri, 21 Jun 2024 11:37:13 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C85B82004F;
	Fri, 21 Jun 2024 11:37:12 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:12 +0000 (GMT)
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
Subject: [PATCH v7 07/38] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Fri, 21 Jun 2024 13:34:51 +0200
Message-ID: <20240621113706.315500-8-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: M26Qsv0wYYoY7ZdLYkxPUzFolJ_IdfF5
X-Proofpoint-ORIG-GUID: 7hAxF8dJwBBtEW9YMS-8PINNDm1huIJ0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 spamscore=0
 clxscore=1015 bulkscore=0 impostorscore=0 phishscore=0 priorityscore=1501
 mlxscore=0 lowpriorityscore=0 adultscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kHBtbAMz;       spf=pass (google.com:
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

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL. The right hand side of the assignment has no
side-effects.

Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index b9d05aff313e..2d57408c78ae 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
 	}
-	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
 	prot = PAGE_KERNEL;
 
 	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-8-iii%40linux.ibm.com.
