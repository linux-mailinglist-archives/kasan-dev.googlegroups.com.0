Return-Path: <kasan-dev+bncBCM3H26GVIOBBAOM2WZQMGQEQKKTG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 35C9A9123DD
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:39 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1f9a0cb228esf19209905ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969858; cv=pass;
        d=google.com; s=arc-20160816;
        b=sq6YYRbIeT4X07Wd39yuq6vGCqnx3He7Emn0I5kIV5ZnQfPFETtJC1SFvy2R7UuEyv
         M9UDxZuiZ1mraFTTLW6C/eot44TBuxGZwKRoXnOrgrKLb3m565f2LrIQoNRs3OQcYxDj
         apSuxTKMzjKKP5Ob1tZAVcBXJkm1QEPGH+QJ7Gc+DB4cMaM6mY2Y6xiSabZBi+4htEpo
         hLx247yCmM79hicwfAG++Rkgew42unsjpFaQlb4K4iMP9iuY4Yrwb1fjwZ5oOeiJw18v
         a6UYhs7b14J1qf3WJag97fw5sggeumMYZvGCAaJH4GtlftaVrRxvELb9g+Iceywad8SV
         ImwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=A0qSz7dA26zM5qKWQTB92yw+QAEV6R99L3+9PQsjKM8=;
        fh=oRxnaXqCkp/s6R94hBgUDp1KVwVc12ug412ePO4QOcs=;
        b=WsDFn4XKD7jvhhfjVhRWxaGGiGHzkEOljVCmeomFDSrnMrRwCAkF0WPDPnIWyINSDx
         suoZOjXkgin8QzYEIfMxfklmmMlJFzmzAcaD6Kb05N64gDRgs7XA8HHk80lase8nXuq4
         9PfQHj8hqTqEZxvnPzz8GdFj9bjfanoC17UfZK3KyMnUhXDzYLHD3y/SxUGPfPznVaeO
         LVSB3dWvu1N/Q1GLzClB+M4p2XxPt6APl/hg/d6oj6XGbVfqYNYmWddnj2J9xW+r8BPC
         osOBMHEeWEhuTCLlu0dFxtsZLL0nc5JXom4N/Ut/MN8T9+OagK4a0CkGs5fSGLg7HgE2
         Pbvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iYs1hdzC;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969858; x=1719574658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A0qSz7dA26zM5qKWQTB92yw+QAEV6R99L3+9PQsjKM8=;
        b=K5lbJrAib18EOihFDIU56d8qlHfyHpdrOoK1obdLBtp4TJXim9AKiMzYCJA4xRdmhV
         jhWxZirsmHnSjRA1Z73BhBMLa4xJ/bpw2JmlQsMfkaX/KpHDjcwTNviPdZHPJ/No0UgG
         iCi2VcmZCQN3mCe2Lv2dwWNZ+ZC41Ug9Jk7OOUszhNac7R+MG6D4hSn8V6LcMnZ8OmCa
         CswBuUeVMkHVYCKqxPcrOx6MwtjMArfrlagqhpdZCCKonSaawn/af0yaYbvPmI29Ak1a
         zoKZBIzk7JtXjsqpqY37heySFy0JtmEzuXcD/pbthxcKufrSIcoaNF51U5zTUz70PZbP
         fJzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969858; x=1719574658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A0qSz7dA26zM5qKWQTB92yw+QAEV6R99L3+9PQsjKM8=;
        b=eSphvJtjeAxfhxZ32HBkZXtTkB+FXvyNYCtaWG9tbRvonkY3kgdlIGyxUtnm9tZs/P
         ZKmH+nf53MnZo07fnCGIKo+8wS/9RimrlKbrd/YoaGXqkk0NQ7Yi+ImNxYg1GujlUQNM
         aJavNQ+pbDpNDlZJDn9MxdOhw6FbIkUiQ7uwP62pYejuYR5DbkBZ5fJe92WuS11pVm2D
         8CimkiGbCnENnHwcTfpny/jVZeSu6aeYTwd078v9whj2fMx8zIjbzoSCLpgunPGQmT3P
         mqSV5UBu+ihSb6P0FbFkJxApc5my/ilr22SFWLCe3LYIDfJOJhd4/cSKLl/iHEvgQ+Dh
         AjIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5zE1Rk6pFw4KDQImnEzx17J9XabsMmVvd9Vomm0YriPmJuQ/LMzLCBAxuR1z9+3CID9Py5fxOqiQQZjgZjfvK6lb1psg+fQ==
X-Gm-Message-State: AOJu0YwFwO6xHvVHMxJCOpnNMrH3TGsepAtv/NsP1FGKqsZrkt+alwh7
	te8TOzN2X3x2vpwkDqV9DbnaDi2YSZQmtvRBW9WhY4GbpZFIURNK
X-Google-Smtp-Source: AGHT+IHAqlChHONkM2errxxEmwptzs48uySyiBZtECyYav+8FVAN9fBNAOMgy7/UBS0WXzfXZ1AwGw==
X-Received: by 2002:a17:902:c086:b0:1f9:bc8a:b58c with SMTP id d9443c01a7336-1f9bc8ab601mr48502935ad.12.1718969857690;
        Fri, 21 Jun 2024 04:37:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:2780:7276 with SMTP id
 d9443c01a7336-1f9c50e6721ls13249205ad.1.-pod-prod-02-us; Fri, 21 Jun 2024
 04:37:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmnQpB92EwwBQ4LBLU9aw9B1Q6YxddQjzcDIowngKrBSAgULbCGKKlx+8XQJX/dbosRy//rJEXL4Z+bwJFWtY1O0OJNnVyaaur/A==
X-Received: by 2002:a17:902:6548:b0:1f9:cea7:1e78 with SMTP id d9443c01a7336-1f9cea71f5cmr32253395ad.50.1718969856145;
        Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969856; cv=none;
        d=google.com; s=arc-20160816;
        b=C3zyOznBMXQ+WWxdu86BvVnGecbvp5GQSIwTEABPoKH/NH9Owzy4AHyGHUm8QgEVmJ
         l1L+5TCMgIYEIaJMAEPxvqjeH0cyJZlD+TWdXPU6BWSB2znxuSzhJywWu9hFk7JN7Qe4
         UtWLuDff00SkYVlN3Gf+8sgS+jNzrspEduVO9cKbzU7B3pkl82hNp+hU8hyvJfXYxyUh
         WDMXV5OLAkuLKFPBV8t3AbqxRK7zksiVrcrwWM17Dq5ooqXG2r7Xtp7jOYqU8eup1vtp
         MaWH/FmLCOPnpGa4NfTQQ4oeQrDR5axpxac95KiqIzmNZf5dOz/8tq3WodWIwFpBanoT
         APPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K/viBy/PeNICITSZpD3tBAO/npQA3ucnq3Zo5JONrlk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=nSPRnrOEmOvROwBDMWkyd7VXBf68wrhSP9KlypwAAhVgmMz6q/xLvUAOZwlt4pVQwX
         Zg9rM2kig/YMGXkKVHL7WDkSLLjsJofJ+KbuWblcANmHVPcwOOZeZWZXD5H1prFL1t8y
         xyUURC8wBTJri/BaFLG1jE/eR/LT4ONF4HjRt/397o7GtFIv70rEdNJ0h5v+cLdt0TKK
         GX/HoE0aQpOrgKe3xwhuEVkOiPbVUe1Mv923XjNktOl5nJjXJxWUFLyEDRNAtJYnAhO9
         EORHdS9kQvumW8a54TXweK5z3Adr9FFql7AEVTh1KzwK12o+Jxkep4EvT4TuqKDViajE
         9u1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iYs1hdzC;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb3b37adsi521235ad.8.2024.06.21.04.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBUfcr008189;
	Fri, 21 Jun 2024 11:37:32 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t50467-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:32 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbVkE017536;
	Fri, 21 Jun 2024 11:37:31 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t50463-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L94RmU031319;
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrrq6vg1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:30 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbPFO18153734
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:27 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 020D82004D;
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6B5152004E;
	Fri, 21 Jun 2024 11:37:24 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:24 +0000 (GMT)
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
Subject: [PATCH v7 26/38] s390/cpacf: Unpoison the results of cpacf_trng()
Date: Fri, 21 Jun 2024 13:35:10 +0200
Message-ID: <20240621113706.315500-27-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: I7H6xZfZqOjODjPNPTm_ct-_p8FpZMwq
X-Proofpoint-GUID: 3FJaVmD-eWbIAIcr6r1ict5AbgqpNVvY
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 malwarescore=0 phishscore=0 clxscore=1015 priorityscore=1501
 impostorscore=0 mlxlogscore=780 suspectscore=0 mlxscore=0 adultscore=0
 bulkscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=iYs1hdzC;       spf=pass (google.com:
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

Prevent KMSAN from complaining about buffers filled by cpacf_trng()
being uninitialized.

Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpacf.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/s390/include/asm/cpacf.h b/arch/s390/include/asm/cpacf.h
index c786538e397c..dae8843b164f 100644
--- a/arch/s390/include/asm/cpacf.h
+++ b/arch/s390/include/asm/cpacf.h
@@ -12,6 +12,7 @@
 #define _ASM_S390_CPACF_H
 
 #include <asm/facility.h>
+#include <linux/kmsan-checks.h>
 
 /*
  * Instruction opcodes for the CPACF instructions
@@ -542,6 +543,8 @@ static inline void cpacf_trng(u8 *ucbuf, unsigned long ucbuf_len,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-27-iii%40linux.ibm.com.
