Return-Path: <kasan-dev+bncBCM3H26GVIOBBA6M2WZQMGQEHTAWE3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 250EA9123E1
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:41 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2c7a8fa8013sf2124509a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969859; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ggyxb/O8iG4Q6k7H60B2It0r1VF203rdBTTpRVPVqbdjmLyhtoPBUhW1Y7/qlOq7+A
         wUUfW/hgPvfHwVFdNTLwfla6FYnHoDuL/B35JsRSw2Uqb4D4rEwvkhlVj4qqItC+El5O
         kgo+/c1dPzCrrQy6qJUbohpW4CYFCkqIk+k8iJ75IInSB5vbgI/Tob76j4MU21DtIz/y
         sLEtg8JVXLvf7y+lL7zZlnS4g9I8rvwTSkosg5RfaVGKgdEy0NmHDvOUUBCmOfug3eLR
         oYZDfpTZHNmkdW91+d0KSkpS7LsiNY5wm2MmT9SfaDxEK6vhnYO1DyXe6WS53PGW30So
         tJyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=17xR2cMt/c31SLtrDJc51PRv/33Qre+p38/IohqT4yI=;
        fh=WZ5bEy+BIJae39wJ5vWW+V4ABVdKHo7ow8xd42jKhUI=;
        b=WVsG4ffuCVisZlndeZvvihOhkod8wr7gfBI7CoVPw6xRpVYSE/QKzYhe7ud9s6fIsv
         wOYsCBAsm0+8BzHKr4drpeSQAS3Ojeuh4A4e4eHH2q99ZaKDAoFIqtRczb2Lvi+W9wNe
         IqF7Exy7D/SG3P0PchtBmZXVdKzvOjsbvj2PWpKdtITkWI3CA4wfxfmYK2pf/TmVe0W1
         CHq2LbaHv1D2RPZtZy89fYVq5qjMo0AcjFSALlIoqbujdxGUi9PZAxpa4nAHYkkqspfB
         bouqf02cpKk9kGKX9nWgEOsAKKSrds9zvWiXSHjBPcLBeHZzt47VSvbaNLOx7IowP59X
         edSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PnM2VyUr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969859; x=1719574659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=17xR2cMt/c31SLtrDJc51PRv/33Qre+p38/IohqT4yI=;
        b=FO4DJGp6w5BxWQdLLnBQ6ULiF1YcqY2GceITxLrby/mA4Bgi93dI2NC7iI5guvxlIQ
         02bJwc3u3FaiwDatvatEtbD1/QdXZC8fABVMet1HxsoXLui/CtOrcV2B80oHWfACKLUx
         jXQJzYZ0EVsv4jym0viDyc9t9DoXKa9fE8im39ZteFGRgcNwxPUZS+58YdHS77IVI9m+
         Vj9vPLe4T56Vj1sexU+V6Gjm/4e3yVvC3b8M9QEHDyDkU7ZnC5BMaMVvqrGyELA8REl2
         uHfuyqINX0HNHioc4AVvbPb47oYiSwN0HvEoEp6W2J2DaJ5nJtB4N5ncnBvfI+ETY8+A
         XTFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969859; x=1719574659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=17xR2cMt/c31SLtrDJc51PRv/33Qre+p38/IohqT4yI=;
        b=CI0oKwQh1etDomYAKzxBNl83cB4DDmZezJNLOCgP1Syn49kRcevLmI8YyugsVFInZs
         vsrk3N0S6IByQmCynfzQTnLkujdfpZDqhDLd27jYEJUn1krjWADOSAQ4xAWeso3tVq+9
         bj1aZ1LzPaNZaQN/UODd6fvUOefIzrZIyAMWF2eMexd2IPHM+SB2Y5w1PzSRztndJO5L
         FkmyXkCoW4OhcewNNbAu+9GoSFe7b1UR1GgBIw9RIMM9kHynd6lm2TTuq5EVGMYEmFA6
         FpYz2lAu5PP6vpxrcoHnYW0R/MMX+Oui2KDuxbmOjymTfbOAR19diX4V+fQAMPtItfW8
         FAug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5pKJx2DJwL+u+qz2ktKDpSXbfj5ei5MkSRD8DKQ5SeE95H/5Wt8uxaMdJE8r7gDQr9tgXGpIn6/oYqTb2R6x+HybVUx1RQQ==
X-Gm-Message-State: AOJu0YwPgorQ32a0a423rtBmWsqpuBf5qfORDgGhuQRpxxakxbnSxD+k
	SKT6AVFp4zZGYwElnY02ovm4z8MYkH7S4kQAXIrUXRAM4yWWNAt0
X-Google-Smtp-Source: AGHT+IGBr2UDPSL02dw3Tf4a6XkcwCkCFG/vWZOBSzFwaGWnwJaaBMM951C0zr4UhRnW+KFWnPp6zQ==
X-Received: by 2002:a17:90a:1fc7:b0:2c7:c788:d34d with SMTP id 98e67ed59e1d1-2c7c788d4dcmr7046593a91.38.1718969859733;
        Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:224d:b0:2bd:f439:c1da with SMTP id
 98e67ed59e1d1-2c7dfed94a6ls1178593a91.1.-pod-prod-03-us; Fri, 21 Jun 2024
 04:37:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBZ4Q8LmmX9b+HMwO3ohjhe3z9ZbcXg8v/ZClAVyPXTNeLyEi5kB8+bhevzuui8ObVVm8o8TxSYXmmHlngGhZb6fG8gLyCN11yoQ==
X-Received: by 2002:a17:90a:9a9:b0:2c7:72ea:c4bc with SMTP id 98e67ed59e1d1-2c7b5b68c5bmr8291119a91.11.1718969857589;
        Fri, 21 Jun 2024 04:37:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969857; cv=none;
        d=google.com; s=arc-20160816;
        b=TRf4BBcrCIh/zPkcAQ05pjtoe9GzjHN81fEioygyf4k5yJlPdA9TV80OXJfard5gzr
         Q0DmoUPP8rsPW7OBVspgSePtbqoV4a68Ro7AenqgibwloKYeGa9bIWp41kCPlOuQVtdy
         YD45zHx7iZ+G6BUicxhYyO7Xm+nJ6p/duDzqrTnFQTpBVS1u58UxFTwK2K0s5JQliQ/P
         di+ha5hMXLqFHbQxoaxl3ndvqRFqSugkcc/jDv35H42YD1B3KgWiTx23S/kALc0/5E4q
         +KSL+T0ymM+DMM0QTic+0TGkLSN61APg2XcWmHsaFEqL2A1xGXnsiHOqk3LNotW0kPlM
         WTVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=//0Kc+3BL5cKzp2INWy7uHqYWutu2bfhjte7hQD65vA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=tGRLr3DFxtVhnmkyiWHcB+xyIuIQiIi4W0s3sN5+sqaG2RytC7FHyxr49s3MRsCAqp
         S+OfRjpjEws0IGKgV3Gm2zPkLsRJj7vXwzY150p9X2oBx2JPZufIH9mqgGmLKONbrWru
         OSXefN7sWcDBjp+A0apotL06KhGC4Yjea4a5X/wBehkoDx5YxY/P+LqgiDrEseI4sy/X
         gZ8SwfMnlxgfP15C+j1KP3y/hT9TVC+jAU/pqcmQvfGR9tJReplklVAyMREUxCVW4axV
         vR9v2BY2fKhP+9EiERfVvf5f7RXpQEcZwEzFI0a63OrU7Es7BGdD2MOHyo84T/T7w/Cy
         ZbxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PnM2VyUr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c70ac0dd5bsi547099a91.0.2024.06.21.04.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L8D1FD021879;
	Fri, 21 Jun 2024 11:37:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrgv2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:34 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbXVK011203;
	Fri, 21 Jun 2024 11:37:33 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrgux-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:33 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9EaNq019935;
	Fri, 21 Jun 2024 11:37:32 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupw0c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:32 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbQvw39059716
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:28 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 446842004F;
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9FC8720043;
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
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
Subject: [PATCH v7 28/38] s390/diag: Unpoison diag224() output buffer
Date: Fri, 21 Jun 2024 13:35:12 +0200
Message-ID: <20240621113706.315500-29-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: K1yfeVLY1XzD6dN6lzEspmtPxCXRFnpI
X-Proofpoint-GUID: 0TwX7BudASTb7mZSUIMXE0d_8a29542w
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 malwarescore=0
 bulkscore=0 adultscore=0 mlxlogscore=999 priorityscore=1501 spamscore=0
 clxscore=1015 mlxscore=0 impostorscore=0 lowpriorityscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PnM2VyUr;       spf=pass (google.com:
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

Diagnose 224 stores 4k bytes, which currently cannot be deduced from
the inline assembly constraints. This leads to KMSAN false positives.

Fix the constraints by using a 4k-sized struct instead of a raw
pointer. While at it, prettify them too.

Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/diag.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/arch/s390/kernel/diag.c b/arch/s390/kernel/diag.c
index 8dee9aa0ec95..8a7009618ba7 100644
--- a/arch/s390/kernel/diag.c
+++ b/arch/s390/kernel/diag.c
@@ -278,12 +278,14 @@ int diag224(void *ptr)
 	int rc = -EOPNOTSUPP;
 
 	diag_stat_inc(DIAG_STAT_X224);
-	asm volatile(
-		"	diag	%1,%2,0x224\n"
-		"0:	lhi	%0,0x0\n"
+	asm volatile("\n"
+		"	diag	%[type],%[addr],0x224\n"
+		"0:	lhi	%[rc],0\n"
 		"1:\n"
 		EX_TABLE(0b,1b)
-		: "+d" (rc) :"d" (0), "d" (addr) : "memory");
+		: [rc] "+d" (rc)
+		, "=m" (*(struct { char buf[PAGE_SIZE]; } *)ptr)
+		: [type] "d" (0), [addr] "d" (addr));
 	return rc;
 }
 EXPORT_SYMBOL(diag224);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-29-iii%40linux.ibm.com.
