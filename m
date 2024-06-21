Return-Path: <kasan-dev+bncBCM3H26GVIOBB76L2WZQMGQEJCEEEHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 386C09123DC
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:37 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-44055f6d991sf51508761cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969856; cv=pass;
        d=google.com; s=arc-20160816;
        b=ej1QvoPCRfKkcTwKvuq7mfmPBzhJoSYI96O0JR0WYbLFPEZUuDL1cSMdPc595Nwmu0
         BY8iMdiNEy6FPpqaYW4SiEMSLnoDqDzSxwI3LFgK69XumTRFxTN+4fZ2fG1WUGWnKa2Q
         X7KGjJQJnJe/XUrv2cZNmZ9G6gCNPT1lILyhNgOzhuxxN4/JxQnRVkdqm7x8vnZGPAEx
         0DIJOD0P75spNUKl7zlHjW/5J4t67LDg1BHiTekg9yZQ9y4CsKGDBbkqbqLjBJYfC1NS
         4O/qEkI6ysBLBXs5vptfhyqEBCALPlbPyzJsrg9MUzGjzbcL0Et63KFpiOvD0KlAQxDE
         SjdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fETEZK81rkdm6vcC1JeSPYM2D3aBK0j5TkiZSoDfFGA=;
        fh=mpIZ3iHEQSqvhpbWeoho8XlFHrtGa0/UnBzn3zOML7k=;
        b=qNdCwU4oFv4VsBrKdczxYkc4v0JqzrZinE1oBcLJqy+fVQ28ACfg4gbTO37JPczkfz
         qFMRDBNT31rtR/BZ2WsDyLxvi2SUZSFUM3SiSyBVjc1oac0KnROQ00g7VpeyXxG0zgHK
         Ev0vygR+476HAJLhug6l9qUTncDMF+2ec7aJD5KIMxPzd0HyntLvUixa6Oz+bDQo3/oj
         yeuXTs7+/f5hjXMSVhsNCag1k7NC8QOQAnTIwfyvLaJMl7WBGwFjt0sdDkPUtZnoKhsg
         NCRVHjeyAlVTw0bsRl0tjfJBlTG8l3PRjjappFfewd7T0u5PPghgW617NqOpOzDVErbl
         Wt4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UkWan7cU;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969856; x=1719574656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fETEZK81rkdm6vcC1JeSPYM2D3aBK0j5TkiZSoDfFGA=;
        b=RcNspkBIY+s639F9ThBW4HtMjRwNNJcl1z3acdbiiPMEcF7seE62snF+QJ42snS8X+
         vUHUFpBOCak0ROlx2Wrn+ak16cpOgc0CvpfxOZ8nt3mnrnI/qm0VjYIjHYFQX2MC/IWf
         +mtRxSpbJAfmVkvs/+rBNrfTBofnCSmubTPXxnG/EoYL007Vz/BAHp9fhRpqP6+Qcl5R
         BjcnPRBkG2Esna8IITP2B0cSyNyV293FxxFVgiA1yYHCCjCfMgDi3nH5xFdTFlhwXStq
         mWr9vFd+LAI0NIdWHOpQo6ZaeHek65Da9Ia15uyjSI9Q3VklwyzixGzqcQcth5RkKmwn
         3Wrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969856; x=1719574656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fETEZK81rkdm6vcC1JeSPYM2D3aBK0j5TkiZSoDfFGA=;
        b=mVCA7AnIYhe0mMXGrkVG//NG4vyxOoQkCFkklPKQbZy+Oru9DBDOBNcg+Ra15DnUeB
         g0z9GBe+J/ETVM8mi1AQ57/gBDVbGUQsJE6UqA+FgzJsRzyROuB+61L6j+D+N6Y7vP0A
         u3JM1uwwOZ7Oj19pSq6VUkGM7vfrmC84BTc9BBeXBgFNkKlKlJl6fKGuFN2cf0cOLxFR
         scvYOxWtwvFT03fiXug9oU3KxNTTlMhum/fpxzZFzhkmTmwNt/xh6R6fCBvUY1QVwfT8
         Ig/OGj8QGtJXKp2WLQ0F/quu1zx/AcJV3bHoEzpGliNhgSlAiLEoU/5fpbNLydyHCBjY
         pckQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEjFhszwPoSLdJzp5LvTx14HavBH3IVntSUxaUB8LsK54HBYHS+NAIs9gUTWrkxLFEkU0V4o7zaL6PyK+l7LaGsL79a5pZCw==
X-Gm-Message-State: AOJu0YxCfytj09nuF0K5iHGxSKwTDJTvBx0U5QaGOE7G9q2iH4FgLDCh
	kVLEVKU3wQXyFjdn5ZaGXdL0LeGBgCrFXYT9PhKtIeK27WB9NYcn
X-Google-Smtp-Source: AGHT+IFTj4bak0Q0HOZjDRZEDg2SdiNL+909zQkdMVxsBKr5y6naCQZuH4iF+G2Ln4G7whg+EOUGxw==
X-Received: by 2002:ac8:7e88:0:b0:440:62e1:9a75 with SMTP id d75a77b69052e-444a7879b85mr142175921cf.15.1718969856061;
        Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:591:b0:440:38e6:c194 with SMTP id
 d75a77b69052e-444b4bf10c2ls35608351cf.2.-pod-prod-00-us; Fri, 21 Jun 2024
 04:37:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXT4By2Mb0ah7rofX8Gqk67JY4IdPWtqhrWIllABhO1Afm7Zh4wRF7tELmi0JdF2Q6sGpbS+BlCZY25Y2VHl7DJ7mSOWIwThr7yeA==
X-Received: by 2002:a05:620a:4050:b0:796:48b7:d00c with SMTP id af79cd13be357-79ba775a10fmr1777041285a.37.1718969855281;
        Fri, 21 Jun 2024 04:37:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969855; cv=none;
        d=google.com; s=arc-20160816;
        b=u360dkf/sTdyf105NMbl7nzxmJu9yHnNCJIAwwS7N8BEcw09/zSR8+sZ9+xaSHor24
         RIVR2npRpdp1ke1hX9DdP54ZEAH2cZgPQpnL/1b6k74Xw5e548d0qpvljmZOZlPP05KG
         SSaCt8pqaGc0JbF/oXpPWhGb9MErAGG1+899LLFmCn1yHm4jig9q8C/MvptxV1YrjCBP
         qZ4AblwzcD/LOBNEBoksX1KNs+M6qJtXYF4Sq5N2OZyOaKqdw8QcNn6V3feUqLjdIBHR
         Rgvoh9C9uKrs4rdVTvtR6iM73ObIHL8uo5W/WxEjjJCtpcypfmEK44OTh8iHy1fkbH4e
         ahAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EM2Q29X1oynbiWdgAiIUaE04pJnjihVfcXc099lsq1w=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Kv3UcKNY5UEZyPJYMfnAqEg33y/VO3g+BfKfhjixAAmjbzw7qeWCdPqB6y2Gl8itx1
         /bepcRrmCnDk/ONo3xtePQQKbblS58aH3790lVxORCkAQBHBXIVnMHuvDPYwOZsPpNbh
         5tV4M/bsF5tAIneNd3/pClT/bpEm29BSrHHjp6K2IM4N9AyHHhJC31eLWwzsoU9/+3TT
         aQfU5CokUFVH9rMcx8A2W2Qr0rwVk37MhOCZtwEmSlrXR5n7/COrxgSIjpN98pN03asH
         0A+nHKjBE+a4H5CYks8fwjde5/n/0NKhPZIGQeyrA2fkum635HHsPPqnPdwM/wQvkbYV
         x1ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UkWan7cU;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce918a7asi5943985a.6.2024.06.21.04.37.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBCX9O024566;
	Fri, 21 Jun 2024 11:37:31 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw89g0294-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbTmw029867;
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw89g0291-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9Jwlo007675;
	Fri, 21 Jun 2024 11:37:28 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspeuq7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:28 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbNVf18285046
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:25 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2DF4920043;
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 994292005A;
	Fri, 21 Jun 2024 11:37:22 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:22 +0000 (GMT)
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
Subject: [PATCH v7 23/38] s390: Use a larger stack for KMSAN
Date: Fri, 21 Jun 2024 13:35:07 +0200
Message-ID: <20240621113706.315500-24-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: LpWocQY_2z3LBTS-d-yrj84PF4O_dgDf
X-Proofpoint-ORIG-GUID: q9YeCvfYquJu68q92OV0j4NyHKdiD2Re
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501 mlxscore=0
 bulkscore=0 spamscore=0 suspectscore=0 malwarescore=0 phishscore=0
 mlxlogscore=869 clxscore=1015 impostorscore=0 lowpriorityscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UkWan7cU;       spf=pass (google.com:
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

Adjust the stack size for the KMSAN-enabled kernel like it was done
for the KASAN-enabled one in commit 7fef92ccadd7 ("s390/kasan: double
the stack size"). Both tools have similar requirements.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Makefile                  | 2 +-
 arch/s390/include/asm/thread_info.h | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/s390/Makefile b/arch/s390/Makefile
index f2b21c7a70ef..7fd57398221e 100644
--- a/arch/s390/Makefile
+++ b/arch/s390/Makefile
@@ -36,7 +36,7 @@ KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_DEBUG_INFO_DWARF4), $(call cc-option
 KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_CC_NO_ARRAY_BOUNDS),-Wno-array-bounds)
 
 UTS_MACHINE	:= s390x
-STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,16384)
+STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,$(if $(CONFIG_KMSAN),65536,16384))
 CHECKFLAGS	+= -D__s390__ -D__s390x__
 
 export LD_BFD
diff --git a/arch/s390/include/asm/thread_info.h b/arch/s390/include/asm/thread_info.h
index a674c7d25da5..d02a709717b8 100644
--- a/arch/s390/include/asm/thread_info.h
+++ b/arch/s390/include/asm/thread_info.h
@@ -16,7 +16,7 @@
 /*
  * General size of kernel stacks
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_KMSAN)
 #define THREAD_SIZE_ORDER 4
 #else
 #define THREAD_SIZE_ORDER 2
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-24-iii%40linux.ibm.com.
