Return-Path: <kasan-dev+bncBCM3H26GVIOBBMX2ZOZQMGQEA4EU7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A757A90F2AB
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:55 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-375d8dbfc25sf73117495ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811954; cv=pass;
        d=google.com; s=arc-20160816;
        b=jW/a17jJIF+EhK8PrNgMmEqAaY6MX1OXdD7uXt8IlZUTeA047PKy3YWxf4QEK10d9e
         nOhSF98Ixr7/PKCespHAz9GzQ41VO7Ozd+Me8eNOlJak5cYQNWx9UGsMoWzBXYGvKcjV
         xituQ3za/XbwtL/bQkkpNSPZUd4h6m/cHF+ME37ZHML0ZzmWQiG529pAmQZF2h5LfSC6
         J2UELXoXM1PpQ9NIRwpZai0bdDYsegF9uQ5BnSKHK+5Hd6fIshXKsDLmj1nTtr5DEO2k
         U9HzqJn5PcL/5fDroHlqtm7oQ2pe/F5H3ksRGHsi5ZkGrEqXtsc6voByp1JxiNinBsjO
         X8jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=S3UKgibu8uKKAkZShZS9kCf7xapzE3gbY2ZByE02Ro8=;
        fh=jUp5z7PJGE7TA1B1si9T2SnIvVmqW7Bv1Xb2P8yTvM0=;
        b=h7NS9CqQZcVgLiQ8tdvScQ8wgAcPfkuenIV5oqd9L994UuIByJv/KzduOQmpM852L5
         lXthNQ1xalwMSB8FPPIeRbmFpjgdwPDjhITR2Kta9sH1MkXKIMHEIzGy+KQBTrsr3QGq
         tGToYNbNiVjPQeWBSsVZ8nxpd2BkbWV7ljp6SGKE+zoHZfDVc1ym0Tk0L6DQ8GROE6ET
         wm7dQZMZDGmGGSS6Vvch9kYtU6KEq9ujjEXW4KeTxXtNxbQXgdZT1wLLdJv4zwq2KtPJ
         nnjL1cRRNADw9H6SaigrLiBwHEZzRViNGPnpphpLbvY+meOOO2QcIZAJklhXU601cTdy
         TmLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SsKZn0cK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811954; x=1719416754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S3UKgibu8uKKAkZShZS9kCf7xapzE3gbY2ZByE02Ro8=;
        b=WkcHcXHFHbv4Lge8DCJHZmnY1IUGUrzokeaXIFqlYuyBDGTZfpnusODYD3RWLAmyQt
         WamPeY9U/XnfeLYbNS7PwEj7JtNgRkcqsU3PTYZ8oMvdxnwSdtu5JWpLU1uvKAVmsWV/
         7TB+5SZt5idGMXWdEevrh4OEf8SCXNvgDjQ64kCUnfQHLyNC+myvuqg0JCLBrm6RuPbT
         fDtqa2HfH9tSwT2RlAps+nEVZkJ4EBONMPsJ6ndOzCO2M3NwbPhVGz+OYoCxbwN21wtz
         ZtSKzSaL1KmS/HRbA1ZtmVasuXSiWAxrUAexvJe+PixGE2Q+txVoFanhDRIcnO10kWMH
         Tt8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811954; x=1719416754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S3UKgibu8uKKAkZShZS9kCf7xapzE3gbY2ZByE02Ro8=;
        b=vNwAd27fCdczg1QbQTNsWF4xMu0mo/qXRtZwe9mIZWCfz1jttkBDvbiZrH8yK3o+q2
         p8+G3mst7MQX5JcCBTdL80fa0CTRy+u9sMnWqZuLIE7oGM8QatMwr6Z1qb0+lvyPB+K3
         Qb+RoS/Sn446kd+ePc+xotU2GvDocRHj+HONJapomJKq1anIrMWi+PpeI023tDqXeuTC
         9yQFkBc+YCHa+xNz6u2k7+MncmDbkFN2bwoYwadU4Q2JeOI/z2TADS9J3Ke+aC7ZiW/Z
         kyjpBM7kpLMblnADmNIb+7AUtadTAHLSBEiLxOoFWLQj1rEEw+5Ovo5lSeC9bYfhgTYe
         gTIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8w6PShsW98oY4lKOyuZty8S2SZLuw7rWbrtUGFZ41t399iDvy4QI1M6ruN2BkSguimdEzGLYnv3+ePK9B5TtFTlHhnOaqBw==
X-Gm-Message-State: AOJu0YxQ4c1dQqqgXe/iyFVMPou7gjbrLVIhGkkx+xEg9mnYcRuUwJar
	W40ErNkjRXkEOEA1QuyzDANtjndPW0d/8orTEg4QuD9hT+NbHBqT
X-Google-Smtp-Source: AGHT+IHbkfKMpY68ecEPFkHfCxPPkufxbSGM9Ea/PaEqLW2NkfkeeZw5byZ59TqliYLVCG8SuS+7wQ==
X-Received: by 2002:a05:6e02:1808:b0:375:a202:2554 with SMTP id e9e14a558f8ab-3761d6b9a5dmr30183265ab.17.1718811954492;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:746:b0:375:b071:f481 with SMTP id
 e9e14a558f8ab-375d569f5d4ls59045455ab.1.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/vwIP4YDZ20LJEOs64IRXEQk54TQzTWBLyiaGk4HH+qQs11eGc71iwh88kpkTTy579kNGNYAmfWNGxB3GXAIOX17r5OAd2lbBTQ==
X-Received: by 2002:a05:6602:1583:b0:7eb:7c8d:dee1 with SMTP id ca18e2360f4ac-7f13ee135e8mr320076739f.11.1718811953763;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811953; cv=none;
        d=google.com; s=arc-20160816;
        b=wTYlCxknkDIotdx3Z4X+psVlp6OdqTQ7Z02DfCA7BCg2jk+DZZe1qHd5obcLGWAFgn
         ValxNGAnchqsWdj1QqMTETuMpcJVKgNWXXWltLn6U9KJ5rIBQKWh+Pv7bvOptHttzs0x
         t6qc6bJ4/0FzinHv4nb15nDdmADgTKTZsbGUeETeOFnQpRT84OnIREHdOSwwy3NXAbPR
         FRsMJAPAJZXo0qdnP8LgvPMrtTCy11ocLaoqpTxeizLqiYUd7fQRr6elY/buqXuXP9Vm
         bx2wDxXtv3vOHCzRvdyQ8m9UK6Sc5mgfaC5pLnQTNDD4lVJUBxwMlGV84NDCKwVZrA/b
         R7cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K/viBy/PeNICITSZpD3tBAO/npQA3ucnq3Zo5JONrlk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zG0i94aeiae5SfID5eGsCeCqWMi1K9R1meIfY3lsYr3R3hMb8+i+6kpgY4oSrORVtz
         SnfEyaUWg5gw+FYGjdSFL3bOL6/Da7CglbbzQJRkeODhdnmHQFLU7hiclqaeuemvuceS
         V08lsfr/tqjQHwfDeUPO7Q4JFmpVz0tCtc5/wuvFffrvZdaOX00P2EDyjT8lmFH2kyYv
         OTlOOT+XXBxWYcAM+M4tytpUxzGx6iGB5BxTjc8dBDFru7peqwwLD2Mc2NlhEPVngTlz
         FuMPsIxRq5UxvpQCrK28rUsi2nbMqr3w2khPfBUjt87jrg0ljTLf00KeQySy8ePkazzo
         zikw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SsKZn0cK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7ebdb75e03asi60036339f.0.2024.06.19.08.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JBtn0b013583;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux7j0tcg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjnY1028879;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux7j0tcb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEK19d011052;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yspsndtnk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjgNr33948062
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8C6D92004B;
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3DE1D2006C;
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
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
Subject: [PATCH v5 25/37] s390/cpacf: Unpoison the results of cpacf_trng()
Date: Wed, 19 Jun 2024 17:44:00 +0200
Message-ID: <20240619154530.163232-26-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: eRJ1Fir0D1OliqMOkMThbCdRt-m01UDf
X-Proofpoint-ORIG-GUID: sHcrT9dgmrwcrd7AfF1kVUbgkO9GX7zc
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 mlxscore=0
 malwarescore=0 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0
 phishscore=0 spamscore=0 priorityscore=1501 lowpriorityscore=0
 mlxlogscore=780 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=SsKZn0cK;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-26-iii%40linux.ibm.com.
