Return-Path: <kasan-dev+bncBCM3H26GVIOBBMX2ZOZQMGQEA4EU7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 14D7E90F2AD
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:56 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1f70b2475e7sf58118665ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811954; cv=pass;
        d=google.com; s=arc-20160816;
        b=oBWEdwpEth8Pu+3eqx1T/sjEVBFjdyAz3adlyfhM75iDjWHAJZhjaz/OPXZduIQrH0
         ECoFL8DNPjWCEMMIWpTTw/70JJQLN1SWQ2eSVslL+vpP5A3/q/nFQ0RP8DtVzJFKQuXc
         duXYXwVMFt9YaIu0aCTXD/Bfam5WlBQDr+nYsulgzNLYFfbKShXRchUD0iU0Rsb8/N7w
         lJFphevf/XaIo8VhHayxNvAuZAETOQF+/eJn5wIm4p8SMxWMcJrti9gMhditAZxxdNf2
         qalv8Y0GNhmPoqiWbRwOSCoGLcBtFl5sbKFCp2ZyDgb+UEXDtiHVb9R6LPwJ1uWRBWy9
         fWzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KfvYT30lefrgqRFy95ZNCLl0iqr3MYte/hEBxvBIh5w=;
        fh=Qz92lNMYQF99a+R0iWS+Vb6OzOxON6ee5wRJwwbqhiw=;
        b=iwGhd523Btf63mLqia6jEe4BRh14My3uyoOMzWLBxntMkNEtBb9uyy1XtxUdFLJ3pz
         +3t8O4+idrG/ferP+NOWDRfDVQEoC0YjIlRiSPFCI1yAQhgS4o3kbv9MnnpydzsLG7r9
         OmLclxCG4/FpFrvbBAhL8iD+aYeJH3NrR4bWjwtMvPMe2lic4C1zGeqzcP4zHkidzozP
         2cOC8pQfwMiz+Dq//bN78lVBGTJbyyaQcJIa/JFSPrCGRabhpFM8IcdPEQ2DPHqPAqFJ
         af7RV9vjtQwa6/qEyeW9Q7J/EDUANHW9sG1YnG75/50gX1Jt5wOkzCkaQ3Rb8MdCLC2V
         1Ovg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iUuVlM6Y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811954; x=1719416754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KfvYT30lefrgqRFy95ZNCLl0iqr3MYte/hEBxvBIh5w=;
        b=dkr+Ykx3fuMA+PseKZeS6NM7d/an+udf+fCN9Qg91rEoBvbrQ5bEqSg76A+JPRJ1Z8
         fsdwAmW7/RE8gcscxmQ9JRru9O6TpH3cl3rOlNdr1Bvk/mvBhQbioTDg4e4kawovj3Dl
         dNvfMmB2OmlxmAQNNfnYfrP+F6WhuNw+8KyhSpUP9scUG7nzuVCgMhIn7ms3EGGDGW7h
         ZFYjKUvnWL0WkZdPyu2h79XQwA01d0aS3mYr20z5Nc3da+T8kbJp4m7ECjKYSrlVLFb8
         M95qXnsTmZMalnYDbqVRcRbKj/EPz7OffSTxeM4Q6zEWqFeUeUbpJzTK/g8n3OUBt5il
         mUsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811954; x=1719416754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KfvYT30lefrgqRFy95ZNCLl0iqr3MYte/hEBxvBIh5w=;
        b=jJScLZTBnRxaK9ZbEgtmUTE9ZmJZFV/3dahP8hrmncboslUgBEdXeCDcjHSxaheL/D
         nBOci6bt/QReMgmXaBqAKlOruFahVtvZ529yAzDNfV/9FTYRZE3/b92mEXqnsn6d65w7
         ePV2YYhizg1bURpCJIRiEIvdA8EGAlE9Qcqo8tBsDcM9Q2+kW2faIeU+An0Msa/kbHc3
         PpcOzMsNgYEHefSaQQBIC28MIEreND8rfHQDrsIvJ3KN7GXQHwV2trj0FmJGlhw9XWG7
         avgxOYiZF6CNs/tpW1uMluHyVFyKty1pj0x/+LCFXCPhqa93wZE98iNBsHy6zUttJ921
         rgoQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULWkFrVXMiMPQdfeBRLvCQ0N84X/GIV6TApq4+dSW7mJeqBmmt1FwBpAnFDUk91vYghh6sIDL2X/vhm1X5PO73tmvsZEovag==
X-Gm-Message-State: AOJu0YwaCPsxSd6ymo/VAHRrM5oWEAEYZJD6eHzAK7hFisULgQs9Bc7m
	FuhIX+tlpgQK0nCt/f2nig3ZhZ5TFiqGlGvy9Bje4AAcho+qCRNG
X-Google-Smtp-Source: AGHT+IGu99Yitd6/bVi85p6l78nLd4jZAnEJsMW+E2I1j/HoAb0McVq/rr39vTswOTQB9D/jdLak8Q==
X-Received: by 2002:a17:903:192:b0:1f6:e306:1786 with SMTP id d9443c01a7336-1f9aa45dfeamr32660015ad.54.1718811954579;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e54c:b0:1f7:166c:6c61 with SMTP id
 d9443c01a7336-1f84d6429d9ls2783235ad.2.-pod-prod-04-us; Wed, 19 Jun 2024
 08:45:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5ffr5/PFRNJz/fu9n4R04aKqbqJ8S00p/N79q0FL/E7UN/pHcenT7ZBDwNkV0XMVRN4wdDatw9c825uAxcLi+OPdZU7UqlY7euw==
X-Received: by 2002:a17:902:d484:b0:1f6:eb56:7831 with SMTP id d9443c01a7336-1f9aa47c414mr30234765ad.63.1718811953378;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811953; cv=none;
        d=google.com; s=arc-20160816;
        b=AYeKxTu4A36bs2J6SlNIi0qa02woYrFmDee4dY9Yle3iPoUrbqF+ihWXPPMT6PRd7K
         OPOPFTJB9Ikgwb2YOu2MafCCiHF9XOKMCSgDi/+tT8f75BrHEdfRqb51PFbHqj/QPi+4
         REBpHpTbcsS2iEQS64nmqggkdxLGJmmv8ENQ+EaB41V1Kchcbxk13UXE3c2CCBQvBYn4
         cde3EYc4RknL8m9FZSWuK8R3XcOp4+U9ZOmyTW7U7nLcyjO7+sAwD94T8s+M3hZSyEk9
         ppavK0vJ5pPX6bu0PHpTan57DcIOtdM4g7iuzfBlr03TpeySIhSBzTbjrFt90D/tSXj6
         2hCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WE3ASvt90HWWKhjLUTLn3R+jUtOfzIMMtdYDGL1//DQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=md6nsNWdpw3krHLmXOBWh76S9PBf3E+vPTTF8im+V4jQa+dolEV7RntrsKDf3XINSW
         p20tKpmNlt9fiF34nc0Jualpzdkw4aa1zSM+jyjnnedBDw67yxjdNR+coGxnNRfPOO9K
         JGGfYxZoxHbcz7mC+hyt8y7raQ6XY9GIg1Xbg/4xX1ljyiX0tqkO5kkrcIv59Pv3VfM9
         nfFbL182OM6Kaif3SGvQg3VmWuGYTA10UUqV2khv/GOlGHmiumqVimrHi3ksAkQJ+hcF
         cKBaJLHpIBiCDl2DmiB372oLExlPiZuLtRve27TXHYExCCem/kTrTGkQYdhUWbCatlaF
         Rx/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iUuVlM6Y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9a786480dsi1230105ad.12.2024.06.19.08.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFSkbb014145;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20hr1f6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjn1h009037;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20hr1f3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFEHbP019519;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysnp1e4wv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjgwd40239564
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3831420065;
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DDCB32006A;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
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
Subject: [PATCH v5 24/37] s390/checksum: Add a KMSAN check
Date: Wed, 19 Jun 2024 17:43:59 +0200
Message-ID: <20240619154530.163232-25-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: Hn2GME85KkjnRdLhqN5eGP0SUkWM6kFG
X-Proofpoint-GUID: Gj-cVYCQ0uqm18nKozEI737ERcJzjF2d
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 mlxscore=0
 phishscore=0 clxscore=1015 bulkscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 lowpriorityscore=0 impostorscore=0 malwarescore=0
 mlxlogscore=937 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=iUuVlM6Y;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-25-iii%40linux.ibm.com.
