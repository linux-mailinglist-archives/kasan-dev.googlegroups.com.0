Return-Path: <kasan-dev+bncBCM3H26GVIOBBNH2ZOZQMGQEKHJH33Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 42E9590F2B3
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:58 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5bdab2e0eb1sf6535354eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811957; cv=pass;
        d=google.com; s=arc-20160816;
        b=nJjJz3bapcHgG/4M1VDgP7nkwgm8k6cyRedQ/PeHSCvTQ4N4ZfKWI3edcqqU3REZ19
         0+S29abmvH0CwTJnBJ16mUVOndmxX8jqMu1WiYrhqqzJx5+QviQIPSvRWg3aPV9I/8um
         oCbyiVGz+y75uekEQFM4D7nznyIOvYG0PhRyz3j0cSO2tKO4FCpoB7E52xy/2VZ8MUew
         TrIycjNWpK2C4CqKFyxxa+ALeNIPiAbFWGN+VvkEFA0kJHNMyYh3koRwP5KZacy6c3m/
         wo12vX14hZ/nfLKma+7uhnWxt+Gvh7UKzOa5W3iVi2YkFx+sqTtLqvRLopbibYtuadDS
         vC9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5IrvM97WK+fu9fOxqhwQ2ML66ZQffod87LuDPL3JcoE=;
        fh=Y7KON12MSzfDI4wvoRLyoXZ96KJnZRPyJsEJogfPS9A=;
        b=pRR6f6OZrAOfHmeS1OJDU91PfxyTB3cOqmHFSz/ddI2wihD0+8WGNUvzyom9PtZAUb
         PaJx6bRjCF+InhHUox9e6qohF/JyWxku28fGIIhwAnYOdHj9Spa6AQRsjOF19emWl/UX
         M+LbPWovhPd10YGWHA6DbNIpXm+FGsfQcapGj/K8DnfbHhbEbNpsnkghdXnxtgjb2YC6
         F5k2YILzQ1Jf1y5aVfPHCNyGESvDz07G0jDq5o/lHLY146moDjN+w3fgyp/Db8fRGnn3
         coYPdiU4yIsRjUYJOz00U7pWQuBZJ8KfiSXsXeqXWFgWchWmA2ltPyw0XteglQuhiyiZ
         z5jw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=A5caICuy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811957; x=1719416757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5IrvM97WK+fu9fOxqhwQ2ML66ZQffod87LuDPL3JcoE=;
        b=fO0byQrBSQcPTGOa5kKFwf4c1WTOU9BaArZq/M1I5PNXOjeNVmApw2SaJDR6tDkh2L
         0d2FG383ygUYXxnrQtjVLJ785GmUJxVJYjobv+yA53/o8wM/Lcgi/r90cpWtLCAx3bMV
         QZYz7ZW8pHgcAWOxaxEjNKhVdcLREbCF90FhpfB+3W8hELYeF5mY5MZUKSXH76Hvbb88
         gas/0vVAkwYk4EDe8RyhgAwwCYg+Qb/2nEaL2GN2oz8esDl1Jmmasf+xeQpiRPat5Tzd
         XrYdhQ4Y0Hk7izEcKjBqe4qSjYwOqmi43e6GCngwWldGqbBztoKYQFe2Hx3sSoE39yJo
         ZfLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811957; x=1719416757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5IrvM97WK+fu9fOxqhwQ2ML66ZQffod87LuDPL3JcoE=;
        b=YrvSi1ru8koD6N+MEWF8j5EU2CZ/RDImHcrKYny1dNdPpa5+Hfun4CgCYZAKcchC+P
         wvYPm6T/xjEhD1y6ghtIldwG2sPV6Oms+1YPP0tct2TpLm79xq917pv2uw83dd8XU1rw
         qVDYOWPXNQtKnjgRXNC/JHAlI5EG9Si8cKg9zI9Ql3n4K3BO8GWX5rEZ50pN4adqRDN1
         zP3QsfxaphnNOFtZNf+Gmw4G0pQDs600ilNmwux03Nk7geQbATtJOO9BVxxcPc8X31Y/
         ZFSTUasXF38Gyvf5dRoVc84p71EdbwqQBHJUNsxLg+zYuDiLnp95LHgAelWeIUXWe6ei
         /sdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDpYKPWKiIa5c/b6qRJfd3UoI+J4sD/t490HOherSfNlwqiDX2XAL4C+tKpBisvMBvxikVWz59g3klGZJEaUtcl0Qy2u9UCA==
X-Gm-Message-State: AOJu0Yxv6F4IJ8NeuXjkJnEujokfidryK4Vrh44yPCdUkuUgn1cxq2F2
	EQfJLiARoNPee6TGHA8QdQ6ki13Db+ZBKdfnMyqhke5n/39pVvds
X-Google-Smtp-Source: AGHT+IGxzsipVlpSRUfISjJ4ShO1JLIeyR2HAxQZx7N57WdzNyUANmTizZRtahrG/nq5PWCWQio2rA==
X-Received: by 2002:a4a:d288:0:b0:5b2:ff69:9814 with SMTP id 006d021491bc7-5c1adaea158mr3344356eaf.2.1718811957054;
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8604:0:b0:5aa:18dc:5145 with SMTP id 006d021491bc7-5c1bfcee75bls6773eaf.0.-pod-prod-04-us;
 Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUP1zGFuJjb+cOfqAihca6+sUlMclR5QTN9VHSHHVI6ee7vKNAo6964ZdPCnIqxkFOPDwEzrRQx0RZm+zsIjNcMbeG4Rpoln5IMqQ==
X-Received: by 2002:a4a:3816:0:b0:5ba:ec8b:44ac with SMTP id 006d021491bc7-5c1ad8a17aemr3269216eaf.0.1718811956010;
        Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811955; cv=none;
        d=google.com; s=arc-20160816;
        b=YqOst01mxauB+ya6RZgApTkuGpMmzmMnea2dK5+VgFB3GRptbD2wAA0rvZnanMjUKU
         MQx3OW9ehjs4hiGwlzqPusyG1/xGHjfV2g4wUUCxJPdbsuS1qElIduOMppfW2DS2pLUI
         jRGhkjWzQ6l3OJqxTjPRtWOY34NNY7eO5xDOGutA+TZKG4QQZ8L+CDFu92nSXS/3NAos
         Dvgi3961iQnLa+N7273ch687Kj+7eGwFUO8h/JOz/3sL7IjFP0ijgxVgwNUVg7AwYBm2
         7bKML2FfHdFm488ecJ6lTpkHeXYbHfjEhLnIthj8PcafdEVQp2rWLM8R97dukZ+/l3E4
         RGKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=//0Kc+3BL5cKzp2INWy7uHqYWutu2bfhjte7hQD65vA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=KBz3GdpFxVOIG8wGpN/AyvxQqk2S9bLmfoKN3lle8e1VK7NCDpvDPU6zLos6SZk5ud
         3fP3L+mj7/Ue4CsHQB0EsYt2OU+JiD5KEfV/QBfNocbR2VYioe1+6lUa9esjs/Q4ug2t
         kkVbc61cCyomf24RRBRG0FXUD0St/Hx4OA2cGnkoECrfr9nPUSE0NBeV2uPNqP2NKsL8
         nQ+jTHc8FYGR6g0FuIIM00ishZyy8qOmtl7m9AFPyJYeOvgUdboM6TLkJlyHESZIo3TW
         3m/QEHS702ch6nTFPy61ykgewBHdtJKPl4oKnhnYTjmduqlb3YbWi+dBPlyEajNY9qBW
         3+0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=A5caICuy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5bd62c4ca61si886393eaf.2.2024.06.19.08.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFSRAC028320;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81kq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjoT4023087;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81kk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFclPS023957;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdyqp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjhhx53149974
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 43F5920040;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E6A2F2006C;
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
Subject: [PATCH v5 27/37] s390/diag: Unpoison diag224() output buffer
Date: Wed, 19 Jun 2024 17:44:02 +0200
Message-ID: <20240619154530.163232-28-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: QudXJDIvYziPgdRiaXecLoQXxGjFWwwP
X-Proofpoint-ORIG-GUID: A9WWSzulaN_bPfxFgfkLwK1RnSV4YAj5
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 suspectscore=0 malwarescore=0 spamscore=0 impostorscore=0
 phishscore=0 clxscore=1015 mlxlogscore=999 priorityscore=1501 adultscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=A5caICuy;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-28-iii%40linux.ibm.com.
