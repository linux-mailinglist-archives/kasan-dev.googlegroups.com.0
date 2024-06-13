Return-Path: <kasan-dev+bncBCM3H26GVIOBBTVFVSZQMGQEMASIVFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id A87BE9076E8
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:59 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-62ff8aff966sf20230997b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293198; cv=pass;
        d=google.com; s=arc-20160816;
        b=kUMr+X32fg85TGHl1Cd2fqaJCr6ZWRgileLGg5KyuAwDGvnygKnUtrf0CBr/aZRoVA
         zrqU+6pbe9diMAVGQaz6E54StB1neHKroIJhTss3uU6mpdMRqy/5Wv3NASIRVFg9LvIR
         kPnyWU5z102hsPF0DhLh9uyO23kXON+dCl2SwXGZkZcEFY5iEtd2jmm1D17PlC4Cx4tf
         TEHxLvwrh3WSyeVG/PTU1hzNqs0CP2FoOXhC9RZwlQyOpBHwP7UhtXiyR1Yyq5+QBeOD
         DVbKG/zkCoJ+Aj00nW0You9pe30jrjePTI+jtdyTPsWEmqQzBHLxTWNuys1UIuHXlMEs
         jIHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PMibnQcXfjcI668HSKuFwlzV+54YBbHbFE0eQClJQJU=;
        fh=yubA9cEVmoxIuP5AKQOV+52iyPLf6+Rts/Te7sCQCOc=;
        b=MGObOP2tktRmiylYjp/HVuUONHdJPDXq20DQ1hGVsyhn1P4ZKW5B3ksgxyC4dSYGDF
         EtQTDKUllfKhdl+zTLq8Qpa3ei+s/3UtuVLZmoAF3vyw9nq6UGs+M1wUXO3mmwynVM6E
         5MWrdzuwGjhosYXwNBQRt4ZCb+wEj3croIvhuHRHxwK5rwMqFy/PFnTszY1Foq6vnvqq
         8bsor1HPMWn1vQRLlELv9J/q+PYigTNWwQqr1MbTclTxVTS2KgTisMRfkPl355qeyURe
         7ot3E9Nvd3ovW4jKnME4UTuAE+xMAb1z1p3PMwOqNtF31u7UbXDs0UBXi3a/q6D0jTm9
         Y3pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=S+yKKexk;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293198; x=1718897998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PMibnQcXfjcI668HSKuFwlzV+54YBbHbFE0eQClJQJU=;
        b=I6JC18HOqGcGdHg7gvJoHGiOIsHhH13QnXD5sJFa8khJRvUTq6X9taU8OLCEnF5AzY
         OyXJB/ZOwTdauHMOGmJM0eMHWYTo+sdUs5aL/01qOuae5KeKPvP+wkocwqUseT9dP9Om
         GQcA5bq5aMtjo++khmYhw7yAkDry/+m4HX/a4X+hQw49L4wogUI7lR8Tw2IMZk7XFVI2
         3Oelvx2iJJLj7d0xJNOKEH/PJXABNFAE48+g24vr3yORe1pEyiiyaI36WhU4XU/a1z51
         vpKEgsSfC2rMLf0sI4Ti3tF+iJEschjcKyziuYK36I8eAkpeMgh2tNBZZXAJO/tN1tS8
         tLBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293198; x=1718897998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PMibnQcXfjcI668HSKuFwlzV+54YBbHbFE0eQClJQJU=;
        b=bGGm0Za/jwm67HYsX5/yt4509H3eDplxGQUeHVAzsZOT/L876rMJaHOcLQtAeuTeCA
         Wo8yKyQfMTQztLdyVYWf3XQ3+bnW+OeplSsx3F507kXkFhdgR6ksSUbfjJ6QxlYWoSQm
         H4seaChlAdqQuJDU5GfSAU3XEGBnQpg2beGAp9G4rMIjbq6+ZQEyFCyWDtd3eV+YvEq9
         6OrB8R5msz7KZ2y+Hq31zP1rvKnnu/HZv7huGJRa8YCkSfELs5tQVmK9Mu4xMpinOdfb
         T1zYo2Iaht+q6gNnY//qInbcmUYPGnLw8ro4vZc4vCWkCyaiByQLu56afd7pzKcMs6j4
         wK/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWM7hRA6kGfVZuqcbaXCKRS0WMvE+gYFGKmHQMpyAbJMvgmY8hNVWxu/y6PNxt+jJ4OKtNiHEskW4YK21qK1+XwvVtaLxpXqg==
X-Gm-Message-State: AOJu0YxEOxKHFb2vw3kn1EpHkFSCJxjK6nPRAGZOCtv9bmzCAH6syTQu
	HRZl4Lc+5zxuPY0Vqp+8qzLwwaMX+DNZp4KOm5Ur735luXYJ6Ifq
X-Google-Smtp-Source: AGHT+IFVbIM9zJoeEJaGROuNp/DJSdjceseSYV9H1arn4sHR+QUgEp60et3qH0FD25/Cw2dggP8i4g==
X-Received: by 2002:a0d:f941:0:b0:62c:c5f2:18a5 with SMTP id 00721157ae682-62fbbfdfa9fmr49760007b3.40.1718293198393;
        Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2d43:b0:6b0:91e6:b46d with SMTP id
 6a1803df08f44-6b2a350a4dcls16188616d6.1.-pod-prod-02-us; Thu, 13 Jun 2024
 08:39:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtFkhUz/sMi4iSV2JLOE0Ex0TCLPbpoUwlxYNJyIdJEKdAEKjgM6gqMLkv7ze+zNdHOY22Ip2tvIKwu7GaZNZtCIGFt8sxs5HpUA==
X-Received: by 2002:a05:6214:5713:b0:6b0:839e:ba6b with SMTP id 6a1803df08f44-6b1a7ad4c35mr47762736d6.43.1718293197637;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293197; cv=none;
        d=google.com; s=arc-20160816;
        b=dibxatYxlDGFIiAPvzEEHOgzQNUxbhY9S0Rg3kvsZtMFhMXOI0WDhACGY/FYDTe+Q7
         sARqN0xuN7lz8TMSTwaTx3xpacuVaze05+6yypv7mOeTtI6fXTGuJ8sXEXIIRfzMi9n7
         MgLyPqIqN4fPH/KmZHAWYAQ2x/apV9x61XHe1rnzdIML0GQ2NVzvuAyIZIzsOlVWf6N0
         RX2T4Cba8p1ff+uCrmjv24iBn/thfR0DThJ2xP3zRy+rwtWdM5ltO6UfTNAhjsF4YFCw
         EHZE74Yg8mjVDXvTNo8S2+ZAMLJxNKP+awvxxPETfBBcu9KztynwthGuvjZTcL/AaAJz
         2F2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fXcYk+VdmTRPCkYYKoxIVDK6lI96vBOrCjw2t1Z32BM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=XfKLLrsQnWPD1DvKEb1b+ZIhBmExGvv+zZBJAf/jA7FNOzqkYrGWVLyvTD8G7f0pP7
         S5h9ZWtZavfOuQDNBbfnXXN/c+NdW72jcX+5bifR1Zz1FL+OWBXw0Zm72KFJ1BJ0BkuJ
         PUw1UeuQ1CV+5V332W4K0GAXM9djbh5CRWPMNSXWL3C8bYYvuKWQBQ505lui7QEAuQnd
         4XwcjGp3GHNbwI3jFt/KJojC2z0pEMxZhpvmnd27M/xjdblf+xalIWCMB0r1ArfQQcuP
         SNlozMaOLlf/JvBAzt5HpmTZzN5brQ00fVi/Ffkv4a7zw3701L+3SwMlcNTp/Y4xc6Jc
         K1Og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=S+yKKexk;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5a28c00si513906d6.2.2024.06.13.08.39.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEZMqu011319;
	Thu, 13 Jun 2024 15:39:55 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqx9b11u6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:54 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdr6p006622;
	Thu, 13 Jun 2024 15:39:54 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqx9b11u3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:53 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEIs5l008716;
	Thu, 13 Jun 2024 15:39:53 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk1n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:53 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdlCw34538120
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:49 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 36F3820043;
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B8B4120067;
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
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
Subject: [PATCH v4 26/35] s390/diag: Unpoison diag224() output buffer
Date: Thu, 13 Jun 2024 17:34:28 +0200
Message-ID: <20240613153924.961511-27-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: sBifeLqkoYZGxv3xk2zoKYFp6VPoCgvk
X-Proofpoint-GUID: m5hntwp6bIJOI40CcQ7BmmQ7MU6AE2Xn
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 spamscore=0
 clxscore=1015 suspectscore=0 malwarescore=0 priorityscore=1501 bulkscore=0
 lowpriorityscore=0 phishscore=0 mlxlogscore=999 mlxscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=S+yKKexk;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-27-iii%40linux.ibm.com.
