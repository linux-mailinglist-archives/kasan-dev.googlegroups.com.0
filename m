Return-Path: <kasan-dev+bncBCM3H26GVIOBBHUA5GVQMGQEAZGOCRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id EDFDE81230F
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:03 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7b725f0a886sf547642039f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510622; cv=pass;
        d=google.com; s=arc-20160816;
        b=WWjil1UaDQuFJK6Ol3KVTg4eo+EuSTJadGS2rBaiyv7UCkKqChnjfrkNuzFr9Efksk
         /CMGlMt25yjwjHbbxvD64P7Wt5AXvhxxoRnSaxakvkFOwc5zMheY3cUjPiBJTSfvNLBC
         UKrQU770zgcSnPoq5Qdj6oLXRnK7Q8ExTyxlYUZieqvG98L1EVrAfuvc1A4X4lueNh0w
         Fz1Qp1Gv5Mq314EQfwELTXmKaZE6vIKwsUfKASf7RE8rQEj+PZvkJeG71NwvUc+Q25x+
         tHLr/bIzNpEx9cY4SwhfgLy+uWCuMm7gTsGKo6b2Wz92zKcVemWGo6bThF/6lh63j9i5
         wzyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zu/DppnrLpGz3IasKf/CVMQwC2M18CNyOTRrlwYfGuo=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=a3Ky35xda3uMvYmbbjlGMxOk86FUa3r2DOz0eqkjwPKZAdkOwZhKTjjALg5cxxIXgx
         XzT967Y7nE9gp5ypVfdlCR3IN1WTV83sBVzdA34OnnSKxqelnHzkZahsbW4QfcSJEL3w
         q/4Q2EMD+gQwT/RVlotACW7THDf291r2PkC7gW2F653aW4ALo4gS5jPtmY15Y5Bsc2n3
         SnRzhwxnC1o5luOiD226sFW5g4lYEPMA/NUN0Lm1hz7/5cq7QJc46WW34l8fCsQ2N88e
         KWDkJ41tbf3KUX/s2Wef0GNMvhApmjWZUaZO44O0Q+DzyK3UcC4Ibo0KgBli/9qsJ0s+
         ow8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ORxq1rDQ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510622; x=1703115422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zu/DppnrLpGz3IasKf/CVMQwC2M18CNyOTRrlwYfGuo=;
        b=CunUWZVx0wP2ls6vAIMx3Q1BAP7Mgvk9decFOAnNVNWAAPRV1i3KWzF8ca0ivnmWLA
         lOlqf7Wblctkx7HBBrx6JDjpOfXgCfEDwyEM7Eu1WfhxwPLxBdeprR+Q7ex5LYUI41IR
         YnF0JWmd5kAwLZUqVFAJelUGez+ktzEu/APhV+HHit7Ou2JC3fu+1asE1TY2qOs/JGEr
         A7jLxoEu9iaa7IlYikStyPMgnwsaraSpwPqauwpSaMkUq4KmQM6vz5ItzaxPDmDPHQgI
         6VukqlLTxQDsryYrSkL7Hx7vL7Ho7JxFenfeOmocS2CfvCpLRlUfe7PwGut0Ga/cJXK/
         xN7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510622; x=1703115422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zu/DppnrLpGz3IasKf/CVMQwC2M18CNyOTRrlwYfGuo=;
        b=S627pqdsJpUr06uHRUMTpKhhg8RuhrLdGmjxU8Nrievf0g3WwthwtRzck7B6+iPLax
         vN9lW52uVj0Rt3JBL6as4UZWI0eHuLVBjfk63ez3NVzYbweQRKl32kmqbaoKbwPVy/JN
         NgjeiuSGyzbEvarCCQyWdl7k/owTnCLsnZZ2R4CuZM86u0mYr9CeMCZFlrH3l3u01bJI
         5L7HaoAX+mr4wl313yygHCBfzgMxq2oez7IaAj9RosyBgD0/C/GPD0qen4OFAgyxFF7a
         fVJkyyZs0+JNt5OANQ8PBQcFNunHHVCxOhKLpnhWFYTGUMCVltmRFPEGsxXHDV5BVbjD
         4cGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyYqlYBHhsAaqW/LH/3r7LzhEWCGSMmtm+9cAW1oPHxDoSsIKip
	Ml+ckzPBxmzHktNzJcujbSY=
X-Google-Smtp-Source: AGHT+IHTy7ik1Y0FBFQkrCgR0rMyFAU8pNRJgaJ6n/5ucY70a184Iw4P1yiVGjkbuRqy9ep3XKWbrQ==
X-Received: by 2002:a05:6e02:1d0a:b0:35c:c4a4:2537 with SMTP id i10-20020a056e021d0a00b0035cc4a42537mr6772691ila.20.1702510622435;
        Wed, 13 Dec 2023 15:37:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c68f:0:b0:35f:66eb:f9d5 with SMTP id o15-20020a92c68f000000b0035f66ebf9d5ls2304917ilg.2.-pod-prod-03-us;
 Wed, 13 Dec 2023 15:37:01 -0800 (PST)
X-Received: by 2002:a05:6602:24c2:b0:7b7:846e:565b with SMTP id h2-20020a05660224c200b007b7846e565bmr1233981ioe.27.1702510621719;
        Wed, 13 Dec 2023 15:37:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510621; cv=none;
        d=google.com; s=arc-20160816;
        b=Xh/pejgAyWOmr/vQazX3ZkIkiVwSsv0MF+DTBkD3cdiarX3NeCSipXjPIs/DY3XXJ4
         aoH8NZQk6dKqDNaGMdxBm6p2L4yHH4yr4TMEkgNvv9Fdl9XSMS3aiyhniLKfQ2YqkQE4
         YmwZsMgcFQ8nkqKniQ2HP42dMB0sOVMtn6w9fX4i67XObTVqhabl4w94pJ0ZLjN28m22
         waT6b8F43xO8E/AeSCu9tpV5BdwszUaE+2H0VNBYJBQTiwjbyNppJXK4F5sQMFxw9vNr
         Rgn5wLq6Gj9Sd6UAmiGWSsnJN+Cf7cWqqQaF0PXUdPA9DzIn+oAfJI8RYouJIbYJ/JIs
         IY+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=I5ENfpcuS8SJJyzq1oQ81hBdZSUgSzt986R8mOGLRSU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=yGH8NB/ELDrMA5jHPdkYwd36biQke50/6aikXFNq8v/RCJNoe8KVBPepCuvw0cXvag
         pCyOCb21pvp8lTFo3S10RciUjnbkR1ScidiEbEPKj1vrTrI7p/F8YDUpmDCX9rqSu/wR
         WUBf2yQoSeQETies6/fIBN8ZLQ4Ctl/kKQq25UflomlEWnKz/ff1FQse+dIm8U1+oDKS
         MKRcJAucPHyS2ezc12bNPwRiRzfO4ZDSQtEuZsDF4SDRwyCQXHLNs0+5yWc9H7piX87j
         RN3vusn9AQGheg+c/i0R+t/3uDuxkjuix8IujJoKlEu5j7pLZgMy5uSEjsrZqoWj2iyP
         Mp5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ORxq1rDQ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ee17-20020a056602489100b007b6f5926de6si1289599iob.0.2023.12.13.15.37.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:01 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDN5vPK008487;
	Wed, 13 Dec 2023 23:36:59 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne61654-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:58 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDN8eel015721;
	Wed, 13 Dec 2023 23:36:57 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne615yp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:57 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNVQIw014813;
	Wed, 13 Dec 2023 23:36:28 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1xh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:28 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaPsN13042400
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:25 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 60DDD20043;
	Wed, 13 Dec 2023 23:36:25 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EF7D320040;
	Wed, 13 Dec 2023 23:36:23 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:23 +0000 (GMT)
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
Subject: [PATCH v3 10/34] kmsan: Export panic_on_kmsan
Date: Thu, 14 Dec 2023 00:24:30 +0100
Message-ID: <20231213233605.661251-11-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: EwR19qvGJvvQNtGfAc5QYrovTRDCMqim
X-Proofpoint-ORIG-GUID: Anx1E9rKy2HSndM7YPLropkZzAYNqtaW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 spamscore=0 bulkscore=0
 mlxlogscore=999 lowpriorityscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ORxq1rDQ;       spf=pass (google.com:
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

When building the kmsan test as a module, modpost fails with the
following error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for
modules.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/report.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 02736ec757f2..c79d3b0d2d0d 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_lock);
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-11-iii%40linux.ibm.com.
