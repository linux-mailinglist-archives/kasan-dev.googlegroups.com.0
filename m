Return-Path: <kasan-dev+bncBCM3H26GVIOBBN72ZOZQMGQEI4RFZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 74E3D90F2BB
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:46:00 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-24fd9850021sf6017799fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811959; cv=pass;
        d=google.com; s=arc-20160816;
        b=0KXmd6KYXCvs/yvfaKykGuChTdtFiSgtONJG4GNsRxZsMZlgI3yg+ZHFINfB06Y0g0
         EZxVbHi1OcE+m3mTLm9CKlgZ95nAYXWv+mbhLIbzx+xBKHbtwVcSYyAMq8QqMcM5i4+w
         ePUYlJ9QBuN1pAggu56oQpn6tsTRNnsIrxQEgiBGRNh90UtaRtDMVUi1zigdMt0AScai
         RW6O14NuNiwDlvqfz4kNSyMelzNlij3Poor5/ZiKQimUfkzMspTiNteXQxU0bQK61mSR
         y1/j1m/jjhliFwtGp9dssP62RHIKLmlu6Q2jtZQqDN3HudUvC7cxfSIlpdxbvNimwbE7
         KQ/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pAMWf4ccATumFUwKo7W8k6zynBOIPJ9bZi7kTwXdgEQ=;
        fh=5+FngXayFXFRi2ccSoTiFgkFAOOVdWPBWIpArTQnCkM=;
        b=DWE+3MTq5rFdsFjUt0FdWjVPu0JvRjlgenOJ7xHQKn9QsucQIfTnl5UqLBlycJSvrI
         yY6PiKItK1HgLK+Uq2dZ/8fEkIn81+mhupU46dl6tBj9CPSi20onfSSv0m7TjzX/m+SY
         xeHIs5j924Nju2MnQszlL3/o0w6/ecX7mBtOOYFusAgTKeNS6DcDUar50nsWETkeAQFQ
         VarZzEibQ8QaE728IWeEEcvVwdBxYRznGntVGDGSiXasVH5WvNHW1Me3Ob3l3gX2pDP/
         Ccve8rqJZA6GKdFngoYpOdp76/RE3FW9Q2c0a+DTmraQpOZ6EPUk+sVh4v1KGHCM231t
         mQiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gFFnuzcf;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811959; x=1719416759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pAMWf4ccATumFUwKo7W8k6zynBOIPJ9bZi7kTwXdgEQ=;
        b=Dbk4z0m/0VGUV8WOSaK+IhMFoMLPLLyz3ayuA1k858p80m5fLJ2N5wBPm6QreWa9x5
         /58cnwS7KzsGVH22mwy0fs8EO39yYbcJZusQekQ/V2k+BHFD7vLZa0B3Ft5CTYkXgAjf
         r48sOnTISG9WY1Zjc3zJzHHSmuuijHKjX/3NaP5pbbXmT8Wfd+KhfvLuGKGPMDCl9Jnk
         p337o3NYKe6oPa4AlK4oChphfRVGfFBhKVMXdVyHIVnsWUx+ZWg0kJLdu4K6C0uCP2eG
         Fx+8ChyLVeqFTpRnzjke2x9vThf5g/Zltoz6NeSYT6My3UMhbJKTMrFfIkt79IeN/FMh
         KQtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811959; x=1719416759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pAMWf4ccATumFUwKo7W8k6zynBOIPJ9bZi7kTwXdgEQ=;
        b=F6w8HPH9ljMFBpwtXO9H6ZLpst3pJVc4PEbufDJrZTmd2730GOpX39Uv+NrR9BmcpX
         SZqJHW5/BkaaGBk/7txI+ISfYr7e9Zx8QxA9QBVIj+gFHomL/3OnCq/NI1DoCz06DFxS
         Qcgtg3ZX/1R87VqUrYpXd/xUIbNOEoV3Uuxvq9Y4H35cpmGU3K7z1bnyQ3NQu1RE2oFs
         ZJS12VrC8OU2tfzkPuEaL+mkDll7XQ91aYmJZLAJZH/i+P/EDrmYhJTl/jpxSt9mllwS
         KQinlGtTHMLSB4r3Eqo+crp06qvOjB4rEHV6/oLCOcGnX0/bQ0qBZeilthOMrQYn9l2Z
         5gYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnjPecJo6vAjtG3pGuah499Yl9A/FfaGi6bmRGAUiUuLCJ/yEfpFprG+/0v2rmQxnFc4dzFyF0Im+ixGg2lqq7E6/8aY0IUg==
X-Gm-Message-State: AOJu0YzzYxX+QJY5b0uVZJypbN3fGDrj8/ybRVj10fjMCWuVHU14POnk
	kzzJ+SUkEgB8vFg9YFRNnrVFtFakksBSZXcGf3VV7aDeDF31sNQ6
X-Google-Smtp-Source: AGHT+IFUTKX6zTgz+1nq7DDd72bdho+dh2c5IBZdgXKelacpGvy95kWSvjDUnWkHn/VLd6fDTfiEcA==
X-Received: by 2002:a05:6870:1714:b0:258:4ae8:4af3 with SMTP id 586e51a60fabf-25c94d04c7emr3390844fac.37.1718811959201;
        Wed, 19 Jun 2024 08:45:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d286:b0:250:719f:50cc with SMTP id
 586e51a60fabf-2552b685ffels1622172fac.0.-pod-prod-09-us; Wed, 19 Jun 2024
 08:45:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUc31S0Xd/QvdgHvHqb/j0y8OpbvBHMIQAdwx0xeuZ9FnHejwMDJuVoxyLaRQhCBAW6/J7cJoNS6Mqq4O8EtwuA5MC41TmSFEP71A==
X-Received: by 2002:a05:6358:7f1e:b0:19c:5226:e29a with SMTP id e5c5f4694b2df-1a1fd3c9232mr355249955d.13.1718811958143;
        Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811958; cv=none;
        d=google.com; s=arc-20160816;
        b=JsHtXeYfdJxlI9fSHqvD47LPjQSxG9zzbfOeqb+SQ3m5GpqFYvvwsUIUgDBqz2ZLtj
         DGizvpXmX8Jamo1RIeGuOUerzRwioL1u9CTzACNQYA2f/4TPbWFykq4SwxktYZBzV+91
         znydE1ormg9cQI56ZsJo16CXrC+RByxhmFZM5kTaSxJ7wXXF6ySYMK6veu+Xp2Bk4eN9
         hjZREGWjyadjOBbEL385BM5K/82UoNiru/WgDgHqttevoN5gqtl/BpzsvGiOZE9JZqQq
         46PpkJa7O91TfqO2puNukN85/wFcLbCKYz86tupKaPA0nhye/DgVKGf2/gq76NEVtNQ2
         Xe7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s6DLbG1DAru59Tf4t+R8cAAAi/8gRk1lHndotnkU+E0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rqI+4bXg6pRLal6O1bLVR5NhrismzrAELfFl4svSQZWVcHUjg/Wt5RCZfIQW3hKBwr
         UyEtwo0n7SV0al1d0mK+FKXFTEcrYGqxoUQiL6shsg+h5QrA2p3ZjO9IYjr8n0hwB6+6
         bqr4IYQcFhlkU50P7OH36T1pWGEJw+yzfPIJWbYnVr4b06AKtGQuU+eB+DHR1M2g+7le
         M+0mXtUSWqly+b2aLHjfjavBDc3nYREO4HqtTwcJbJ009Bk77k5NsIAupL+ZSBsZbsAH
         02cfNWa/ABjx58yPl4kqpIz8rwahT61vauCyP/nS49Ng9QL7YRmyA8zh+U4KWOlSdioS
         +Y5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gFFnuzcf;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bb9794b7dsi6809485a.2.2024.06.19.08.45.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFSJRr028077;
	Wed, 19 Jun 2024 15:45:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81kv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:53 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjrfB023106;
	Wed, 19 Jun 2024 15:45:53 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81kr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:52 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFhxiv023990;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdyr5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjjt651249438
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B283E2004D;
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6378320071;
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
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
Subject: [PATCH v5 34/37] s390/uaccess: Add the missing linux/instrumented.h #include
Date: Wed, 19 Jun 2024 17:44:09 +0200
Message-ID: <20240619154530.163232-35-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: x3IdliaCP9_W0APTwBxLUteBtiEkeKIa
X-Proofpoint-ORIG-GUID: eWk2j-5jOwTKPdqUCsgQlthFXyMgUyxL
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
 header.i=@ibm.com header.s=pp1 header.b=gFFnuzcf;       spf=pass (google.com:
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

uaccess.h uses instrument_get_user() and instrument_put_user(), which
are defined in linux/instrumented.h. Currently we get this header from
somewhere else by accident; prefer to be explicit about it and include
it directly.

Suggested-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/uaccess.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uaccess.h
index 70f0edc00c2a..9213be0529ee 100644
--- a/arch/s390/include/asm/uaccess.h
+++ b/arch/s390/include/asm/uaccess.h
@@ -18,6 +18,7 @@
 #include <asm/extable.h>
 #include <asm/facility.h>
 #include <asm-generic/access_ok.h>
+#include <linux/instrumented.h>
 
 void debug_user_asce(int exit);
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-35-iii%40linux.ibm.com.
