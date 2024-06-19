Return-Path: <kasan-dev+bncBCM3H26GVIOBBMH2ZOZQMGQE2TQ7BSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0487690F2A4
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:54 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5bad2fe768bsf6774108eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811953; cv=pass;
        d=google.com; s=arc-20160816;
        b=NkAmDDf8g8O4OC2cGOKJVJwiAYJepmKHFZ+PE0iXnQ4T6cJAysCrP9lIAt+h349WX5
         8nV9rApR6nY9Qp387M+afahI0lcxPI18srU0bigLjUqqxpEw10AgdJNs+1cyxqZjsSM3
         tVNPiNZEbGlbAEr159/t+dTGroCmIWiBQcIEcWKNt5gHWSJY9H9BexRMvrxwPwTTWB1O
         N2A5egmxIvLTeCEfU9H/B+VbwJZtMyoayXH+oaRUgWsuj+n9hs7ar5ljCF+yESbRkvC1
         q3f62Bq+PKsZ6OCBvoSIoyShAOcuJozyffKEkqRlHwBIAHaw3ky+U5VeZPZFb2scQkQd
         9Fzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=36XYNVCl4IAs2gDEnUUY7fI9a/YINdFYwRi52AiXnC0=;
        fh=7exNdvmcHKfNTR7mdT0GBVcdtSSeG66rtGHt/TdsIG8=;
        b=G9IkrjsLJb/y7vnN2V2IVVwdMSVL05HCfZxj7cuac35tdgfx/vA3aEhNL94bda/GHf
         41oXL8C5ImsoLqsWu5WYxGZrwigxwgPyFn5ig90mYZyoo/r6Vb7kngx8ciUXz6fj+WFI
         TcNJgNaQ+oS+TA8su962t7nETOy3eSpWdJMIBaaXZ5rFu6mKzt5jfD1WuUtFcxuLualJ
         d0ctnec+6jqwPjpKr3A/8gpPouOw0MZ3KrR29kXfNeMJJpq5yS7zA3XWkkZDAbMKghNs
         XwyfyjcUkNyqt3bXEs7TNP9XZ//uORhFa9i6e+a8YrBrsNeKFnKh5mQ7cG7I0qOAHDtn
         oDoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NmnO1vO9;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811953; x=1719416753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=36XYNVCl4IAs2gDEnUUY7fI9a/YINdFYwRi52AiXnC0=;
        b=j8I4PvL61pdcIOAdOH/w2/spZ1jCNABqZJoC2eC06zlO8C7p4x22qSVKvjmfg4Blqj
         GWz4CdFW3vvFYunIqO6JpdlQL1bVGP3Adyy1W4/oyOejysnTru44DV7IuR9YChgr8VRy
         /mcKGmfh992Cl+S0JNOvKubkMS70bJWqTq18ujhS/AcrsAxNbcdq93PN7wifF0ijI7ri
         od0JIvBLO+ziPZcLFbU6viXi8y5OglRAVeIcD8WdO0FYA4QyhjFRYek25VXJZo8wOKrm
         XWBIflvNBL13nlDIoJhqYauVwxyVKz+mEs+QeQZsRdezQAeunte/XibnT0NiZvJTMoEl
         Gdqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811953; x=1719416753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=36XYNVCl4IAs2gDEnUUY7fI9a/YINdFYwRi52AiXnC0=;
        b=enu5e8EUFj+JEKufZvxq9c2V9e1kDBhzYYMFzwmxJ23DM9upoxOyJW8VqzyLwxzVe0
         3eFLge70qsivdIc+yKi19CO8ZmLobiiBNFA0kFNAKZJtQ5GrIH5FIydXadUjncPXDdvi
         sDiQab+zGA0X5DkmKTHDFqVZ4bgSZTdJoc6GLB0pMPcugzZVRUni0TpnMMzAFVxHXNB6
         7nz0D2ua9FTTKQ7tPy1KVXch+IuCGIpxacVWIDRaYxwyncGM9AqW3rdDuol6h8ivYddH
         H6+Pn/0za4diIMwk5i6HJCpzwc9i8iSJyyD3OFxWI2XQFrbk9yPMOK8q4fQOIYtDIGtJ
         6mXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUR92ijlhZTo/XNNhaGXAdw6UcY23+Qt0sqrptVASpWBs40ucC199+ogOYy9UKbUYFcWNqSStffG2bfcuh6O1pMpY1ybkjzXA==
X-Gm-Message-State: AOJu0YzWpVYNwdjzv74orWLmq5GAXWAbRBRhZwzdlD72NNgLyDQRBEgj
	VVhjvcadAfOZA2Dj210w9i8qmf4IR6QpMmC1hwqygNmnFofFH/xp
X-Google-Smtp-Source: AGHT+IGlSkkamPo0oWRitdkZcbZ0pUc+KV9kaJ1cbKsTFyPSvRY4/Du+8UIaL2/iYg4TLc29SlZd1g==
X-Received: by 2002:a05:6871:3a23:b0:254:94a4:35d0 with SMTP id 586e51a60fabf-25c94d5ae1cmr3100422fac.48.1718811952668;
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:7390:b0:24f:c233:20c1 with SMTP id
 586e51a60fabf-2552bbf4026ls1331231fac.1.-pod-prod-01-us; Wed, 19 Jun 2024
 08:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUeHd+KwCXRKBTYkh6k8YuncnlbowmItlQiaazp+sPZ/85YsL2n/Um00AsIJY2CPNzKvojfef2A/yp36MfBEFduBV5s4zxvdwcqeQ==
X-Received: by 2002:a05:6870:1653:b0:254:d72b:b65b with SMTP id 586e51a60fabf-25c94d02302mr3098208fac.39.1718811951865;
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811951; cv=none;
        d=google.com; s=arc-20160816;
        b=bAup4UL+bmN2AFwv/mUNUxMvFVUVvNA8o6MHHiI44ejsA2W2ENYieCdWHAAMe8tgML
         xTErueTKkYE/4qOqycjcWkVdaIpqiOo5oGS+iQ0Z24Bi1T4znz9iMncPvxk47EGSrKU8
         /tsKDXtK/1LeOcpq4kDtHsxOh5Lu5IRILQYgO2vnNN1YNaYRbaSJq1D1IjMQt083Z/C7
         JjWjtE1b+qBbe6JLNUH7wAq9xvxFD0f2OQ3hz//JC5xSQh9eaTQAS/iAdxPTN99idCHg
         3PJzeHUmrH1e52tVyEK8sGVlZYpllDDlOzBta5HNETa3udMDaIxHsz6leDdpS4nK14eO
         LM7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OrFUkNCKCdyNkojULrcA9z04Ys3K5qGxpLIcxQ1wcAk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=frDtackh+SI0OZnPfAc2rfLenPQzwLunAUlwBaA4tf9UIuB7DwpNhYsleaRJdsJyba
         Wtk7LayksUI3NsRH1QjTKK3v2IdfQ8vPxXtiCNJaobmnX8uh+zAKa3SiANeho0W2FgMP
         pXJ7VTCpsk1v2HoDECVGdLUgvzL2z8omyFEx51YQIKhfnATb373a0eOUUi92nEdmF5Lq
         AboTNjjRcZbWQsRWlyav9+4RPcdGH/nIRR0JfUSec7LzL+oHdgmvil0j5hKbPGFHEbvr
         MozjT3zkbAyuyeh0bDbONkvZi5rGDDgH4LmWEeUgLeKnQ/X96lUhJpLpoX10PISD3WLs
         7lfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NmnO1vO9;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5b58bcdsi5091566d6.5.2024.06.19.08.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JETABQ000635;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8c3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjlhJ027631;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8c0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JE5i62023914;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdyqg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjf9V49807778
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2EEA72004F;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D53EF20065;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
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
Subject: [PATCH v5 21/37] s390/boot: Turn off KMSAN
Date: Wed, 19 Jun 2024 17:43:56 +0200
Message-ID: <20240619154530.163232-22-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: AMLjrFLACtM2O_4hV_AucX17suvuVy4t
X-Proofpoint-ORIG-GUID: hv4IkaMQTSysB8s_ElQqQbhr1xAUjpaM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 mlxscore=0 clxscore=1015
 spamscore=0 mlxlogscore=751 impostorscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=NmnO1vO9;       spf=pass (google.com:
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

All other sanitizers are disabled for boot as well. While at it, add a
comment explaining why we need this.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index 070c9b2e905f..526ed20b9d31 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -3,11 +3,13 @@
 # Makefile for the linux s390-specific parts of the memory manager.
 #
 
+# Tooling runtimes are unavailable and cannot be linked for early boot code
 KCOV_INSTRUMENT := n
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_AFLAGS := $(KBUILD_AFLAGS_DECOMPRESSOR)
 KBUILD_CFLAGS := $(KBUILD_CFLAGS_DECOMPRESSOR)
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-22-iii%40linux.ibm.com.
