Return-Path: <kasan-dev+bncBCM3H26GVIOBBGMA5GVQMGQEHUE2A2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 72849812306
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:59 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-6cef5207290sf5939689b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510618; cv=pass;
        d=google.com; s=arc-20160816;
        b=cdwZ5y9m+16f/SW5dkiT64lls4sRUHA7HAaQwJGWAoXMcCcdXttEKRtX7OdFSgtDvu
         UQ8KgCQmPfHpkxSI5eLSkuX4pd0ZK3knMVJznDgUVSsJ+gtwb8yqN41YN85TqwZP2IJI
         w46EEm6NA8vBNuBHs+f1p1FccfMPFXpf0YRVNyJ1zJnvNX7LIcM5DbOyCR7zrpipW8TR
         qwiHVOMPO2wxVMTfOnjwr3FTNhyyOekOot7iwmHfXAcktSfCf8Gx3a63KSs+1MTUeV1N
         VPNZvuRWGGUnN1DMviOjlYIS6SoEmJtUf+HzalBl+wMjGeANv5qFHi36TsUthZpQ82Ff
         55IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wrkXNuoqFEb5/Vz38mndC31MT1u7mBZeju3vneQ9Vm0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=jCivz9BGpZjuQMvUt0YmVdQar1rQp4kdg17IjGGXEJsIug/C4+c7X6hGx9DYSOO5jI
         VQmadNbWaCXmmUVSaJrNlm3HQR+rF7Ewec2c86WftcpeKdBIZe3xdjJtQmbBGwX4B1Z7
         WcQroDLlxHyCyBcPvlBa07F80dlTpB4iVrAPyv4fEyY37wnv/bpd90WDVDvm0laiNVVQ
         nANVmVRCtkKT0hRVJzpemGgQOiepLIkXPDMffjhurNJpmQCo9w+zgbhJdNYdeTG0HoxX
         gqigMjuYqUs3gPM15dMRYQydUKIpl7Iynfzf1OGBmqtw57H/JIGE5N7ZeIAHVK9qZAbl
         iC4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mlUMheq4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510618; x=1703115418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wrkXNuoqFEb5/Vz38mndC31MT1u7mBZeju3vneQ9Vm0=;
        b=GFZL2Kj470Rn8uJR3+4pTH1WL+RElNQ1Z8o1YMHBBF/mv5asQQ/496YFCICfKqfX3c
         SiINOLZCX1+ZZbtMNH7iEmsF8YgST/LoOBJJ32PRfctGg5r6wFxTHKZwLeTP3ZY549Gh
         5Q9R1QZRIT/DwqhpAfeiVG5svgYfXVztBqrKr/5UoRnzuWttLaFJ8Hg68nwDRdNkGB9l
         p43k25cXLSZTAMLdTtGGZioGKi4YKxnX2uZtBmWQuSLJuts4Zc/Ud6BRUQzB6iKR2wbD
         IsjUDtKmgS0mLsqQquKEing7fP1Dcw6sXknCL+6TZofykCo3RCr/fsf5GoEqFyvKQfzY
         i8Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510618; x=1703115418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wrkXNuoqFEb5/Vz38mndC31MT1u7mBZeju3vneQ9Vm0=;
        b=QVScsZmo8OEJSdqHcEsz6f2KfAYjDnDTGE2nQNJmwvF2K4ywADn0rtAuuKDnuTIoLq
         CuqaOeyIVO6I16KMZePEMvTeJ9NSsJKiw8rRVeXuBC6p/OorpWkYb0pEST7yeWOo00oe
         ck2HlZyYlpbamAQofZOqxH6hyh3v4I5OwBZrKfp9q88X3QFKr4RsDVAlgDS8vkjl8gBX
         8T37QZ6uKUZmt+RUsY6Q3HsufrWxmLVhMDoQrAJ5zUVKQU31GQOu9uYXLSADMoBa61Hx
         OCNvH/pTvEGdKvVIKrjawTHcVu7ZK8kx7zDg7rlhgytszknZXDWsMYdSGZihJBu+6ETd
         sCcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxUwExqV8brY/QxoX15LU5UyvPDHQ9PlfLXdvyTxt7nB5V+sKEv
	NW/uimorCYt80yss/Lany6s=
X-Google-Smtp-Source: AGHT+IH+Y8p/sU4ioVl9vDAhH1gJNf2vxBR6IdOcDpvcxwk2GpazcpqdKu/OM3vXbBB2psQwdDroKQ==
X-Received: by 2002:a05:6a00:4b0e:b0:6be:25c5:4f74 with SMTP id kq14-20020a056a004b0e00b006be25c54f74mr10676107pfb.13.1702510617901;
        Wed, 13 Dec 2023 15:36:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:c8e:b0:6cb:a089:9b3 with SMTP id
 a14-20020a056a000c8e00b006cba08909b3ls2379004pfv.0.-pod-prod-08-us; Wed, 13
 Dec 2023 15:36:57 -0800 (PST)
X-Received: by 2002:a05:6a00:2301:b0:6ce:f81c:a436 with SMTP id h1-20020a056a00230100b006cef81ca436mr9579601pfh.21.1702510616922;
        Wed, 13 Dec 2023 15:36:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510616; cv=none;
        d=google.com; s=arc-20160816;
        b=K0WN8tC8ilKkBTdG8YHtRYB4QVL8DVrgBAQ5iDbJmoWptsCh3Zx1f3GPDefuyMJl11
         p4g14hzy2Ilv4IRi7bm4/AMwgIBd/wNULexTS9JIcA2TedhVUrUa4MmGHBM6b30wuvpd
         KyGiqzxPsUC83cHy9PTCFab0KMs6fIKA93AnbxzJR5gjEX+AfLYvldbB+kNM2KLsi82L
         gkK7KP8knKTNnECYKzeEoc344uSKExxQhQBkSdwKlyUmXFzb66PQzfdCdXKh6Lt0fb4k
         hrdSwAbUrdDbUKOpDLLlmVmDI1Tb7FZZ1Uo3gn5a4/uh5vgsIFf8WkaKWhUlguNPaG18
         /YlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/1f8B4egk4r6fv+RsYfCo9KqsjTFkCnbhVG41i9k7hQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=JW57o9yiWnXB0b11LUo+MtopzaiuMfN8Bp9GgEWqxvCtXjGb9F2iC7URJDRecrEZSe
         vcCxnjx9nO3BkGY48csJemEp3DgVTkL7Ic89ErfePvUcLkHEo3l6GgUFhQFVSJHr0jZE
         /51J4L9vuJNc7f5dkVWT6sQyt92Ljd43gdr+gXis8FVQeXdxmXtFFb1PEph1N4X87ElY
         XHh/5IVWHCmS7nsbrUqCwLazGsx81cHVQlICRrJkaGnzW5czDzhTb/YACeORxkQ0kB6i
         LGnCqEfSr9GuzKET6tq546cOX5P6pl8glq+3UCHAu0MuokCnq3iuxZZOijNeJAFUNS51
         xB6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mlUMheq4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id kp18-20020a056a00465200b006ce83ee0556si773590pfb.1.2023.12.13.15.36.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:56 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKrEiB021636;
	Wed, 13 Dec 2023 23:36:53 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uym1sbnc4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:53 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNaXka016366;
	Wed, 13 Dec 2023 23:36:52 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uym1sbnbj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:52 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDGTUb7014824;
	Wed, 13 Dec 2023 23:36:51 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1xu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:51 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNamrf17695284
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:48 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A6EB02004B;
	Wed, 13 Dec 2023 23:36:48 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 40B7220043;
	Wed, 13 Dec 2023 23:36:47 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:47 +0000 (GMT)
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
Subject: [PATCH v3 25/34] s390/diag: Unpoison diag224() output buffer
Date: Thu, 14 Dec 2023 00:24:45 +0100
Message-ID: <20231213233605.661251-26-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 1cQ1gAU1Iv4juOXeCfxDVhgu2689iazJ
X-Proofpoint-GUID: iGbdxxrIYcgZBGhmP7OXYB1v889bVZ49
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 spamscore=0
 lowpriorityscore=0 priorityscore=1501 clxscore=1015 mlxlogscore=999
 suspectscore=0 adultscore=0 malwarescore=0 impostorscore=0 phishscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mlUMheq4;       spf=pass (google.com:
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

Diagnose 224 stores 4k bytes, which cannot be deduced from the inline
assembly constraints. This leads to KMSAN false positives.

Unpoison the output buffer manually with kmsan_unpoison_memory().

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/diag.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/kernel/diag.c b/arch/s390/kernel/diag.c
index 92fdc35f028c..fb83a21014d0 100644
--- a/arch/s390/kernel/diag.c
+++ b/arch/s390/kernel/diag.c
@@ -9,6 +9,7 @@
 #include <linux/export.h>
 #include <linux/init.h>
 #include <linux/cpu.h>
+#include <linux/kmsan-checks.h>
 #include <linux/seq_file.h>
 #include <linux/debugfs.h>
 #include <linux/vmalloc.h>
@@ -255,6 +256,7 @@ int diag224(void *ptr)
 		"1:\n"
 		EX_TABLE(0b,1b)
 		: "+d" (rc) :"d" (0), "d" (addr) : "memory");
+	kmsan_unpoison_memory(ptr, PAGE_SIZE);
 	return rc;
 }
 EXPORT_SYMBOL(diag224);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-26-iii%40linux.ibm.com.
