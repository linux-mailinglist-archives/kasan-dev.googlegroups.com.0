Return-Path: <kasan-dev+bncBCM3H26GVIOBB3EB5GVQMGQE2TPELTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 049DA81234B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:40:30 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-203479ee255sf125006fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:40:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510828; cv=pass;
        d=google.com; s=arc-20160816;
        b=XPmkBvRm76MSaE/4CNFGsyywdmrronob5fhnW9RTxtfWsOMeYWf+k2Z6eheTz/y+5a
         rb6foM6SxK7RiD1C/lWe5C8Lc4GmCa5y0g+G/3VcsHeTC/Eof87XvL0THRorGdkxklEt
         HcGZ7D2GwBbVCV5RPm1RkxY+csPi5ALpoJHmwpNd0IDucATk+o/201oI0oQ7k55mrZa7
         JEhlWN/spYKQeGijZV9ivM8jsCbzXCAFUv4viayyguBt9/6iK5RiaigIsyi0GqrM+Jdb
         EtV43W5JL3yM8/75WFz8Q8KsDgKhO+oygLz99bZUovW+5OH99d6z/v2AU8z2tgPPy6AD
         zljg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YAbH1yxXmhiyNVaIm5d/w8FhecLKWt0WaOrBu/tj7Uc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=gjPmpWM2YPlZUkRtenhuA0oUuK+vUD8eE1RoiwPQspjOd+pnsK+nDGlxp3CG8FNIGx
         H7tvOs5jukuTNxiZWG/IYB2O2+rzJ+05vb7kBcku2ISf4TtzAQrF2K2YGm/iTMLWcpBx
         D9XoZYQ+JE8lyRZBE7pG06DHlvRg7fANoddzp4kiWEFBATOkMQg+UQ3OWChAcbRTNALm
         NC/8fbWc5IREFXTfZ9giP1jWJbLajunldJAf/71qTGv4n3vzRkcBc8yCp5VC0QAN0CFa
         hiMBjnqDM56CFKd+CVp0j1ndHkJtPwVsmi99HPluX2CNzeaY8/6jGsesHFecbCPDQsDq
         TMkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h3Ohq2Bo;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510828; x=1703115628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YAbH1yxXmhiyNVaIm5d/w8FhecLKWt0WaOrBu/tj7Uc=;
        b=vZpWu6cnuPGmq/TxuSzbwXGr2sdp1/5z5fycjooEcXPJ9ji/6bhHUvNXuCxfI9Fxfj
         L8V8WTx17YzAur6SARVzFmV8ejaStvmAJxHJaqFTJL6Gb+fxaA8hUbvNPOM6i64687B5
         RWPLdkxF/Dk58NOTnWltITQdeJN1sAsgrUguKMI/Qc6vOc2Z/n7qYJSDcD3UapYh24OW
         PBT6o4m3vU97hpSbBwDPiF0j+9O1hrhDOxLyVWxa9T3Gbtql+DnXuYO3vLnmVsrsuTR2
         TAaJjz2FXKsaEG5iaIKJqkbqR8KlO8+9/V14fFQwCYo2z3FHkYigVrEendkowTcOq63Z
         totQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510828; x=1703115628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YAbH1yxXmhiyNVaIm5d/w8FhecLKWt0WaOrBu/tj7Uc=;
        b=eMNDnWk/OH4Hq0fD4prfjnKKR02hZLqY2aw8XHOac/M3UZxe/7L3h4IQZ6qNSqJSNe
         QXju8akRF0R1+M4hXmkOLVbhj3jucnRpsRLzPDfntlUcZq864HNp4C2MlUkW64hblvve
         jmrMl+Aha/aOy2L8g4a9sy+jL1IvRFZVzjTm4Lf9FH3lYOEIamCGayPZL1//FnAjvcx2
         D7VZV5+bp5STXOO3lcplNc60ohhNxwLoCZY208QKyfjlsyBEikfbzJl6WmmhDvpt5Bhn
         bXam0/HaR/9K0cVGIo2Vzr0JcltOltWUHONHOvUlccDOhpJ2hyVxi7hrtVRGugqVWEj2
         RRFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzQYlmet0tqSf6fuvHMSoPyQ1G//GQBHUuKt1LD6LfMHPPD5cmn
	mvmzDGtauGrrDJkEVuvVGIY=
X-Google-Smtp-Source: AGHT+IHOrW+K9iShRAr3aGqIoNkPOh8KTjSyRvM8YhTHWKfAXpjwZzLjlC6Fo4oGsEpwD/wZbScwPA==
X-Received: by 2002:a05:6870:6114:b0:203:2d7b:2534 with SMTP id s20-20020a056870611400b002032d7b2534mr1623731oae.30.1702510828691;
        Wed, 13 Dec 2023 15:40:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3d9b:b0:1fb:29aa:69d3 with SMTP id
 lm27-20020a0568703d9b00b001fb29aa69d3ls1439144oab.2.-pod-prod-05-us; Wed, 13
 Dec 2023 15:40:28 -0800 (PST)
X-Received: by 2002:a05:6358:51ca:b0:16b:fa51:4862 with SMTP id 10-20020a05635851ca00b0016bfa514862mr9081527rwl.29.1702510828159;
        Wed, 13 Dec 2023 15:40:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510828; cv=none;
        d=google.com; s=arc-20160816;
        b=l/ZaZDLbaIi3nzV3Kl3MduP62PAOq3fJTsx/Kay445u/3rkw/coBeFaZ2+IDNlgwK6
         B42ofWCEasELfZcXUXXL7SBZ9LQkarQGl3FSPxRvYoDa1J5CyZFbG6KRYlsJ0V+aGhVI
         7Sxozfy7qZ9TKuSZdxuEUnot+R5gJo+yuLxoXg159FFEtroomCjLAtKwhyst9KRPJQvu
         RSweGh5+Dv5KLQ/jrmkfQ88X10E55Z1dPiPrGVKupXk3fhdgUuAIsE4yA3ObuMQ2XQc4
         Rp5cJKDrXPS0RqCP1QUCPF/ZFzE+KHrFzlYXIsPCrbzK4Ijo5E2CxMVOqXYiLvabbqKT
         0SGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RNAEdf6yu7dcjX2jOn112T18heV7subpebJzqiDTVHU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=FBxiboUlzy/Q914LDtDbxZdPB13PiI4tqqzV5X77KF3R20oyZq9Rimbl0CWgd/9wOE
         8qL346LyRwe38/JgZBg/SKO9PTdSbq/cWGSbOrOAQ+RYnBZ39teH7+2rx/1R0J0FXUeK
         dW1meoQQ8dqO7CFTRpsDpppqWtyfJCVBvbcceej2i9NY4/mu1Z5RF+/zMzJbisTTUO5q
         lLLQ2nXNMhlKn1D6im3nWa86dsEywd4tdib0vYOUxOIk9rsba7ALq2WW5rJCgm99Lwzm
         mfcKn4JQWzlCdkktkQ8m9iZf6f7jLD7Q2hawjv8PvcL3GF/m/eiN4xIz7QJBATmeE7aI
         DBTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h3Ohq2Bo;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id z5-20020a17090acb0500b0028694acf28asi198979pjt.0.2023.12.13.15.40.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:40:28 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMe3sK026112;
	Wed, 13 Dec 2023 23:40:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5vt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:24 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNWTIR009723;
	Wed, 13 Dec 2023 23:40:23 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5ff-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:23 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDGkI3J014819;
	Wed, 13 Dec 2023 23:36:56 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1xx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:56 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNarHZ45220132
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:53 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 46F5E20040;
	Wed, 13 Dec 2023 23:36:53 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D4A2120043;
	Wed, 13 Dec 2023 23:36:51 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:51 +0000 (GMT)
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
Subject: [PATCH v3 28/34] s390/mm: Define KMSAN metadata for vmalloc and modules
Date: Thu, 14 Dec 2023 00:24:48 +0100
Message-ID: <20231213233605.661251-29-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: vfBS-CdzCAtBe0eAONYSdh2uF2-ntzde
X-Proofpoint-ORIG-GUID: gLjFNC89khIf6pZ9lL-ibBIu5mfuKJCk
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 phishscore=0
 spamscore=0 malwarescore=0 mlxlogscore=816 priorityscore=1501
 impostorscore=0 adultscore=0 clxscore=1015 lowpriorityscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=h3Ohq2Bo;       spf=pass (google.com:
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

The pages for the KMSAN metadata associated with most kernel mappings
are taken from memblock by the common code. However, vmalloc and module
metadata needs to be defined by the architectures.

Be a little bit more careful than x86: allocate exactly MODULES_LEN
for the module shadow and origins, and then take 2/3 of vmalloc for
the vmalloc shadow and origins. This ensures that users passing small
vmalloc= values on the command line do not cause module metadata
collisions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/startup.c        |  8 ++++++++
 arch/s390/include/asm/pgtable.h | 10 ++++++++++
 2 files changed, 18 insertions(+)

diff --git a/arch/s390/boot/startup.c b/arch/s390/boot/startup.c
index 8104e0e3d188..e37e7ffda430 100644
--- a/arch/s390/boot/startup.c
+++ b/arch/s390/boot/startup.c
@@ -253,9 +253,17 @@ static unsigned long setup_kernel_memory_layout(void)
 	MODULES_END = round_down(__abs_lowcore, _SEGMENT_SIZE);
 	MODULES_VADDR = MODULES_END - MODULES_LEN;
 	VMALLOC_END = MODULES_VADDR;
+#ifdef CONFIG_KMSAN
+	VMALLOC_END -= MODULES_LEN * 2;
+#endif
 
 	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
 	vmalloc_size = min(vmalloc_size, round_down(VMALLOC_END / 2, _REGION3_SIZE));
+#ifdef CONFIG_KMSAN
+	/* take 2/3 of vmalloc area for KMSAN shadow and origins */
+	vmalloc_size = round_down(vmalloc_size / 3, _REGION3_SIZE);
+	VMALLOC_END -= vmalloc_size * 2;
+#endif
 	VMALLOC_START = VMALLOC_END - vmalloc_size;
 
 	/* split remaining virtual space between 1:1 mapping & vmemmap array */
diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
index 601e87fa8a9a..d764abeb9e6d 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -107,6 +107,16 @@ static inline int is_module_addr(void *addr)
 	return 1;
 }
 
+#ifdef CONFIG_KMSAN
+#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_ORIGIN_START (KMSAN_VMALLOC_SHADOW_START + \
+				    KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_SHADOW_START (KMSAN_VMALLOC_ORIGIN_START + \
+				    KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_ORIGIN_START (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
+#endif
+
 /*
  * A 64 bit pagetable entry of S390 has following format:
  * |			 PFRA			      |0IPC|  OS  |
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-29-iii%40linux.ibm.com.
