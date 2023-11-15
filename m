Return-Path: <kasan-dev+bncBCM3H26GVIOBB56W2SVAMGQEU6RERKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 331057ED238
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:05 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-58a23b6c2d3sf63398eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080504; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y7i5Ue5DXR0d6M9+dib9kk/Nc1hzP3vGK2OtnZzyDMVSJ0Z5ljPDcdQARY7HNFfHLu
         ELCdbNyjPEvMlQmzPFB8o7kOHr2mYCG0dFKKtaRfPHvD4rUYPrE/mFbyfIP2tmpUswe2
         fVVEHNQanlScSjvp05j0vi+jxC/RlujoziXooFNiAwYEKTNQwNdkzAi4CU2uUiqUgSkx
         +D4+Ls1h+qoIHV4CIY1YqI1m0AfTwUrdak8KkUPuxR2CfhxjGSAE4m3oDatg/Lqsrvm+
         MjKLvnhomIN3nmawW4cla+zxrYNCYl7a9oTr890ps1/3QhzowyqokLlYeaodxMBfn1iJ
         ckuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8X85bv/rgNXNfObKyxj3CsmwpXv3/BANBsh0A2mBWA4=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=d6IOnv8l+gXu2xvIgJvV2Mk/xOx93Yxzf78JeEiIb8Iq/2jY/+2R3epeAReqs0ZQB/
         /4c67WT+TApKOcmYyvresUrDVF6QRoJR0Wap+D44/pJ660yDjxBpoWyXoZVh3kTFEp1Y
         gCpA6IB0Gg92kRymzvU7pC6y9OGsBaUu+DAJyTXsuSi3k7yB4KiGy8nIaYAeNl15wVie
         fW3aq3ToMFyyO56mOGS39xxY12KWxTS+D6bQljfH8oKq7hp9SPY4KQFfyOOzgY2WGYf8
         H/ysdARx9AOJkDi9qXgh76p/GtgBni5OW0YpuNz6Wdjl0+SbymMcQYYw0K3M6SrCYUHE
         zQig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="IoV/CdLK";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080504; x=1700685304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8X85bv/rgNXNfObKyxj3CsmwpXv3/BANBsh0A2mBWA4=;
        b=NrCfFe3qtQJU6VsD7jyE4Vle5YFPl30tqjbfFwLhvkFHuI16VHZ/a09+YHR1KmGG5X
         I55eDhU3rUyzrTRaRTcvsmHUK22LaRfyZh882ae9N5a2IVq+xg09J+OUb5r7iqiHq+dS
         /8+zjWVRWkRp54plycWrK6SV9XozMaqln5TSmbDwc9vjDD6qxZrBVL4AvQrtLkGjJ3hP
         OIAVCQHmdNVjZZ8e3MddTFBgFulkE7prtnzEwc7eP8nPW+0v40E/hxSLeAmmHOtlRrz8
         BxzgpkdJ3o+2jo72y90Q2CiU1TRvoYQuioNzxfjVgxbDYpTXc+lJJ4GT8Z2WNZFuwgFy
         /g6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080504; x=1700685304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8X85bv/rgNXNfObKyxj3CsmwpXv3/BANBsh0A2mBWA4=;
        b=oYZmZk+tNpd5F3HRluBl5pc8xbstWctK/vRjP7NCZbTZmxgFzyjHoQCT1770s85yRG
         8IMtGfQcKgoWdeqMX4R6JR/GY72H1wbIkZCBYBJRAHdRX+JzK/SH3FmC0e2lmwuA7KfD
         WRRdq5lgkQWhPhsgywHm5BIIqqJG/+0ilZv5AIDuFn6GKvBLZFpRM5jLcpWSgUy7I8jI
         qT2wl9qYSz0nFhX2lZtU55tG3zP5SqGs8ccHtpBtPeO1RJUwDxLGujCXmrV5R2AoARPy
         JjRYHOA9Nv1hRk8sqD8UCytFOTnVryPhCT/8dOcA/KP3XjMHxmzWbc17Ek48TTdc+Qt4
         PQHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxu8NxrhrCZ12GPwMLJRaqsyVd8mN45B2cOphpMRIMrARJOlN9L
	pLx5PNqM0hJ47T8F3zMalx8=
X-Google-Smtp-Source: AGHT+IFh2upN0x1Q5FEEn7fMxJQVssY3Ir5N7kM/5E5xAx+rn+xgfx96OqHIEc4kyANlO3SHhTJW+g==
X-Received: by 2002:a4a:305a:0:b0:589:d42b:d88 with SMTP id z26-20020a4a305a000000b00589d42b0d88mr13802696ooz.2.1700080503839;
        Wed, 15 Nov 2023 12:35:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55d7:0:b0:587:9479:818f with SMTP id e206-20020a4a55d7000000b005879479818fls88318oob.0.-pod-prod-01-us;
 Wed, 15 Nov 2023 12:35:03 -0800 (PST)
X-Received: by 2002:a05:6830:1e13:b0:6d6:4d4a:8500 with SMTP id s19-20020a0568301e1300b006d64d4a8500mr7297765otr.21.1700080503232;
        Wed, 15 Nov 2023 12:35:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080503; cv=none;
        d=google.com; s=arc-20160816;
        b=cWfcS8b9hMEYLqzibm/a0617xeZituGVOmcCo2YlOkGMVa57lMcXQBoUiyJrkC4CZq
         mEJ8TrcisBfYI5Tv5LQNrjVArC+vLuHTty114qsxgC+nRSWwYeqUEhq5Cd147C+LbhNp
         71XjEfrYA/nFmAoex8aPbaqAhSTw46v77ysEs3aKtGmgtOUgOFtLCUUeoozjIiLIGSyf
         HS5XzGWNyG3rCwhNoFn2Bbg4V6CAXnk7kmADzIZ4q9fuk0c//3d0YGJ045OYxyh6CUX4
         inA+3Z/WMjctMLO+M9CGsehH0L/sA4Lc21r6W1gDhISVYwOOhh1Os25kZuRjWQBIglEY
         rZ2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=asdPuKgysJe4FAig3LXjVvUDTsM5pyq4fMAhQ66oWUQ=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=h8Ls45cK0SOARaRaqrAFedgaZZAyBM17WN+YuwXRnvEXG8K7qGcnk4eyS6xYFSTlUH
         hfJ7ZjtBEbLwDcPhjHU5PZNJmEf5IoNeaaWl/VJfg8Cxt6PLmCe6pQWEGazhRBwEVew/
         R1L5OMSReTYFqDGlCNb/MiIso1/EKr4pvIGAjcb/aB/LYRaNEn0HMxMYaTUwEYZmUU1e
         hEhfglB7m16vbm9Gim+7SXbKZIjfdAIiZOCiIxYFecsBz3udH2lzqMFLj1Fh2ejw5Cwx
         U6qcsBj6aWfJVJZaZD4H2a+TThOa4StNWB80xdHJJH4GpBodDAVjFbeeBx2rIZBuuat+
         qGLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="IoV/CdLK";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d5-20020a0568301b6500b006c6510a80d7si607884ote.1.2023.11.15.12.35.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:03 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKQk3x031373;
	Wed, 15 Nov 2023 20:34:59 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4tk8fwx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:59 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKQjbM031266;
	Wed, 15 Nov 2023 20:34:58 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4tk8fw9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:58 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ070014625;
	Wed, 15 Nov 2023 20:34:56 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvxb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:56 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYrrj22938112
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:53 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 58D382004B;
	Wed, 15 Nov 2023 20:34:53 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0BBD120040;
	Wed, 15 Nov 2023 20:34:52 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:51 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: [PATCH 26/32] s390/mm: Define KMSAN metadata for vmalloc and modules
Date: Wed, 15 Nov 2023 21:30:58 +0100
Message-ID: <20231115203401.2495875-27-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 9rXu4AjXUjT1J9zSVl2CpI0z2C-CA11e
X-Proofpoint-GUID: s4ZHT-IpHSSL7EXtoiGwwWPzfBiMndPZ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 phishscore=0 adultscore=0 clxscore=1015 mlxlogscore=839
 mlxscore=0 bulkscore=0 malwarescore=0 spamscore=0 suspectscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="IoV/CdLK";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/startup.c        |  8 ++++++++
 arch/s390/include/asm/pgtable.h | 10 ++++++++++
 2 files changed, 18 insertions(+)

diff --git a/arch/s390/boot/startup.c b/arch/s390/boot/startup.c
index 8104e0e3d188..297c1062372a 100644
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
+	vmalloc_size = round_down(vmalloc_size / 3, PAGE_SIZE);
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-27-iii%40linux.ibm.com.
