Return-Path: <kasan-dev+bncBCM3H26GVIOBBA6M2WZQMGQEHTAWE3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 089A39123E0
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:41 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5bfad6bf464sf2040034eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969860; cv=pass;
        d=google.com; s=arc-20160816;
        b=eWpZZXwmtWBDvd3ut89rS3Pp6CkJ/Q7Hpp2s39kboUPN1YlbZFSsEf3UDIxVVbEdvU
         a6Ir3T0ur7wCwzIXPV4dl5jxMi16CQTDizO1Sg9abpMdAz7zmr7RN8JWfWFj9JbbZO5s
         xYx2WoVI0sPPAaYNgiTZSeUvaviTABkoBwWmIxMcwWBR17hkXzTcvnsN1TCzItasPNOp
         zcbr8bHUKdS8SB25Jcpkw57eZrRKJSDc5f80Cu6zaUeBK2swdZWO+JNkyEujIItdAQet
         A6umodvyJymjS8KqSwlMNHYFxrjf+uEnEULvx8cSgetUWKKUtjP6Au7d3GSMTbrmXcB5
         4xtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dlRAc5QCbUtuZq6wU/5ndoiwuasp0sMNH/8EzcHPHW0=;
        fh=d7V+eWI4w6OODto1Y8oL8sOBliJR/NMP1LOaaQyJ2sU=;
        b=N1TrGTDSM/7EBHvyv7w0POP3f+Ci4eR+OJQdl8ckuft3DMlXXaRl7FJ6Ir65q7VVif
         02+UkasqzLVOWgh8n069o5SU2lIr7Ke9AptlYRL7oT8E7kUAmXnXWxXM5mqLOl5WO9JG
         qgx2v4ujrS5+/oF9z0M79x4GKUFCbeQGpaPOmBL94iUH0QdjPHD33FbTvXKjVROH5byc
         eCjOg8Rhnt0VLRRWQeMqu/K8GFPX5Ew5zj+ac1gwkK5z/O7Bq62YOH1IuFoGl/6mfPTE
         Ed6y5Py//LQvGOrVIkehYDKy8QVFOeN3FQxXUNyS+SAV/D3bpH8VF0aqgte2RMMaEohu
         K0JQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cHS4AIQu;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969860; x=1719574660; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dlRAc5QCbUtuZq6wU/5ndoiwuasp0sMNH/8EzcHPHW0=;
        b=Z3KueSMzCxuvf9r42QTym5ZWlxPlRsYfzB93t4s+LAk4c+OwsEofQCq05vWywwUmpw
         0iSIu6YZX9NrpNklp+igBOvMkY+VGwjZcSxJsCvi4wr6MoTtrfyFo8m8h4YJlfPJYNf6
         rcpF7HadExmO+1lFtSqfhyTKK7Q1CU8tL0AHHs9e1gqwiyJvsD2NjUnFYIwd6kHWRKPH
         G0A8PP/RZlSGIGhwmggJu2NbxVTTltu2RpoNQ5tQr/1L5+7DM0gwdWZETIeneUFT1viA
         HDNORXqaM+a10TmF7lqisKkO/a5MPRAJJf/SGYPD/ME6pQhSgMqmLHBrXfOzgKPplFWT
         zhpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969860; x=1719574660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dlRAc5QCbUtuZq6wU/5ndoiwuasp0sMNH/8EzcHPHW0=;
        b=kklNmw5YYvozJC5QKpDwqbdGme806RaM8Be+lGOCbKAvT7AwDBvCBERPEpvbozVwum
         4FlYEQnAHLAoeMMDh+hNAwGXdcb6w7CFKLGTjA/8lE0nQig6RnNrjPeuu8Wo3QFvyk3h
         3lB5t9xUg07OWgmmgAzHvko0M35jvsAoMc7a/L8RLo61A4REqG3BEyMCzqDC/06l/T4G
         wiCdvzz5echQxS7in+ZovMuT5rLSM9lT6usDlg/mE1dm1CjvRlpqPM5Ty6Q+YJxbFmR6
         wpzZRV+/GqNTevzc8aU/vtq38fxfwMb5qQKis1IrzFApOHmxMhmP+8VNeIN9pk5Mn6g0
         JB4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUH5Y/wyB3TzZlzXW4GasoDTd/TShlWiakHqmEuXeUshJW1I8YwUmVmdNeRgOjB1lb43Qubj73g0zahzQAIli0LvgFtJ3g5uQ==
X-Gm-Message-State: AOJu0YwMFIfhqyaFAuoFYfqZQ7O+ccCQkI7vJu78LPqjNuXwfEVPPzeq
	emSBDMJfcb+ZndlrlhApOGg4pRxF/CLorSWpzHOX2zuYmauPDILq
X-Google-Smtp-Source: AGHT+IFv88SvQ/4haFWGw0oaXulxR2Fs8ZyZ7Leh2PadWjB0D9VOzG8zZKCRTcjiEQhMc3d0Lm8xqA==
X-Received: by 2002:a05:6870:7250:b0:250:8255:e793 with SMTP id 586e51a60fabf-25c949a55efmr8430014fac.23.1718969859758;
        Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:724e:b0:254:6df2:beae with SMTP id
 586e51a60fabf-25cb580f452ls1708289fac.0.-pod-prod-04-us; Fri, 21 Jun 2024
 04:37:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5gsZ5FSqQgU2yJJ4ZpApsFYseRLCztivB0ohAhfg8nVs9GJvgOmxP5ME4Gwjpj80oPRNpJSSjdk+9WsRhRXac6CQL6iXP0+yqrA==
X-Received: by 2002:a05:6358:3115:b0:19f:45ca:c1cb with SMTP id e5c5f4694b2df-1a1fd35d52bmr1015711555d.7.1718969858962;
        Fri, 21 Jun 2024 04:37:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969858; cv=none;
        d=google.com; s=arc-20160816;
        b=skodX/Zc2wpxdB5hug7K1OzWX6yI0yovMUchqyHlbjOWZLEP7RfgFFw7m2lebrUG+X
         vpaICm6ZyhPdsTYsqVvy/zaxzIjP6OC5w6Y4Kxs86CVQ2IUpf1B1j44o1K5m37Rnd0tj
         AywlW59oKYwhaUBwgJpwMG523j/jYk3qkuXUWWRQ4W6BJb2+IRUMhwkYkNd7xnJoT8u7
         DNFlShVOgl+V5ot/pFZKBL2UPt7amwPDHhNd29UrcFoD+boJLlI34ev7JTRQwY8vdI/T
         rCZ/CIeGcvKGZNA8PXwkzVuwkbPO0z94lMqt58Q3Xq7XUT3Z/DGyJPdD4Cz2tEaSirG/
         dz8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=X1oGap99TVdqBvzHLWhv+TXBuFqzUMdrRG4OBua4bwY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vWEpKqTpaHFvb5ZJEkw9Rjx6phjRHtGaHyi8yARD/Bajck6a8aLmvgxfu3Y614yiWJ
         y4npSV54gd3ay/mbfeycd3sUlEx7h7Xb5SifIC1Vq7qejQuINnrMqW9MjYfs9lQeLMTx
         2OintrsaDqZzbnE+YszEFAvaO5ELC5RKCQrVPMmOyt3qLNO7QC2TY+/l6OI0ZkxXOGGq
         GiRroe/qufZs6nHimZcU3srf0UwQWRVGqdzd1+FKA3fOEqjJyEDBL4Ntza075G5TRiVI
         0IL2h0tRmFl1YWanuuHXmmmQ4EMABrZuQ2zTUborN8z7fNzVZI7s84iQqDFH03+a4m+T
         GiZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cHS4AIQu;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7173d8a40f5si39340a12.3.2024.06.21.04.37.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBSug8032437;
	Fri, 21 Jun 2024 11:37:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0kn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:35 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbYUM014376;
	Fri, 21 Jun 2024 11:37:34 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0kg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:34 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9AHOT019941;
	Fri, 21 Jun 2024 11:37:34 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupw0g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:34 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbSnF54853978
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1D9972004B;
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 81C262004E;
	Fri, 21 Jun 2024 11:37:27 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:27 +0000 (GMT)
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
Subject: [PATCH v7 31/38] s390/mm: Define KMSAN metadata for vmalloc and modules
Date: Fri, 21 Jun 2024 13:35:15 +0200
Message-ID: <20240621113706.315500-32-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 72Oak4PnOY00Ouh9gmqCpCVl-f00e8x0
X-Proofpoint-ORIG-GUID: B6QLHfkbQ1aHYH9UguQEGWXygvTuApGV
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=663 spamscore=0
 clxscore=1015 bulkscore=0 impostorscore=0 phishscore=0 priorityscore=1501
 mlxscore=0 lowpriorityscore=0 adultscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cHS4AIQu;       spf=pass (google.com:
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
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/startup.c        |  7 +++++++
 arch/s390/include/asm/pgtable.h | 12 ++++++++++++
 2 files changed, 19 insertions(+)

diff --git a/arch/s390/boot/startup.c b/arch/s390/boot/startup.c
index 48ef5fe5c08a..d6b0d114939a 100644
--- a/arch/s390/boot/startup.c
+++ b/arch/s390/boot/startup.c
@@ -301,11 +301,18 @@ static unsigned long setup_kernel_memory_layout(unsigned long kernel_size)
 	MODULES_END = round_down(kernel_start, _SEGMENT_SIZE);
 	MODULES_VADDR = MODULES_END - MODULES_LEN;
 	VMALLOC_END = MODULES_VADDR;
+	if (IS_ENABLED(CONFIG_KMSAN))
+		VMALLOC_END -= MODULES_LEN * 2;
 
 	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
 	vsize = (VMALLOC_END - FIXMAP_SIZE) / 2;
 	vsize = round_down(vsize, _SEGMENT_SIZE);
 	vmalloc_size = min(vmalloc_size, vsize);
+	if (IS_ENABLED(CONFIG_KMSAN)) {
+		/* take 2/3 of vmalloc area for KMSAN shadow and origins */
+		vmalloc_size = round_down(vmalloc_size / 3, _SEGMENT_SIZE);
+		VMALLOC_END -= vmalloc_size * 2;
+	}
 	VMALLOC_START = VMALLOC_END - vmalloc_size;
 
 	__memcpy_real_area = round_down(VMALLOC_START - MEMCPY_REAL_SIZE, PAGE_SIZE);
diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
index 70b6ee557eb2..fb6870384b97 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -107,6 +107,18 @@ static inline int is_module_addr(void *addr)
 	return 1;
 }
 
+#ifdef CONFIG_KMSAN
+#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_SHADOW_END (KMSAN_VMALLOC_SHADOW_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_VMALLOC_ORIGIN_START KMSAN_VMALLOC_SHADOW_END
+#define KMSAN_VMALLOC_ORIGIN_END (KMSAN_VMALLOC_ORIGIN_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_SHADOW_START KMSAN_VMALLOC_ORIGIN_END
+#define KMSAN_MODULES_SHADOW_END (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
+#define KMSAN_MODULES_ORIGIN_START KMSAN_MODULES_SHADOW_END
+#define KMSAN_MODULES_ORIGIN_END (KMSAN_MODULES_ORIGIN_START + MODULES_LEN)
+#endif
+
 #ifdef CONFIG_RANDOMIZE_BASE
 #define KASLR_LEN	(1UL << 31)
 #else
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-32-iii%40linux.ibm.com.
