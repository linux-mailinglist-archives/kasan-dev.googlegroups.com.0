Return-Path: <kasan-dev+bncBCM3H26GVIOBBLOU6SVAMGQEJMVZKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A70E7F38EA
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:07:42 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-41cd5077ffesf111621cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:07:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604461; cv=pass;
        d=google.com; s=arc-20160816;
        b=fsF7UhoCO1lRvOBDz6+I2+ssFmJrcVZPlMtCDfp7YNXthAETEG8aAVzzD8hkHIA7nN
         SdJmHvJSD+cqMTvjKdGzerQ2kX5D3XQzHBy89Ak6Ho159ToZYT7W+hRhhd8lEO6fcJfJ
         q04gUJXJep6gLSVV6iqmUDvl3xp7StkR9x+SqLPtdDWyD6VYAlX5ZgfL6GDltxfiuEcv
         oQfNWIAdX7rv9m+rxtPXp189PrhRvWoUgFWieI/D9rXyygl2RXABVIMH6FY+tQt7/Uo1
         X/kajFuYAGmp6kAJY274LxRi+t0ERpxGOlMqksfeA/YX+/M4JdT4nuvgKPDGEI2Xmer1
         BxCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Xfbpv9wqc4r9J7QMj66oFIiWZxOiWMgOKlr5dz+zuqs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=hx97rxnPIACKKLXyWyh6Z/DcKeMX4JaVGjsqHqHcJkl9RB4Ex/0cK9PoGC+P4K9CEA
         VzZx4baboLtnYQ70+dXcQ2v0nSF6VyIlcVPkXs9FSfhrhZrRuVj2haGKo88nGPXL+SfB
         VGqDkjHJ2RCdWSK11DDlmI7dR3VSpck/Taebf5doSwYWBqIb7JI5GcKOO4av3guPwR9t
         AfC6JwAmra6q7AcUP6kUU9YhHiGRR1qVr6GrSkhPkcVth8+rbMkPY0Nsz3/VFcczhufU
         +VeEWqsDPOay9HoGZ/M6M5YJqJc54jmQC7lCrFzpBPQ/XSXtdbfdgk+umf2Hh377N+8Z
         liFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ezLj3E15;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604461; x=1701209261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xfbpv9wqc4r9J7QMj66oFIiWZxOiWMgOKlr5dz+zuqs=;
        b=NA06nV0kUXn7PGYJvYZnX0/v2lwfsheMth09wg/l0sKPGYdDSteBkp49uKSX3ijYsp
         ig6PXCd5AytUBEsNTysLWbpJ+lrkR/eeDgXLcv2sd/8gzeZKzSL1mil3YqWom/p6dM/D
         if2GZRGAfvxS+HRCImHiGqdlZg2cfMrszgXflzlhv6Ktq5iztW7pv9ff31JyXFh80OqQ
         gB0RQdt9gdWj6Ngm6F7G2Hg3ueFuPGfTwMAl8oMPrQIEXVuk5WvcwE6igrEj2mfuB/qK
         DSW+NV0peo4rV0NliQqFqAiO251YVbKP3gSe2t5yYvKYE5b9+eE/nKzVGOiQKPIirunl
         L5rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604461; x=1701209261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Xfbpv9wqc4r9J7QMj66oFIiWZxOiWMgOKlr5dz+zuqs=;
        b=geQ2m6RuyXe11Er11DXb0tEc6zQeQJO6h7kbt+CBBXgZr6P3SnB66TQrgVRbVek4aa
         jd5VZatQhmkONzEWteLJ4/U1oaqdln79XsuhA+DkBj3lrucjD5M3uqptKLs7B+poZ/NA
         O74NZJWU572ogtSNZmEayDDdR9B9kd9X0BHGCU5d9PuD+9kBCPJBLo+10XBeBCT7wK88
         9smyN1fPeNOotg3lIeNVnWKUD6jxibrm5BrT94hB9M8ZD+HbV6vYvfquQu9MNz3qg0Do
         zIbllb4hr0Vhnm44VwsrG/2ApoSAa24xzlFfvw+bQFNdhb0XduNtHiYAZaJ2DIh5NpZU
         La8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyEW/ObRKzzLae4hb/P4ls02h4JiBoTvLnUXDVLnAp8i0CaLUDz
	7uQF7rhp+x12zM65lEgg9ec=
X-Google-Smtp-Source: AGHT+IFxgIwrZr0zPVkLtvF7Xsq5dwl2mNznFSogGYMTCgF5eXivblhEg21yNnvkzkI7WaKsvpu74w==
X-Received: by 2002:ac8:574f:0:b0:41c:da4b:21e4 with SMTP id 15-20020ac8574f000000b0041cda4b21e4mr81343qtx.16.1700604461217;
        Tue, 21 Nov 2023 14:07:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7a82:0:b0:d80:8d0f:1129 with SMTP id v124-20020a257a82000000b00d808d0f1129ls804725ybc.2.-pod-prod-09-us;
 Tue, 21 Nov 2023 14:07:40 -0800 (PST)
X-Received: by 2002:a25:218a:0:b0:da0:48df:cafa with SMTP id h132-20020a25218a000000b00da048dfcafamr297959ybh.16.1700604460407;
        Tue, 21 Nov 2023 14:07:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604460; cv=none;
        d=google.com; s=arc-20160816;
        b=XZg+OLXouXbAXtAeZ5VmSeGgy+DkiKk9XkGMPoG5vtVIatytUgDQPejU6dG4TpG1XJ
         x8nLS1lRJXuK1XZdojW69hyhHsdl0RPJJU0uL7osyoNx+Xi9bbDO1bExqdUPyrMDrI7y
         Y5C3UuJnlA8ZBj9r2lrpWRLLo188uTcuYPuqKBmhXbW5N1s8K8jHjmFmZjAsGoh9bjVk
         4WlX/+vAgVkFEFxqf2d+q/HBON3AVWcVYsLuT9KpT7w6gyyJ3wdpzkV58/okWpIZU7Z5
         F2NTA9wgjojctcetcVLkTFvX+eLuUGdYuD/pPVo4aiX4eFwlSw3dgOYeAWonZXhOXhLU
         0H3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4RaOA/Sg5LiWRu5GILmoDX/dU/kL5d44emuuC2WIH+4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vvzCWMoDmz0poxSkioq9QgoVKuZ+NR3Wmx7Or9y8byEDO3O5l6c1IM0aiL1EdOYtzF
         vE0eVdvH2UoOmzbwoYWcKEYBGUccx6Kwiin72lJ3mGshOFnPGePrQclyOcx0ymdAKR/N
         pUIepIhmHqROuSWiipB1xSD0LQmQQ0AW3QVmLfMmsVkAPxrHr2iyYsl0GwP3KA0fLbhR
         Bv4oEE5aNTVJ02V/e4pIb08XCGroPhth/a9PVbMYqnSc9aspV20VoUGL41fM5eML1U/6
         LNmThgtVl34VsslwbEt70B6bImkkfddApwEgpVrNMYP945l34i3DOdxUssFm6ViOvRNN
         f7Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ezLj3E15;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id jo30-20020a056214501e00b00679d9453629si425819qvb.0.2023.11.21.14.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:07:40 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLv7vA004924;
	Tue, 21 Nov 2023 22:07:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn8b0r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:35 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM0GER015220;
	Tue, 21 Nov 2023 22:07:35 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn8axk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:35 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnbtg011094;
	Tue, 21 Nov 2023 22:02:58 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uf9tkbbnq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:58 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2tvA17629900
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:55 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1BA7020065;
	Tue, 21 Nov 2023 22:02:55 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A76DA2005A;
	Tue, 21 Nov 2023 22:02:53 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:53 +0000 (GMT)
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
Subject: [PATCH v2 27/33] s390/mm: Define KMSAN metadata for vmalloc and modules
Date: Tue, 21 Nov 2023 23:01:21 +0100
Message-ID: <20231121220155.1217090-28-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: jEnlnvjW__i_LbTWx-W7S62a6qYl7uUJ
X-Proofpoint-ORIG-GUID: HljdlJiOL-60qRArOlIXIwpUORUdqkXz
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 priorityscore=1501 suspectscore=0 adultscore=0 malwarescore=0
 impostorscore=0 mlxscore=0 bulkscore=0 phishscore=0 clxscore=1015
 spamscore=0 mlxlogscore=840 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ezLj3E15;       spf=pass (google.com:
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-28-iii%40linux.ibm.com.
