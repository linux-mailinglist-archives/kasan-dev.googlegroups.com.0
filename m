Return-Path: <kasan-dev+bncBCM3H26GVIOBBNP2ZOZQMGQEGJZY2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B207E90F2B4
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:58 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3d21bac5358sf8220185b6e.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811957; cv=pass;
        d=google.com; s=arc-20160816;
        b=GaFfSqKCHoTnKCg9um8vDyDFDnEwNYDoEYxFb9hpEH4OgbCJx1nUlwFFf4AULbJXQg
         0yN3QPViDJ1j6KyDMzOukdee/fbkGNA3GgAga22TNuk8cQNtuIsx6f5HMqIjba2UEMak
         o/9NLo0eyBi10qNjH7IKZv1S4T7NhBz9/nkFJhOs7eeyC6WQ29GgfSc/vwCQXLd9FgtI
         QoyCDGNHNZXkzQ17Uy+knA9pXBBS5hQTCDv4+IP4fB4R4RItwysWTdBmHOoGwdD8kfHe
         w3NjD0rDToLpU/we0GbZqc70z784oAwe5M+EmlKIcTfEXZn1ZGyHBFfyO8YunKy8Ckr2
         sXgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=J5zr24iOl/CjHa7o/9tlrNljAfVklTO05+thfWJUtfA=;
        fh=l4rbhZJjY5ybR+LJOQPdQzN3r/DE+Xz/47++t2ldE8I=;
        b=S6WjtnYf4I/EjGyeEC3M8+R4YXTl2Hltz2cjocyxKVoY3fRWa0mARK3k0tjn7HXEE7
         KOJHxlx7BFNh0pgPaxhKNJcCmaGJ9jkpFdw9G6YsTOA42ShYvhOlAWRy5hvBZHviHmdB
         R8IL4xop9tokCFL8IAOiWXzOQzdHmdKtXiFOakgoiE3UoVvdvo8aDCJlY3dzqJndYHxE
         5HoCdKaVlOeylrF7Xhezl8qaA7XuKqfc0LzNFZKXddwa/7CxonhLPAdFpjokl7MKXhhx
         FfJ1LsMv98TmV6nLSdC6PTaLPtrPqBWaYnkFbPVdT2DiKzsZv2loNk8+/qSXl5DLC7wt
         J86Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=giV3GCSu;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811957; x=1719416757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J5zr24iOl/CjHa7o/9tlrNljAfVklTO05+thfWJUtfA=;
        b=C6JLIO+ZzDootuJuqC37ZJ/sRBevLubtBzho8OCyeodpWRFRq+uqDzo+scrs6DxTsp
         jc+LtU97GXRr4i/aqAk4Hvdv2II26S5h9L1+W2b3NrCgYkPQxIOvNxF4efFB0/89AIqh
         M/Pl0I0mMr4dfkmalhaxPArDSqI/9+MO7GyvyHzoqRSlVUOxay1uWJO7ObT7a7coHY+0
         ZRcQU1yQ0RTzrRUox8w1RVMfoa5OncdLFYsfLbh7RytHDZtoWKK7KRVe0gZbcxBY4cmN
         lTX1W32wrXselFohh8VTweTqKYqBv9/c6GPFlR9dv7aPBHr211q7sKL6oyzky+Z9iQFt
         LXmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811957; x=1719416757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J5zr24iOl/CjHa7o/9tlrNljAfVklTO05+thfWJUtfA=;
        b=lUoVb37X1NkLlRK9tDd6Is0M1pc3Qn61l13EvN25HOn2wJoc5r2S8fVTAclyyGl9HO
         tEeB6Cc8inJizNDNVV/ZXJ8ptVXK0XL9ptO2o4A5mr1AP3qCc48f1krh6J60ggFtnrHI
         ha2ifMo34QoVR4PRI0VuadS8mcFx8A48+m9PfS2IP7X0hImK7xatDgZftp4iBiyB3LhS
         pX6Y6fgQCj+LyuNkqOpQSsM1ammuqT9LzdEI6xqfOSNvF+picXgi2CGcxU/eLeMtg+DG
         K0YR51cYIVoxxDuCMYg5Nt6/SzZXZvo6kc+x74DpY299/bLpfNdsxV8UuFMwSs6UfzwO
         cKvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9jFmGJDq2/huO/RbCUtsh/tALjSbMHeHtRXC/n3TYLCItWOsleFGUjW9Dc2BoAcQdyx3TDj6+rIiYImVEEmz04ifhup8X8A==
X-Gm-Message-State: AOJu0YwgXXqzN7x/Gu4jh6TFVXjEnxczryXP8L3A42FikT6tsGYbFlLW
	m7G7IlwtCVoqtKsNUYv5c/hd16Y2qIOoGNki1Y6KipaQ8nY8Qy/w
X-Google-Smtp-Source: AGHT+IEF8tfI3QxXBIRcqSmzw6kdtq3qS7SI+qj5m7TsEy6WhL3Fc/X/q6HFVMNRpIAx+L9N3ZyKwg==
X-Received: by 2002:a05:6808:21a9:b0:3d2:2721:8a85 with SMTP id 5614622812f47-3d51b965556mr3270596b6e.12.1718811957421;
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5e53:0:b0:440:6208:aff4 with SMTP id d75a77b69052e-4417ac32867ls100842781cf.1.-pod-prod-09-us;
 Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+FSdLrKSb9+gtt5gBukFFf5hWvBYl4i05paI7v4HYKL3L0+lEurnLv+OTxeMC/0NQDO8HUgWYfZU6/+sZO0j7itLYBH20ERdEYA==
X-Received: by 2002:a05:622a:24a:b0:441:5985:3fca with SMTP id d75a77b69052e-444a79a4050mr36407291cf.14.1718811956645;
        Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811956; cv=none;
        d=google.com; s=arc-20160816;
        b=pc5PdWeysP2E8aMZqQbL3KInVQ7lon2HgiIoQJzwWaRpALPG5ch2MyxJxsDFhzML2N
         fu+VMbKmhAuxak+TtG63sVuyVWnP5R3ylNtAzBRDhjpSn1jP9oGIY0OmkSaVfARQacWp
         Kj7i5ZYskDsiZYfzXQWhSsmu3g9nONnRzhgPu7eqX1aLfcR8Y01LLKdvwtD5Xe3a+GiV
         fZQlmBdWOFFSqAF/WCgBaBhy5uKoO+1FL5vseGgXUYTGR9LiP67Fzgptlhz7qXBGJbD+
         nEUloah+NmxPdO97ZzayHkZMksFAtwbHyqX/yD7uUBa229742LTSLRWjd1Z97Ro3LX9v
         Nddg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1loLMhtSJ//mVR2W6iv7p+SprUeUNXIsjh3OlBetJcI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=EvmurGdHQ99BPPlpKraeFTYwVMMmTg013eF69F65r12p352pyYvYCssiVwUOC345yG
         +5dln5q7KPZLu/gd2FxvczxFlSqW/tX+ERi1Omotw0v8qcrmGg5VHCXf4QTA2dBoG8Oy
         0OapOr8BnCh8famLBG+0mnceHhe+pOlfv+nAu/cgzua0rQpD8uSReX/Fvl/eWMsj2KNU
         Z5gLlGcQ2EErdd4DR9aD1aJ3QPvj62HP+h9g4cORQvQTSUf1v7zsIBcAxWGkzm8uCjfx
         8xGgfHzbp/rx38/Jkh40APhqRG7YkDnMrwoj+1N8ZbUDtG2X1FM4oZLNs8opLDEvxm8z
         z7NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=giV3GCSu;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-444a41c5be9si1733951cf.2.2024.06.19.08.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFQlR4018028;
	Wed, 19 Jun 2024 15:45:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg8546-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjol9016365;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg8543-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JExeaH006285;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8n7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFji9C20382130
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 49C5A2004E;
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EF5F52006A;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
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
Subject: [PATCH v5 30/37] s390/mm: Define KMSAN metadata for vmalloc and modules
Date: Wed, 19 Jun 2024 17:44:05 +0200
Message-ID: <20240619154530.163232-31-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: AecUav4zPu2pbA3kMbY9tgEYraj6MXQ1
X-Proofpoint-ORIG-GUID: aq7PB1sVMkX90gQQlshy4s4Ee0lgg62B
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=702 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 impostorscore=0 priorityscore=1501 clxscore=1015 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=giV3GCSu;       spf=pass (google.com:
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

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/startup.c        | 7 +++++++
 arch/s390/include/asm/pgtable.h | 8 ++++++++
 2 files changed, 15 insertions(+)

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
index 70b6ee557eb2..2f44c23efec0 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -107,6 +107,14 @@ static inline int is_module_addr(void *addr)
 	return 1;
 }
 
+#ifdef CONFIG_KMSAN
+#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_ORIGIN_START (KMSAN_VMALLOC_SHADOW_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_SHADOW_START (KMSAN_VMALLOC_ORIGIN_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_ORIGIN_START (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-31-iii%40linux.ibm.com.
