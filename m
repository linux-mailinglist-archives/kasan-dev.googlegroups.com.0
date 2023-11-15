Return-Path: <kasan-dev+bncBCM3H26GVIOBB26W2SVAMGQEOYDEAFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8072E7ED229
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:52 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1e9e17b3269sf8792fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080491; cv=pass;
        d=google.com; s=arc-20160816;
        b=N0biVIq5i/d6xbtoHQWFujVQ+gcHMyGnw2x88wg9TuPUAKybibrJCgSupJW5FyueQJ
         1Dn27zCZUeeSjvdProwrAbtuQwOLyWrRBrFFbFGshrq24w74Yho0i8oJo/ABGBFjOjdk
         U6iIp/jBM02mMQtSBdRE9E7XKUcGH0IBIR/Wf09hfSi7PbB5eA2i3Sapzi4WT5iaYURm
         HwimcllzG0p2ZhCHyY8dmQxf1135WiTYPYcxq+p+a5HFxjK62HVaQ9a3WgrPxnmIcnNL
         D5Vk5GhtMKHO9J6WrDHDIGmHCWwjJWmOQBW2tl1zong3uEpVCScorRjJZlj34KJ23n+e
         w/Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XorUJJif43TpZVCrr976PifS2BmZyaxzOlnnbBZ8yf8=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=bfEyhZbKYWEAUoig15D7M7o/SDfun/FRj+icDbfGGuams1Pj1FQVF79JvzOpWdZr7N
         8aXgvJJ8gCBXzicxalVHXiBKuJDcUvmkkukccni9iXal4QU2D1S1tWAC4rG+lUzPw9lx
         9OBmqHGQt1ERed9XS8pfOPG1aQ2GgApwZd2PI/Ea9Aeel2onLB8loHRESZUq/cHdowuw
         M6C9uEatbXumaehjZf+23nvLq6A3upSs/SBvJUgo9xo9onGBs8olPU0EdrFjsyhyCZ/j
         ZkH80xSgVR3w70pHVvohMrir2I9WLLxeYe7hx/thKw3jjNnAnX3RiS50FyKbTnU0VlVa
         2xqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SQHhPpvO;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080491; x=1700685291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XorUJJif43TpZVCrr976PifS2BmZyaxzOlnnbBZ8yf8=;
        b=AOHO30Tg+n5GUOdrnKemk4L0Fc1QE9R850L0xR/Ns0N+EzEgaLcBIPzAtCJFlsdEQI
         x06afto7C2cJ6YyGtmB6dgjpGQof5N/DNN7MltEWa8crQMhqFdLSjpVVkYWupdCJNfKH
         nH1yYqTZr8USJDvg+lXHcV9GMuTYxpahOYNUmmFNctQ8oWiouTu+N8rakaE6UkxVBNYS
         6MITYUo5KabPI4A6DCKqxkMvSzpxNSUHw2eyWMl0kL5QW1x3RB2ja9MKQ9jf4o+ZeDaD
         36qxLn/ACyA/nUmbDdWpRPAey6ZSIHUWN0gA0Wlw0K8jXMqEYB+nSVTExbl2X0/H6cxc
         kiSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080491; x=1700685291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XorUJJif43TpZVCrr976PifS2BmZyaxzOlnnbBZ8yf8=;
        b=CLgjz9QBJfseC9+/HYpWQHfek0goUTzxeFxTZ1d9afDd4HDPqL22ofs8JgbIfiQkK2
         kra/WWypqKEuIrYm+Y7PQVJwkOeXQvdVJRoUHU/Fr0uPaoUkuoxyD1D45kFToVXoLxU1
         Zhqarf+3+K3j5+mLcdMzKW1uJxdmXg2e5BMfWT9He3xKMfoT/Oqx+GWBPZxpjvB/fiGD
         w0X9xFiV6ylgYaufMaru+3gb3TcVu1zfEv3SAN+kj6GLcbMW3TSB8rB9BhBRDK2UJQY/
         sMvykUbitghMCeC00YrEkLOvPAgBTadkXp0t/9LCrU6hZhX2IV7U1M8ZMOks6LPDZ2aO
         NIQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwXsackdliMra77slpG2WzaKLJbcqYxgelVYk8+Y4qGq5jpc1TH
	P4BzcOPgtjMkzD93XZSEMYU=
X-Google-Smtp-Source: AGHT+IENRdLS9IUxQH5TryVxFaEKTv11ctn1LTrfvjGI5QnJdilbqD0LZ3expv3EpjJxEhfRwMLsRQ==
X-Received: by 2002:a05:6871:3392:b0:1e9:a4c8:1da7 with SMTP id ng18-20020a056871339200b001e9a4c81da7mr17342580oac.20.1700080491363;
        Wed, 15 Nov 2023 12:34:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:6a6:b0:1e9:ad59:9f57 with SMTP id
 l38-20020a05687106a600b001e9ad599f57ls103275oao.1.-pod-prod-08-us; Wed, 15
 Nov 2023 12:34:50 -0800 (PST)
X-Received: by 2002:a05:6871:7888:b0:1e9:a741:44f3 with SMTP id oz8-20020a056871788800b001e9a74144f3mr15745554oac.14.1700080490747;
        Wed, 15 Nov 2023 12:34:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080490; cv=none;
        d=google.com; s=arc-20160816;
        b=cPW7mdIJIAtTYv0ynglnofEpk/pS1wzijbcH/TnYgJ18K+IyRq4JA4rQ/5kZrs5YoT
         MbLePUQWaUAxg9c6TdR/NHcKcQ8lpPeyinYnfK6rtULRQ5gd1vZUydiezy+8CQ7SMSx/
         3wbV2h++Popix7Eog28nqV4gnPaEy1tItbyz9mKAPAxyBseLK37crqh5TZdnwyDGWYKo
         INI5gOsN94HA6QhmA/49J6EUq3Z/l4BYExC1v/DBlIBuIp8yQPsuWVUx2eEsp1lDcVCK
         f5nTyksfz6iRZ+R3HtTQX7zLlR2Cm0c3kE/rD/Nz1mnxBHIgha1Ja/lps+7h98sxPvBN
         nyAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7EA0rB7Lnz119cXET77DqVvo3LoXQifKy9ond6IQu6w=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=ncz+leXFO5OrdAlTI7rpLHWcx+0yxRVQn/h4qiqrvi8fWdIMG3PsgUUgOG8BO6cD0H
         LQq+J6jDSAL+2vkVQVGBTv6eAl7H38vk2AfycjCRP7FStCipSQfuUB9xmHGse5nNrkq0
         MVVsAjFRHy638SWPD847THiQC9o4pJXmf3N/uTSbD2bqRmxRTJ37ob37uzPWPfP6PFh/
         AYdS2Ri85L8xq1XRd3sImM+xobQ8k2Wi6E8yEDXoNTbbS1mDmVvjt5q7a+U2KAGtC/Cg
         jp+2mXLmG58iIf0AQ+ECXzl4BGFqiN/SBx5jXB0Za8xub6MAwyIU9ggbhOykxNI3AHzw
         DGQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SQHhPpvO;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id v10-20020a05683018ca00b006ce2f207148si644757ote.0.2023.11.15.12.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:50 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFaD7001501;
	Wed, 15 Nov 2023 20:34:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38cxu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:47 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKSBUm032287;
	Wed, 15 Nov 2023 20:34:47 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38cxe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:46 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ06o014625;
	Wed, 15 Nov 2023 20:34:46 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvv7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:45 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYgHK64946494
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:42 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C055020040;
	Wed, 15 Nov 2023 20:34:42 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7150720043;
	Wed, 15 Nov 2023 20:34:41 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:41 +0000 (GMT)
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
Subject: [PATCH 20/32] s390: Turn off KMSAN for boot, vdso and purgatory
Date: Wed, 15 Nov 2023 21:30:52 +0100
Message-ID: <20231115203401.2495875-21-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: sORo9VaUfpyXlGPcINpF5RzPmD7I3Yie
X-Proofpoint-ORIG-GUID: BZ3SG3oEyN8wfwQEeBvu4En7U_68x4iH
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 adultscore=0 spamscore=0
 priorityscore=1501 lowpriorityscore=0 phishscore=0 bulkscore=0
 mlxlogscore=758 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=SQHhPpvO;       spf=pass (google.com:
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

All other sanitizers are disabled for these components as well.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile          | 1 +
 arch/s390/kernel/vdso32/Makefile | 1 +
 arch/s390/kernel/vdso64/Makefile | 1 +
 arch/s390/purgatory/Makefile     | 1 +
 4 files changed, 4 insertions(+)

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index c7c81e5f9218..5a05c927f703 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -8,6 +8,7 @@ GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_AFLAGS := $(KBUILD_AFLAGS_DECOMPRESSOR)
 KBUILD_CFLAGS := $(KBUILD_CFLAGS_DECOMPRESSOR)
diff --git a/arch/s390/kernel/vdso32/Makefile b/arch/s390/kernel/vdso32/Makefile
index caec7db6f966..8911c55a7f07 100644
--- a/arch/s390/kernel/vdso32/Makefile
+++ b/arch/s390/kernel/vdso32/Makefile
@@ -37,6 +37,7 @@ GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 # Force dependency (incbin is bad)
 $(obj)/vdso32_wrapper.o : $(obj)/vdso32.so
diff --git a/arch/s390/kernel/vdso64/Makefile b/arch/s390/kernel/vdso64/Makefile
index e3c9085f8fa7..f4f75c334d59 100644
--- a/arch/s390/kernel/vdso64/Makefile
+++ b/arch/s390/kernel/vdso64/Makefile
@@ -41,6 +41,7 @@ GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 # Force dependency (incbin is bad)
 $(obj)/vdso64_wrapper.o : $(obj)/vdso64.so
diff --git a/arch/s390/purgatory/Makefile b/arch/s390/purgatory/Makefile
index 4e930f566878..e8402287b0cd 100644
--- a/arch/s390/purgatory/Makefile
+++ b/arch/s390/purgatory/Makefile
@@ -20,6 +20,7 @@ GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_CFLAGS := -fno-strict-aliasing -Wall -Wstrict-prototypes
 KBUILD_CFLAGS += -Wno-pointer-sign -Wno-sign-compare
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-21-iii%40linux.ibm.com.
