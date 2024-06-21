Return-Path: <kasan-dev+bncBCM3H26GVIOBBVER2OZQMGQELFZWQVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CDF9911756
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:01 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5bfb2547babsf1490190eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929620; cv=pass;
        d=google.com; s=arc-20160816;
        b=VxNbYYmovDV1nuUqT3PIebfjCl4JjirXbOL40sENLmGD+47Q/VOwsdWAcyF4bZJfNB
         MojRKqr+14XAyMfsfT/kJ9iYBVMSi/2MItKl1cqhVjhkaHn5vBZ9QsYo36L7gl5W8m9O
         YMGlv1/zxs4fXA/546Cm5mj7TI0GWXwdiTTiYotU5UgGqCa2q1Z2oJQ+uxKO/lN7HEko
         BLxTaXLWBa0opvoRLGJGys17rtlyyNJNmPc/tyObrXMk6t6R0cEWh025VfHQAk25eR8/
         KX/GxD4ZSFVrI0z6FRPku1H40jts8ovQzgCPhln1P7YvV2Y4c+/+UuWLG9bxfwVFZQEa
         e1iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hy0ct1wiCY/C3+Fm32doFaOYJ7gj547wBdWKY+HKhD8=;
        fh=jo9XKWlvVoy0ChXpiaX/OWOSG45DTKNQiPSiF2toPXc=;
        b=lg24EuiakyYZI8FBTweysMDwN0UlhWqNBWq3OoZknKHo7IsHFIR4cH1H8W722EtXj2
         sacCoq+8y13nOPz0fTf2qtIAFz6pxWLGImlXWytp9m7URkBg4G7TeuUlrGYfZy9vDVGX
         4pQStuONoqvCUnrfVRow90emUt57wrUzGVqoLz3Mp6g6yI7KRdaRSf7lY6g0Ny+ociXT
         mKUHaJqNp3WJHp+jfMTQLCd2FRlzMZuw3gjeiZIiP0Sy14sWCKOzBHKn5+d3NzxXy4RN
         z8smpJzMY/1rG1o/BEZYkowxCP0v4TZrhUAm79gSh87eCxhIKX2U32r01EQRyi1Oce5B
         sQlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HsKrXHfy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929620; x=1719534420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hy0ct1wiCY/C3+Fm32doFaOYJ7gj547wBdWKY+HKhD8=;
        b=hJbJxXzQlJv8vFsNM83bN3XN9FdLkkwYi2qBB1Z7BXvLzQuKwrwT6bl8D+eLbYqlIB
         1tbMpeYVkjq+lxS/a/CHg+X02gKUoVnWCrVrp0WS5p74iHC/lS1OK9Ly0yIfubnEQNoG
         pG4AmiAAj5FFo8RFYVJz2f/O6WdUlrLztCpM07ilDA15GsLpMcTDygHhFFVLyxJdq/ZN
         78fussVAuVsh0Vxd/LMMPChtFnouY5PGKNX+/17+j5GfjG58gRXfGtmvEfN8+ak6Jwr4
         4PPXzlVfhni2yzMyCuWBBu2OZxAkyfUuDUI0g8hkQ7n3iaLYU6oVtngdFgFqI180Nobl
         Qo5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929620; x=1719534420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hy0ct1wiCY/C3+Fm32doFaOYJ7gj547wBdWKY+HKhD8=;
        b=KIkKuj1LjOPwcIFAo2AdCwUJ+yigJ4nHgcVifXmXLTL36TffsnB1tmIMSpwC2d0ooj
         SsNeUmtw4fzvZ9WGlALAfJQMDvJhxi7L34gTlTGS6TZJT4Vp1ENbZLXle1GdQyFjvn0c
         5rPR9f8Ot1t6uqOkVXc3bOB96UV/Ea1i8EqMXGZFZ4pglXS7Ee7URnJFPMNNPQmK6nD+
         zlKdtOuHggNpnwQGKjxashqU0MWgtaThfxXZP/VetSLiWP9Q0OBs9fEQMD+nPyM6AbAH
         NYlhZJpkPA/X4n6OT/co4YSl8Shvvc6oAdRGol/w5PGZs0gC/w7OjSW0lcDCmNo6Fzvv
         NoyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/2LY+wKUGTO7baHD/YSoL98hQIHhpozov8UiMpvUErSZIITTUafOOb1Ov36U51gjZSl+efYxzgRdzu/Gyh4WAtj9JLBAH9g==
X-Gm-Message-State: AOJu0YxybdjSiwRJOnY+N//nPPUHZFybvIv9beMrRg0+1l23RxAFbFFu
	IpR8Z7q/UiBmd9Ih4HNlhcNX1FCeMebXhthBPQAsEUYwRTnaTwNw
X-Google-Smtp-Source: AGHT+IFCJH4z+tBTOHuxtTJW8Ssf95DBBU6K8T09HwBRjQtwUzHFI7+Bei1q2PnXxDdEBJ1KeotObg==
X-Received: by 2002:a4a:829a:0:b0:5bd:b862:b216 with SMTP id 006d021491bc7-5c1ad898fe6mr6990861eaf.0.1718929620269;
        Thu, 20 Jun 2024 17:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:655e:0:b0:5bf:bc4a:80c9 with SMTP id 006d021491bc7-5c1bff7a317ls1291498eaf.2.-pod-prod-08-us;
 Thu, 20 Jun 2024 17:26:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVkTkHfKCXEnldB5ivkQIymrK4JAbRJOgWpnLllMYwF6ErVuI+mVrupuRMM3Ie6bejck+1NNZ3NE5sG9CHVnM6FciSsjOjcTsDa/A==
X-Received: by 2002:a4a:380a:0:b0:5c1:a296:6b2f with SMTP id 006d021491bc7-5c1adbfa8d0mr7306366eaf.9.1718929619278;
        Thu, 20 Jun 2024 17:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929619; cv=none;
        d=google.com; s=arc-20160816;
        b=nPaUe8dEGSv4o4EHj6HYkNzQtIzoRWYvXt9LnXs2GoQrbYpPewBsHfm2Zf80O9bAw/
         EfaI9CoglazRREGuSJhK2Jo4obG5OwMYu7q4hhOncBhtgZi8VTKVKj2hxpmaVvlB+HeE
         r52N9ApMOcHAnvNUDz7R3m8KUgjNMtlEVPTMZBmpgPo67KKgDMMheardApwfDYGsUw5B
         sDajTv1xY28VrGFXprR4rZuTF8wDPpASsBCTeQA51K+J+u2wCAp90eOOiCQ79YycotHF
         c4N2cYGqfiTBN2YP9IaKBAcQEgULUkd9I97fQIcwHfh6yxC8SmV7hmr2Gc/rlo9DEhFC
         2m8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=erZvlatfvJVe/hx7BkMgZ/7G1oP598/R1HnuL1JF6tI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=DYANxDA4WVzwPIw26Tj1uP08BfTQgANZFVpQyIjdGTqyOyUp6wQ7un/9dvPkAUwcQL
         YlPWA8bHgTJpm9ERRAjKI1vfNlBkecMMtsAXgHUKRP/MM6HiJUZ4McbRbp2AxJ01vUeq
         KjCJnY4VXDiZHejGU3D3q75vTJA5PUiuk8k2oLXOxBQ/scuh4y0p4EjiMPjTd4tMOBlo
         tZb4HcGOfzo+rS0w7x+4oEB1DLuHq9w2IiijU2I/WbLdw3pZ7aUapFfaA9Z8/ml5UosC
         DPX4N8f6u+Mo5g6IALd4TfE20o4LLpvtjMhkL0ivABs2l2I4yXML92hpp7eOhDnzUM3L
         j3ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HsKrXHfy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5c1d59a0dd2si13232eaf.1.2024.06.20.17.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNugHH003832;
	Fri, 21 Jun 2024 00:26:56 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07tv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:56 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QtVJ017251;
	Fri, 21 Jun 2024 00:26:55 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07tq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:55 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0Qo1h007675;
	Fri, 21 Jun 2024 00:26:54 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamqe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:54 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QnIF26542838
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:51 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5F0C52004E;
	Fri, 21 Jun 2024 00:26:49 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 38C3920043;
	Fri, 21 Jun 2024 00:26:48 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:48 +0000 (GMT)
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
Subject: [PATCH v6 24/39] s390/boot: Add the KMSAN runtime stub
Date: Fri, 21 Jun 2024 02:24:58 +0200
Message-ID: <20240621002616.40684-25-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 9dcK0ufp-zk6wCTiX_6yHz6QVSDZTOKz
X-Proofpoint-ORIG-GUID: TZ4RD5EfkJbUFEJTfU6D8Katl0egKWBY
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 impostorscore=0 adultscore=0 malwarescore=0 spamscore=0
 mlxscore=0 suspectscore=0 bulkscore=0 lowpriorityscore=0 phishscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=HsKrXHfy;       spf=pass (google.com:
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

It should be possible to have inline functions in the s390 header
files, which call kmsan_unpoison_memory(). The problem is that these
header files might be included by the decompressor, which does not
contain KMSAN runtime, causing linker errors.

Not compiling these calls if __SANITIZE_MEMORY__ is not defined -
either by changing kmsan-checks.h or at the call sites - may cause
unintended side effects, since calling these functions from an
uninstrumented code that is linked into the kernel is valid use case.

One might want to explicitly distinguish between the kernel and the
decompressor. Checking for a decompressor-specific #define is quite
heavy-handed, and will have to be done at all call sites.

A more generic approach is to provide a dummy kmsan_unpoison_memory()
definition. This produces some runtime overhead, but only when building
with CONFIG_KMSAN. The benefit is that it does not disturb the existing
KMSAN build logic and call sites don't need to be changed.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile | 1 +
 arch/s390/boot/kmsan.c  | 6 ++++++
 2 files changed, 7 insertions(+)
 create mode 100644 arch/s390/boot/kmsan.c

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index 526ed20b9d31..e7658997452b 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -44,6 +44,7 @@ obj-$(findstring y, $(CONFIG_PROTECTED_VIRTUALIZATION_GUEST) $(CONFIG_PGSTE))	+=
 obj-$(CONFIG_RANDOMIZE_BASE)	+= kaslr.o
 obj-y	+= $(if $(CONFIG_KERNEL_UNCOMPRESSED),,decompressor.o) info.o
 obj-$(CONFIG_KERNEL_ZSTD) += clz_ctz.o
+obj-$(CONFIG_KMSAN) += kmsan.o
 obj-all := $(obj-y) piggy.o syms.o
 
 targets	:= bzImage section_cmp.boot.data section_cmp.boot.preserved.data $(obj-y)
diff --git a/arch/s390/boot/kmsan.c b/arch/s390/boot/kmsan.c
new file mode 100644
index 000000000000..e7b3ac48143e
--- /dev/null
+++ b/arch/s390/boot/kmsan.c
@@ -0,0 +1,6 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kmsan-checks.h>
+
+void kmsan_unpoison_memory(const void *address, size_t size)
+{
+}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-25-iii%40linux.ibm.com.
