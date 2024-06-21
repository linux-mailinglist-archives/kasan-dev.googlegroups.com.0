Return-Path: <kasan-dev+bncBCM3H26GVIOBB5WL2WZQMGQEIEXNEWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BFE819123C9
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:27 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dff16daff8dsf3299619276.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969846; cv=pass;
        d=google.com; s=arc-20160816;
        b=0as3cjsMo/L3FGHtu1s3qfXFgatf96gIrekOmRKeLu9yBYKEnioK0fmOTqg21bzDIz
         Ao+jFtiHlk2bB7oRGM+Y4yJGWOrMZ8KQqnjgoz5j0qjx7WcmpgSTSkBNS/elfN02Xs3H
         4WwIe9jYEoBSAtznbeikyAkd0TT7VelyKFjf0w3CSSFcGmsP0kmMWVx8tI4hlhBitwOz
         WVCYmzg+TRjXKwvsYRdLkW+fDARwra+DLoI/Gd7NFfem50Mf+HkFr14k+qIVRnP6gFDj
         hKexM2FEmsa/x3r0ZhCrhnOo2sJhTaMnsfvuUT+/3FgbEyLtIhj8cn/NNGezKKEbGIXP
         ooCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JtKoSN+vxZeNqeRx9F9yl7+n4qkx/sNGZoxmFGtyKOs=;
        fh=dTKnkn/dl0XKeMTaRcCG/YHQdQlhhSy8fjkLNYtj7x0=;
        b=nPeSZ6ksmeDFTqGT7Hc7B/nPW7Vpe00z9XJ6CRkN/lI4hLsU6GzyFjBz205tqDbVbk
         VOAlP2yBumEZFwsX2xMoRqTfJ3SViWWFCNNfFOV4CPtL/RF+Jc9eQlzLSZDIG5OwirPT
         iV/uh8GzfLytta7jPULVitzn8PHxPm1R+sWT8Op57Tc9rzTo/JEe6f5wVTOFs3WL6uxE
         cOsGjunK9voHfa8WORfatGgH0uOHlAdn6e6CRibzjYwyiiFNf7tNkAVFBLfHFhQcRamB
         dPSJhw8728wqGKTBm8Po4Au0N9uiurFGiBOtzq/MxUsGCXsc9TSS8MX/O5St2eX5DNKl
         4umA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NwRG9w7a;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969846; x=1719574646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JtKoSN+vxZeNqeRx9F9yl7+n4qkx/sNGZoxmFGtyKOs=;
        b=e0vk9ubDRe8Ckx5u5Yqz4rz/DZ8UqE86+gI9DP2HwVUdiEvzxkVeoL2P4F89/lOJ2J
         xGN6dcy0UdK0LS9wc4sinBMBtMACqz0aWnafl458ILF+qUhoZebxNSWozKCTn8j5I1GQ
         eyINu6V1B8B6lpIFttsSRr9QLiMfylrFSB0+E5TI1H2GtCugI6LXZyoHTWZ7akwOMcz3
         Xqh2Ruw76wvmTjkT+WRZtqYB8ROl1hjt1y+Dy+U8vjlRh3TLJkhtgTtb75AUmKtUOJLk
         BxktkSzGiCE9UA6JBdQn2XEU2GbooQWI+ZPVGEPZC5Pmm8kpjmXe3BUFijmlx6DGa846
         4XaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969846; x=1719574646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JtKoSN+vxZeNqeRx9F9yl7+n4qkx/sNGZoxmFGtyKOs=;
        b=upPDueqxiTclTbejA1sKnP9WFk8dwnlQOsgo2aXxQK6ahNIH1u7tRodv7P2AuKlVf0
         VghJyjHEAQ6m/PpIB16IHvnFKDgTtB6ysvuz+u7+sBAlJJKB1RUCD8Aw4Wrk/CQGe8vS
         HJzaBX1JCaCuLSPIIZKmlzZa5fSkwcGlSdKMAXGCvzpHOjYqht/To3biI/Gvw7L9f5Y2
         M4h+nFeJWXQwKBSvHxJAyKSCJdPplduB3fELNMKgw9FwDnotboBguVMY3mlP/qNnwKii
         vnUGp6OVYVxCxCTtIbZ/tW76R/jqVOX5bKRrdc4gEwSpvn9hY1i1LtiPnw5d7koOLMIj
         XA3w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8BwiN7u7aKjKGlmaeA8OpZyRxqS5IFegPooze3BAlVKqYg7BfNd2CV4rcVj8uzVwLo+WPH/swKYGuIc7CQT48gblocn0rag==
X-Gm-Message-State: AOJu0YwCFgJq/pUTYC01mcxpeSg/Ng/uzGE8jyoDzDW9bu4KiWOpm4cl
	uh1SV58fPrYii3GHYFmP6PmN95mmA0Wda2rY0Muj9Ga3BHxMRorV
X-Google-Smtp-Source: AGHT+IHk6c97aXeldFG6u55crSpQI9QKvxztaTxCkgVkmMi/j/Px4Zpqlxc5mDAsHGKVsHLuQ1BU7w==
X-Received: by 2002:a25:ab42:0:b0:df4:b01b:3d21 with SMTP id 3f1490d57ef6-e02be20f9f2mr9298881276.49.1718969846682;
        Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:722:b0:dfd:ee2e:d48e with SMTP id
 3f1490d57ef6-e02d1003557ls2548084276.2.-pod-prod-05-us; Fri, 21 Jun 2024
 04:37:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsi9T1L80Do4HoGazEuDhV9hNh+voyr3+ePrLCafualx0Xf58ttYkDgC3+t1t7uOnIurNS+vIxbTBDVJ1vOVskmKfkUoLgRBT+PA==
X-Received: by 2002:a81:9e04:0:b0:62f:3278:a635 with SMTP id 00721157ae682-63a8db11467mr80054477b3.20.1718969845258;
        Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969845; cv=none;
        d=google.com; s=arc-20160816;
        b=UiGMWS9n5cCxMq706EGLVgTGdqzb3uf9nxO2W35JFKzYA3AAw9kCvVDhw4wMbE0NTW
         STEOuhIwWSkAnS/0PeDlhwPNZfpWPhXPPReakSEKOrZbbYGGoNJkZQcM1tI9yIcvQ/fT
         PCIxvA9iwwlaN0PMjrp2TKzkyCqFy+kYwicaT2ZIcCR5lyRtO7BEQyE4IXbOR7qhAugO
         uaKkyEVByHo8pRPi5cUSgOa4dLuRURXmlJTlRytnRYrbvyQRCEtyqV2UKJlXwHg23V9W
         UPO2yRiy8z/O5Em6oiB35DJSRPnskHIvyb7KfJfDAiTE7jAydUjx4h1kie9YSusIUd9h
         AacQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9fryXD6fg7ZWH/K5Ic2hWhXvK+X7HFTa6K6lMBwUrkw=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=o5ZXR83zIBNg+q7Q3kpTgR3vjRV4AgyMgtN8oMLoD5v3SxaOAGVQq7n8PMtOsc7KlE
         vOktmg4aHP/9YxWsMmNsI5ag+KM5GPLqi4QyMnq3FqlVbY5tufROJeOp8uwrvWClI+5i
         GH2JtHA4JSe0jUFWn2Q2/6exQWZPNz4RdSaUFPkADi0wkQW7nMwu0m9Pmkiul5rgcBqZ
         0Rc+PjqpFgUjgePkPzJwr5v071SCac5D7w0+v5AxYmHegM1czScgu+EYRwog4IAGO0Ys
         A/UeqsZHAkVVNrL0rE/AgL7Tdg9gj0+ELLDZFuF3XiaYSxTsuuEoJaiAIS4/K67SP4mW
         h0lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NwRG9w7a;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-63f150ff86asi322157b3.2.2024.06.21.04.37.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LATGSV018103;
	Fri, 21 Jun 2024 11:37:22 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t5045t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:22 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbLLw017458;
	Fri, 21 Jun 2024 11:37:21 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t5045q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L99jFH031338;
	Fri, 21 Jun 2024 11:37:20 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrrq6vfk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:20 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbEHR56754514
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:16 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9D48E2004B;
	Fri, 21 Jun 2024 11:37:14 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0868B20067;
	Fri, 21 Jun 2024 11:37:14 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:13 +0000 (GMT)
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
Subject: [PATCH v7 09/38] kmsan: Expose kmsan_get_metadata()
Date: Fri, 21 Jun 2024 13:34:53 +0200
Message-ID: <20240621113706.315500-10-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 2d2yzejn_5N3eie6A5aHac-WohbQjPgg
X-Proofpoint-GUID: LxBKq5auC44MABsbauNQFbMiBqpPPcNl
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 malwarescore=0 phishscore=0 clxscore=1015 priorityscore=1501
 impostorscore=0 mlxlogscore=884 suspectscore=0 mlxscore=0 adultscore=0
 bulkscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=NwRG9w7a;       spf=pass (google.com:
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

Each s390 CPU has lowcore pages associated with it. Each CPU sees its
own lowcore at virtual address 0 through a hardware mechanism called
prefixing. Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to
resolve metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the
arch code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h      | 9 +++++++++
 mm/kmsan/instrumentation.c | 1 +
 mm/kmsan/kmsan.h           | 1 -
 3 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e0c23a32cdf0..fe6c2212bdb1 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -230,6 +230,15 @@ void kmsan_handle_urb(const struct urb *urb, bool is_out);
  */
 void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
 
+/**
+ * kmsan_get_metadata() - Return a pointer to KMSAN shadow or origins.
+ * @addr:      kernel address.
+ * @is_origin: whether to return origins or shadow.
+ *
+ * Return NULL if metadata cannot be found.
+ */
+void *kmsan_get_metadata(void *addr, bool is_origin);
+
 #else
 
 static inline void kmsan_init_shadow(void)
diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 8a1bbbc723ab..94b49fac9d8b 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -14,6 +14,7 @@
 
 #include "kmsan.h"
 #include <linux/gfp.h>
+#include <linux/kmsan.h>
 #include <linux/kmsan_string.h>
 #include <linux/mm.h>
 #include <linux/uaccess.h>
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index adf443bcffe8..34b83c301d57 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -66,7 +66,6 @@ struct shadow_origin_ptr {
 
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
-void *kmsan_get_metadata(void *addr, bool is_origin);
 void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-10-iii%40linux.ibm.com.
