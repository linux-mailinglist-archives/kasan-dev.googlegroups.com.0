Return-Path: <kasan-dev+bncBCM3H26GVIOBBTVFVSZQMGQEMASIVFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id EB4E79076E9
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:59 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1f6fcfaed57sf1785645ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293198; cv=pass;
        d=google.com; s=arc-20160816;
        b=WhijOuFpDkMs18xtOse1Sfhkrs4UT4SadrGmge54VNE8WhP4TYyq/7Yb7iwyRRbeRE
         9Ll81NmvYlmtp+T0y7q/5s5VoU5B5WbCm3iXVOqhPdDq5sim8HAj6LR0jkhsuUNJyGcd
         FvWNyir4cUxUPKesozadmCnGbQjMnmlC33ijt0gan3tu+7KiijYzGEhRj8wh8TIHUec7
         hjL2OS6W/g6VCGI1LaruiJ4PhlbQCu89CP31X1iIZEU7da9DMx/jBJ6YWdjJzHmeIe7g
         wbn6eHwNsKlXEG8+ar5LXkAdNwG5eGLOR+UxwEPDSMomRsZb0KFQCBDcH2fkxjpLAdom
         7fog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6qMb9EnS0jZIzvWS4DgBmrtAKi7IRbhgJxATFv/8n30=;
        fh=47EMevpUa8OwS0XDAZ4gwwmvHDGFUZ91nx3O274P6hA=;
        b=npKEOcE1nxkvi3sH2+Me5LZ/hvdTXKt8wKJFYKP9QPOASyXKT5VLE6P2oz+qjIkqkk
         223LQ27oTdHhogl2AeNkytcQuNJAX8PJCBrPdA719abtVvxNT2VuZJkm3yXgJTWNZS3M
         5etn6Mqqv0ItqTZgVxnHU1Ok+i6HS6fYwpjnBHRn5q0kCONzXYkguYj8hoft5HmOBfmo
         8qfeyf0nt7xLwbyQh9hg6uNOX5M8rJ3ekvBd0u12UgW3fpwjfM8gH3H9GD/EsAv58h77
         0q39uzDsEw8mnqLWI8Tu2fdNnI0suhWHNMrt2oX+VA6epIMp7Hzi2BjF8VVc7eldtGLw
         uosA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="p25W7o/C";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293198; x=1718897998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6qMb9EnS0jZIzvWS4DgBmrtAKi7IRbhgJxATFv/8n30=;
        b=dxKU32Os1wdf2mHLOhwBxLR7ouN8IJ9w3I/J6WuokG2qbB3Zk9Frz0b2DEIolFgg+v
         Fh84Qt4hTuZmkH+V7S/kjt1IKhAL03WX8uyIZYjxZXh7DWtrK+lmsBV9U5yl6DyoAXa+
         OIBm4C+W9hgP+PBw6RdniSHU1WXVUnRwuW7QCh4Ywjt1jGCt7sgtP4L2A1z9AShbj675
         HOCo+5Ir2YSo+RvMsyXdlKYgELa4J+KMejiKlGYQfB5kmI2BF8Hf7+LMv0YkScYKPlNE
         0Pb43rSiJegoj8XHAOtu2k9oINvFsjIIh86E6QHfgj3lJEmulF9hReMSr7urs4Em2HVH
         KTow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293198; x=1718897998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6qMb9EnS0jZIzvWS4DgBmrtAKi7IRbhgJxATFv/8n30=;
        b=BjXwe9XhAI87Xfr5++5GqvFsBH/XgMwFCdd+waB/t2gjN5MOpJUTQdIWmidlf1GFsa
         mZ0TQZCYMsgBmo29tvWCtXQR8X6C9cdf25oVH/jNb/D1Jv/W9azBNRsgMnhgINrkDGIJ
         tbtHZgdhCuSEUuZxpZj5xHxfzcZEcIOVMT7+bt4o9OAz6/C26Qs/o12YyKJh0pP5OW+J
         EfMEJW5qPbsT5UosFooSaOxrw8LfhOpnj69CIBjp2cZwW79u973yMvFKAi0obPvXj7zP
         BRxiQCnJkOawurMXT6AbWVKAbtvWnRbOLcgWeWx1CopKvaDx7DlCaBa7LbjV2IQeN8iB
         dbtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrKyT8JKupPFeOF3HlHj+ChoRdm9+fQE3RDITF2q+xloHMzsGijJpU5g+tIiNzVKuoyCoJQ17AxLwKl5O+kzdqzMR8yfAa2g==
X-Gm-Message-State: AOJu0YyxRqeyir+e7VupHD3ko9GaDMAJUEPjzl7HMy2n/kmZsMaXggxa
	mDc1yxEorsI6hNve6hKHAPnk5fYo1sMQ8HlBz4BgplleLtMhuNlc
X-Google-Smtp-Source: AGHT+IHUfDzaKZQ1PE8zEopDfQNVEiCCX0z36xO9yzKYDYYsYUGyRm1homi1t0x0zgVNDrSlsoNv8g==
X-Received: by 2002:a17:902:690b:b0:1f6:7514:9f85 with SMTP id d9443c01a7336-1f84fd51582mr3397195ad.8.1718293198399;
        Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:f07:b0:2c4:bb5c:5e81 with SMTP id
 98e67ed59e1d1-2c4bcf6e3aals670122a91.2.-pod-prod-00-us; Thu, 13 Jun 2024
 08:39:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVd9KUibIoqA5iMeoCkKnBPB23/aB/y6+bV16vmFqDBnysPXh1GTuTSX1LT5fI9kf8k+YDnZzi/KOqb+AFbIsYxMtxcwGvlFg4qtA==
X-Received: by 2002:a17:90a:cf92:b0:2c4:aa78:b485 with SMTP id 98e67ed59e1d1-2c4da567fb7mr262203a91.12.1718293197206;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293197; cv=none;
        d=google.com; s=arc-20160816;
        b=DpbJDX6rI6DzYR4ZBbtkQ87JrHa4XIA8QX0Vq6P9ebeHVW1JJh39KIbtM5WnJqi7LV
         xzHZrvuG7/aqZfljAp0W0CnNkRuP/lpDIPeaS+zNIRizkaHRcI/bq9jKjvS1iIJCtQil
         MWSjX6wT32uluhObs3kngyFiKr1hyCzaDcaLC/2cwzqh0Kk+9OJu2vY50Ngcc4shUR7z
         Wbw2GShnazatxOqJieWvh3nHzKetq+dswaobvsirJT/8gJPPzuidSj2uIbYT9i1fND+u
         waCXUsmWel6Ga3ifDE71m3t4kbU/+4ax8MQOaThVtAh+rbjwDFuWs13OfRq+dwsvyyz3
         gnsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=erZvlatfvJVe/hx7BkMgZ/7G1oP598/R1HnuL1JF6tI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=r7bU7BoQCxrfXvhcbpcfle4vvmjnC+P4Yd0MyJGozUjzNu0tMBYsdsEQt3OYYf+TqH
         4+iTJ3EszH8BHDAtb3yc7SRTu33pVPvJe+6BAaRd8IdaqKoyo+5IIldKdAFvvS+KZfwA
         rQEJHWCxjEyF8xl7yxO5NB+s+VY443ZVYNBTUJlgx3dpA+p/IQ+OF5XzRhPsqf6uFKI5
         7QcbbmbCHZk02AF3Y5Syv/6N2M6t/x/w5yYo9bYEXMXacpX7K3ycIQTsY1SeY+EyVX6I
         vOBVmN3JZAJhW5XHflVi/ZrZx0HazJLSuRk/5E8nFAaTPGcSTmF/Yd+36B+yWSqnU+hV
         RXVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="p25W7o/C";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4c460f23fsi82776a91.1.2024.06.13.08.39.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DCR5FB031311;
	Thu, 13 Jun 2024 15:39:53 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt376-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:52 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFddrG026714;
	Thu, 13 Jun 2024 15:39:51 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt371-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEfGBi028808;
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1mus9fp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:50 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdjMV14287222
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:47 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 09C862005A;
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8BC4F2006E;
	Thu, 13 Jun 2024 15:39:44 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:44 +0000 (GMT)
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
Subject: [PATCH v4 22/35] s390/boot: Add the KMSAN runtime stub
Date: Thu, 13 Jun 2024 17:34:24 +0200
Message-ID: <20240613153924.961511-23-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: bDXYjt3QTW4jb1VpShiRGF98SrMCVjqT
X-Proofpoint-GUID: gWs7Typp_vs9CO1C98hB18fAlqU4x_JW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 adultscore=0
 spamscore=0 mlxscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 lowpriorityscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="p25W7o/C";       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-23-iii%40linux.ibm.com.
