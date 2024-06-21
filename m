Return-Path: <kasan-dev+bncBCM3H26GVIOBB6GL2WZQMGQEWR5AAMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 110119123CF
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:30 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1f9b6b2fb8asf17838105ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969848; cv=pass;
        d=google.com; s=arc-20160816;
        b=X+0ScO8Hw4ArCi/wbQtMeEioCig1k+GW1IsvAhwqY3/ooWTTWdnVkWKkKST/tsM6UF
         4VvDSVJsuBqrqg8LpuoN1FrYJO6/LCXC79FLmFJov8KX8UX6VNu4bMo0Lq673Li6HMot
         uQRstbJzClNjFYt/hfQGUyp0+UsnYnvy9Mk4LfakkIZIWgrCL9uCfD2jbJbfniMV1MiP
         TKCLq54byiexsOKA1plQdsjqa1gNSsiNU/dS5vC4c20GxuOQYt/t1fgjdK0Nm8Hpqyf0
         RvxhaTaq6VwyYHd2/j17NvVSTDNITDHSZ/Uo5vv+yuAtaaMHKLY9avNfBiX67m2IkZhs
         Vljg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aIj6VruB+JKCJBmIDv8q3w5tQJG/BYBfwt64zrLlBwg=;
        fh=DZU4yOi0jmoX8KeoFYVShINzj+3Xq1kIqK/83PsWSA8=;
        b=uP7HxD3AASmJGYcpjMC9Vs2UYESSq/qlB5IErAZeqmHYtTyAhhe9cR6gpQJ+A/zIEr
         VuVEE9IRyaU2i1mukec63wt0SllB/mo7hJzp7UXxQSOFRACZOuBNM7px8FcwPYp3Aqd5
         vQV5aomIWMcND5Zv6u1GJL7hfV+plYDr3+rXHol/5AYNT8KEYhTIJ8CsUMBwYQkg0pV7
         ZxtsYAF/OGeu3O8SfDgfHDKj65prRM1QrwF1MvHrhXIgerGKPLIhILvQY/ZFpl4SmLoa
         URlKQAEJYFFYh8+8oWlSgbUkHujOU1sZvwdYzQslNPGZyjEZalMGmnhsXKNOGaDOj7cD
         +e3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Uy3pF/XU";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969848; x=1719574648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aIj6VruB+JKCJBmIDv8q3w5tQJG/BYBfwt64zrLlBwg=;
        b=dUmF8v0dK7NT1jkhSw4HRnJHYndpif+SmHr12yo0gbF71cjnGbYIpm73LScxctzkFp
         EwfzYaUutTon2YbUEQIi9wk/HGG2Ff4qKM6yraGrZR8cR9jW04E83/CcIVEA484UCdvn
         jK4rOAD+i283tql4zxgQvUCESr9f/FGl9+vkPEOertGk7JR2CKwcXj0QEkxWKkl3BI7R
         6xHGQbWWmD5qwYtk505i7fCyWEnvQFrqmqxnGoPxA1BrSiGWcdAoqvgBGr/bJydEuDHZ
         oCvrh5PBPFKjSHEtHNDaVKUnr/fILJ92xFROBMe/+kMzXqbSp+miKUPEQf5+lXHeVpO5
         bA8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969848; x=1719574648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aIj6VruB+JKCJBmIDv8q3w5tQJG/BYBfwt64zrLlBwg=;
        b=Zlic9nuCh8XMgaMWG7lYFvzk1TUuc13eX5akhZrsgTULTCAfFDwmaeUwmcZJGmVI7v
         5xbkXwhtoVPY8lLeb11MvFEKrciTAsEbQnTgI5SpkGP0DTdzOpbKPtSEjF7/DIOl6PDS
         LNP4HeQqNbdRT2Iiwgxul1F+7i8goZr4ezEcUkvq/XGXMzOu05LkcGdoDPaNngqdwgCg
         tU39dbcEqVBxPDoFCpb+k3BvUIsRTrT7Ril2NB0M8mbQRUgz6rnkQ/8+3rboZw7wwbtB
         Lm3fWPhobOkaQazOtoTwsHvl59o6kYNxPqYpE+R5d0f0gr7x8KAAcwF+GI9ldMzSU83R
         lWGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjqQuitsfBkhbbBFgLBBeWoNsNn5jOI14W0HUr1QB0PcFhN5Xee6jbzxcxAnTIUTVc5OTh/AuY0ZRQK+Q6PjhUquYTR0qpbw==
X-Gm-Message-State: AOJu0YwpKc0BWYl+A2lqoR2Dx653xuYwJg1pEZ1zJNfr4UDtOmYlXKer
	WRH7El6edCa7i0q/H8VEwjEI+juuGBstgkE5jKM5z47Sq4zQDqr8
X-Google-Smtp-Source: AGHT+IF+roQBWXe0y0SGUaNn+kN2bIb3z6no6yRubl9WadPINK1rw6crJYaY/oNHCWR98EBI0Kevfg==
X-Received: by 2002:a17:903:18a:b0:1f8:733d:8c15 with SMTP id d9443c01a7336-1f9aa473e3dmr92400805ad.42.1718969848560;
        Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e84e:b0:1f7:12c9:9438 with SMTP id
 d9443c01a7336-1f9c4ee5390ls14330845ad.0.-pod-prod-07-us; Fri, 21 Jun 2024
 04:37:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtAjajTvSZZVSPblhC7Xh0zEhBnsiL31rpAd6eTF/KoPIs21GgnWEweA7BwSGQw3E13oRlD+ylspygnPFQysDoHR6jrEuFci1Kvg==
X-Received: by 2002:a17:90a:d90d:b0:2c7:1370:f12f with SMTP id 98e67ed59e1d1-2c7b5d935famr8395779a91.40.1718969847490;
        Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969847; cv=none;
        d=google.com; s=arc-20160816;
        b=dz8jn/6FfgMzQILRXefdM6sDWMSWrcgdJBFTXXU0nq1QO6t3Q9oHas7eOjrvia6kVU
         EPQY/bD9gi/DrdhT757zM01NNDh4qxlFuKJpMaUqY3ZOFgJevHBPsQmaWQM0EhCQ67C1
         IX86gr3p07P7s7UJh8VaflS4FJ9I21zi5i4WlGZvd97wl+nEChf9kV2Z611exKqJL/A1
         TP4GujisOjHQMDYL22l5IJNXAODM86J2As6QuCPjFhIeRivTnujasEAnxTPhAv0zqp63
         7Pp0qEKnRUMkF2JhRwJW/0CPZTVcZdPqO61F1JO9m8JCSzwoM6ebbM2Q14wnVsbWl35y
         3Xdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wYZcdN8GaCldurJMmgBO/xn6iWaosLK3Wj+Mr2vvPT0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=r1x9jK41C8uLTifYc5w9Z+NaoaSu1o6zOsdL+yV5VxAQsCKQpdP7mvr5/v7gzg3chN
         O7ThQt3DuEAP54luTXJjHaJ5s9u8zlGqu4V2zEr/a0So1H6jksYYNAidaRa6pisyT/Ep
         1sTPA4jYqCsLJHxPv6e5Z7v56g7P7StWznIwZkuR8JcGrWLqBdZZqEvz6Aj9w0Y5+/dn
         pP35F73qUe0g7jXQdGxzBjQekVFysLAikrWQ4u0T5MbEoAej6hcuDVxW1DpnIPuZWMNO
         GElBvbJHmROgiuD6lL1VO0AlWsgi1tfDAsWMxIMgz5BItgzUDpWlwnrscHtW8GTA9xw/
         tugw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Uy3pF/XU";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c819dbfa52si60160a91.2.2024.06.21.04.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQ6q2017930;
	Fri, 21 Jun 2024 11:37:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t80444-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbNBg004459;
	Fri, 21 Jun 2024 11:37:23 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t80441-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9DLqA031890;
	Fri, 21 Jun 2024 11:37:22 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv5d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:22 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbGZD29098536
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:18 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 846032004F;
	Fri, 21 Jun 2024 11:37:16 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EF0D52004E;
	Fri, 21 Jun 2024 11:37:15 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:15 +0000 (GMT)
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
Subject: [PATCH v7 12/38] kmsan: Introduce memset_no_sanitize_memory()
Date: Fri, 21 Jun 2024 13:34:56 +0200
Message-ID: <20240621113706.315500-13-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: VwxZRfQ3cXg57HgZFoMU6oP7gsoih5J0
X-Proofpoint-ORIG-GUID: G_uxCB2oXSPBxyKOByo4l-kVnAAe1299
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 clxscore=1015
 suspectscore=0 bulkscore=0 mlxlogscore=867 spamscore=0 impostorscore=0
 priorityscore=1501 malwarescore=0 phishscore=0 adultscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="Uy3pF/XU";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
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

Add a wrapper for memset() that prevents unpoisoning. This is useful
for filling memory allocator redzones.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 14b5ea6d3a43..7109644f4c19 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -255,6 +255,19 @@ void kmsan_enable_current(void);
  */
 void kmsan_disable_current(void);
 
+/**
+ * memset_no_sanitize_memory(): Fill memory without KMSAN instrumentation.
+ * @s: address of kernel memory to fill.
+ * @c: constant byte to fill the memory with.
+ * @n: number of bytes to fill.
+ *
+ * This is like memset(), but without KMSAN instrumentation.
+ */
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return __memset(s, c, n);
+}
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -362,6 +375,11 @@ static inline void kmsan_disable_current(void)
 {
 }
 
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return memset(s, c, n);
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-13-iii%40linux.ibm.com.
