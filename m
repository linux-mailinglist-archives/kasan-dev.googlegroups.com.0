Return-Path: <kasan-dev+bncBCM3H26GVIOBBYMD62ZQMGQEVMZ3KEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F098891AAD9
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 17:14:42 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6b50f078c46sf124111036d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 08:14:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719501282; cv=pass;
        d=google.com; s=arc-20160816;
        b=yp2Ngb9MWi0IyJNOlLQlqNpzFUy7oAoriM6en3iqxTF8hoo6pV23fX5OFvlhuIPDZ1
         XQb8LZ/Yw4ptaSoseQusL0ZeFgII6/pDiEipNjYv6Wc1fwMYcWk41uCOukNEcjaWfX59
         kh1xlci11NIyEa47E8EnEyR6ufGqQWWbElFp+7PQHdNSMEqmP8vCT6JXhBx9kXkqqd5b
         u86BwyVIyD3WQUguozWLBMxf4ZXkhNLat7BzdL6qbSM20WToWtcMYflhAC0vuw6ZPPNJ
         SuqQwWhHUZSuHackZa8XqK7uhZK1nBpCZQ8DDL4tDUa9HO2bG+/t7riEVlmhKyM+JAoQ
         99cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OTRVmnRYdq17uFhCZYKaHq71Qj/BmS7CFMV9xxXBX2E=;
        fh=fKzAbpBib+cRf3749JfjG+ywPyE9G8Bb3sGuasoruwI=;
        b=H4NTrh8EOv5CgkGjqlq1PdmMRmAH7jPN1WgKYMi9jvSBKtFVs3DrUFQNh+IyYxLqkX
         41TU/FsNwoyWOayzaY7OVJudqkTPmuUo5jFEOgSdb4xiIFhzyF+J7dQcr/kORQv3ZL9Y
         ec4oBBSuDFTL+rSFcAnt3j2hrDkj8Ee8/vD+YqcUIFFNjBzqv/0bBHSjxnMpk1Gu9dpj
         f3BYEnOER5yN4519uKJqAxQk/XWR2qJnjxzI3GV/4M9RvZGZ7Fk9oqeQHtF2kYFhyllT
         R7L0m0sTe/9e00+z1mrVMX2Fq+KAQKueza/5UBhiAcIliF4tlkNxg2NXkhhNZRNQCCNY
         vWug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Y5PFjIf5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719501282; x=1720106082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OTRVmnRYdq17uFhCZYKaHq71Qj/BmS7CFMV9xxXBX2E=;
        b=uaJSoEr/R622UhmcvrxXhI8ihSE3i3gpZMSLoZCVmMUFoCs0WfMBhxqa6RNkx3qZYA
         1JaXbZrqiVd9dMNYg6EvDR961mLgeNo0uLgCO6uEJldIEkEFvhvlozB3ZPJH1nPx/U6G
         wug/v8Wjq3B+s/2ZJf6VTz9C8VIbOlsCg1/rJu49+fhBU0fWn1h8fczppfSdk7naJmyj
         05OE4/CU6KQqZvMpYzU6rvEp1EWNn2XEMZYHzBtUIdhpd+sBE99uXCQvn/pT6eK4z7SJ
         nwrvNREkbUunUrwTpWgvdjPtYGHEzIqBsv/9rzalBcEZkTcFKVIvUwvwXcfvcToau5np
         CFRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719501282; x=1720106082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OTRVmnRYdq17uFhCZYKaHq71Qj/BmS7CFMV9xxXBX2E=;
        b=N7fLnCIlYuiGGJYxiRkhojz6t+V/+1aII+QQgKOunVe2s4d/ydAPCcTHAA1nESnCuQ
         qDX+AHgAG+sBKgob5RDFCnlB0EYoeaTc8DPLH+GgOz92k59JZM+YcXfBOS1Y43LRjZIW
         TFLW/im85JHt8UhWTtBYLHBMFB2SlwKqkEKgn3/6v6CXALV5gKr/aa6uXaq6OgRTHL+g
         VjSGPXE6YocuA8vMfJ/FBQm6SPRo7bhClYOqSOesf9DQyxGexFv/eY9Op1a84gMw6e+h
         zNRs3QhPJK6H1JHNTPpo89nXJX7ZwdPNu1i45xsSmsmQAjBw0NUjoL1I8fG7yIWrZRBd
         sVew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmLR5oMTqddYnM4MRBNdyqzACNBHnmPQEigfliK0hjI0+lgpY8gRAL6KwVmbvDFtL1w3Dy8zmMcEXHsiTEJq8TyZJF5arzgg==
X-Gm-Message-State: AOJu0YxmQd6Yq9I18oveI864YMdy+jL+xVtAxdb0s5oeqq1MnQUZO1Vg
	HKn/tEXvyTbvinY65E3HIckogU9rXrAzcLVw8JAeBbREe4xjxFXU
X-Google-Smtp-Source: AGHT+IGpwwr8ESB4OG3NunkU4rA5ts64WEoX+2h86nt0BLK/aWa0JF4CX69P3bskZHBSczrDBp8GCg==
X-Received: by 2002:a05:6214:2b05:b0:6b5:752e:a345 with SMTP id 6a1803df08f44-6b5752ea5f3mr77194796d6.63.1719501281699;
        Thu, 27 Jun 2024 08:14:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5292:b0:6b0:862d:9779 with SMTP id
 6a1803df08f44-6b59920d66els5844576d6.0.-pod-prod-04-us; Thu, 27 Jun 2024
 08:14:41 -0700 (PDT)
X-Received: by 2002:a05:6122:1354:b0:4ef:247f:b633 with SMTP id 71dfb90a1353d-4ef6d8069eemr12562211e0c.5.1719501281078;
        Thu, 27 Jun 2024 08:14:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719501281; cv=none;
        d=google.com; s=arc-20160816;
        b=OiNsT+TacapFjVRvRYYxleBbEvGBBvy/myneHHgurh2drTlzm0N80jA8HhGsgEikYT
         vbHs+pEE4kgNB7V/213YHnu2/KStWocuZHkbHZi3im/Y/+Q+oYojtMCRSGkCm/vuN4ke
         19S9B09MTQ8PRsJuIikZb9o1MnJDrAdr200yCoeYYBcj8TxdpPlAkzOKMHMwYh06LtM6
         kXCRLJWb2A3lGrTUfitXrbpG72LHjKYbK2UupTjpuKCoDDiYgGjRrMuHjyuBVI+qwdOn
         IPliQixzK81Y/ffxr0a/Wzk8UVZj9cTvbc6BH76R/QXLK2DOD9OBpkuZvzG966UAIBa2
         PktA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9nSO8vQ8LysldJ41kUs8BTYUja1+gnKPMCjMQs//hno=;
        fh=uWS0ctYKU363E7TZo1JbUf4LNo3jJz4pzV4p0GSEd80=;
        b=rhBctpNJXOERCnadco+xI67RrRhmWX0pPq3CZHoHpLb4LZN1s36uvfoZxPoG0YenvJ
         vs0/WWfecox24FHM+/UeqCNOd1qDS9Fp4LeutNY3lF57DdhebDtGgurlcS3Pf2vCj8/X
         DW0Zz3eRaWnEeQ5irKIBzER9nWnjsmv4gBqdJajwztIRa1Rw/MYmI4RPsZZH5awrJQyV
         1GJVZMmG6MaplS73VkPY/WYOLu6B5FZXh7YKn2b5BpB6cArtnyfs2Svg+iudu4jQGF94
         8xxu8whiHEPtcIovCsoYtesYXcrImAQJpEtGJsaOx+IGQRki5T11TvFULCiyg5xDT4ZJ
         3f9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Y5PFjIf5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f282e2210bsi96828e0c.0.2024.06.27.08.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2024 08:14:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45REuqR1015553;
	Thu, 27 Jun 2024 15:14:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4015fsrryj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 15:14:40 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45RFEdCP008846;
	Thu, 27 Jun 2024 15:14:39 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4015fsrryd-4
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 15:14:39 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45RBjA4l019602;
	Thu, 27 Jun 2024 14:58:02 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yx9xqba9g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 14:58:02 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45REvwtr20054466
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 27 Jun 2024 14:58:00 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A80522004B;
	Thu, 27 Jun 2024 14:57:58 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2346220043;
	Thu, 27 Jun 2024 14:57:58 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.182])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 27 Jun 2024 14:57:58 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, Ilya Leoshkevich <iii@linux.ibm.com>,
        kernel test robot <lkp@intel.com>
Subject: [PATCH 1/2] kmsan: add missing __user tags
Date: Thu, 27 Jun 2024 16:57:46 +0200
Message-ID: <20240627145754.27333-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <20240627145754.27333-1-iii@linux.ibm.com>
References: <20240627145754.27333-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: -d7cZN-z68hAjVNQeXA7A1nEUn9qEmjC
X-Proofpoint-GUID: tjwTrgx4dkgHL1UYAClt-09Hv4Ljjbml
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-27_11,2024-06-27_03,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 phishscore=0
 impostorscore=0 malwarescore=0 suspectscore=0 priorityscore=1501
 lowpriorityscore=0 mlxlogscore=988 spamscore=0 adultscore=0 clxscore=1011
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406270113
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Y5PFjIf5;       spf=pass (google.com:
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

sparse complains that __user pointers are being passed to functions
that expect non-__user ones.  In all cases, these functions are in fact
working with user pointers, only the tag is missing. Add it.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202406272033.KejtfLkw-lkp@intel.com/
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/core.c   | 4 ++--
 mm/kmsan/kmsan.h  | 6 +++---
 mm/kmsan/report.c | 2 +-
 3 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 81b22220711a..a495debf1436 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -249,8 +249,8 @@ struct page *kmsan_vmalloc_to_page_or_null(void *vaddr)
 		return NULL;
 }
 
-void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
-				 int reason)
+void kmsan_internal_check_memory(void *addr, size_t size,
+				 const void __user *user_addr, int reason)
 {
 	depot_stack_handle_t cur_origin = 0, new_origin = 0;
 	unsigned long addr64 = (unsigned long)addr;
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index 91a360a31e85..29555a8bc315 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -73,7 +73,7 @@ void kmsan_print_origin(depot_stack_handle_t origin);
  * @off_last corresponding to different @origin values.
  */
 void kmsan_report(depot_stack_handle_t origin, void *address, int size,
-		  int off_first, int off_last, const void *user_addr,
+		  int off_first, int off_last, const void __user *user_addr,
 		  enum kmsan_bug_reason reason);
 
 DECLARE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
@@ -163,8 +163,8 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);
 void kmsan_internal_task_create(struct task_struct *task);
 
 bool kmsan_metadata_is_contiguous(void *addr, size_t size);
-void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
-				 int reason);
+void kmsan_internal_check_memory(void *addr, size_t size,
+				 const void __user *user_addr, int reason);
 
 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr);
 void kmsan_setup_meta(struct page *page, struct page *shadow,
diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 92e73ec61435..94a3303fb65e 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -148,7 +148,7 @@ void kmsan_print_origin(depot_stack_handle_t origin)
 }
 
 void kmsan_report(depot_stack_handle_t origin, void *address, int size,
-		  int off_first, int off_last, const void *user_addr,
+		  int off_first, int off_last, const void __user *user_addr,
 		  enum kmsan_bug_reason reason)
 {
 	unsigned long stack_entries[KMSAN_STACK_DEPTH];
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240627145754.27333-2-iii%40linux.ibm.com.
