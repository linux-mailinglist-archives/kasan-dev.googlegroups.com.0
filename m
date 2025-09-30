Return-Path: <kasan-dev+bncBDXL53XAZIGBBDUL57DAMGQEYQBDW7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B89ABACBC6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 13:57:04 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-648b3bc226fsf1484972eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:57:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759233422; cv=pass;
        d=google.com; s=arc-20240605;
        b=T7c1c1gJ//7/rMdoRzU7L/KGhJrPhPjv5bfQmDZHiUGGge8vlvP5aqNKPb2Z3CaHNV
         bp5NxjAtYSo5zAsymqXb5G9yuuIdw0xsLlFLIpENx3IwfieceHsNYirFIE5UaeUwPEaz
         9LDVHJnLZUCT9/JAKJc0cof8FW0eKYDF9KhiVQ7R9+f4m9oDQwJKjZbCTNiX3iE/eLAr
         7ZitYKoK7fEMydSADzg7ROJj7c8DjVDWrUTqJP3SQU2fhi0+drZpG0hqZEy7dxkNaDn8
         OGNzuoIfcNcXW9EDZqApjfuG+O3mteBszQ7pRNWoXJ+T74dZg5LfeQ4IunMMUNlbgVYh
         bfdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JM+RWZI+LV3ET7dSzIPH/pUool0zCMUUj39zKTAhlSA=;
        fh=v8Oy6YGeyJCEyvuPF+pQAdmjiyRw5663GD36gLHUuxg=;
        b=BHSJyEQ1M1Vmc2RRaI4IuofOdD7uG11T/OL40soyZc/k8kQcSVGtb1dXj2OKI8COFw
         1ujeIli+A/gspmBFjKku56ucbmqcNZ9Qoxor8PCGt5LgNCao2B2vNb5/tmupug9BglDm
         Kyu/DFnSvfwAda+YovIQ2hWE9CnvgEWovVqq/JMNzXEhJvBsxcUHYJZhbcLPk4BIkj3E
         r+tS4CWljt5RJ+FDE2gT49ofai0LPWQzYtIwQDQiML7xF9iQO1W4baHgWipDxECe4pqN
         oE75saeLyg61ut4pigHY68XUUZDhb/PEp8ZFdqW0Wzg12+HCt/u5RPJuk5tJiPRqpHsl
         H9Ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qb3jH0OU;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759233422; x=1759838222; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JM+RWZI+LV3ET7dSzIPH/pUool0zCMUUj39zKTAhlSA=;
        b=MzCeY7HzPnb4eHfIazBVu03DOjAy3NBEsAKTcrLC+IWnTFCHhpCtyGtzPmSaEepjK1
         OPeYEIydgssjtzg4cj3/+IfObzQQkqYnmSnPKAKiQn32wgH9dVMdpE0Q135x7/eSTo3F
         KB00+LwJKXHsVASVkUyGheI5fySXrPaZfFMcsSz9U9XhNT/dwV0EaYQRS/HmO7cdrsJ1
         HiuOhq+OrrBqGFHGbHWO5JmmgkL6OR3Irjx1WL562HS64SbhHdQKwmcO15mKW6Wo3vlH
         VkVmkDjDFPRrZq/UT6pCS3L736JQyCMG/LOcmSF1GIX0HkNHE5hILtUH+5Pq2Jzd50SA
         jGcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759233422; x=1759838222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JM+RWZI+LV3ET7dSzIPH/pUool0zCMUUj39zKTAhlSA=;
        b=cCOvrrCUfKE4NgKKS2pjqDHmW2/xIwz9nZEvgq0OkGZEYNh95wPdyrBhIxwubp/2g0
         NORSQpnt3lQJwJZ7lDHUxQjAuh8N1Q1hKDT3MjdBpoC7uGpYsCde5hFVtPcOEydE2Q/h
         wbki9cxjrcbHlaTw995RrdiooecHaZo4mBdBHArQkA5AUkEzvmliYA71g4zMjIGVHVpn
         jmtPHfUM2z0Q49QVDvMM9JvDNaaXSv86znqUEyfxEYncC9oW6mKetpghdPbie/trNAbU
         YuBvdPYh3/mf2txG5S3HnYL9CpkthqVLR5Q6mvLz9nDQ9XK5ZZJXUIiZ4lxREx2KaLgV
         7t6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVV5JbG2p2JkxA6R3veptrZRJEI7BU2/djZYq0a7iiAIFkIekGu4/qma7PVdF8ef85LZKBvw==@lfdr.de
X-Gm-Message-State: AOJu0YxyUEtvBUPxgvlHC25XfH9tc+9QUm4iGBA6VtHhdBt7ir7xLUpS
	idmZfzWB6CQl/f8oeetq+rjf4tfeVGYdQLqUwaZq3Btt0Fnyc6OF9j/X
X-Google-Smtp-Source: AGHT+IEYLeXKKNglQf2vtKzb4mHyKdk1l6DppTHwhnVWsOjQafFrc+PokISA50WCxBLd5IKWRdstqw==
X-Received: by 2002:a05:6820:1ca5:b0:632:d187:c4c5 with SMTP id 006d021491bc7-63a3375aaf9mr6964977eaf.2.1759233422311;
        Tue, 30 Sep 2025 04:57:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6m17bW6i4bf3xGklCYrKWa/ASZi/Y2XEu8LToeC5tPPw=="
Received: by 2002:a05:6820:6485:b0:623:4d59:817b with SMTP id
 006d021491bc7-6400cb78cd4ls1093115eaf.2.-pod-prod-09-us; Tue, 30 Sep 2025
 04:57:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXo47kJ3A8YK5bpFgjLBASc1LUzgQ/YmEESvS/8gXXIdk4YHCIEI4x/aK1BhxidwzM0IjHrqPAyeAs=@googlegroups.com
X-Received: by 2002:a05:6e02:3e8c:b0:425:799b:e05a with SMTP id e9e14a558f8ab-4259565519cmr309690275ab.27.1759233421073;
        Tue, 30 Sep 2025 04:57:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759233419; cv=none;
        d=google.com; s=arc-20240605;
        b=N3nnqdbrf8MvqmSfX7KYgY1ManktmI3hoYy/zYKxvoBGUXbD3xPc6WIQXABaIQLmyz
         W9aVpUMNe+FTQty+Uo4rOxsZMIYBzQQfpU9c0iuCMzD5lLJuF6uito5kAReXooXLGmN3
         N9pIykGAhdn+IdDcQYk8NdKxFmzLc738y/EDS8F42ec2OPx55VFm86hINcSprTYPyk5u
         yXQhCKNyb2nISHgtdqFcANEysB1UIgP2q73YU4iLKmCaQPFTXJKKuGvuWt1jGYxw3h+9
         n3CTIs5DW4lzxsyKFMK0b/XZ0uIh5TqehwnvHS/ocWFesQx1aYlelexlltjsh+VvCJdB
         ND4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=uLYdFPrLnyCJeuiXqE24UjB9h+DlRVVlfV6Wh3glndE=;
        fh=n81t8NaBeHtscqy4JIgc3piic8umd1QiR1xY9bkDm5A=;
        b=KgWwu3cIWr0wlYtIvu3495jg2mOPvL1hS82hWvg9XazyylV8WAoiwLlZ1hGQnbGgYc
         LMUWV+KEUO/3iCagvRCr2equ5r9whdOrG+2EXFBYVgzr2nDJAdX7PMsip7RLxVIQntjQ
         ReB/9CeL8GTDORnbJkiqoIuQ7+iJzF2LsWIeATQUUWxI7Z7atmbsrcOhRXyE+l1aGfP1
         TghzguCTirhhY4E8clci/bT9fJ3r+9L1ba4sqLj4I5ahnKqOFt862aaIwKIKfVOlS1dW
         MpIC+CtWoQ9usank3AyqzKglkL3b6QL00OwyQm733T+ESXrGNGO22uoYr/B1HdWW/64P
         Uyqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qb3jH0OU;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-425b9038e16si6772405ab.0.2025.09.30.04.56.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Sep 2025 04:56:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58U6FWuC023184;
	Tue, 30 Sep 2025 11:56:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49e7ku8npe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Sep 2025 11:56:58 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 58UBspmK026015;
	Tue, 30 Sep 2025 11:56:57 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49e7ku8npc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Sep 2025 11:56:57 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 58UA5hWh024110;
	Tue, 30 Sep 2025 11:56:56 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 49evy12vjb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Sep 2025 11:56:56 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 58UBur5x44237072
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 30 Sep 2025 11:56:53 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1D7C320043;
	Tue, 30 Sep 2025 11:56:53 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DFA8120040;
	Tue, 30 Sep 2025 11:56:52 +0000 (GMT)
Received: from li-26e6d1cc-3485-11b2-a85c-83dbc1845c5e.boeblingen.de.ibm.com (unknown [9.155.211.236])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 30 Sep 2025 11:56:52 +0000 (GMT)
From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        Ilya Leoshkevich <iii@linux.ibm.com>,
        Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Subject: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots are allocated yet
Date: Tue, 30 Sep 2025 13:56:01 +0200
Message-ID: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
X-Mailer: git-send-email 2.43.7
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=T7WBjvKQ c=1 sm=1 tr=0 ts=68dbc58a cx=c_pps
 a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17
 a=yJojWOMRYYMA:10 a=VnNF1IyMAAAA:8 a=8O52IJZf9AqgYq1AvSwA:9
X-Proofpoint-GUID: 2MlcIaOIPNuSYhLYF18xUsDti4D8uZw8
X-Proofpoint-ORIG-GUID: r2AQStiL2pyVn3dzbFpUjF4YW448Tcuo
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTI3MDAyNSBTYWx0ZWRfX7QSBso6vH+ZV
 XAfmtLz8OQ/2I8tdOrQn3yK5c99+12X9I71rcuJjgvhqo8+S0YHJHGkZz88TqHi0usYR85tP03Z
 VNFnCQ41hhvy/yviYH7OYZXZWJ/fmmItE7cqYYlPNsg/IbX+d+7SS1/KiMvRZWqIphB3bUIE/jk
 eEzO8gBeZMcC7jBb6zXvRv3s50do6/UnrmHUc2jI8bexjGnPw7f0je5hhgdpvg1Nt2w9vMhjOab
 2JVBhlpCHz0RlNkDxICdJFjghcUusdwmi9zD/I+6FHC99ZqZJmp5j2+nehc7TrqxPxWQuBytgTd
 wVCDqYmtmY1ag/L7jIUmnoALaIGtpWcD7pAdeujJh/8Gtd+1F5E2VBvDDQ3Eb+k3rHxf/r3FZgK
 Kram9+fp0Jq8UcFfSZuMteDhJb6LGw==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-30_02,2025-09-29_04,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 impostorscore=0 clxscore=1011 spamscore=0 suspectscore=0 priorityscore=1501
 bulkscore=0 adultscore=0 lowpriorityscore=0 malwarescore=0 phishscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2509150000 definitions=main-2509270025
X-Original-Sender: aleksei.nikiforov@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=qb3jH0OU;       spf=pass (google.com:
 domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

If no stack depot is allocated yet,
due to masking out __GFP_RECLAIM flags
kmsan called from kmalloc cannot allocate stack depot.
kmsan fails to record origin and report issues.

Reusing flags from kmalloc without modifying them should be safe for kmsan.
For example, such chain of calls is possible:
test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
slab_alloc_node -> slab_post_alloc_hook ->
kmsan_slab_alloc -> kmsan_internal_poison_memory.

Only when it is called in a context without flags present
should __GFP_RECLAIM flags be masked.

With this change all kmsan tests start working reliably.

Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
---
 mm/kmsan/core.c   | 3 ---
 mm/kmsan/hooks.c  | 6 ++++--
 mm/kmsan/shadow.c | 2 +-
 3 files changed, 5 insertions(+), 6 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 1ea711786c52..4d3042c1269c 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -72,9 +72,6 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 
 	nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
 
-	/* Don't sleep. */
-	flags &= ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
-
 	handle = stack_depot_save(entries, nr_entries, flags);
 	return stack_depot_set_extra_bits(handle, extra);
 }
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 97de3d6194f0..92ebc0f557d0 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -84,7 +84,8 @@ void kmsan_slab_free(struct kmem_cache *s, void *object)
 	if (s->ctor)
 		return;
 	kmsan_enter_runtime();
-	kmsan_internal_poison_memory(object, s->object_size, GFP_KERNEL,
+	kmsan_internal_poison_memory(object, s->object_size,
+				     GFP_KERNEL & ~(__GFP_RECLAIM),
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
 }
@@ -114,7 +115,8 @@ void kmsan_kfree_large(const void *ptr)
 	kmsan_enter_runtime();
 	page = virt_to_head_page((void *)ptr);
 	KMSAN_WARN_ON(ptr != page_address(page));
-	kmsan_internal_poison_memory((void *)ptr, page_size(page), GFP_KERNEL,
+	kmsan_internal_poison_memory((void *)ptr, page_size(page),
+				     GFP_KERNEL & ~(__GFP_RECLAIM),
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
 }
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 54f3c3c962f0..55fdea199aaf 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -208,7 +208,7 @@ void kmsan_free_page(struct page *page, unsigned int order)
 		return;
 	kmsan_enter_runtime();
 	kmsan_internal_poison_memory(page_address(page), page_size(page),
-				     GFP_KERNEL,
+				     GFP_KERNEL & ~(__GFP_RECLAIM),
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
 }
-- 
2.43.7

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930115600.709776-2-aleksei.nikiforov%40linux.ibm.com.
