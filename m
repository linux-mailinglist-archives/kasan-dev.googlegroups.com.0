Return-Path: <kasan-dev+bncBCM3H26GVIOBBUMR2OZQMGQEN7KBXAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 8199A911752
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:59 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2c79f32200asf1609108a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929618; cv=pass;
        d=google.com; s=arc-20160816;
        b=gLHYuU/x3RyouLC/VLpCHL9v8y29/NCK4f4Gf7L0otd/EGTm/oQyDbpG+xbU2tCHSG
         vmv6SkJqrqmaJzHZuDrP2GNthpdJzYjfbzjz8x+4DTtBapx9PmJwweHzL/PuUXXGyWPV
         3Sr33tEwcHErHLQ8ChmFfSyROod3eVQnBSKoBQu26kiTH2lDx/fje2xNoHcmJ/B5hzB/
         e+3Fq1lE04IG3VA76/f4Cp3nnqh+zHH9O0cKEuQ9EpKD8L/rBynX8PmZLHxWtSa0uZa4
         BFi9qDrOfMFiH2yB9ZpmEZwLEGYAb5Z85mNQvNQcT0WEdx1TZPCe4s9KuUTr2JOkRim/
         28GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Qd4phyO+Wf/5trB1KLXb9OdrO6htgUPPgNB67h1xzMc=;
        fh=UDFVYlDIYUn7fG82oI2OxNHkI8yWBBZ/2ALPsp7+PVQ=;
        b=pgwvWhXPHyBgui15djz5riAUVG8JWNBPbhSNeEfbQmQ4CyduiFVtrb6SUahoKv5Tqc
         +z5XUnttYAnYAjDOfnAJd77y9c68qGkCGPJ4VwjzvzY5OC8GLvf2adLQrx4QDXIUQGdG
         PTXmlAF3SHmE2ZL4kuU2xfu+ZvXkf5WIT4k0YxGM6ggIafNjQjTgmD0EB/kWdZ7FpZFA
         Lt85tI5RKsnb9lluGFuLTM17o7Pz96gfcqE/FXPLZWhYvi1BdpD7A3Mnmz11TsiHUhpo
         /l+4v5muIcKoU4QF+vxjl4iiyL2XLhaTaMkzHzBZkwY7Cz1vwo3GKGZEKzbBia+H7Bh2
         /72g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mjcB1DbW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929618; x=1719534418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Qd4phyO+Wf/5trB1KLXb9OdrO6htgUPPgNB67h1xzMc=;
        b=iAu2f1VfmsOlRUNJAao/TFo2mflLqJ3JTryQcU6j84N9aGl3Tnqkv1tRq+xh0gRDJr
         Am31vYI28faymh7PRpY/GRhiw5uiuX6tCrsez4jA04jM+SSZsmGV0k5pZgaBBSqo1wcv
         /6O9746s2nZ7Tw8DcfHgVlHnF+ljEILOsw8yf6fzcYcmadJ6GMugeCFGkSBWXC9XKhLo
         A00SJShiuxsRObA2FLzh2UKxIKeE6I+Ly4XSfwFIo5b5POXF/Z+kvpvYLnRuvNzp+Rvs
         MchkLBoSbNLDlmQpd9QFu+ZPyoYz29AxrfeE7Fji9Lc0UmDEGJnEF9KqmBqjXlHQuLpe
         LmMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929618; x=1719534418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Qd4phyO+Wf/5trB1KLXb9OdrO6htgUPPgNB67h1xzMc=;
        b=oV0U1vkx5HQcGb5FaF2XPeZOz7B17/qcvborzqc1dG+sOhjo/lvLosyFJQ9oexSZn2
         fkQ0LrLIotnziQF2DDdP8jT6tfXRa2HB3lM1ZFzY8zHwtD4Z7wzm2sBQWWgI47Z6Hz42
         DnGZd7fO4U7RYQN1UBv1kmDVvHgW2Va6dx2niHlMoOEjYLJXRi8IFz7Nf3auyCgmZUmN
         QShly4Ve65mWBwFJyM4S9DAFraHE1jFwxFHfGs3e61d8Rs11Q6I0UTZieVFEdPizFCJr
         mSmso1nJoo4Qbg71XSCplu2Zh+OrmYnHql2DKCgPGukQDHCe1eWph/s8rcjx5fke6mS2
         3Unw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQvrKr8CHFxvX39MQfpaIIcr+z2C9lurMBRWBB4c9PCVWpP3K4XR6TBkMqjZk1+1NEUxZrm9jhTsuaHxyehTOADZgnZcII9g==
X-Gm-Message-State: AOJu0YxYxaAYdTKDpUYNK4sdvqfRNDWjvBiAicxkvorWTY7+GvOfOvB4
	KH9oqnuaNhnPZx5gnJwpABqTmh2jH/kXp+fbIfvjG8TpB1Rhw0aA
X-Google-Smtp-Source: AGHT+IFimGZ5DExIskm1vamweg7NETmbFkvVNsFMZmZdIQERGPNosRK+rUVILhW30QNDJfCS6YWBOQ==
X-Received: by 2002:a17:90a:fe06:b0:2c4:eab5:1973 with SMTP id 98e67ed59e1d1-2c7b57f505amr6752255a91.7.1718929617967;
        Thu, 20 Jun 2024 17:26:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c08:b0:2c2:cf68:663f with SMTP id
 98e67ed59e1d1-2c7dfbf1074ls1013325a91.0.-pod-prod-06-us; Thu, 20 Jun 2024
 17:26:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8cQaR+9Er+4NhyjR5tl2KDpPvh+1TfpSVsvlSk3Q3LZMXiXjrKj34SrhWqUSfSWs1FxzB4ezTpZSI5F6aaVMv+wVQvWglduhQ5A==
X-Received: by 2002:a17:90a:a892:b0:2c1:a9a2:fcea with SMTP id 98e67ed59e1d1-2c7b5c900bbmr6621479a91.24.1718929616924;
        Thu, 20 Jun 2024 17:26:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929616; cv=none;
        d=google.com; s=arc-20160816;
        b=tC1+iuu6dx5hwruZAJUhIw1ANfR99v2p67cHCVf2m26p9qwkJMyVzxcFTAcUPt77JX
         cJQA3uuyTGuGd6NKVMwsk/Y3i45LSpopzXSt3tkre4ogX6WDiSgYj3DegC5jC/cHX7Z5
         wI2XDh7d+8bBRDjg50m9G+WzZpYhIU0q1BcOCbmYPGZbEA9tG9EOHUClNLre8vZ4HDZT
         O/c7cGqOYUNbcfTLrAArbrqAms3MW4lgrS7uy98OY7Qp9NX58wB5QovqaOUGkwe4w1Ma
         RmNSxQ/9VPLZuojuC29/DXLMDXzJsIDyZ1OQUQJuXI7M35mUmpY7MrSGkXpNDYx9rXNt
         bqlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o5OLh1G5igJ7wfCkEas83RRSlonR9xfZGMUuvDY/DE0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=fm3ZNPH5kU/bD2oyrCFKMA9W5RoJdK4sO1PxVGZj/gXR/BpvgCdYGdMU2Lc5b6q4FL
         6MkckzJPvUo4S0m+hcG6g+HV7AgKunvsv+6T2x7yEd4clR6OZN64I3DoJ5kjdqPyKrGq
         LT6mAEj6eEJMS01jc1uZNGOQShJlIjKoz4gIKUTCXU+WHAbGNCcQ2hRWreQBKOKJUht4
         5jEz0RsM3AODhFyS4iNFp7hAuEYStQ1MacrSagcy9vZd/lLuw2BOns4FiwbAKnmq6k6l
         WbRqk/ryp/m7ALgipzLEcpI0wGFbSg+oPkfDQgNKKel/0ocFflk0IvWXSh1Tr3SSmd8j
         8H9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mjcB1DbW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c819dd5b75si19049a91.3.2024.06.20.17.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0Qjxo017866;
	Fri, 21 Jun 2024 00:26:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvx4g02na-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:51 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QogX017926;
	Fri, 21 Jun 2024 00:26:50 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvx4g02n6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:50 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLcxoc031347;
	Fri, 21 Jun 2024 00:26:48 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrrq2nbb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:48 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QhwD41943326
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:45 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3AA5F2004B;
	Fri, 21 Jun 2024 00:26:43 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1905920043;
	Fri, 21 Jun 2024 00:26:42 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:42 +0000 (GMT)
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
Subject: [PATCH v6 19/39] mm: kfence: Disable KMSAN when checking the canary
Date: Fri, 21 Jun 2024 02:24:53 +0200
Message-ID: <20240621002616.40684-20-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 8qSPJ9dagl9d4HYS4smcsKnsM2CTqo8A
X-Proofpoint-ORIG-GUID: 7LaTOJcW5B_v5GZ1BZoY_IdSR_2nuz-u
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 impostorscore=0 mlxlogscore=999 phishscore=0
 priorityscore=1501 clxscore=1015 mlxscore=0 spamscore=0 suspectscore=0
 adultscore=0 malwarescore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mjcB1DbW;       spf=pass (google.com:
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

KMSAN warns about check_canary() accessing the canary.

The reason is that, even though set_canary() is properly instrumented
and sets shadow, slub explicitly poisons the canary's address range
afterwards.

Unpoisoning the canary is not the right thing to do: only
check_canary() is supposed to ever touch it. Instead, disable KMSAN
checks around canary read accesses.

Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kfence/core.c | 11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 964b8482275b..83f8e78827c0 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -305,8 +305,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	WRITE_ONCE(meta->state, next);
 }
 
+#ifdef CONFIG_KMSAN
+#define check_canary_attributes noinline __no_kmsan_checks
+#else
+#define check_canary_attributes inline
+#endif
+
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+static check_canary_attributes bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +347,8 @@ static inline void set_canary(const struct kfence_metadata *meta)
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+static check_canary_attributes void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-20-iii%40linux.ibm.com.
