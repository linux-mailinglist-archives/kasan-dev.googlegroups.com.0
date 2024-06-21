Return-Path: <kasan-dev+bncBCM3H26GVIOBB6WL2WZQMGQELO7L2MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CB1A9123D2
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:31 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-44350001e65sf511881cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969850; cv=pass;
        d=google.com; s=arc-20160816;
        b=BD26u+Bdanwdn/fVR7T9HE8v2NSQ65wMO9G6qXhrpw758RolQLys7dtHn+nPrJKfyN
         YM0YdAW8vsKKtAwai/dZ4xPRphIx397ApjBzGoXCZLC49aEvIwtbsu+Jq70c9h6Fexlw
         9LqpxjEIOf6LxAmSdAWCD7JZbvemPP4aXOl04ohg/Ybcsam5dZdULrw+dN8s3urGfI8H
         9mn70QhCN59a4D9d9urEXDUphZT+cap+24+HOzsVuUtzuhakSQ1VsM5P8X2pulTqRi01
         6jS8GZHCxZDnVSnrYAF/WwPu6U9RxC483fPuBPZpXwr3LQyIf6xIgvhBdOYjWN7prIY7
         7vSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0MWoW8UozBlCv7prZ808yfePGxIIX11o3jlJOJb+b8w=;
        fh=AH5gA3DQp140BkwZf/h1Tg9XljfN9u508SHt5By8tB8=;
        b=lrAKXoqfs3cYGTUMenqA8g7I2IsR73Kfe3weHzoRJYSeFoMyiizg8prI33ugwe2AW2
         UDyD+foHt1Byyj2vK++UfFY9BWvc654/JriB7zJAWxUsvEHwbVd2fzIRCalYxfAeWZ6G
         QqmpHQqW42ctHYl66rUdB6zvPAhNB0rxk5zsArFEXSH1umWaEpUmtNi70YiXxqUSKvTz
         QSde3xbsGMeFWVljsF60VCtB3Lk1GcuDdP/vUQ2sqiw6d9rhLG+KvTn28adC8aocIauA
         s9AY80DbYc6Kt/6WFL/LZecUKTi6XZXsmbBydvGDR3CebX+Sh0FwXpo6/MXBOmCHLJ7a
         WHqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gqZiDqgM;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969850; x=1719574650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0MWoW8UozBlCv7prZ808yfePGxIIX11o3jlJOJb+b8w=;
        b=p8zuOEorzQSYmT70d7lzrlzjqCCTI2sfyl9IhUcHNFpim8mNgzQa952+xNbQJPoB8k
         c4wjUY/2rTEmBG+rK3WW6DfVNSnRzmIGgXxJwQPCkl0rkgR4fNk7JKA8+OsSg4pSvRw6
         Gz3TMKOnJdkxEUvI7hBdyp1rYBQe+Q86/RGYvv8YPb1UDaQGBLZdzuNBBTMge2Pajtkw
         RlQSIzNX+yJIyEph75NZSC7l96bkdRrebKy9lMj18oQvbigbrjz8V8HPvq6GBwj6Lksg
         eM/6H/tkP4AZbUIOIcft5Nhb6uHShOcXQrEgJ7u0a+ht6fI6/hhNpZ+h1HrUootvOc3G
         TkVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969850; x=1719574650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0MWoW8UozBlCv7prZ808yfePGxIIX11o3jlJOJb+b8w=;
        b=rjRNWw/gK6d+//QLixpsTNHnPhNSpCfoG7Pc9bFXdx/pDu/OPLAolEpalP/eKz8XHT
         rxg2agFOssiGDCnGYK3jSCAs1nAfxyq9gwqB7Dt2t52LLJAl0xWyupyqrOAhRVeSkHWs
         waT+93oj8gKGD6SM+nX+wton6WBKhvjB6W+ln1vaxl9TsT7pxyZGGlrhjzY1t6WngGoZ
         wbJUnMl4Eesajldujvw/1acFnpIRxV0Nlzyoo47UJgMw5EolqUyYztsArq3dSxYdscCN
         Wf9PStcJwAgDUpuFgTyLltJdc0b+eKD0FPJljcCdCHSx97Fv187LUpQ0WN7EZTQQ9iXp
         9k8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7XlzQNLwXYEkdKgePhLR46v0bEHgLyjqsiv++EJko83QOQR41mavdt+ePMXHxg0gHUK3mIIj8vq5Lfj81/WHQ20tKPkSLsg==
X-Gm-Message-State: AOJu0YwrXk8i23p1Sxtf4BG1AsFQKfKOYH2rxr+CLYkD0O9CgWIf4u/X
	E8LiLzpnTl2yLk3uZ/2b2X/Cau4uYHz8qJnV1WdDiZoC791TSgGC
X-Google-Smtp-Source: AGHT+IGP0jP9gNEkWp2F5UQWbhHe3JzS/7j1rhQM/gl/YhGcxrBz9+amBNIf+FZTd+1nM214ftzJyQ==
X-Received: by 2002:ac8:5f52:0:b0:444:aba7:8c07 with SMTP id d75a77b69052e-444c1b4816cmr3038111cf.18.1718969850264;
        Fri, 21 Jun 2024 04:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:60e:b0:259:89be:cd7e with SMTP id
 586e51a60fabf-25cb5f3ea86ls1423614fac.2.-pod-prod-02-us; Fri, 21 Jun 2024
 04:37:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPawJumLK/U/nPF+5rpRzgUC7+ilTL5ffrlaT3048vJIo+Gki25MpI/uYR0UvJlIkv+7KQp2pUvV6DoLaWEC2Yu0/QnxAdCqnFQQ==
X-Received: by 2002:a05:6871:712:b0:25b:3e23:e5e7 with SMTP id 586e51a60fabf-25c948e9cdbmr9238933fac.3.1718969849249;
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969849; cv=none;
        d=google.com; s=arc-20160816;
        b=wHSsiOyCpao1Q49/thLOPYjJx3iq4ALnxoiBF2VJi4FYWC9OneY1XcbfZOkGqcHerS
         NDgpOoVfZO4n3emlW0Uyt2jRFqn6D76QfXM8FzycKn7Rmaxlx5rKHHPgiaDy20ohIn6M
         5eXCUfP5GtUReXyXXcHAosuk/Ubm57G96ipyCzaJ7jrMGQRT0D8ArN+oT9O6qiKMj9p0
         swayj48WSaUXwtvtYNeqcXeBUFvmdI/pxaeuPc4Tgl8z7nCGLLrt0vFBpjj7o+h0hVEv
         G6qmSakcQqUxkpfvkHOuV/ClOrSOTtfnn0TZoD7ZDTIGoOMFxEDYdGecKbff/H3TbzZY
         p6ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OuTJsGR9CKQp5KU/moT9q7/MyfMfBzEfOFMR8s/AFMc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vVrFIhxOlRqlaLwot0yZ35bjT8GqTYSndsp5zRh9rU3yO4YojyxSDHqsUtUXmiRpc8
         JRqZhPNzzl2bxhDCMfmfmmBiVCzfK7dy19OzSyK0YNAcIF+ccEwAU3cAipvLzOvyguTU
         fTAQhKZUSsxt/6tUX71JYrGbkPu3rBdeSRtLkBq4c4Sc9wNoc2kPW7WAPwjRTP6HAhyr
         dCzbQk3FVPk7hs/HWgOvciyEOcIyA8+s3QgdORji3+FWmtboLJmrsmmEoDmDJoNBnw/i
         FGAAhEPdYEHFgSOtOzP7j61lCfnFFyUePJAIeOKTyizjF96rcuJcxseI/QmmBH/vlacZ
         J9Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gqZiDqgM;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7065284dfb9si41551b3a.4.2024.06.21.04.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LARVq6000817;
	Fri, 21 Jun 2024 11:37:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrgup-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbOJv011157;
	Fri, 21 Jun 2024 11:37:24 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrguf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:24 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9EbHb025663;
	Fri, 21 Jun 2024 11:37:23 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv6vyt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:23 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbIUG33423986
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:20 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5A2D020043;
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C4AA22005A;
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
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
Subject: [PATCH v7 15/38] kmsan: Do not round up pg_data_t size
Date: Fri, 21 Jun 2024 13:34:59 +0200
Message-ID: <20240621113706.315500-16-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: QQQtRzRRwUcek39gN4CFZV3ao5EkFrFL
X-Proofpoint-GUID: Yppdcd-who7And8-8JBrVh6w9lixbZ4X
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 malwarescore=0
 bulkscore=0 adultscore=0 mlxlogscore=975 priorityscore=1501 spamscore=0
 clxscore=1015 mlxscore=0 impostorscore=0 lowpriorityscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=gqZiDqgM;       spf=pass (google.com:
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

x86's alloc_node_data() rounds up node data size to PAGE_SIZE. It's not
explained why it's needed, but it's most likely for performance
reasons, since the padding bytes are not used anywhere. Some other
architectures do it as well, e.g., mips rounds it up to the cache line
size.

kmsan_init_shadow() initializes metadata for each node data and assumes
the x86 rounding, which does not match other architectures. This may
cause the range end to overshoot the end of available memory, in turn
causing virt_to_page_or_null() in kmsan_init_alloc_meta_for_range() to
return NULL, which leads to kernel panic shortly after.

Since the padding bytes are not used, drop the rounding.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 3ac3b8921d36..9de76ac7062c 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -72,7 +72,7 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
  */
 void __init kmsan_init_shadow(void)
 {
-	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
+	const size_t nd_size = sizeof(pg_data_t);
 	phys_addr_t p_start, p_end;
 	u64 loop;
 	int nid;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-16-iii%40linux.ibm.com.
