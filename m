Return-Path: <kasan-dev+bncBCM3H26GVIOBB46L2WZQMGQEE7V6AIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 53B519123C4
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:25 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3762a1c1860sf155605ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969844; cv=pass;
        d=google.com; s=arc-20160816;
        b=GvMOFlNbw1RuwwosSEkury8pN5UHuINZiuggol+PtN8BIUXn+u4Q4o6VsM+4nsIJWN
         CG6j8LI/r9VyFMfHE+PIEETQme/4A83HNHs05+9PLUiqauDuTr+SKYOfM8Ee1Mi1Uhqw
         qQrxEFOHuiRdX9CUcNzQWCnepOkzEFwkyI9Bsr4Irt6sJjtZCxnfP8ONr7CVNmJTVxIH
         ilGxd/Wfw4PDXA0cA2vKKFeTS717r49ZPWy5eneuXYCz8sTGl4VSS0GO/rUwy58mqKbN
         SBc17AKZwHpJjKHmamx1UY51dIpQjWwK+Xn2sF3W3OS954whdLUTSt/uOeAljY4ZxvX6
         vvQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9RWn1R5w0CWr8cZ89co0mW36bX3OEYWT38tE7yO/LCM=;
        fh=PkXupJnZRBxfOVCRix8nOrl06b+SS9FR3TujtTnRdJc=;
        b=KkQOPFnzcchRcbn9U9j+o9pprAeNjRfUSfzQ9JQh2bjM6IlSCiuD+hIgmpBunmVGW4
         KEG3F9ph6xGzl8osFZ4U8WtT6Ypq8c69ugbIs/2Gc00IeNMhb9w6OKPZiO7qBUriPc5Z
         Bljr3yXPO1a3awQ8Ei6Mm4oynD98Hw/2LYOun6c/ITH3H0G3zeymzlbeIUYMWDxiSQGM
         iUaiDznYvrYNMrrN3Zz11921YJhtdahWbVLBAU39r1NyAd5jYLUqyWgNMkzbaAm/oWZ0
         6bEO3cvAtAUAKYhEXanI52kBBUF0z/q/tr6BqHkFH9xId8yaT0HtcVno6QCP5OJJd7QO
         Uq2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TmuWzqBj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969844; x=1719574644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9RWn1R5w0CWr8cZ89co0mW36bX3OEYWT38tE7yO/LCM=;
        b=wHiL/IcPjTyMCOOjfob3nBODwqo9TVR4nT59jScoKNxSwrc1h3jJ9d5P0bU9tUxiO1
         8PT4iMpb9daCMF+tn7PM1Mw33YEkj8UCiwmdHBRv8Hl60JZ9pu5He7JaBzhjghfaXT/m
         ULQDqR2fga9PBohIRvXsiptlqbQyBUo7GtHPX6+gbMuD9lWEbxguL+1r6m/kWT2s2fcY
         xsY0uu/WfPGLSKoX58L4rmQslcHHHtdliIPwUSlBUe2pTzENi39OXcZK7XGH/ijjU3Oi
         cmka2IMlmT6Egv0QxZGe4u/Z8MkKL4qYDSy1GH3W8FdQhFrmDAhf+PXGawB12YG0Uq9m
         zEzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969844; x=1719574644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9RWn1R5w0CWr8cZ89co0mW36bX3OEYWT38tE7yO/LCM=;
        b=pmuMXkQblhM4p998OaVwD3cgky0P6D9dNuJqXIoV4vueKtXhVX+AcfmpXRXd1kwope
         Eov8jFGyUA64TO1NUGngOk30QGswlI5d4ZAugPnBOYjbtcllOzsdTtB3ghEADGiKiDwF
         c5SjEJUHj8KTd61sO+kpDQchsyOQ7mjrk6XTQtF46ki4ylWvyDzLCcKLtSZYoz0ZCj0Z
         QgQ4E6WCx4hqjEj9YDbyI00pl4t2IuKMfCsX1PqnDSvfvFPA0/swG0k/kMgfIYwC70UM
         Y6nvOSsSqLC9DQjiSuZ/D/0BvIsIGLD29Wn7xQBz15Ku0nwdArpZdeWE8JKJXSfF0Icq
         tFhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiJWVTZ4B2iZF+AU3nyJx4BUM00aDHC7wmTxlbuXX01kKr5kBDcBiUy9yE01z7puD4VIWqaBzd7ALW6WTFz/Xq4JDA3cjASQ==
X-Gm-Message-State: AOJu0YzgVVK0XIzHL8IwVaQOEpHD6ifcnawPHhMP561TYI82D6VZGqMb
	AM6Y6s1IAK9sRMCLjgFqJI6sC+IjFRTO/upzyoF31nh0DE8JsTvM
X-Google-Smtp-Source: AGHT+IF8beTUZc7m8CTDsVOpv3tVMSK49eEz+W0jz8Jj3fzwzFfNV3axJvvBGN6ni6eXd1nTiuYyvw==
X-Received: by 2002:a92:3647:0:b0:376:d36:7058 with SMTP id e9e14a558f8ab-3762e975e75mr2532905ab.2.1718969844082;
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a03:b0:375:ae19:e63e with SMTP id
 e9e14a558f8ab-37626b1e54dls16030655ab.1.-pod-prod-06-us; Fri, 21 Jun 2024
 04:37:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGWuJAbNhGZVfKsSchSl9/riGEaDM7ajp2PLsi3696xSueUvIRbAoHhRvCQDIE7J86gFma3hJpAuiA22b7alKp+ZRLObx7jje09w==
X-Received: by 2002:a05:6602:1544:b0:7eb:7089:dfe4 with SMTP id ca18e2360f4ac-7f13ee73e1cmr868572639f.15.1718969843093;
        Fri, 21 Jun 2024 04:37:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969843; cv=none;
        d=google.com; s=arc-20160816;
        b=gxt5sexTPVG8s6zwBkuZTd+xHo4rpNYtk9ykGDVC/r8gh7PLyHbsfO6UBx4X57vJGl
         +xCYVunWgeatc9EeiT8WM5I1QMOOjx5eVXPsOK7XRTdtlzkeBUCdo3SyVfiTadHk/IdJ
         vrcSntSqM3+ZjLTwVYNdlvA4fMe2iqMkUsGpfv2qHZcE58X/2V/tTYHf4QG+EsmCvX9i
         yAmhdme7TX9stj8Q65CY5wZq3qgUfb+/euJazYltYLs5tlSpujXw6RuODrB3gyO8il6q
         lPUieZez55RinYTnppuojYl4WjQKgDpkJ90/ecDaSrsABcU6YqKLiMcsCorgQ03QanBT
         yOfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v73BMs0EqfMCwxJniJdo3jdaknlggr5A1qJ50X9w6PM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oCKpnN8U80lwn2gV98g0QsHOZOlV/WmeNOSRx023zMtpBkwbxdqsfRlk30Ovhd6EPL
         mEvEcg3dS/Sgl/KzxfpgldnjI8dB9quq75ZUDdEFjZLdqdgUBI2hbYCseMHEmwS0vwKS
         6aA1nUeMwvMUnrkMxzJFVAPMcZnWrmk84m8ZGLeKNsQO1s2WzLCtYemhpazYfsoKIVIm
         ZYh34yYXEVkdhUtsEIiwi5vUAY4Sw+QCAApUGTZLMxQWiCJdMzftwXfgp7+qiR8epYE0
         H+Jl1rnxN0nNXTrGrhI2AHCq+XBKIgslMNA2QIjWi9NKAlgZGtYZuTxAIYBNOjFHK/A5
         eIKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TmuWzqBj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9d4389e64si33692173.5.2024.06.21.04.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L9vTqn003912;
	Fri, 21 Jun 2024 11:37:18 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw49cgpw3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBXCYC017744;
	Fri, 21 Jun 2024 11:37:17 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw49cgpvy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9ITH9019974;
	Fri, 21 Jun 2024 11:37:16 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupvyh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:16 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbAq548628064
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:12 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4FADC2004D;
	Fri, 21 Jun 2024 11:37:10 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BB2742004F;
	Fri, 21 Jun 2024 11:37:09 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:09 +0000 (GMT)
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
Subject: [PATCH v7 02/38] kmsan: Make the tests compatible with kmsan.panic=1
Date: Fri, 21 Jun 2024 13:34:46 +0200
Message-ID: <20240621113706.315500-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: z80Vy_rqUrEB7pD3VgizD3Nec6VCI77p
X-Proofpoint-ORIG-GUID: 73JqdirNA9Gc3nOItCCEysTgBSv4zoyr
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 mlxlogscore=999 adultscore=0 priorityscore=1501 suspectscore=0
 clxscore=1015 phishscore=0 impostorscore=0 malwarescore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=TmuWzqBj;       spf=pass (google.com:
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

It's useful to have both tests and kmsan.panic=1 during development,
but right now the warnings, that the tests cause, lead to kernel
panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan_test.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 07d3a3a5a9c5..9bfd11674fe3 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -659,9 +659,13 @@ static void test_exit(struct kunit *test)
 {
 }
 
+static int orig_panic_on_kmsan;
+
 static int kmsan_suite_init(struct kunit_suite *suite)
 {
 	register_trace_console(probe_console, NULL);
+	orig_panic_on_kmsan = panic_on_kmsan;
+	panic_on_kmsan = 0;
 	return 0;
 }
 
@@ -669,6 +673,7 @@ static void kmsan_suite_exit(struct kunit_suite *suite)
 {
 	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
+	panic_on_kmsan = orig_panic_on_kmsan;
 }
 
 static struct kunit_suite kmsan_test_suite = {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-3-iii%40linux.ibm.com.
