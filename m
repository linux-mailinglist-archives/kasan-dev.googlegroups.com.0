Return-Path: <kasan-dev+bncBCVZXJXP4MDBBOFORXCQMGQEHCB4H5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AE4EB2AE57
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 18:39:23 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7e8706c668csf1306017685a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 09:39:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755535161; cv=pass;
        d=google.com; s=arc-20240605;
        b=SLJk8D2ZplJOAhmH4WPMHYhu63Xa4wQiTbe6+2r6xLjDtG+D8bbPKl9ktPHtRG9Phv
         f8T8jzUd4Z1p1xW9JnFz+IbVljloipiTe24hBfbqYcvERLjJ6JklBI/R2UWuVED4je7f
         ooGkOaIZV2YzpEdRGHvZ7p8VN/Kdj+ygLZ2WmTh+fowTCdG7dFGI9Cql1LubJkGvj40p
         tEwVIU5wzrdsjEaZb8ZBTbde96yXfIn6DYwF3jw6Neljw77aeQdJrAJIgE254HGstJ5Y
         pKeDS6n5r/Jl+jR3xh7bBfg1RLMlH8aNNwo9gHCQtVf19MskRB05dCA9RXC0CZc2DaEC
         xwlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=65qXbnfIESgWPxPjAAD6xhe2HVEezivuymSfk0OJqTM=;
        fh=61IvABftyAkSahl/wHuLK+UdaVyn5FdpLO07kIoKYAo=;
        b=T2PDirxtYq70uYh+J3JWbTcrVMJ/cK9b9uc5/+4QOVPj4Z1rQ9dmfH9mfNIqy+h+/N
         vyvLD16b9hwFqxbQAK5+yCk5uhtOQ7Mla2xYankF4+gwU91eMjNpgFCAHWl7/vGSMq0R
         HeqcydtAU2VNOrYJM3s8ZiQY48JEAIefRSFEgpIXhVGHe4nSldwOEsFMz8GGtOajwi6S
         c8uO4S6s62g+egIg8H2eO49pWvniVy39hNN9ZkelAS8F/hSsfqSNUsljoTzXWcqKqeEU
         PpP4iUq6LqDqrF0JBYTKtjxWD+o6kaZQ48wHW72rKB4SKvRSPAp8lntFQ8gdj5eXzjzW
         62Pg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lxvmYFxk;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755535161; x=1756139961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=65qXbnfIESgWPxPjAAD6xhe2HVEezivuymSfk0OJqTM=;
        b=ATl2xGyKI3JTw5bAtr5jkJEbazOpt4vVLJMyrx6qxeJtCUHb8Q7vicFWhZ0iMSJJ1Z
         P4e87l5ESvyk51gD3wtMIPTc5LRR0hbxAYxqEacWhOSIRaLkK9vAFaOliFfU2KOVwfcI
         WYHP9LR//q0WLJIb2HG8IXLbRsjcaSk/FvMDBwUo5Rc4PkTJz5ME2sfoecjdWaVMJ8rt
         saQCL8vaUExKdUg1UI3cjAQXA3g4geLMaW6//oXG2TQcStfAxSLjAHZnHjj1DurESFch
         xx3GGt4lfCDRkP0of0Yx7HSityoo98HXRD8obOPYHPhCng3hLPG8kJNjDKUgZ943BSZJ
         lgHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755535161; x=1756139961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=65qXbnfIESgWPxPjAAD6xhe2HVEezivuymSfk0OJqTM=;
        b=b1NLgOhpPAUT1SKGNXtTaiXvArvG0jxfwaTQhTnZ5WHq4nAhySvmYEIahxACiqSDfp
         bNic3A28imhZNQlt1kdsHrEt4ch1tgceeCmbK53THZkEHxnCFCorD/hnMRoOlhitRDpN
         uUL697+OKLDW7Qytp0x7DGODPFB+Ieu6LSIGA7Wskg2Wl3cjL+a+Q9xvtFFmeI1iVz9j
         FSlyzkM4g1uEtfknUnB18NSQ4gbb1vPEPTqdPQ4Nee2Z5cY/2sDapBlKRIMvAT4iNBwe
         wYIpRYeK0+IMA4EuwlEjPv11omKDe97IZ8kqJSK7YdsKmsv7K7oqxIozhSqan3CD+Kq0
         E2NQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkUNF/wwsSISSCJvACFhCJyNeezmlU3Wt4/r9skuyoLHhMCeAk6rGnncn3/i1eGPRZ7uEJFg==@lfdr.de
X-Gm-Message-State: AOJu0YxiN9aDldPtp6I1kfUzlp/HGA88OmFoG9rBSW1951FKR00CMSMK
	yrqW5GdIpmNy6CF/A3KpxIYrH97oVCQSOQIgIr1e8DsSQmoZ6yiGaOuf
X-Google-Smtp-Source: AGHT+IHTAtFMRVe9st9/UVbO38yD0tsh+VOIFUN8y0aZqNHVUKLsFAq4C6N7yAHl7pwfdAwLVLvWgQ==
X-Received: by 2002:a05:620a:4496:b0:7e6:5f0b:3264 with SMTP id af79cd13be357-7e87e138ae1mr1634938385a.64.1755535160960;
        Mon, 18 Aug 2025 09:39:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfIqAnhtjYE0R5WfXs/Mc/wesPx32X8IgHbxuw+qr9QAQ==
Received: by 2002:a05:622a:189d:b0:4b0:7b07:8987 with SMTP id
 d75a77b69052e-4b109b957eals82549911cf.2.-pod-prod-02-us; Mon, 18 Aug 2025
 09:39:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVokRYOkMqJF7ITfuJLm5bTfBMbYysXSW4X25iHhxHSlhnZHOwgj0moTfsHm08vBbYMXMhAMbx8S2o=@googlegroups.com
X-Received: by 2002:a05:620a:4043:b0:7e6:2f6a:5bae with SMTP id af79cd13be357-7e87e137b50mr1906600685a.62.1755535159639;
        Mon, 18 Aug 2025 09:39:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755535159; cv=none;
        d=google.com; s=arc-20240605;
        b=hsg9Hfce3bU+bSwkDFUgP9S5oRbayukZt9HYOVV5jSzp6ZotKD3t9rgBAr/sMiADXP
         Le1f1yToNLXzzPX0qsV2yQgFP0tkHEZhbJ040BWOfeGQm0jbNusNc0QDZwVUlAwO4y3a
         da37MCDUwAvoTvddEhJbw1s562MZIFxxMyZfCV0qY7/X0wkfMiHc925oOBmg8wtZUw+P
         DQTPviAaUOG9JdQRdvtlpLDHM0aTzyUqAWGG6iyExzsC5xTaQmcahDVbzgwXiDPxzMFu
         gJKVCYr2+OoISl/ZBFJREcjjSuXR9Kqyrk/y5EmFPxLE0+DW1uUQNQ290f/T2dwLgSoK
         rGAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ygtR6f2nWYzlzt5fL2eFvz+eu0ybJnfHHIWv/65pn8g=;
        fh=LdYAWUXcdYrCqzsb33cHKMTwCaURP2yfAndH6C0pUuE=;
        b=a27IwI6069ppvUkizixcTQR2KljOXTXa73P8diHm91FNQEFs8h8HGW6e20p89VLMgL
         3VxHuCi0g78TMQYHHN1cU/u8hD7euUsyE5A9bBr3A/1iKL1rRmJ3GQorr/EEg3SNWyON
         EZFJPBKWBWTM8J3NYimvfIefWcPMA2myuZ5RXGe7FtkxQIXrNQSC4JL/0TZAHV48zZdN
         s0xB+qrj7O+GtbU3JjgEWtaqqjWbOVpbYueSCdJxHM8SJo+gwcoNZ3bUtj6MZWAAf4wT
         Nv+hZAPBIO1zLw29mv/ybz9pgr298SptEDW8cc52rMHdW58vlCBIcyQz1FF3zYHYL9Uf
         8lIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lxvmYFxk;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba8a8ce87si3444526d6.0.2025.08.18.09.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Aug 2025 09:39:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57ICrWD7016582;
	Mon, 18 Aug 2025 16:39:16 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 48jfdrtd5f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:16 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 57IGamgX027674;
	Mon, 18 Aug 2025 16:39:16 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 48jfdrtd5c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:16 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 57IFRaAm002340;
	Mon, 18 Aug 2025 16:39:15 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 48k712xbum-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:15 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 57IGdDse31851050
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 18 Aug 2025 16:39:13 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7CAFA20043;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6D70D20040;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 43E9DE138C; Mon, 18 Aug 2025 18:39:13 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Daniel Axtens <dja@axtens.net>,
        Mark Rutland <mark.rutland@arm.com>,
        Ryan Roberts <ryan.roberts@arm.com>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 2/2] mm/kasan: avoid lazy MMU mode hazards
Date: Mon, 18 Aug 2025 18:39:13 +0200
Message-ID: <0d2efb7ddddbff6b288fbffeeb10166e90771718.1755528662.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.48.1
In-Reply-To: <cover.1755528662.git.agordeev@linux.ibm.com>
References: <cover.1755528662.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: v-pPmVsfYB8aWZ696MiUmjnkn_I1mE_A
X-Proofpoint-GUID: qXQLAt8GvgBgB0va-hWWdqzwhhp2QqFk
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODE2MDAwMSBTYWx0ZWRfX4fbSHZEHXORf
 8ZQ7fcfOW8VZI4tcwzj02pawPeHcEa4Wsit6guhDP78kZB8b1PMUyieogeS7DMT9nqm1ojizMID
 5V1YD9jjlOYPmZEKG1rrjVj/OS5Hcbhpx1ZDSH4MdVaN2qucNtqzMsWsfIBC622IfAYyp2l6W2l
 L2Fr6YAvvxA1sKPXltEXgEPZpJ/uposFoosJb0bkYWF8JGsMQCncxUI3UhFheHAOn4zOjnY7TWQ
 PejEMNGmAdUAiq/rjauWG0onl1GLvmJRVwATw+luOlKL94OFJdrm2LFy+XXyK4QcZlDQCqnAzZs
 wHtElihoYSDX9vW602V+VHqu3Dj2/ndPM4kWyXT46UAUkLwNZsG7LvfjC2cpeY9QzfbRE6Dr4FF
 Pxd/mqd2
X-Authority-Analysis: v=2.4 cv=GotC+l1C c=1 sm=1 tr=0 ts=68a35734 cx=c_pps
 a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17
 a=2OwXVqhp2XgA:10 a=VnNF1IyMAAAA:8 a=0CqGaNLKB4nZpUE_F0UA:9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-18_05,2025-08-14_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 impostorscore=0 spamscore=0 adultscore=0 suspectscore=0 clxscore=1011
 priorityscore=1501 malwarescore=0 bulkscore=0 phishscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2507300000 definitions=main-2508160001
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=lxvmYFxk;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
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

Functions __kasan_populate_vmalloc() and __kasan_depopulate_vmalloc()
use apply_to_pte_range() function, which enters the lazy MMU mode. In
that mode updating PTEs may not be observed until the mode is left.

That may lead to a situation that otherwise correct reads and writes
to a PTE using ptep_get(), set_pte(), pte_clear() and other access
primitives bring wrong results when the vmalloc shadow memory is
being (de-)populated.

To avoid these hazards leave the lazy MMU mode before and re-enter it
after each PTE manipulation.

Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4d846d146d02..e2ceebf737ef 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -305,6 +305,8 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	pte_t pte;
 	int index;
 
+	arch_leave_lazy_mmu_mode();
+
 	index = PFN_DOWN(addr - data->start);
 	page = data->pages[index];
 	__memset(page_to_virt(page), KASAN_VMALLOC_INVALID, PAGE_SIZE);
@@ -317,6 +319,8 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	}
 	spin_unlock(&init_mm.page_table_lock);
 
+	arch_enter_lazy_mmu_mode();
+
 	return 0;
 }
 
@@ -461,6 +465,8 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	pte_t pte;
 	int none;
 
+	arch_leave_lazy_mmu_mode();
+
 	spin_lock(&init_mm.page_table_lock);
 	pte = ptep_get(ptep);
 	none = pte_none(pte);
@@ -471,6 +477,8 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(!none))
 		__free_page(pfn_to_page(pte_pfn(pte)));
 
+	arch_enter_lazy_mmu_mode();
+
 	return 0;
 }
 
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0d2efb7ddddbff6b288fbffeeb10166e90771718.1755528662.git.agordeev%40linux.ibm.com.
