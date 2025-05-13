Return-Path: <kasan-dev+bncBCVZXJXP4MDBBZWGRXAQMGQE27EMZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B987AB585D
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 17:21:12 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-6062b390adesf6650985eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 08:21:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747149670; cv=pass;
        d=google.com; s=arc-20240605;
        b=WrOKOTrH/b8rqmOwTbvQu+6RkqBbMNHFI7JBsg222vlM/wcgPU4ogna1prwLZANL/W
         5SRDc09jrW50RelQCQrjOSbIiE+38/4mPeMXfUGLuvGZDsdTvfk+P7eGOjQ6u0e2SS6d
         quFxU2eK4HJldXW2JKn1yTsZvORLC5r6xrsrXbXlWCe3QQvVcdZ7CIy0jywpkty1lEGn
         iun48vu4rbNn5kJ6MD7BUoM8dpTQ9z4a7Rknv3rVkYPwEGbQcnVaPqNtADveXhmssNhG
         KN60T92QS2y2maQ7ftBDVA+kdn+zsC9RMX09fi6lyouCXCyaKfGWnpytgpv/ZIFDawqf
         VY4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rIhUK0euOD8WtYh5yHQZPEXJ6rpW0GPlMjrrxe6Zyfk=;
        fh=vwQPr8xj/Ghvr7tklAyTiJqNnB7HIZQS1mA47Qkb57A=;
        b=RcEM5uAB24FFTMEJy1pOxVkfZ1EykbeMon0a07Os2nheH3SpusKKkHHHzng2qIu1Xg
         JaiZLmDUfOvrY0OtAIbhP3jpOwHLoFxvIKrcFD5rnKXHMv6TI07tmFvqsJlhVuAtg31/
         tYUnjZ1qHuIx7lx8LIBGFjnQzYksE0XabID+J/eRJUMQwZpsA8w/PcO0InrP+x1G00l4
         CC4U4ctNKxIGzYUe1muaPRnciOlemxt74vWxlQEfokPLVJeANXNudXMZV95/2U9GqMn0
         S4p3d0JK3KkuWHdwuQWhO2kHlTDq7yX7qzKTGysoVEcycTTY4ndCQD3AGdXKGGDH4jBN
         aZYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="M/I+POFJ";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747149670; x=1747754470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rIhUK0euOD8WtYh5yHQZPEXJ6rpW0GPlMjrrxe6Zyfk=;
        b=ErKJid3wXRKXnL0eBjg6qn2O1dP01GLqNb7srTL7Y88HOHGIkUZF0D/waxrN9+cLOL
         /zMuRIjWF+wK/Vds3JScnUgc+bnVf4DoQHLX46ZraWo673I2VdRvxpVWNYFvX3UjFBc6
         T/fxX4olD+uxcL0jmar1LZSHW+udeD/06eEozCvqrLJQiWGSWgDFToMIuYX7OTxolSyw
         1vJYAOox44iLMwpK7nzDSfHzdyUljPsh5hING9cIb5TsAegyTVCsV4w6SBaZARE6fUbR
         NQK7lliBJc1Jc15PqmQvhoTuTRMgpbojNgyEEcSSxFXqyyQAok6VdHx5r65POf2PQvDU
         hh3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747149670; x=1747754470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rIhUK0euOD8WtYh5yHQZPEXJ6rpW0GPlMjrrxe6Zyfk=;
        b=Hv+tpR3DWXK3TY4xc/KaUqiAmVPlfp+4ATqMyyoygBU1W6zstlz0Osz0CHApMxJFwY
         xmHvHUvkPiHDjQtGg20J3g0PSjFywzyAvPAAz7b4OZeqpCW4oUzAc5MlTyiZN+E+S4V3
         bHIOZ2dgZMJrtTJNhjwUaadpMT+juIpMiLB+U9JQkaYXxdN/jpst2tUCQOxB+TMjWph0
         LY7inLkVR2WJbMmGwjtwbile9bJhdLqWCTPE8wz4YxrLmhvX73UUvb3hpCt7Ja9s+0MQ
         yjswzK2e6pEKfES+k7xDT4PUydnV6VQomoN9s4IHk48x7BfPhDu0Ymy5O7BRkjahoaAQ
         fW0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVn0FAWkbnyUx3+jJX+XmpzDy9pCcMhNOuZbFiV5v7gIzn7QtkoGINb2FMH6CMvPd45Tp07Xg==@lfdr.de
X-Gm-Message-State: AOJu0Yx/v1Cg3i050gdFDHKS8gUfiDcKv4UIPIUZxaCJdv7iS5iR0OC3
	mho/pHEwH3A8cE/ddtC3O10SLMUNc1zHqYenykFqHLLO74GI7w6d
X-Google-Smtp-Source: AGHT+IHJJIcGwTEFs5pNdkL84YgjcYarhayMv63Ba2y/SLzcaHhFQaIpS8VDgO+qQIU5uMg1Qs4fHw==
X-Received: by 2002:a05:6870:891c:b0:2d5:23a3:faa7 with SMTP id 586e51a60fabf-2dba4201a67mr10499334fac.6.1747149670346;
        Tue, 13 May 2025 08:21:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFIjkAfuGbcjqpz5ffrQTZC2po4HRcAtasB1UBsBcCIjA==
Received: by 2002:a05:6871:3746:b0:2c2:2ed7:fb78 with SMTP id
 586e51a60fabf-2db7fe4faf7ls120991fac.0.-pod-prod-01-us; Tue, 13 May 2025
 08:21:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3YM/QHFZO+bqjurf3oFe8cCJROXnErYPyuebSGSUgFjWzRADVzm/EVEdrOoPyIxfUZaAAtHPqH9c=@googlegroups.com
X-Received: by 2002:a05:6870:1592:b0:2bc:8c4a:aac2 with SMTP id 586e51a60fabf-2dba44fd054mr10656868fac.27.1747149669124;
        Tue, 13 May 2025 08:21:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747149669; cv=none;
        d=google.com; s=arc-20240605;
        b=hFw9x4LhE1Ch/eMMEvJYwHaXhLY+fxCjs0idF4Icjdla0q0StcyRUKrAgGWxmZvnNx
         EYShT27AidhrCGLYkPrNSySXuLVzBMB7BGLE28+9EyHuQZ3CV2PAO5oi/+rP4Q4huwS7
         s5GXEusBVcQOuJqBfI1bE/ieoCg3BNobqBktVLram+Phsb7VfUS2pdlwydb/j2mMlmja
         /o7ZoU86ACRoTnU8JP0lqCRh4t8/NLP9t59qmad9gOF2JgtW7UH9fvApsuaNHya6mY4D
         Rdl0yTht2ZjFBXvV7A8rHptCZHqENQs7njENZ2+8eNafjmMQaMklcITQWCmIY1Hh5/eR
         Df3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ILGFWDUIQKBMmAXxVAtqVwS5FzKw9CfdLlMdgo1kVVk=;
        fh=JeYjkRDw/VSjlVIISM+t2OTgWgKSm5f4n50024gbhWA=;
        b=RQF4QQXtbwnUa7LlLU3qb5rCbhYiRDGz61T3ZCKfhYJ1WR/4aEk9bmyYrXd7/bc7kB
         kbUE8/2IiOIgv7RDoDlO4e03x0+R7GLhKA/2ytt8LyME1lF9K8J22YhN4x5b/RWHcrxP
         peeiI2ANjoGZf6p3XJOv9Chs4Qn7YvgElY0CyXIVYt19uto+CBH4NDU0vEvnNx/Mjt4g
         WK9uxcXgSyjMz9ZfEww74RvnYWoue6lilzftTeVrJIB0gdrXiRx6+rEiVmCQAmF1xdVt
         oAr6xXDsI7nL7CoUCRB1UtjPaOGDTivIfZyV6i6gPt1ek0ul++3ujVRCAtS8q2S899LW
         D5Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="M/I+POFJ";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2dba0b10f0csi43648fac.5.2025.05.13.08.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 May 2025 08:21:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54DFKC6p020981;
	Tue, 13 May 2025 15:21:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46m0pttmf1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 May 2025 15:21:07 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54DFL6WT016777;
	Tue, 13 May 2025 15:21:06 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46m0pttmev-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 May 2025 15:21:06 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54DE9NfK025954;
	Tue, 13 May 2025 15:21:05 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46jj4nupwp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 May 2025 15:21:05 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54DFL3ah51118378
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 May 2025 15:21:03 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 49BFD20078;
	Tue, 13 May 2025 15:21:03 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 331ED20076;
	Tue, 13 May 2025 15:21:03 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue, 13 May 2025 15:21:03 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id CF8B4E0EFD; Tue, 13 May 2025 17:21:02 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v8 1/1] kasan: Avoid sleepable page allocation from atomic context
Date: Tue, 13 May 2025 17:21:02 +0200
Message-ID: <caf870bddf1c04dc36810bf7e516e86e942811cf.1747149155.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1747149155.git.agordeev@linux.ibm.com>
References: <cover.1747149155.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: UqQRHO515bbCYcDRPiSEVSyMWO-5F8iv
X-Proofpoint-ORIG-GUID: oNfo_Ese7GAuY-_mIhjDeBHy8zqakdki
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTEzMDE0NCBTYWx0ZWRfX+CxMMO4F33wt 1aw858zPJzzSviQX7FZ/cdGQi8STMM2fsjQ3bkDxhxq5WsD4MaG22L1F6EpIex00WaXaZ1qp7GO stWV17yE5mhwHR8nva80BWHqyBXmYrzfgOroBV8l+IOKk0VSTxPxYLt+ONDFGN8GA9IWqxJZH8d
 hjliNkOOxhCWouI7CpjP2CcSneawNBEMXKsgPOqoOOdn1qe034UvNufW5g8AaFcyyA6v1PheEEf hFB6Nw5koUNx85QDLR4MCg2kKh1o3yo+KBuJcD/S20xIlfy0ub2B7z9Jw+KigsfyK5ul0wvoJlJ 8F9SHwwC0D9Js75eKKzEWTeYKBLvILAP5NKv2Pa+9/6RjZk0JUbjJ68Ouy1Tp86hRCW99SySNyh
 munKWfSBngjYFfNLq/dkbxqK3wBdJQELhILKzUIQ9onKs+CHKKPLtKZ3G44kQWDPvIrkNaCg
X-Authority-Analysis: v=2.4 cv=Bv+dwZX5 c=1 sm=1 tr=0 ts=68236363 cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=dt9VzEwgFbYA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8 a=VnNF1IyMAAAA:8 a=JPUNfvWgwyJmovPnq6kA:9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-13_03,2025-05-09_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 phishscore=0 malwarescore=0 suspectscore=0 mlxlogscore=843
 lowpriorityscore=0 bulkscore=0 spamscore=0 mlxscore=0 adultscore=0
 clxscore=1015 impostorscore=0 classifier=spam authscore=0 authtc=n/a
 authcc= route=outbound adjust=0 reason=mlx scancount=1
 engine=8.19.0-2504070000 definitions=main-2505130144
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="M/I+POFJ";       spf=pass
 (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass
 (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

apply_to_pte_range() enters the lazy MMU mode and then invokes
kasan_populate_vmalloc_pte() callback on each page table walk
iteration. However, the callback can go into sleep when trying
to allocate a single page, e.g. if an architecutre disables
preemption on lazy MMU mode enter.

On s390 if make arch_enter_lazy_mmu_mode() -> preempt_enable()
and arch_leave_lazy_mmu_mode() -> preempt_disable(), such crash
occurs:

[    0.663336] BUG: sleeping function called from invalid context at ./include/linux/sched/mm.h:321
[    0.663348] in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 2, name: kthreadd
[    0.663358] preempt_count: 1, expected: 0
[    0.663366] RCU nest depth: 0, expected: 0
[    0.663375] no locks held by kthreadd/2.
[    0.663383] Preemption disabled at:
[    0.663386] [<0002f3284cbb4eda>] apply_to_pte_range+0xfa/0x4a0
[    0.663405] CPU: 0 UID: 0 PID: 2 Comm: kthreadd Not tainted 6.15.0-rc5-gcc-kasan-00043-gd76bb1ebb558-dirty #162 PREEMPT
[    0.663408] Hardware name: IBM 3931 A01 701 (KVM/Linux)
[    0.663409] Call Trace:
[    0.663410]  [<0002f3284c385f58>] dump_stack_lvl+0xe8/0x140
[    0.663413]  [<0002f3284c507b9e>] __might_resched+0x66e/0x700
[    0.663415]  [<0002f3284cc4f6c0>] __alloc_frozen_pages_noprof+0x370/0x4b0
[    0.663419]  [<0002f3284ccc73c0>] alloc_pages_mpol+0x1a0/0x4a0
[    0.663421]  [<0002f3284ccc8518>] alloc_frozen_pages_noprof+0x88/0xc0
[    0.663424]  [<0002f3284ccc8572>] alloc_pages_noprof+0x22/0x120
[    0.663427]  [<0002f3284cc341ac>] get_free_pages_noprof+0x2c/0xc0
[    0.663429]  [<0002f3284cceba70>] kasan_populate_vmalloc_pte+0x50/0x120
[    0.663433]  [<0002f3284cbb4ef8>] apply_to_pte_range+0x118/0x4a0
[    0.663435]  [<0002f3284cbc7c14>] apply_to_pmd_range+0x194/0x3e0
[    0.663437]  [<0002f3284cbc99be>] __apply_to_page_range+0x2fe/0x7a0
[    0.663440]  [<0002f3284cbc9e88>] apply_to_page_range+0x28/0x40
[    0.663442]  [<0002f3284ccebf12>] kasan_populate_vmalloc+0x82/0xa0
[    0.663445]  [<0002f3284cc1578c>] alloc_vmap_area+0x34c/0xc10
[    0.663448]  [<0002f3284cc1c2a6>] __get_vm_area_node+0x186/0x2a0
[    0.663451]  [<0002f3284cc1e696>] __vmalloc_node_range_noprof+0x116/0x310
[    0.663454]  [<0002f3284cc1d950>] __vmalloc_node_noprof+0xd0/0x110
[    0.663457]  [<0002f3284c454b88>] alloc_thread_stack_node+0xf8/0x330
[    0.663460]  [<0002f3284c458d56>] dup_task_struct+0x66/0x4d0
[    0.663463]  [<0002f3284c45be90>] copy_process+0x280/0x4b90
[    0.663465]  [<0002f3284c460940>] kernel_clone+0xd0/0x4b0
[    0.663467]  [<0002f3284c46115e>] kernel_thread+0xbe/0xe0
[    0.663469]  [<0002f3284c4e440e>] kthreadd+0x50e/0x7f0
[    0.663472]  [<0002f3284c38c04a>] __ret_from_fork+0x8a/0xf0
[    0.663475]  [<0002f3284ed57ff2>] ret_from_fork+0xa/0x38

Instead of allocating single pages per-PTE, bulk-allocate the
shadow memory prior to applying kasan_populate_vmalloc_pte()
callback on a page range.

Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: stable@vger.kernel.org
Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 77 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 63 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..8212a7007b02 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -292,33 +292,84 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,
 {
 }
 
+struct vmalloc_populate_data {
+	unsigned long start;
+	struct page **pages;
+};
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
-				      void *unused)
+				      void *_data)
 {
-	unsigned long page;
+	struct vmalloc_populate_data *data = _data;
+	struct page *page;
 	pte_t pte;
+	int index;
 
 	if (likely(!pte_none(ptep_get(ptep))))
 		return 0;
 
-	page = __get_free_page(GFP_KERNEL);
-	if (!page)
-		return -ENOMEM;
-
-	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
-	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
+	index = PFN_DOWN(addr - data->start);
+	page = data->pages[index];
+	__memset(page_to_virt(page), KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	pte = pfn_pte(page_to_pfn(page), PAGE_KERNEL);
 
 	spin_lock(&init_mm.page_table_lock);
 	if (likely(pte_none(ptep_get(ptep)))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
-		page = 0;
+		data->pages[index] = NULL;
 	}
 	spin_unlock(&init_mm.page_table_lock);
-	if (page)
-		free_page(page);
+
 	return 0;
 }
 
+static inline void free_pages_bulk(struct page **pages, int nr_pages)
+{
+	int i;
+
+	for (i = 0; i < nr_pages; i++) {
+		if (pages[i]) {
+			__free_pages(pages[i], 0);
+			pages[i] = NULL;
+		}
+	}
+}
+
+static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
+{
+	unsigned long nr_populated, nr_pages, nr_total = PFN_UP(end - start);
+	struct vmalloc_populate_data data;
+	int ret = 0;
+
+	data.pages = (struct page **)__get_free_page(GFP_KERNEL | __GFP_ZERO);
+	if (!data.pages)
+		return -ENOMEM;
+
+	while (nr_total) {
+		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
+		nr_populated = alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages);
+		if (nr_populated != nr_pages) {
+			free_pages_bulk(data.pages, nr_populated);
+			ret = -ENOMEM;
+			break;
+		}
+
+		data.start = start;
+		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
+					  kasan_populate_vmalloc_pte, &data);
+		free_pages_bulk(data.pages, nr_pages);
+		if (ret)
+			break;
+
+		start += nr_pages * PAGE_SIZE;
+		nr_total -= nr_pages;
+	}
+
+	free_page((unsigned long)data.pages);
+
+	return ret;
+}
+
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
@@ -348,9 +399,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
 	shadow_end = PAGE_ALIGN(shadow_end);
 
-	ret = apply_to_page_range(&init_mm, shadow_start,
-				  shadow_end - shadow_start,
-				  kasan_populate_vmalloc_pte, NULL);
+	ret = __kasan_populate_vmalloc(shadow_start, shadow_end);
 	if (ret)
 		return ret;
 
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/caf870bddf1c04dc36810bf7e516e86e942811cf.1747149155.git.agordeev%40linux.ibm.com.
