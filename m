Return-Path: <kasan-dev+bncBCVZXJXP4MDBB2XES7AQMGQEJLQ7HHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id E3454AB8891
	for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 15:55:56 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-6064d0103f8sf1767552eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 06:55:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747317355; cv=pass;
        d=google.com; s=arc-20240605;
        b=TrheJDbzdyajZEAXx/L+9wFBDU+QiDWLHDOo4sTsNLPcR2GSuO+dJ3JQy191kiAwio
         9IEiygNzu5XYdHVIl2y6+DdligairFB0QXJOpoM+XX4oniaAnPQP7B3W8QgiA5BLggp9
         iCjl2jUEdq5MzvL8RwlFBvnEELlGPVT1ZW7tqyW5R7phNBKHVyIT0qaSwLEMHuh1sWp4
         h2hAk7TPq5Hz44QcDZK+D0yBN5iSc/olMysxbmBSti0oehe1BzbBdM6isTEERGbAJTZ3
         ZiS1kAD6KPUWS9mUa9pbx6ovUXMMbSjzGPYf+3ARZjwY0e8VYdRYltKfbhAc9SBXwKPc
         MqWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QXLW7rLKGiLnDVHrdTk/3vtTnXEk5QVV6z0cpNqgVAA=;
        fh=qxFYR2Gikkii8SjzToaEKHCiL5TATz6DKXM9Ee0foLY=;
        b=D0TcvfOB/GBDAu6jqgXV1LHLM3uE/cAAM2IM1xL83oi5b1P1tf5PJb+n0OhknMc4Tv
         JnHZbeQUXEvLa7ZaujI+Yo85wlwDDy2epB0WbkG7olwOrb2QP/uhbbj+yzDYQKLsWr0K
         Wxr43hPR9fJqb6I3ID1NwsGff/KPpaQ7ZDQUHxjBqPb0EmETC9wR0AtKtcVRDcREtoe1
         yhLNQSpxWw2jN5Ikow2iZrC/h7Av4KjxxtCxptW5zxlqaYRdqn1g0oOe0+s8pSuB/CkM
         md6xGLySzhyMxdyzCK+b0UOAMeOKhpH0d56Fgcx8HrWaGXvThLO72kvCuGyD5jCYT9rB
         aO2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=afCfW+f1;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747317355; x=1747922155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QXLW7rLKGiLnDVHrdTk/3vtTnXEk5QVV6z0cpNqgVAA=;
        b=fZzPqbQjn+WOejjbpnBeduTnGbSA2zjmuHtEI6QF7NiXlt+DyPFXKJhGcFNI5K9SCv
         d/dBuym0uoMAI0+ySc8WHfCnJ+Nw9n3x31+Uuz5RZ77aw4iP1+PAKrulEkPzCx3ASBXb
         3yVpLb/AEoZ/FRVuUoTGwvX+aRWgQONxfQyIcKHjAPm+RwSpuwpFlIpMOjOCmm/eq9j5
         iKMOT3mYWrCnABxb5LWdVnYZKeU2h7LlFLvBnfcuBst5bcdvmPOzWACgqwaBzl8ezGWc
         RePhG6QHvvadc9L+4McBZmq/9+pePe2iJotuKKDMJWdyiIZE0B5ifT5/wJxbM75TS8Lm
         ua3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747317355; x=1747922155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QXLW7rLKGiLnDVHrdTk/3vtTnXEk5QVV6z0cpNqgVAA=;
        b=AWam5amfmCXi7lcUu/lk/Xk94Mum2J/KUFcGi7LkywhftCLbLuvxk4rsg0mphiV2ge
         R2yFZJtVZXFWBl7h6IYoZCDxOnv+iB6j4MPD/FQ67w24/OzZR03dO3lqSmSaSHTSOg3R
         MBumXw3JecXhDAOIX4pVMHy6Ulr+7mkdibXGTGhVG7RIC2Z72ALqGBcKav7VUVxaHjHD
         xOXWsIj4AHVUfYHEUzCb0jAh68WJabyEknAg98O6D/b+jVklVA40VtmPbREPY13RDiJn
         0eCH5lYX3eFurQYEbJcw/akXlXLojTwbcFyXEUuIG5U95l7ZXSI7J10MO2+6kBxF4jty
         b9/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXX3cSO6lUbIiLciBnjKjqOmnMMu2tTWQVZANsL0Sd4Rt/Q6mSo0SoHgdHAdipP2D8eDAtGCg==@lfdr.de
X-Gm-Message-State: AOJu0YyONAbs2sXeRgTwuuqliIg4uaDHeqOQvgMbjcH6tTT3oL+039fS
	1pe8KTiEGmLKgyh81/z1+77VzqTtxTX8XFYwiAkH/IxX3YVEVNAy
X-Google-Smtp-Source: AGHT+IFrewe6CPVSdsTlgPwUDVDU73RsrwT6z+4RtREfYqfEejzi9NqD9NLgq4VIQvJ7iaqWaeZUQA==
X-Received: by 2002:a05:6871:4d0:b0:29e:2594:81e with SMTP id 586e51a60fabf-2e32b1356d9mr4151395fac.13.1747317355068;
        Thu, 15 May 2025 06:55:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH8o+kuukMa1ZWY9ReKUZCuXZGfv9IQlxcD4btxAeNGJA==
Received: by 2002:a05:6870:8303:b0:2da:b91c:91bd with SMTP id
 586e51a60fabf-2e39cca7867ls750882fac.1.-pod-prod-09-us; Thu, 15 May 2025
 06:55:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtl1sZCillGaUMr6GtdfzHUGCk3buX2ZV8dQk3Czc+Y6U/ofJW7Tl8miDEgBfCJAEn/Xu8n/vJtZY=@googlegroups.com
X-Received: by 2002:a05:6214:20cf:b0:6f4:c84d:d1bd with SMTP id 6a1803df08f44-6f896df90bbmr108723496d6.6.1747317343341;
        Thu, 15 May 2025 06:55:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747317343; cv=none;
        d=google.com; s=arc-20240605;
        b=bJTX9UOTSlQHRt/0aQ90QJef5oNMYzwXarIyfpUvS5cEx7GsQmkZwaIJZfcwd3iO0P
         4Q39D4jSr32j4nQb9jP1koKFnn8YKUyzSDoIWyQfXJzA8iqZowBDr3MhCBWrOwUMbEWN
         3PMuWcwiwv5n3g/dnAY4zb3LUO8I2ZgMoTvWtKvmxeMejyeW0w0icSIc5hSggyZ4rvc4
         p80ACgPts8m1GI257EnBEcNE+ByT9RtOe0FbGMotLb4xST8Wbc0G3z7OFDDvYveQih2Y
         o1nePMm7vamFReHNttaZazTHx9fN/9ZKWuWFh2zw7aOtx3/z0KnyGALn0z/UciuBeN84
         v3ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D8Zkzg6+jShC5MWa9L+V8BhRRKNe9yq/QHgWeXrDV7M=;
        fh=JeYjkRDw/VSjlVIISM+t2OTgWgKSm5f4n50024gbhWA=;
        b=AEm6RhiTvI+vfdO7Il1ZUQCKVH4vqBKrQbfUsFkrccUF1s9HkSOV8bTbUrIc3HA3s6
         rMeHtWZdzkvGo2mQRaw5f9MI1I6ZljhYbjAWEHTmuGUqt9eylBtx3UIwWVMcqJ9TLafk
         odfetWSHB8kGSub2HdkUE2fg033nHT3vwVU9EdRU4eo21gL/p1TnljMnBunO7BWhAwAV
         0rUvndHSokQjvIiMYbTtqiWkbvW1a7TsWr4RDQVGaNoi5i1cC7q2Y3JoRdioa6HnOp3R
         F2u5DKwZ6+8yANo8VIL2H20PLZpuGWRkT7bNQ1sFlwlZeMKIbpN43Lvfj/0Vk8bibIpq
         4O2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=afCfW+f1;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f8a7dbb652si424616d6.1.2025.05.15.06.55.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 May 2025 06:55:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54FCgCBY002495;
	Thu, 15 May 2025 13:55:42 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46n0v6msmr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 13:55:42 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54FDoYnB008311;
	Thu, 15 May 2025 13:55:41 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46n0v6msmn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 13:55:41 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54FAmrwW026961;
	Thu, 15 May 2025 13:55:41 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 46mbfpjgv4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 13:55:40 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54FDtdaJ51708328
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 15 May 2025 13:55:39 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 45DF720043;
	Thu, 15 May 2025 13:55:39 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2E81F20040;
	Thu, 15 May 2025 13:55:39 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 15 May 2025 13:55:39 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id D23D6E0F9B; Thu, 15 May 2025 15:55:38 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v9 1/1] kasan: Avoid sleepable page allocation from atomic context
Date: Thu, 15 May 2025 15:55:38 +0200
Message-ID: <c61d3560297c93ed044f0b1af085610353a06a58.1747316918.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1747316918.git.agordeev@linux.ibm.com>
References: <cover.1747316918.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=IqAecK/g c=1 sm=1 tr=0 ts=6825f25e cx=c_pps a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17 a=dt9VzEwgFbYA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=JPUNfvWgwyJmovPnq6kA:9
X-Proofpoint-ORIG-GUID: ydPVqpzFxPM0z_9oTLGhcjSKAdHNRpLv
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTE1MDEzNCBTYWx0ZWRfXypSuCdgFy7aN Vf7FcabpAUzJk0DkkGwvfW1LvTvwzakjaP2vcAdfxEdOcTao1f5bKPukFCEguAKsZGrsk1Z+TKL rsU01iPRECJ5ZH8rPGzacTasePzv7VGWe8OLFo6zdNAeLWgpCGpd1BLU6ZtZ0Wfz9revA072y2q
 uhrKQlakcujuMbbZD0KfiDLEWjo+c9S/kxji3HDqmOtwcdm+BP+fMYblpBzWRSvM1Qr/LEB7ei/ ypUWjMYAN3vRrM27Kspl24jwZtNmLk38h8A5PnTnU+E9RtE9+3DJHBgwexHvN4ku+G7VHNT0+Kb PyhLP4cMGUEjKxJ9U0YV39sEAS0bPEJp0QNEkLYVKYlmp8zA8fvfR/E6r3iy1YrmyTZEN8jlbsH
 FKtiUyE6Yf8j9JEDI5LUvEOCvsrgANYFEEhEiMmPl+pp7F1HGJvrH2oDj1TACtQDZDU0JtUV
X-Proofpoint-GUID: h3dLozVcWtnqxc6yylykVEyeIFyaqAnC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-15_06,2025-05-14_03,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 malwarescore=0
 adultscore=0 lowpriorityscore=0 phishscore=0 impostorscore=0
 priorityscore=1501 clxscore=1015 spamscore=0 mlxlogscore=598 bulkscore=0
 suspectscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505070000
 definitions=main-2505150134
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=afCfW+f1;       spf=pass (google.com:
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
Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 92 +++++++++++++++++++++++++++++++++++++++--------
 1 file changed, 78 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..d2c70cd2afb1 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -292,33 +292,99 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,
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
 
+static void ___free_pages_bulk(struct page **pages, int nr_pages)
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
+static int ___alloc_pages_bulk(struct page **pages, int nr_pages)
+{
+	unsigned long nr_populated, nr_total = nr_pages;
+	struct page **page_array = pages;
+
+	while (nr_pages) {
+		nr_populated = alloc_pages_bulk(GFP_KERNEL, nr_pages, pages);
+		if (!nr_populated) {
+			___free_pages_bulk(page_array, nr_total - nr_pages);
+			return -ENOMEM;
+		}
+		pages += nr_populated;
+		nr_pages -= nr_populated;
+	}
+
+	return 0;
+}
+
+static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
+{
+	unsigned long nr_pages, nr_total = PFN_UP(end - start);
+	struct vmalloc_populate_data data;
+	int ret = 0;
+
+	data.pages = (struct page **)__get_free_page(GFP_KERNEL | __GFP_ZERO);
+	if (!data.pages)
+		return -ENOMEM;
+
+	while (nr_total) {
+		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
+		ret = ___alloc_pages_bulk(data.pages, nr_pages);
+		if (ret)
+			break;
+
+		data.start = start;
+		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
+					  kasan_populate_vmalloc_pte, &data);
+		___free_pages_bulk(data.pages, nr_pages);
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
@@ -348,9 +414,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c61d3560297c93ed044f0b1af085610353a06a58.1747316918.git.agordeev%40linux.ibm.com.
