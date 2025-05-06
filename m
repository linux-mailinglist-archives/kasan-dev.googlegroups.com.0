Return-Path: <kasan-dev+bncBCVZXJXP4MDBB7535DAAMGQES64EO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07313AAC817
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 16:34:41 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3d90ba11afcsf67665755ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 06 May 2025 07:34:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746542079; cv=pass;
        d=google.com; s=arc-20240605;
        b=gkQeSQLfzVPYG5cHdgLh2jhxA92eoZQlLoZokXNVKh4YC7Mkf6ENPvET/k8i0QiHL8
         GxXJJrfSI0S8RAUqn8a3C/3NGGmkBVx8z3vDpVkbwY7PTmaDi7/GrREmkd/MnfgqM/pW
         clPJKhl7I33oRpYmBSvi0fi5cI/DNtKsqW87RHdwRKy0N46sLKQqZwu0eDMsHY02QZIc
         uwvB/O44WhbxdHbAIAP5prGKoUteIW/UmbE8WkNKu/1X65InBylb5AmO1AMLq81xu7yA
         PTKLObcKT8lI9AfAvVDJmCQaeGenjn7YuHzffPS8Nd5YNiFEWwy0O0TtQRhJtM/b52dl
         b6cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZwP1pMF0rDWauI9Ajlyuldg1ZWnb7TVtJOcvGvH0kcs=;
        fh=3d4Xrz8vvrp/4VvKLlh5//IpdDLtZ+Q5mHZIUQ6T9+w=;
        b=lkXyuvEePtyes03oTVpmr33eqTlmI3KOBNQtcDkouzhtbsbArbJppDuMW5cClvb39y
         FKkna5wm6vQS7a0nlmHbVOnKI+rX5UsoXwejQWrZfaBJOvsXxY959wYmYdOTzZIN2EhO
         At1Ru/ZJm6EF1fkIfz80o4c1q91YCojEiK8iDbmUSpYbiF8sdhyR/DBqR9yszHixuiLV
         V42WGrPCaG6lFkfx9AmMmy4hUUj5/QK1hAa7k6bY07YOk4/RwWsaQai9cR/CYI1Swa/m
         e4KHHdNIHEgLEg9SJt/EZRPEdU3IJwvQzaal1gIpl4CgA4mUXqH1zat7P3AdVECbXI+4
         1MdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QByLYebl;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746542079; x=1747146879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZwP1pMF0rDWauI9Ajlyuldg1ZWnb7TVtJOcvGvH0kcs=;
        b=QyZD+mTr10X60eoIStNW+M1uOAN7b2ImaAT89sa6uAwVKw1bBatN1zgqXmpwcbxUiK
         E5/MofzJlR5y5a5vh4Ra5tHXWdpjR1OYPTXRuI+y3ABAXpOmYbG/Tg6EC0OAZ2lgS++Y
         GEE6RM+DrQs3fdbmSni+Zo/JEj+l7wy9V0JWVL3xLRyzoXF67+Ia+nmq+H9I/61I+u/r
         76yi3UDRyZ+AK4GLlElv634DjRufEr6Y8KcbIsVI8LidJ9ARn3U7cl7xTQXFuBLN1LGN
         gwBztFJVTCDTzk7w/A2eqOppqRaVNyXm/20O5fAX00t20rbQoeX2b1HCm/tOKHFK4nbv
         llEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746542079; x=1747146879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZwP1pMF0rDWauI9Ajlyuldg1ZWnb7TVtJOcvGvH0kcs=;
        b=m6lcpVb1Z8pXR660UGKFEuiwXZoBBJ5V9Hyl08yDwiL7b2vfIo86q1TQgqCiUPzJ7H
         chNsItsmrASTyRxgcGEo00cAk8GqSeURZi/4eE4dwzy35Q5aAHgw0SLQ7DDI8m2QeWmy
         jn8WaZO0oubqcCzDaE30aw/uyIa11pflofmMnD4tnfgVNzDalxXwQUzm4my2GOP3sCAU
         0S+8qCxdc+7qsdZKemsawUBohFvx9gGAVzJwPpFYIgCFKze5dCdzfDN/tCb/oSXVPzvS
         mB8hASSK8tzbbukc0J8xzbLRXUTUEqr9PKHGqLy2BjN9xmZfKlBeWNckkx58HkIX4hkF
         HWNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTZ3XG0uaPRgV/i7oBF8XygbLO8GzbWKx3jrpIihFmjeC6Glrlf11hDtAMIJKEcPxNSdguOg==@lfdr.de
X-Gm-Message-State: AOJu0Yw5Ji66N2lQ9WwxbvNdjsmMhlPU3Hj+k3q+qLatvwBFCfsc9z2I
	cXsA15bNHeDsR/aRXB7IOAMW284Kk52RvZTDK6VhUl3b31ylgt46
X-Google-Smtp-Source: AGHT+IHgzZemVVPzeeYU0lAvTDWS8oRiRYuDodcIhps77QLYZpwIKM975wj4b1hb/rWa0qO4ZwodUg==
X-Received: by 2002:a92:c242:0:b0:3d8:3b31:5046 with SMTP id e9e14a558f8ab-3da5b31ec06mr110724715ab.17.1746542079540;
        Tue, 06 May 2025 07:34:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHlOqYnZvmFOzX7LfuJrYZb+xuwSGIlrYVXxFk6vvuIpQ==
Received: by 2002:a05:6e02:19ca:b0:3da:70aa:1eb7 with SMTP id
 e9e14a558f8ab-3da70aa1fd0ls2107695ab.1.-pod-prod-09-us; Tue, 06 May 2025
 07:34:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQkc61Q+//RkV/NDI1Mz5u/lQHZn44cjtKbXByJ1n5WoELG4fhIin17cVgITBQOSVGayC7zkOfDiU=@googlegroups.com
X-Received: by 2002:a05:6602:6418:b0:85b:538e:1faf with SMTP id ca18e2360f4ac-86713b05790mr1256237139f.7.1746542078733;
        Tue, 06 May 2025 07:34:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746542078; cv=none;
        d=google.com; s=arc-20240605;
        b=dGGGeGzTQB0jmLtFuxZ+XeqK5sB3lzypTJ4pd6+6gpeDhdwd111hnUU1ETerPYVjQc
         +xYiEerOjHiyFvyzsLFaHFdGKOKNYmc2xsBxqCasrvpXqbFoy+dOltOuMaCwpIb3JkKM
         /aKKca/6JJGnKz+B0ymqJ+HJG6uNbNdDhZJH9xwOGO7kL+cbD3eNCdM8iTER0Z/SPHka
         5UBepbR0rrcLznPiYLMTrYo/CF0DvKhlp/MvN5crUVWm7cA6DA+BUuutDqaOEv3G1UNr
         s2WFlEB9NL3/OOM5foCVxigpx+nS+AJd5j53Cl5E3+Yfl1h3LpAZk9fLTg8/wxc2WC2u
         ULbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dzBR/+qfdFMk0c8AaJeFQ5l+BbLWcZ5nmAQZ9zLtQDM=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=W5im/FZAMDTbwmy1bDnh9oUJAYLDUhgIZPmDv5eyUWzQR01eiKXov35pF2Tj4YTVp0
         X7M54c1P8jy4yG6kpdkGg2S3+cujcCndE6VxX9Km6DIgWqgyfJAJTNLxCypCpjtlQdXL
         25V27wJS1zXXZf/c79P3+thh/hHsqloNabut41xd5tU/Lbw4PENvhOArWIzK0VZooR1r
         3e6On1tPtggHGG2WiW+u3k5T8n3GTHTL1Dc07V7AAkl0gAw1NmRnZ6gGs4cfra52Qcut
         unJ8UW7vamehP6Kgj357dmxUfLrNlg7RhYHK1pb/6Wqy+De4qxHVU4xTVEENb4+RbVPn
         kfVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QByLYebl;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-864aa407dc3si45020839f.4.2025.05.06.07.34.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 May 2025 07:34:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 546BfhC0014212;
	Tue, 6 May 2025 14:34:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46f5fw3s04-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 14:34:37 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 546E5We6004309;
	Tue, 6 May 2025 14:34:37 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46f5fw3ryy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 14:34:37 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 546CJO7F004253;
	Tue, 6 May 2025 14:34:36 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46fjb20j01-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 14:34:36 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 546EYYPC31326568
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 6 May 2025 14:34:34 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5DF5120065;
	Tue,  6 May 2025 14:34:34 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 41CE42004E;
	Tue,  6 May 2025 14:34:34 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  6 May 2025 14:34:34 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id F0FE2E09BA; Tue, 06 May 2025 16:34:33 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v4 1/1] kasan: Avoid sleepable page allocation from atomic context
Date: Tue,  6 May 2025 16:34:33 +0200
Message-ID: <7d43dec252e2c7e62cfb3e2e28569de8b86cb3e5.1746541531.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1746541531.git.agordeev@linux.ibm.com>
References: <cover.1746541531.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA2MDEzNiBTYWx0ZWRfX/zjZLngcZ6US kotPbBA2uY2erVGlovHf5GUu/TbwDOrQ6eFisROStP5OrixZORB2FiEAOb5f1XCd2fNc0CEjdbb hiLTv0bj6xy94UklVcsa4gm2P/eWOMVFu1poGG/XyCvI2cT1nsK8oHs8vEbVq+FaUor+C0qKcxt
 I7kWwQ6SgelZzPCySaFkBdYPEzjrWRh1A7d/PSEaCdH99/+/c3fm4ZtDc4BBSAaUtsh+IroouVJ hsugKElxXlqstgywgRR1s9cGCTb0bcMk149GiOSALcCJVeluhfrG3Kxury1E9lk2odDuUBwutF+ HtAPDDanMRMGsGNxfcE2gw3tlb7/pN0dno9SB5becVYD8BiQ2pu1R4LHtDDf3QayS/DgjxqOWb3
 Hm3k34zWiwAFwjXXcrV/4xzYToczLrkpZ5oik8/mbOe8wN6gbwiAZ2Rb+gXv4LNcLmDhcI7I
X-Proofpoint-ORIG-GUID: DNGHTKrGEiaGUDmykMvplCGYLuuAbheV
X-Proofpoint-GUID: WgPURwJLc5LYo0Q9X8XE4AgpNAql123R
X-Authority-Analysis: v=2.4 cv=IaaHWXqa c=1 sm=1 tr=0 ts=681a1dfd cx=c_pps a=3Bg1Hr4SwmMryq2xdFQyZA==:117 a=3Bg1Hr4SwmMryq2xdFQyZA==:17 a=dt9VzEwgFbYA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=5xA_3oZvIydUEubUgb0A:9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-06_06,2025-05-05_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 adultscore=0
 bulkscore=0 malwarescore=0 lowpriorityscore=0 mlxscore=0 clxscore=1015
 suspectscore=0 spamscore=0 priorityscore=1501 impostorscore=0
 mlxlogscore=456 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505060136
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=QByLYebl;       spf=pass (google.com:
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

    [  553.332108] preempt_count: 1, expected: 0
    [  553.332117] no locks held by multipathd/2116.
    [  553.332128] CPU: 24 PID: 2116 Comm: multipathd Kdump: loaded Tainted:
    [  553.332139] Hardware name: IBM 3931 A01 701 (LPAR)
    [  553.332146] Call Trace:
    [  553.332152]  [<00000000158de23a>] dump_stack_lvl+0xfa/0x150
    [  553.332167]  [<0000000013e10d12>] __might_resched+0x57a/0x5e8
    [  553.332178]  [<00000000144eb6c2>] __alloc_pages+0x2ba/0x7c0
    [  553.332189]  [<00000000144d5cdc>] __get_free_pages+0x2c/0x88
    [  553.332198]  [<00000000145663f6>] kasan_populate_vmalloc_pte+0x4e/0x110
    [  553.332207]  [<000000001447625c>] apply_to_pte_range+0x164/0x3c8
    [  553.332218]  [<000000001448125a>] apply_to_pmd_range+0xda/0x318
    [  553.332226]  [<000000001448181c>] __apply_to_page_range+0x384/0x768
    [  553.332233]  [<0000000014481c28>] apply_to_page_range+0x28/0x38
    [  553.332241]  [<00000000145665da>] kasan_populate_vmalloc+0x82/0x98
    [  553.332249]  [<00000000144c88d0>] alloc_vmap_area+0x590/0x1c90
    [  553.332257]  [<00000000144ca108>] __get_vm_area_node.constprop.0+0x138/0x260
    [  553.332265]  [<00000000144d17fc>] __vmalloc_node_range+0x134/0x360
    [  553.332274]  [<0000000013d5dbf2>] alloc_thread_stack_node+0x112/0x378
    [  553.332284]  [<0000000013d62726>] dup_task_struct+0x66/0x430
    [  553.332293]  [<0000000013d63962>] copy_process+0x432/0x4b80
    [  553.332302]  [<0000000013d68300>] kernel_clone+0xf0/0x7d0
    [  553.332311]  [<0000000013d68bd6>] __do_sys_clone+0xae/0xc8
    [  553.332400]  [<0000000013d68dee>] __s390x_sys_clone+0xd6/0x118
    [  553.332410]  [<0000000013c9d34c>] do_syscall+0x22c/0x328
    [  553.332419]  [<00000000158e7366>] __do_syscall+0xce/0xf0
    [  553.332428]  [<0000000015913260>] system_call+0x70/0x98

Instead of allocating single pages per-PTE, bulk-allocate the
shadow memory prior to applying kasan_populate_vmalloc_pte()
callback on a page range.

Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: stable@vger.kernel.org
Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 63 +++++++++++++++++++++++++++++++++++------------
 1 file changed, 47 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..fac521b8a7e1 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -292,30 +292,63 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,
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
 
 	if (likely(!pte_none(ptep_get(ptep))))
 		return 0;
 
-	page = __get_free_page(GFP_KERNEL);
-	if (!page)
-		return -ENOMEM;
-
-	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
-	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
+	page = data->pages[PFN_DOWN(addr - data->start)];
+	__memset(page_to_virt(page), KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	pte = pfn_pte(page_to_pfn(page), PAGE_KERNEL);
 
 	spin_lock(&init_mm.page_table_lock);
-	if (likely(pte_none(ptep_get(ptep)))) {
+	if (likely(pte_none(ptep_get(ptep))))
 		set_pte_at(&init_mm, addr, ptep, pte);
-		page = 0;
-	}
 	spin_unlock(&init_mm.page_table_lock);
-	if (page)
-		free_page(page);
+
+	return 0;
+}
+
+static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
+{
+	unsigned long nr_pages, nr_total = PFN_UP(end - start);
+	struct vmalloc_populate_data data;
+	int ret;
+
+	data.pages = (struct page **)__get_free_page(GFP_KERNEL);
+	if (!data.pages)
+		return -ENOMEM;
+
+	while (nr_total) {
+		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
+		__memset(data.pages, 0, nr_pages * sizeof(data.pages[0]));
+		if (nr_pages != alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages)) {
+			free_page((unsigned long)data.pages);
+			return -ENOMEM;
+		}
+
+		data.start = start;
+		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
+					  kasan_populate_vmalloc_pte, &data);
+		if (ret)
+			return ret;
+
+		start += nr_pages * PAGE_SIZE;
+		nr_total -= nr_pages;
+	}
+
+	free_page((unsigned long)data.pages);
+
 	return 0;
 }
 
@@ -348,9 +381,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7d43dec252e2c7e62cfb3e2e28569de8b86cb3e5.1746541531.git.agordeev%40linux.ibm.com.
