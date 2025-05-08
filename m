Return-Path: <kasan-dev+bncBCVZXJXP4MDBBLH36LAAMGQELA23NRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 11BD9AAFCBB
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 16:20:31 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-30c21be92dbsf551286a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 07:20:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746714029; cv=pass;
        d=google.com; s=arc-20240605;
        b=bGMX3DPRohiQtTeeBGIr2rvrJaDM3JZ2TK2Jdvt8qrEjOi66tXCDOJ/1E+OgmqDmuk
         i1FePdDsfoaqCR4ldDsoe8n3YuUIoOSkCdNOYpjPi9HbWpeqmXjL1A6M5Fz1KNkc5+v0
         yZmH9nF1JKxonuj+2czI+0wyUU7O5WG8oOWfqLqAvY/iLw9bjf9H7AvSVYTkHPeTtXz0
         3rCsgiq7r4DOIxCgI1sxht2cnmBWiQQLE6i6nTgRk9avQrS3S4TYjDESi/MyvWqZXXWv
         qOpjQO2zopiMHzo0Dw/Iom4AI7Q3HJw0CZxkp7RWNCd+rFojFKeeGkVItK+/fWv4v4Su
         zfRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8kKXteUseXntyfcaulHSChAqUQbEJm0lxx/Wb/bcGkU=;
        fh=XDfh1S/5TciAWWHhtvA3HRScHPf2H0RSdnY+fzN9PyM=;
        b=A24HUN66Wg0OeC8zVQyNfg+qWZ/fARvJFS7aFkzr62S8tUsDyOKaCmFl2elUu97w2c
         jGYkLoHTVwucoxgRTRPL3OSu/u3RuP4aK5i+WeRi/8ssRgPf+/2il7B/xA2sa8WeJvIJ
         vgYwe/NRG2TqVfMUEOOL2OGlsWORGzmRqbLUalQeLKMK6Dr0NqblNpk/5lDJV1ZZA2zn
         zIXia4ZTrZYFDbxfYhW7Hffzb3c0uNbaeXShbiiTnQzlcFm9CeO6v4CvDladdtR/EBDn
         CMR15Cj4dG2mM52dKTrG71zWA1Lc6VSd5oU6KsNPrgCwEQM+OvVwRCFoRbjEeLCDv58K
         PffA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ahmO8JKY;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746714029; x=1747318829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8kKXteUseXntyfcaulHSChAqUQbEJm0lxx/Wb/bcGkU=;
        b=mRgOQL5T23pgXIETzSZu9X+ncJJ3tXFdDdBVWZrMNpf6ukLEmQXOQTtt1ONAjJHUru
         I82ZHjwheQgrcc5XPAiiGVerMMWQPGd8jL7SQ9KX9OCBxsoAospdDI1A0xP9MtZz07pv
         oMoKEABKp9DLT+6AoXs5thfRxk9hAayOkv+Kv9Tfe2Ar7WC98dv00dxqiHi3/Us8cg77
         mpX/Wyoyd3JrHzMNoeFpf4WiKdN94HHFH7tnm2BWxNWYbaPy+PYkN2kyknpaQtojsjrc
         EATTzvGHDhhXfM2Jg/H9g05N9s0Z71SdtpKRCeVG/mTqk0hxwr3wrEp/8W5PqVaw1mqu
         Td6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746714029; x=1747318829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8kKXteUseXntyfcaulHSChAqUQbEJm0lxx/Wb/bcGkU=;
        b=wh4nQcNHwkMPWM9mkE4qvFIs1bqu4sSpFdBETVTYjkhGO3TS4e4hzy59HxnbkdOjBN
         BrPFoLyN9Lsv0ENYuVx3ok5LQywpGUF6tIwjsZe2mAIoQHd1lC7BGn8KcoSds/nTa8sz
         TZVQu+muk8BqQGovzJGOxsQvLoQZ9qinpN8dulWMCeTCzXzU5JYkC+Kjl8SUlbVfBc6x
         vJ76iRc/ioi5RSdEvRpecifStZZS0GEfQmKn9rn2XVE+vlqAPBykj031D4ahO9PCGlZP
         2SuRNr0MMQIwh4kpBpSxSzcBVOd+Blp3pYIK/yNFTMsgowMGXjFXf3hkgNKCK9oND1Hf
         1zPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDEh26RK01OXiQgXkdJNEeZosqxRN0nLbF6WCDFRK0ZMwD7HJ6CGUKix4f7GHjPwWB15Dn2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy0/wLjKCK6LZgNwHrJ74FN8aj0jZftwZH4A+IQ9ARSL3y9c1X5
	OijvLUEvMu2hOS9BycyTo3z5zpCUs+fL4FbBodTqyPk5YOKw6sEp
X-Google-Smtp-Source: AGHT+IGSyDfZ9DyyFUkIdNuSv2FmUwOEbO0uQuyUs4FAj/JIVJP24Jmuj8ywCqRUwnWDJYnk1BD58A==
X-Received: by 2002:a17:90b:4ec5:b0:2ef:ad48:7175 with SMTP id 98e67ed59e1d1-30adbf6cf87mr5519549a91.15.1746714029149;
        Thu, 08 May 2025 07:20:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHt60jid/Gf64gGc9/wfinzrLwRNugkNVYBryHadZFJUw==
Received: by 2002:a17:90b:1d92:b0:2fc:a92c:4249 with SMTP id
 98e67ed59e1d1-30aac21f4c7ls1552587a91.0.-pod-prod-00-us-canary; Thu, 08 May
 2025 07:20:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSxsvuMlHWvG6urDIDJoVUCGcM7lc8ztcE+o5G0NGhKOZKlCW9g5puwdC3G428UTb+d1qntFdG4WI=@googlegroups.com
X-Received: by 2002:a17:902:cf0f:b0:220:fe36:650c with SMTP id d9443c01a7336-22e84770c66mr64282245ad.23.1746714027561;
        Thu, 08 May 2025 07:20:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746714027; cv=none;
        d=google.com; s=arc-20240605;
        b=kPHw4d5/tuR+gHtLVbaqFm0IZhMJPafXwJDOvGReKc3spLlJ+tYvn/Nc+zQM4ZKLTh
         qiFcs8mk/Lw8n4Yx8lcNJiMx2l5wWHZ1DgKY5qU0zcdy/Sd0gmbwPq9P7Lpvs2x8zbbu
         I0CaY8kQeUEVtrNSegMOfT8XK8BsSXrQPzLXgU4b0aCF8Hne9qlpwKZ7OGM+1heWnBhd
         YL4ukbdlXi9iuUwxSXsL5O+g1HnSl36/Py1mp3U7/isdJwdMiS4JxxIHzs/lwA93qjOK
         EqaSbv6TWmtiU/NTpsbntfTV5z7lL6/0lTlE5Q7VcF1YaqIVqq23HMKp2m67S/eUE6bt
         gYUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oBsvYhNSfnnaJukBuPXgWSSmMLLdrgzw30jITZiQdG4=;
        fh=BVcVK7TGM5Z5p5IiYqSmWieTAXVTEQFeH/cXYqf7WJ4=;
        b=Dz7Ur4toKSFs25dgzHB/2KGxKvgqZOav19RsqAggA1mII2/IDc1yahZSAU+PIPHeWE
         1cpAIwM90wK2HAX1k1zBn6+0zePt/UgKkqNq+idA2oaluIv+KNNsZFyNmKMsSl5H5BGg
         6z9cJ89zyeU/u9DQ3dgrw6qluG9evB4ECE/ATICaG9eQ2y3mbz8Wqx9+xWYkeepAy4w6
         WgN8K0mPJiX8qMt3HAZiwwvn+7ZULide4sMw+JLTyOGM1TtdeVgTA9V72vc0GQnuJpML
         Ri59QJf1/XScIGYKCWSUiwW7FZR540AQ+pp9Fw+z2UAdLvV9JswuGYIzlvY95PKt4hh5
         Eeqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ahmO8JKY;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22e14f672acsi4898225ad.0.2025.05.08.07.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 May 2025 07:20:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5488t3A5000532;
	Thu, 8 May 2025 14:20:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46gf3kv4ra-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:20:25 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 548EKHbJ015305;
	Thu, 8 May 2025 14:20:24 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46gf3kv4r8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:20:24 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 548AWdIk014167;
	Thu, 8 May 2025 14:20:23 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 46dypkwwds-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:20:23 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 548EKMqU19464472
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 8 May 2025 14:20:22 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1DBE020049;
	Thu,  8 May 2025 14:20:22 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DE59920040;
	Thu,  8 May 2025 14:20:21 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu,  8 May 2025 14:20:21 +0000 (GMT)
Date: Thu, 8 May 2025 16:20:20 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Daniel Axtens <dja@axtens.net>,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH v5 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aBy9pJdTyzBgOjSE@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1746604607.git.agordeev@linux.ibm.com>
 <0388739e3a8aacdf9b9f7b11d5522b7934aea196.1746604607.git.agordeev@linux.ibm.com>
 <20250507170554.53a29e42d3edda8a9f072334@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250507170554.53a29e42d3edda8a9f072334@linux-foundation.org>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: -h_qaOlO55CQud-hrKmm4MIkNdoM9j99
X-Proofpoint-GUID: gcKNb_I5z1L24ObaFP9ozqtSONUBoIu-
X-Authority-Analysis: v=2.4 cv=S/rZwJsP c=1 sm=1 tr=0 ts=681cbda9 cx=c_pps a=AfN7/Ok6k8XGzOShvHwTGQ==:117 a=AfN7/Ok6k8XGzOShvHwTGQ==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=7KtnEDDS5azdv5-FDD4A:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA4MDEyMCBTYWx0ZWRfX5oNAmmUKn7st aBprH6+/8ICoXf2xtBa1OybNs5VHbsc1PgZiQQaXRxNpptOIGEebBmzUduBFL97Qn7WoBMKTN0b KgxCRv7P4hRcRhGcTSrdszynjtf3GvXmsc30SBjxIinhbWaPHb8bQswJANOFDKkrET6X8njm+mx
 W5w2sFtK++5/QhyNq2/sWV9UD/Y+JKGE7pqic4pQ5UR0sIooglrxbnck2WmnKiiFajLN5aRjgxx KAGWZy4Aske4EdnMGi7q4u0CRSzIb0BYZsCOqm1Sot9SiRS9bIpj9x+buaI5yYZWPXsj8BY0pCS UN7akEO1hWCHmc3iA6C6FWhkwm1xz1wxGLI07XiymUhszPHsJZHWoV8X+sPLdIhYnJfux4Y/1B+
 rbJcnUXxLMDR2+lzhUKkVzl31gyOAtq2y87uuBkdn1v/qlcxLmMMU7v+AGZ30dgS8g0p0sN6
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-08_05,2025-05-07_02,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 spamscore=0
 bulkscore=0 malwarescore=0 lowpriorityscore=0 mlxlogscore=723
 priorityscore=1501 impostorscore=0 suspectscore=0 phishscore=0
 clxscore=1015 mlxscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505080120
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ahmO8JKY;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

On Wed, May 07, 2025 at 05:05:54PM -0700, Andrew Morton wrote:
> Is this a crash, or a warning?  From the description I suspect it was a
> sleep-while-atomic warning?

Correct, that is a complaint printed by __might_resched()

> Can we please have the complete dmesg output?

I posted v6 with this output:

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

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBy9pJdTyzBgOjSE%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
