Return-Path: <kasan-dev+bncBCVZXJXP4MDBBQVV367QMGQENRRL5SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C268EA846D5
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 16:50:45 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-7271d7436acsf1318013a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 07:50:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744296644; cv=pass;
        d=google.com; s=arc-20240605;
        b=LIKo8IXhEvYLIhx2L4rV9Gc/3Zog6hycg6pqnh6bz8f/3s4gNZ+PULCrA/+j0cQ5i5
         AZndZDkv6Pfe4ha2DnJMolwzOE7oBsmg4+Q31wle0yGH9bxGLmZfFeBVEo7a8GapV38o
         zUizmWVIEygIsPwLQFW4XIruSVPnHD7JXuBZIqPCvaMnAz0H3UY5vCdAR1EzNMBqPG1D
         m9rXNfsO2lzpj4k4RfNnE6FrsdHPyL/22uiXeaT3IsIO7uKb+lkUJ/baFzHTf+46vXUG
         ZHAWi8bAlBqA0xLypx3UOh5usdg09rqp6eYI3nGVKPs/et/8LjMHfs7BcIuw2JIQkVer
         lTog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=aXEg7avnpyFPDuACv3lrw1eOwEku2qbCBT7o7cJ5AxE=;
        fh=dZvB8A2wJfhUgJPCTnQ4uy7+/ST5IZPKVg4F0Kkd8Ms=;
        b=Y2WPaf9drLElBwYHfYUamH1LuSUajVJ9gBCox8yQs7ZWHzBSiUJFHMl/GdnjJrdY/w
         Nf6hU+T1XKX+ksOUHjAsv+QWvnpNfgjJbeiwaw2ParSUPR9V8fk+rC9Ql5GDq6FSlish
         +5MwkE4/3r9E9SqixBicV1oa9Q3LIhuQouJh19Ac0K0okcv0/Y0fzoU7Y8Ppqjv9sQff
         N8Fc5tAq1vev2zoTxu5xFBV55b/gkTVtCTcX0/5GSWGA6GTa0DKj2LKCKkK006iq7uyV
         UfWUzxYXXJXwqxvcPewIByFdF1PHwYgibVY/xnEu12Xr3TD3molC68zsBEnUHZ96ssCT
         bQeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GHSeuzsU;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744296644; x=1744901444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aXEg7avnpyFPDuACv3lrw1eOwEku2qbCBT7o7cJ5AxE=;
        b=bz2RPAcEPC/BEw0UZv15wKCX0ml9sIl0LDG2KJR9FG18alTYs9hyTHzKSx64YtcB91
         Sw8WNPyaT+srcx09PYefKP98UevrCFT+MNe/K9tjUQ2Y9nVw+XOuvn3aHH6+uN53+GYB
         ttHy9e1UPlmiykK4zLXca7anr4pymXZnejGTwAIsjs7cOb879KJfsSCRSMD6hq2QDCdN
         LwT7liQmE32FIj56wGXhjtLcn1xHxhzTd3sYlF4Z10ufzf+AsCQ6WEoBbqMk0OYuPZ5i
         Iy3P66IbNAEBsKPIw2R+Og1gYjN34TMR3fhZ0+PV55tMffpUZUunwJNNBW2LUOS+G7/s
         XmyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744296644; x=1744901444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aXEg7avnpyFPDuACv3lrw1eOwEku2qbCBT7o7cJ5AxE=;
        b=RYqEM7njRj2viRX+BXeoNHi54SJdghSlkfYvSFAfH+4jHiZKYXNLD9lK/rprgmi3DQ
         rPYRwsPgZvRjEhtRXRhOxEnsblZAr46gxasiqOlD18EzhkxuBKU/bmaaclsF+48QOz+5
         HaJUxT6q0xQeNjM5GO9jRdaZ3PRkLoxFmv6rOpf+rRMnM1JwIn+uHPjA1oo/XlT8LdxT
         TUYK2bd1v36Frr8okyYFrt4kzUP1va2ScsSo2zm5CwBcqAxEYlD4ZVt0uHAXrsixWEbs
         UAe3x/8MFYe9tfWbTATLspItUNE1VXlP1iLwFWxMTCGnwLq8S/Q46MjTjZg/tWlFOhSL
         w4ow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV03oVqAnOtHO0o3oP1HgWAU35QDNuo/s9eYHjjDmwbOkvhcaOKXI09XZmdmlaireQi3bha3A==@lfdr.de
X-Gm-Message-State: AOJu0YyLRsZMAji5dBa9wa5oofZ/VyTdp7/WJQpO170Ph+tzcGDodotu
	3UzM4O+vlzwSSvgi6DxVzUTxvTYROhINZ/fVbtH9+adVYRD/ux+t
X-Google-Smtp-Source: AGHT+IGJ+6GsXPqCb4+lUtQ8pKacaR+VGGabS7B5HsmUFC4qrnk1QM2H52YlC95++oC3gboiI+6L1g==
X-Received: by 2002:a05:6830:6005:b0:72b:9d5e:9465 with SMTP id 46e09a7af769-72e7cd7cc3dmr1667679a34.13.1744296642901;
        Thu, 10 Apr 2025 07:50:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALVqc5NUVEWrfPkEsaK8sNhAdNdzD4t36EglR0eJDnIHw==
Received: by 2002:a05:6870:1592:b0:29f:aff3:65c8 with SMTP id
 586e51a60fabf-2d0ae086710ls577478fac.2.-pod-prod-08-us; Thu, 10 Apr 2025
 07:50:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+ZQXsq/cgtxxmKLj2lp2fLO3Yw9RN38QPrqnreRR4q1ydkOItzFMDikJ8WEL1Ox5Pna14zGhoKTw=@googlegroups.com
X-Received: by 2002:a05:6871:4088:b0:2c2:371a:2b4e with SMTP id 586e51a60fabf-2d0b5e18bf8mr1632965fac.32.1744296639699;
        Thu, 10 Apr 2025 07:50:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744296639; cv=none;
        d=google.com; s=arc-20240605;
        b=Q5ukz94uWpMvvA/mi7BYvAR/AYJ43C19eYg+489LmsJO/yfNSnRO7EYeqcUly1otCD
         zGIJQI/gKVsjSyygp8pbb5osUocD7wSnROYyhbeMsoASlTqZXbuCeAttZ4eiQZ9pH9Vo
         FiwcpsGfK3OjsObG6xPJGRqjaGlMK+XkLMzLziv3HH/Wf5x1Lc/tVEA1zuzHsQlC0jrd
         4Ayr7AX0F2vodMHwORG5qDi1ILYkNQe5p9995hjXaaBb716wSBBJogGsHoywAcs/e9KD
         skC0arTmUqsaeiiEU0qRK5sUefVZAC0Fa8CWLCfq8WCbti7eymk/dxmqerfqFb3AGmY8
         MINg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BYsGu8041TJKDiTwC4nSOTLKvk5gUh74iryFT/a8d94=;
        fh=Qpv0vZFsOkAl7OpmVhwpUC70zZ+oFSiffx6v4uyFrtA=;
        b=L+Ji7aLLdetnwGR3fQSKxfEd0dFlWH6U/nN64HoJzAKa6qa7zE16MZuHq45p8PJ0NY
         uBcgbUl8GEj8Zu2ceq172YX5YJ/qYQ7ruICN/5VM8eGnYt0bG9geFrbvxzWcIJYH3HiV
         G1ckd4gINHZr/ka5MXqnG7UTl1jjLmeZvMx3FrgqRAtNZ9p5UeJyxZO3Z4HZaVYzp/4U
         Ey+Qn/2rcLVaYej1xLObY8qxh+NIatwEUYY3qc0UrFhXTMkbwFo9eLwId9+5lPZ6pJHJ
         JPhym1o9ozM2Zxy0dQvr8g0vPA9ZXdeEeuUjD74ZhYwiuzqssttQ8STRwdRraRdz30NG
         PJtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GHSeuzsU;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2d096c6b128si86388fac.4.2025.04.10.07.50.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Apr 2025 07:50:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53AEQ4q4003967;
	Thu, 10 Apr 2025 14:50:38 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45x0405aj7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 10 Apr 2025 14:50:37 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 53AEfDgF001462;
	Thu, 10 Apr 2025 14:50:37 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45x0405aj4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 10 Apr 2025 14:50:37 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 53AC31SV024610;
	Thu, 10 Apr 2025 14:50:36 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 45ueutpp0w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 10 Apr 2025 14:50:36 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 53AEoYcK56623564
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 10 Apr 2025 14:50:34 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CFFC920043;
	Thu, 10 Apr 2025 14:50:34 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 772A620040;
	Thu, 10 Apr 2025 14:50:34 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 10 Apr 2025 14:50:34 +0000 (GMT)
Date: Thu, 10 Apr 2025 16:50:33 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH v2 3/3] mm: Protect kernel pgtables in
 apply_to_pte_range()
Message-ID: <Z/fauW5hDSt+ciwr@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1744128123.git.agordeev@linux.ibm.com>
 <ef8f6538b83b7fc3372602f90375348f9b4f3596.1744128123.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ef8f6538b83b7fc3372602f90375348f9b4f3596.1744128123.git.agordeev@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: qOyZ_qtfAnXBqjGgzKrxZe6XNJEPhu2V
X-Proofpoint-GUID: IFxT-UrSu4Mf43qBHxm909ZShflClWgF
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-10_03,2025-04-10_01,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0
 lowpriorityscore=0 clxscore=1015 malwarescore=0 spamscore=0 bulkscore=0
 impostorscore=0 priorityscore=1501 suspectscore=0 mlxlogscore=557
 phishscore=0 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504100105
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=GHSeuzsU;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
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

On Tue, Apr 08, 2025 at 06:07:32PM +0200, Alexander Gordeev wrote:

Hi Andrew,

> The lazy MMU mode can only be entered and left under the protection
> of the page table locks for all page tables which may be modified.

Heiko Carstens noticed that the above claim is not valid, since
v6.15-rc1 commit 691ee97e1a9d ("mm: fix lazy mmu docs and usage"),
which restates it to:

"In the general case, no lock is guaranteed to be held between entry and exit
of the lazy mode. So the implementation must assume preemption may be enabled"

That effectively invalidates this patch, so it needs to be dropped.

Patch 2 still could be fine, except -stable and Fixes tags and it does
not need to aim 6.15-rcX. Do you want me to repost it?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z/fauW5hDSt%2Bciwr%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
