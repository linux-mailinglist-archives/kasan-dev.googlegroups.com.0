Return-Path: <kasan-dev+bncBCVZXJXP4MDBB2EA5HBQMGQEY3VJBBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 99FD0B0A44E
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 14:39:06 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e8bc2708ac7sf3225935276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 05:39:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752842345; cv=pass;
        d=google.com; s=arc-20240605;
        b=iCuPNmRNhURDgQ2C3PVAy9U+uZHFG5gxBkhHuwTa8eTLV4H0lUnnDjGBMDcOUWLIBn
         gLX4kWcVnH7Luj6omMmsWTIHIaHL5FMZ3Ujk5br0idh4Cv4Tti2KBpR8T8V7cn1kyNEG
         T9y7QflMlBsgphwS8CB7Oo9+7tUhHIIuQAGf0yZZouyON7NRajtY/X6jvOQT4bKjcGyv
         fzqzWilPUnUVMX/rlg1cxhye9fJEmz0GHKIqpIYxbksXNbqhL49uIlf5Uo+MkXwqUKoa
         uOWwd5d0uL9I1jZKeo0iPISblt86es2xJfRa6hYEfGUaxrGJZeaYSlLEa/6BarydejbM
         q9fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PD2IPAkxn/VEToRYn0AJSjnedelQj+2UsKpiqkq21sA=;
        fh=5RBM4B0F0WrHYAGBwv1dRXW/AOIfr2tc7fBbUnW/CpI=;
        b=h/ZYztwsCkfH4hp0sS4XKoR8vU8SRTYkF6+/m8xk24F6nGDsCqhRl0wukkmP7aOntx
         HzK90z3TmdRVMfyuWun7tVYOzUwBgGp0nGXQ1ciqzPk9a5lzdVj4LrOTyQ10qy1AxSTn
         eMnNZiz9c025MhRlIbTYBQdig5KkCAuaXjO2R5awfhjBBv5a/m+IkuPl42/kC9P4WWD1
         P2utnNu7yQ4qdGM0Bm+eK44VfUAICHbJLtGRfGROnYH3c/O22Mys5ZtuwfjCLnHSq/H+
         aQdgtPg1FmDD8f6qasoc3gHFf4w5Mk9N9n46X3kA//r71wzqmQspVovidCUZxXQ0tlcz
         MBxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=orgTmoMa;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752842345; x=1753447145; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PD2IPAkxn/VEToRYn0AJSjnedelQj+2UsKpiqkq21sA=;
        b=BRgxoX1NeReKJuXvm/htyHfwAlGnZbRnUN6sLx30/8ou2vgcfXOFrfty/Zi5Fx814d
         z9HcN16XcCd9LterZuVMYMzz0JeUxyD1dzb79aghnVbNrNaM/bW6Z6TcSXfV9I3gb11C
         yc/K/G3/WYdlrTFa2Xpn917xwnN6HP0fdkElknIs1a3oKZVCAkPKatiRZtxPwj9zEXvc
         dCiinzPLC/R5ZrpIOZWTi5AbVkdahPcla9KIc2VGVZWreCZ2StQpkwhV+O5DOKoc0k0D
         CL+B6OGO9KWog+jcRn9Im5jec6uTMFM/5GbjyHegqTespw4gDuVjET+bOfOg6Xfy/LN5
         bGkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752842345; x=1753447145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PD2IPAkxn/VEToRYn0AJSjnedelQj+2UsKpiqkq21sA=;
        b=NVcpEURqXiPDNV0yOwLjL9Pgw1q8ddd0vGdOb9T9VTj14HqoKNWQNiPEnlyKyAFztj
         YcKTLWSRqSbusJ7lF4TRYiA97lasL3bDn4puvYBX9NgKGS0NVL6Xu4otecvN6vkgiMnC
         iY5bCg4cUYQRSs5REMxMRiIOdyxT5Z3Qmnilsu2Va9Rg8RW3fryxg0AbH6UnRYDNofQt
         jPGjMGVCUiV4a6jdhdFvb9xu/y+C4Kec5QI05Od8GcfbXdHa4DwCeXEDn/NNCqolFXoq
         YvstWUPnzcTgSZWBKGP1DOpuxGKf4ozAZjSOD/1UTvt/mh+0Qe4GdSPY9kJpa6FeW9Jy
         orpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6WKS9qUeXfOVfFx2M7grr80f12JkuOKqO9eF7wdgIt2JqkR6Qsz78VDocco7zdmRU3hh2mA==@lfdr.de
X-Gm-Message-State: AOJu0YzDH4N2Dxbd4BZ6+58JOvUMashIYl4o3xf4KsJwjvFXj3ivBawS
	Vvi52Kpd51yuFgpYA6U6QIU09o4njtPoFGny7Ke0KQ81yKpYnl+uFMUv
X-Google-Smtp-Source: AGHT+IH0gnGQXeovSWYQ95C7wX+PwEOBi65oRDjnBNduAzFCpbKJrMVSCGn7QqJV3HQ0ZacGkYO9MQ==
X-Received: by 2002:a05:6902:280a:b0:e84:3b85:2e0d with SMTP id 3f1490d57ef6-e8d7732f58amr3531164276.9.1752842345056;
        Fri, 18 Jul 2025 05:39:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcWY7b9cpx+JW7L+09PhXkGgbxiY6pnenVNm+HYi5YPNg==
Received: by 2002:a25:c07:0:b0:e8b:ccaa:ece3 with SMTP id 3f1490d57ef6-e8bccaaf1a0ls1266691276.2.-pod-prod-00-us-canary;
 Fri, 18 Jul 2025 05:39:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZpG5yarB3jgmf5f2Rf+rxfPWRulpintWGMs6F/hw/5ySQ4ZGoMvtCJbEHXvrk79JMPIlYR+DZA54=@googlegroups.com
X-Received: by 2002:a05:690c:768f:b0:712:c5f7:1f11 with SMTP id 00721157ae682-7194cee3cf7mr40485657b3.10.1752842344125;
        Fri, 18 Jul 2025 05:39:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752842344; cv=none;
        d=google.com; s=arc-20240605;
        b=UFsM4MALQl34VbHdg6hok3GR7VGzo+glpU4NzpzioSMToqDHoj7TVsgPfm01DJ35dA
         73BbUIjCHPGvMwTYMx/A9F9wyZi4WkYGGUu17wg4AAg93bLyoTnRz2sg4zO/Fv4dM+dA
         cQEZeOfoWl8YUbleGBUwEn3xzj+cDKcUYgNWCgbPmk4GL76sdURh8sg+HUsPs9kNLePO
         Kv1DqPLXCCt/sQWiaQzUhdAosxOriGtJipI6n/nCn6xAhMH5t+YU9AfTE8HQkn8mCF1U
         yZ6yOy0mfnAdB0FbMcfIVOK8ModZLIUUpGwJXErkE3UyP2EG4FK9Zg92TRYCUXeDmn4/
         CEgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YmvKp71r0T0UP05NQIIAnxid0d/8UHkXVDaZEj9a9Ow=;
        fh=guuIat1T0YbT7cNxCBN4i+yC/+npJB0DEKEXacYUZeQ=;
        b=X+hl297+18Dl2o04Hq23qJYCApmonMCwJ2dI+FY7enGiLD2tG6tq7srECA75oyvuPy
         QqJYKmQRozIj8JxPwMGacLWItU1ti6vPNrxxEmGPj/a3l+zSrxbAT/9I2tJuGKnnQDKq
         cIG9xNCqyQOxSlDOtowixZadmJZ5JET87F3rP9Pr1+HhIDtsMparwSMo1QI7dtABY2Xe
         15NaCwuiuoxraCTAfIGGWt3WuMHDNw9KLMJJNWp0b0+yPtlt9VDs9DhS4w07p/+xciYZ
         RUS68WRgnHlrSD5hMdn8KBixkwQvrpfysgzSQ/PgZJ00qdPsH6G5MZCxq1Z/APgT6ZH5
         hClQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=orgTmoMa;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8d7ca52aefsi37225276.0.2025.07.18.05.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Jul 2025 05:39:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 56I4x4dh032640;
	Fri, 18 Jul 2025 12:39:01 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47ue4uguyp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 18 Jul 2025 12:39:01 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 56ICQvHg004004;
	Fri, 18 Jul 2025 12:39:00 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47ue4uguyk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 18 Jul 2025 12:39:00 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 56IB1FqG021906;
	Fri, 18 Jul 2025 12:38:59 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 47v4r3gv3r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 18 Jul 2025 12:38:59 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 56ICcwn753281196
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 18 Jul 2025 12:38:58 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2046320043;
	Fri, 18 Jul 2025 12:38:58 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1EE6320040;
	Fri, 18 Jul 2025 12:38:57 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.87.132.117])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 18 Jul 2025 12:38:57 +0000 (GMT)
Date: Fri, 18 Jul 2025 14:38:55 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
        akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com,
        dvyukov@google.com, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
        linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
        linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
        linux-mm@kvack.org
Subject: Re: [PATCH v3 01/12] lib/kasan: introduce CONFIG_ARCH_DEFER_KASAN
 option
Message-ID: <d5c96fb8-84b2-46de-8f1f-db53d7ed7309-agordeev@linux.ibm.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-2-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250717142732.292822-2-snovitoll@gmail.com>
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=baBrUPPB c=1 sm=1 tr=0 ts=687a4065 cx=c_pps a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17 a=kj9zAlcOel0A:10 a=Wb1JkmetP80A:10 a=VwQbUJbxAAAA:8 a=pGLkceISAAAA:8 a=VnNF1IyMAAAA:8 a=rZjtdVduxoVio5-WNGsA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: TIZuJKi-67oCtWCVyBaOzGkgvN5R-ziL
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNzE4MDA5NSBTYWx0ZWRfX9lurX+WMoby6 8zcw73eBKusO/lI+fsmCswX0W79oAVCdmpWWb4RuL1URCtCPr4UEgtPltbmXzVNehUUi+T6eXmX 4eRfKFVrYpQ27eew83zzkR+KyuIm1pQkr4MRD/AMDdQizk/b9vGMDa1q1wFOSHN5j5u9CnlZbL9
 PESfid7SFSM0zgNdAzD4h3+2AH7N3meARpmGt4UYroHp52sEdyKNpU1m+lbZRTrhHRUqCkTR4mP XWoRcVftiHuDpvOuX3q6S+bAsHfKZ6bUJr9scbjn8qAF/4vinEoTry9C4Lmi2gT7K9g7WEn0Shd IiPx1DI0r79VdBlpJzSfqa6yL5WUqhVubuUr7+O86v5JQgeMPPDFrMF1/F8Kp0Nr1jlKGElFa6Z
 y0z4sKH9jyuS5QG1lBc3a5pv6JbP4TtcPkaYW48k52mMSRsuFypEQKvGct4XoCyYnk4yLR6k
X-Proofpoint-ORIG-GUID: peX60BBMnw2ocO_Fy1XuuKvylFqoptJa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-07-18_02,2025-07-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 mlxlogscore=820
 suspectscore=0 adultscore=0 impostorscore=0 phishscore=0
 lowpriorityscore=0 priorityscore=1501 clxscore=1015 mlxscore=0
 malwarescore=0 spamscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505280000
 definitions=main-2507180095
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=orgTmoMa;       spf=pass (google.com:
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

On Thu, Jul 17, 2025 at 07:27:21PM +0500, Sabyrzhan Tasbolatov wrote:
> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
> to defer KASAN initialization until shadow memory is properly set up.
> 
> Some architectures (like PowerPC with radix MMU) need to set up their
> shadow memory mappings before KASAN can be safely enabled, while others
> (like s390, x86, arm) can enable KASAN much earlier or even from the
> beginning.
> 
> This option allows us to:
> 1. Use static keys only where needed (avoiding overhead)
> 2. Use compile-time constants for arch that don't need runtime checks
> 3. Maintain optimal performance for both scenarios
> 
> Architectures that need deferred KASAN should select this option.
> Architectures that can enable KASAN early will get compile-time
> optimizations instead of runtime checks.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> Changes in v3:
> - Introduced CONFIG_ARCH_DEFER_KASAN to control static key usage
> ---
>  lib/Kconfig.kasan | 8 ++++++++
>  1 file changed, 8 insertions(+)

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com> # s390

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d5c96fb8-84b2-46de-8f1f-db53d7ed7309-agordeev%40linux.ibm.com.
