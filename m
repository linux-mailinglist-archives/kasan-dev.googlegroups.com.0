Return-Path: <kasan-dev+bncBCVZXJXP4MDBBVGN5DAAMGQEYGIT2SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id D137EAAC928
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 17:12:22 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-afd1e7f52f7sf3002347a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 06 May 2025 08:12:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746544341; cv=pass;
        d=google.com; s=arc-20240605;
        b=TilawBNxG0o2l200czlC4iQVQAiKcO2h8c6fQxH62S2hBahRKJQencxr7zL9K+Ynxa
         Q58cG4C5K4Jb7AiRJArU2QeMb8rDQmEic1KlbcIT093T5EPLwsBkr+em9qvDtTjX44U5
         VZVGQUrFZo8BWzH7lFxcezHe+hL8vYnyTf/SrwcgxJx+Pvwwtw7uSNyEl8k/8p6eWDqm
         w0tq1CunEn1wwC4MJbmfB4HzHhYusqDTeqyhzIwEZYaqVXjw+QbjJLlqX16dcYbN/Edy
         TYuQgoL780UtKoX5Wm7j0RjIcpuk4v9Ehm5maQ4vCvw6l4Ty9JnoN/MZA1V0yKc+ZeRO
         elRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=beW/YkrFKvYr7NgeRXqr8BJfybNmftuSXP7i/4IRwrU=;
        fh=Ltizbabs7qlXJqjVslj1wHYCZQVLjlSFoWV0BSaKCXo=;
        b=Xlo/7VECmtMQwFzV3bcUc2yZ9SPyK4fzsGUS+tNjODG1rGMapy0PazqGMQF61F0/FM
         NSRcQ2zKzpGXX49OSQVDNXUOoP10D7WM7CG1wFPyylC6aKq/fE1Af//qsECudWCHUUfb
         V/Op8v9xDUk0NkKqHMe4AGnZ1c2JeX7+WJPVhDVzQVeJv9eu6oxFXcdu1WV8au86IuEt
         JU1CDSKgggtG4KBZOwfS3dmSlD0Ht5CHKbBmJisegFDYfeeHppVWJiRvYFKJjk+rnull
         +jPnc+Imt79L4zNA+oZpTdPUqcHkeRo7wLLWIE0g6DhQB1eJCV0Kl49QwAHMAE9Yp4p6
         bGhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=f7ILB3WN;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746544341; x=1747149141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=beW/YkrFKvYr7NgeRXqr8BJfybNmftuSXP7i/4IRwrU=;
        b=dp1RqngDHlaQ031i8zxw6s4CK/S+xo1hUe8qfiVanss3GtmVoAt8H/xDzowObfrgMw
         Vadc56u7vIKcPN4lh9P+yFyq5ZoFFFKeyGb/DfCocAXy43u4QPHHAKBbeHRhIyOIlq1H
         Zu03T/4Uzv1AjvGcjxwWmyCsh373xY3UkspWsKZ3EUSQ+tdWpV5rC9sfDXyJLEWJjN7H
         Y9uazFEmmeaIh2rxfKj2dixjXPABkIxSPFsWJNveOzxj5gpj6PtuvCjWKQ9MXzyL5d7P
         ormIH9AqAp4GnIjGaSmbzjU2HbMML6+Xzbq1Nz0bJ047+8mSIdhhY7XdSh5twta6lqQc
         u+5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746544341; x=1747149141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=beW/YkrFKvYr7NgeRXqr8BJfybNmftuSXP7i/4IRwrU=;
        b=o5pNAxtM85Q27eNKLbZ9elP63ssivdeupZ39k4OQJrAu/g6joUKYamVtC9DfytrtoM
         5VlC5674spBQMMnLcTNr6n+EKGDPLv7/r8R0JuvgTJqWtk8ZTys4o/qiocCjjGIeLkMe
         ZtwdvxyyJuioTI6lG50EgW35BwjG0V5f5aphFSoDvIAVbBwIDSrlQvBxVfqZPFd+HiKJ
         eDYWniw9NcGn5E7qpHQvjNG7JqSbFtecqbkLqYBl4Gjg00Sn/ST6YdTZOKPMZE0ovQki
         XExRnL5y9Fgl91hovlcnpU/fazPAlEFFJ3VOO+4TK4QspxwueSz3iUNw9n6z8uw4Es5T
         55Mg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN1NcRTQVkkITkc8PxaDboO+U09tfEM3eXz055xR3pN95tC/KGoTPGm7MTIvnYISW4iv1qfQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywg+ABX4fxsLdcqIF57OGR8L59bPCxbawxqsfM8CwX0qrN6EAOZ
	JagXhMcIRkun5ml3g1ism9sf7JeTTEhQ6MVdBvnzyARrJmIYs4W8
X-Google-Smtp-Source: AGHT+IEXeFpDYmD9GBSiyk8s6q2BOj19YFg8QoA/YTU/ha2MEXBt4+a///2Qt1g+bnIrqLJc5Yi+ow==
X-Received: by 2002:a17:90b:4a06:b0:2ee:ed1c:e451 with SMTP id 98e67ed59e1d1-30a7c0a0472mr5486377a91.15.1746544340994;
        Tue, 06 May 2025 08:12:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG02R//qtEUXuIOL+ZlAQnab1XW0GOqFkUDv3zC3CUwcw==
Received: by 2002:a17:90a:de8b:b0:2ff:530b:43d9 with SMTP id
 98e67ed59e1d1-30a3e8a08ffls3541504a91.2.-pod-prod-05-us; Tue, 06 May 2025
 08:12:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+as6sQ2ypmEcek+MDk0X/rqngaeb9Y74LSnYz/snuTd71Q6q59Dj7FvKtqhrtPjXzsxyHir94BuA=@googlegroups.com
X-Received: by 2002:a17:90b:4a06:b0:2ee:ed1c:e451 with SMTP id 98e67ed59e1d1-30a7c0a0472mr5486207a91.15.1746544339214;
        Tue, 06 May 2025 08:12:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746544339; cv=none;
        d=google.com; s=arc-20240605;
        b=D1F7a3IfEKlcbpURAghT+8JaY0wy8r0LB/Ks0M4Ah7jNBStQcLQVfbMICRQzy2z5VA
         dVYXSx4z4KzsaJ6jeE6jA3fj4+yQyb5uCHLNO0nFMOsc16lCfZZhi1XawBYkbSwfN7HS
         xtx8TWp6DaRjeBkm6IIBMQmJfSYioUbfJNsEK7lPVab8c3MWjtOCpR4NscwZbT0NReWM
         FFWAIYSfk2FeJ9fLr3ckl3q8L2iBYz0wHhrN5hjNHrsPFDDvdh4bDh037nTjoH9a8zM3
         WGjtH1AmdgI5I97qM21bIAlc1C9ymaMX2ebEmd0ZhH0vNa0iugaU+MZLlDVVmxO0uOHl
         LSSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yrcWGN0FRR1RmFwO80UnVdv0ehhWHreiwjWlwco00OY=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=NTeMQxr3ivpznxjstFpkWooQPxgz70hYzHcQh5nwhbFJx3R6pI5BN89hUH/QYag9hG
         WBWZaMSkRj414B7zQ7vS889DHaLK7ok5UxOL/z/pIm3f9RJC9CrbvuDLJ44saOreqlYm
         MDEX8jo50SEAU5CAPZPJMmXZ2aEWvAPdAvYATnsyG4HwB8ZGtvM51soiYS7suoyxR0EX
         FxYEer6XjCE6RvwasuH7KnrKhprxsYET6plUHcVQu3ZbuL8E3zr7unCW2wQ8h6iyDq1Q
         hsWSDG2ALCAdLu6AUDcAd4U2Nw0qAOofsIocZ2oXAEYiQNpvNnU8eNb9y1BZyZGziIqf
         bP2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=f7ILB3WN;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22e1520b799si3632525ad.7.2025.05.06.08.12.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 May 2025 08:12:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 546A44ax010338;
	Tue, 6 May 2025 15:12:17 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fgbj9k71-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 15:12:17 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 546F9YA4027233;
	Tue, 6 May 2025 15:12:16 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fgbj9k6v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 15:12:16 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 546Clukk025798;
	Tue, 6 May 2025 15:12:15 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46dwuyv7vd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 15:12:15 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 546FCDAb51577334
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 6 May 2025 15:12:13 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 32AC120043;
	Tue,  6 May 2025 15:12:13 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id ED0A820040;
	Tue,  6 May 2025 15:12:12 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  6 May 2025 15:12:12 +0000 (GMT)
Date: Tue, 6 May 2025 17:12:11 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH v4 0/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aBomyzXY9LK9+B6B@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1746541531.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1746541531.git.agordeev@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: Flo7NbBOtUBXTZo_5Gpx1aOjUuybx3zX
X-Proofpoint-GUID: 69YYGADS6fH5-LuvTenpw2Dg75BsPUia
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA2MDE0NiBTYWx0ZWRfX/X6drwUxPPFI wPjp8DsQhNGJMfga0vYSpVzRYC936Loz+CkS8LmgXtCjGdpwTaTQgmK8nn/Lwhm25c58ldAcaTO NVVyKdh4YPYswJ90hhPJWq4y7kZ3qgOtmG5FBkOeK5yjLTPut7cRrgzAkmBwO1iKi8z7++DzsaH
 XnPE9ApE9NAGkG4hj8VW+xj+jWWYczMGC8LtDryXpSrs74qdxiIohE1swH6ehzte4nCNoux2OGs tPrLI33d4xDfsu9Vte+IBZzObJrqvlGlSK9MpzJP+P6wbbfy4v2H2pWbctrI79YhRFpiZOJKB9s APsv7zqH/cHbn0agWiQh9jXdWVippB0lh2QywrZpY/AYZrSRNn0frtpsJ7pRPzHLZZPnuiVjSJ7
 g6/T9zzOsgB/q2g69FQazs2MIn75IM+hkyTIXce/jFSSYO4gQ+B4zn6IoqTYg/aq/LM5l31k
X-Authority-Analysis: v=2.4 cv=FJcbx/os c=1 sm=1 tr=0 ts=681a26d1 cx=c_pps a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=yOTKoNjM66L08_-4LxgA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-06_07,2025-05-05_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 mlxlogscore=401 phishscore=0 impostorscore=0 suspectscore=0 mlxscore=0
 malwarescore=0 lowpriorityscore=0 clxscore=1015 bulkscore=0 adultscore=0
 spamscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505060146
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=f7ILB3WN;       spf=pass (google.com:
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

On Tue, May 06, 2025 at 04:34:32PM +0200, Alexander Gordeev wrote:

Self-NACK based on comments to v3.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBomyzXY9LK9%2BB6B%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
