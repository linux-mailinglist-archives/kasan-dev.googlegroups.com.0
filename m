Return-Path: <kasan-dev+bncBCVZXJXP4MDBBQWC367QMGQEM2T7JVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D835A84798
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 17:18:28 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6ead629f6c6sf14658886d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 08:18:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744298307; cv=pass;
        d=google.com; s=arc-20240605;
        b=cyXZl4eso83Pqz59eP1cSXRABJxhNFOzfreMrxqm9eIuH6rfWTjk/GShNLJSRdh6cX
         3sv+uWB8kvVVJ3fJ4AChSe7jAhdbV5FJdwDG/4GRVw8QtlUaSfoXM8kxMHkC9hFbksjI
         5qcUiZgJ/9ELb2skX9+yhOIjIvQNHsChpTmaPmeU6GFMBt/0vXiT7bfZHuMZEyNBA8k0
         3uebdz+k1wmk37o23h8rR6qnJk0UIrT4I1XZ2nMlC3XoCqg8/SrKQc91vidG05GfKyCT
         fBfPSGOjUlViLlnPB93mFum4E2kShocXvPs4Ww0awfVfQ30KwQmRQ+wvOCNl99iSsXAB
         Q2og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YDdMmQB1uRq9/59RRJWCF2tkeCx0XP1mHUJW7Jqv4xU=;
        fh=i8C8JXJYtWVldxzaXaTueWZD/4vDBpawzKxqvJCQFxw=;
        b=EmIHvGuVg1ZaMDWZjBKS10KPTq6tHtiI9qSK3FHoNs36HFH5bPYgF6ep++rvEXKhFb
         wQzn32FhJLk60cIRTjjCYNGQdlQkBC4hFPSme3IYxCqys7hyyVu7HruYCbHs1vgbnykb
         WdRPvX/zMN84NEdkTPMmyu7NQA1Gc6saievkbWjNy8jUo1yFBFPXbqMShWiU3saD8i3R
         lmiZC+7ITwow3i+ubys1qNHELRR00EGlItEHBZAIJSSv4qJFHW2je34yYq4IXxQSgpE8
         AZsiZl2UWcnQzW4fVFsONzpN5AYGIOfuhLtukAg5lRrw6xSlSvTPiurxWCbRLblZ26F5
         gcqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="XFA2NdY/";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744298307; x=1744903107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YDdMmQB1uRq9/59RRJWCF2tkeCx0XP1mHUJW7Jqv4xU=;
        b=Gsk7cZ/HotpGb0xhTvbuv5UvqKIzvjvSjn5LeQNAEr3x6clPLil4fu1SvQJieNvswX
         Qoy/lCcVJ8Vbs8RkcZUXwrdpd7y4j2Q8kEd9HYXW8u+vkQHdlc+tJxfIbxWqp7qhn092
         HeKt/qDzj+PYUPDLtk99zPsGvs+y7GreNMNxLOsL8QTPi/azKqqQjUsrqDzCB3+0v+q1
         2CdVRdk2tu3S2lBEsqBASeNQky2VaqlGLVQ/OmtVSTqiv+QloQ/9Isfz9PHD4/fdqqAV
         Kih1BmqhVHgGtbyuWhZN9Vbl75tv8G3HDF+btekiYxtK6TeLkryOiUAc1C8ilyoO2W1I
         nB9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744298307; x=1744903107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YDdMmQB1uRq9/59RRJWCF2tkeCx0XP1mHUJW7Jqv4xU=;
        b=lg+pN/mr03hhxtS3y564DFFUmtij+XPpdQ+eR4GhLQkktvKKErMxO5NovVrXVdLyNI
         1jBOQtki/yGsRypg/5wdnrBBaPe+2omnnFnnML8lLkxm/qmAxzdY9w3RbNEH/4BQCtFp
         TFE8BIBy7y2SyGKhJVv8/6B5f4AoM75tt+pxr/P/unUb40ykcOU7hdh2daW0971WKRfH
         zrAf1JXRLXL0RyTw8buv3LiIAOBEZZrMW6pnxLcPcJFCmkBHproo1ACzp6aXLcVVaO7B
         +vcUtRHIoJBIVfml8GCkidGLPZ52YwduH0v072nQ6ARo3u2q4B+q7wMcHvc+sM97rypK
         rC7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5ONHKEpEl49VxICsHrgc1lmULkXPTvz8llDBzRYBXAFDqoPum13qlbmml5oY/WTTtZFiH8Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw74DDHmpNKZYiR/+2+SBWoQFZK0KqTIOLwQx8KvbDQMcnES2dy
	tkVznS2cNC0DKnpPbHO4HMibGS8jTgKUuzvGxm3I1p6ud2ELYC5d
X-Google-Smtp-Source: AGHT+IEnvx5j2vDlkot5PaQaa98eDah7arH03AgzNrMOQwUodBHsmPwmBQQ52YvuhQjZXLGZON/LPw==
X-Received: by 2002:a05:6214:490:b0:6eb:28e4:8518 with SMTP id 6a1803df08f44-6f0e77c0743mr28897616d6.34.1744298307131;
        Thu, 10 Apr 2025 08:18:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALXV5dWmvMvYsNAK5IYUQMFwVM7c9EUqLh+TsaLgfRcsQ==
Received: by 2002:a05:6214:5b01:b0:6e8:f47a:25ef with SMTP id
 6a1803df08f44-6f0e4aa5f7cls6547906d6.2.-pod-prod-07-us; Thu, 10 Apr 2025
 08:18:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdQy/SLdLFMesk1cFuPLGT8oKRGf3fMB1gZZbVE9hMuTUgDGhkDCZMpNIFtzn5f23i6BNhgNqKk6w=@googlegroups.com
X-Received: by 2002:a05:6122:2202:b0:520:61ee:c821 with SMTP id 71dfb90a1353d-527b76dba88mr1884040e0c.3.1744298305982;
        Thu, 10 Apr 2025 08:18:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744298305; cv=none;
        d=google.com; s=arc-20240605;
        b=jNOAqhQJC6inDreQrIpV3zAnOAV3F+j1bQ3Zp1eDKiL8IOQhqfqyKdq+9Gd1/Vkop9
         kpLe7gDemRCXYBg6eKgTvthDFSozzbwLNPdM2bO2thRvjZtepPT3IVnT5yMIvtbQbO2L
         Htn81Tb29PpR3w1ploLXU31xycsJzAJxgbVphXXWwy9ZsqyJtFes2SrPW95YpmKSOWic
         G6jBWMN6UYZkJ4FO9Ifc907INuLTnLcqCHrrLeV0TE34a5hBtY3zGi1Lmk/wHj5WNowm
         2jG0JNkoVjg8TJHgnunX+90LEQT41sZPPphYpsMGcJX2uHXlwczMULggPsbdy3iXUbQm
         tYaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8yZK2G8CEMH6GwaqesHa1lpHB+Zat5CGXDOr1+EXSC4=;
        fh=bEo5OLhD8AVrR85hCos+xysSMRcih59DHuvUjxRdZN8=;
        b=R68ybV2wSQZaOzYB9rMdlWUH7+p9S397v7Pjfllpetlp27BOtXrEUjcGyuZ0d4Q/P7
         yqRPx9/S/ydDAqOBjGxc+382MGCbLVyTH3pC36rdjhNhj1QM04alyx2DR7uvomor9Ni0
         9Hk5jxpFQUyv3H1DUsknTdx0t4QMJ/nU/Dm1Ablsv3wlMaHjRt3VynVJXjYVr6r68T14
         X114g7S3aLAzx5bMknQZS3gaDHfnyuV/PsFuTT4ogAe/s9sJqlZHuxVLSZOLk/eAJlbH
         oXokPBkzvLrHabLhOFuix+1MZtGVJT9ApYaVz9FYKWuZ2hcj3TjGbGQiQBmVCTBhSGk+
         s25g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="XFA2NdY/";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-527b709379fsi78407e0c.0.2025.04.10.08.18.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Apr 2025 08:18:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53AEK7vi022679;
	Thu, 10 Apr 2025 15:18:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45x02qdg47-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 10 Apr 2025 15:18:25 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 53AF8TYT001916;
	Thu, 10 Apr 2025 15:18:24 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45x02qdg44-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 10 Apr 2025 15:18:24 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 53AD96gI025537;
	Thu, 10 Apr 2025 15:18:24 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 45ugbm6hc3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 10 Apr 2025 15:18:23 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 53AFIMnK41025908
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 10 Apr 2025 15:18:22 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E809920043;
	Thu, 10 Apr 2025 15:18:21 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 95A3620040;
	Thu, 10 Apr 2025 15:18:21 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 10 Apr 2025 15:18:21 +0000 (GMT)
Date: Thu, 10 Apr 2025 17:18:20 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Andrew Morton <akpm@linux-foundation.org>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH v2 1/3] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <Z/fhPL5bH2A2Cs97@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1744128123.git.agordeev@linux.ibm.com>
 <2d9f4ac4528701b59d511a379a60107fa608ad30.1744128123.git.agordeev@linux.ibm.com>
 <3e245617-81a5-4ea3-843f-b86261cf8599@gmail.com>
 <Z/aDckdBFPfg2h/P@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
 <02d570de-001b-4622-b4c4-cfedf1b599a1@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <02d570de-001b-4622-b4c4-cfedf1b599a1@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: jHtw6lgVB7srP7G4ujZD7xCcxXdTfHSC
X-Proofpoint-ORIG-GUID: fFGj102REu_S4ew0_ixvtgn6rzege4GH
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-10_03,2025-04-10_01,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 impostorscore=0
 priorityscore=1501 mlxlogscore=961 lowpriorityscore=0 spamscore=0
 clxscore=1015 suspectscore=0 mlxscore=0 adultscore=0 bulkscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504100109
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="XFA2NdY/";       spf=pass
 (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass
 (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Wed, Apr 09, 2025 at 04:56:29PM +0200, Andrey Ryabinin wrote:

Hi Andrey,

...
> >>> -	page = __get_free_page(GFP_KERNEL);
> >>> +	page = __get_free_page(GFP_ATOMIC);
> >>>  	if (!page)
> >> I think a better way to fix this would be moving out allocation from atomic context. Allocate page prior
> >> to apply_to_page_range() call and pass it down to kasan_populate_vmalloc_pte().
> > I think the page address could be passed as the parameter to kasan_populate_vmalloc_pte().
> 
> We'll need to pass it as 'struct page **page' or maybe as pointer to some struct, e.g.:
> struct page_data {
>  struct page *page;
> };
...

Thanks for the hint! I will try to implement that, but will likely start
in two weeks, after I am back from vacation.

Not sure wether this version needs to be dropped.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z/fhPL5bH2A2Cs97%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
