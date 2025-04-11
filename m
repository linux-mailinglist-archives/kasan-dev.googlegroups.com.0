Return-Path: <kasan-dev+bncBCVZXJXP4MDBBY4K4S7QMGQE5AQVSCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4950A85C6C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 14:04:53 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-7040773fd79sf30303987b3.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 05:04:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744373092; cv=pass;
        d=google.com; s=arc-20240605;
        b=f3rhagRq7prTf43bvwnuIvTcDAwOyOyA0GZRUr7NsSw6+nxUYUpazpvM9vAxjCVS67
         ALMke0/4MRY6+GHcDa9LNSD/0R1qBK+zmcIaY1US8fmUubVdOOLMkfNrjjKZ3AvBGmdr
         OaI4YGf3d8Umx1lhg13hh3fgYIZmT624/lo7RV66pDhIZsb67mOf7RJgq0+/5Qz0uThq
         7LKq5aZJDR9+qcQqWJaKW/ZKjsGiSnmh6ANBs+T7BFfdl3TQZPm72QCipQjLGRXdf+g/
         C+SV+A0Wzx5DK2VwTK1dl1MqlFV7KUIKElvvCl3903U33ET43/ebt8ZJfXdskc6nn2Ec
         8+Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UbG+p0RFuieLKz+b8U/hDudp3XYBlctOLusR1n8YZPI=;
        fh=K9Q5R4Mmc7NOTaf8qZNTj25yiqALMNhAnaufwDlYKX8=;
        b=ItrcdLxSVrhYTVNMhb56TYZQTs0rqWYLkBihvMauc5k96089xOv+Um+eVuJHXuYTB+
         o6mKMq0ilXJZ8kVG941SJmVzboWaemNuSmpoRbcK3OBI3cRf6xRjEKzlS0Aug04XuJWe
         DKA1w9CtCnP9jL9GJmJj7G6YKPhc+Tq5ls4jkFQ2x2kdzO02BS5vCYQaQ0VpHm84jtaz
         4t58CqZrCS9on9PBN69k/6PYC6KZCZnMYIkFZkSdDofcysvHQ30+bdqOUmxE31a5r29f
         ZGu7sX7UhmMmu1zGcCdZ18oxkabhppwId1laz5UdmC1ItWpikgRtZlV6UrADEeiHwX8a
         lVww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rg6+7yX1;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744373092; x=1744977892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UbG+p0RFuieLKz+b8U/hDudp3XYBlctOLusR1n8YZPI=;
        b=c8NhZx4Lwx85vs5iAz/slTMIBGnxz3R+vO9MIeCzer7NlagsDhphQMFKVdgjVaf/+t
         u+HF7IYUBGQEDCSt4cEXKaLwAmnYPx5D5DioB/e2OUO4OXLn5NRPwfOPR/pjmgocT3RB
         ZWA77HZaROhqCUCwlEMbWVz0XJYJlevAZjLN1TvKY6W5INWzwttNoAUTziloHrx3AyYJ
         zVEqKq7Y36INHWv97+zS2YjnEKeZQYpfTACKs2epcj4wcC7HRteCojckFckFNy+Yr76+
         vZ2ovYwc6fH1cH8OTvVgARfFgXkWOUJLVIqj6TusbWblDEXg5qXDhpiZAVeSIhSBJKx6
         DGJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744373092; x=1744977892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UbG+p0RFuieLKz+b8U/hDudp3XYBlctOLusR1n8YZPI=;
        b=uZF4wYl5+RAgn5sbtShhKcCfFxqFfXM5S/k7+Z/V63MfBAGMTDkym6S7EPWI9iYn6V
         cNhhjSUhzJIa3OhvbY8+K80OB3ZAqEpZ0C78ppYv6maVtSK7EkANwPmx7SbPRWlAkM2k
         aLJNjKzvDWzO3uENKWLz2j4sCM6BYyEIYD5VlB2BTKuFDCoQYxRhKsFW5B54u2414EHO
         LEHg7n+/cCS8NYVJufqK869A/xFjm8fX0RF63ZvbAN9F8qWlnbDQeY1xr7+uyEuIm1zj
         BqZRr1GB4LFoO5osRvLHKQGoYCUEY8dH9BHEU6Q1oRu32/7Rsfe+upOTMtaTkVvTgAIm
         51Cw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWp+pdhHYsuVurkv4+utKksJbhmcxCCGYwsqQ0ech3cgocGSWDH+O5t+Bf1dg772/gD6A+3hw==@lfdr.de
X-Gm-Message-State: AOJu0YycJuJCiJol9aZWh6FU7h02EdcMm8/NjrD3+KgnAZY9e3s5E2LM
	aZzbnsc10xknQ9pRgJE1vRSRMUQVuO/wIeiWr7V+TV29UzMl354m
X-Google-Smtp-Source: AGHT+IFTdVqD24G0Hxhqp8Tx2y7GaL+Zd7WTR7lL6Vw63iSN3cavGP+ERsXEBO7YAedp0gy7xwWIVw==
X-Received: by 2002:a05:6902:2610:b0:e6e:4d8:81d9 with SMTP id 3f1490d57ef6-e704df24d21mr4066476276.9.1744373092100;
        Fri, 11 Apr 2025 05:04:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALHzcQafk1/kMnI2wVJcz4EcIq9RgC1mFOSRe0ajz7b7A==
Received: by 2002:a25:aaa5:0:b0:e60:873d:ae8f with SMTP id 3f1490d57ef6-e703c5fcafels543497276.2.-pod-prod-09-us;
 Fri, 11 Apr 2025 05:04:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcO3uq1Jxn8jWVTS/OtAEIAYDzMDS4/pu1f54Xq7bOLLbGvPSbYxBIBs4M+lf6DYBb/E4we/0lqG0=@googlegroups.com
X-Received: by 2002:a05:690c:6810:b0:6f6:cc1d:a6d with SMTP id 00721157ae682-705599ea148mr42990087b3.18.1744373090416;
        Fri, 11 Apr 2025 05:04:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744373090; cv=none;
        d=google.com; s=arc-20240605;
        b=OQEcR3FXafrAcl1qTTyHsQ7Ahp8VZvSKMnvplDGVP0DeHX5t1MMovmICMLBnUddQEu
         rExjBfsfBwzWeGH+POlFEylIUEeX9LVoIlTV4NWbw6uwoZ4egRrNKQaTzqRqhEpGXoPd
         7GeKNze6ikwRIAf4g1BG8vAjL8HZka8MRQlP2L3Zg32GVq9BxY6LhPWJ2lyM0v+o3oXI
         TEi50hmW7u7EdmRszpREwCh+qNqJV2lgNVC6MoYVSgWnUCRfPXkB90vEfsElDXaTMPg/
         3ofXEFZ+qYTEwv8y0Htb7GB6NkKne9kjf0O1/nsSXk940dCJDpKS8bNr+/4a040u8N7I
         NqeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PnqGyYgzHT0Sz+5k6BXWUk5N9daIOAt0miBGvgSDKAY=;
        fh=k7ZYnR6kzy6Q/UpH6eAB60S6YCOdOnTfXOTZM3ObKks=;
        b=Med1N4ZfLbDdDwo+eUAa3i3z1pdAet1cx7zpfTakwtBzrNm+7siGK7Q5eNj3es1MDZ
         nDqhiL2eJdPmZXWlS/DojUYJjjTfV/EWIbF9Y7usSOO/NWOfl7ssZAwjvGOmcVrNKpmO
         NTCusFerndtQV3PBgUDiKJn6eLBBS3gylJzcTtnMY40WhuVS6nRl0tmAsBgvE5lQtIYL
         myCpXaWRrH/YXDHT63h/XbLVAG1S2Sk9GWti0Y+kh5Hj3GhzAc/PR3e8A/ROsKnYhI2I
         +9pogOy3GJmC7n69fQphUtA2EOJ5ym58XpOENVxwoaxJDKbDBya8UwSPQIgRxjuNj4fM
         xJsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rg6+7yX1;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7053e21d7c4si530977b3.2.2025.04.11.05.04.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Apr 2025 05:04:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53B4Hwbv028306;
	Fri, 11 Apr 2025 12:04:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45xj5xmbq9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 11 Apr 2025 12:04:49 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 53BBvsIB009672;
	Fri, 11 Apr 2025 12:04:49 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45xj5xmbq7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 11 Apr 2025 12:04:49 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 53B8Brgm029520;
	Fri, 11 Apr 2025 12:04:48 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 45x1k78q3q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 11 Apr 2025 12:04:48 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 53BC4kR641484682
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 11 Apr 2025 12:04:46 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8519420043;
	Fri, 11 Apr 2025 12:04:46 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 975B920040;
	Fri, 11 Apr 2025 12:04:45 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.62.45])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 11 Apr 2025 12:04:45 +0000 (GMT)
Date: Fri, 11 Apr 2025 14:04:44 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Nicholas Piggin <npiggin@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Hugh Dickins <hughd@google.com>, Guenter Roeck <linux@roeck-us.net>,
        Juergen Gross <jgross@suse.com>, Jeremy Fitzhardinge <jeremy@goop.org>,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
        xen-devel@lists.xenproject.org, linuxppc-dev@lists.ozlabs.org,
        linux-s390@vger.kernel.org
Subject: Re: [PATCH v1 0/4] mm: Fix apply_to_pte_range() vs lazy MMU mode
Message-ID: <Z/kFXDwneQ9yHiJl@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1744037648.git.agordeev@linux.ibm.com>
 <D93MFO5IGN4M.2FWKFWQ9G807P@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <D93MFO5IGN4M.2FWKFWQ9G807P@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: G_BAGoiaaveYky3440tvomTW6sZpx75k
X-Proofpoint-ORIG-GUID: 0HKwRFIDMdOHgUv5TCoToIJxhDHz4gm6
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-11_04,2025-04-10_01,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 spamscore=0 malwarescore=0 bulkscore=0 phishscore=0 mlxscore=0
 suspectscore=0 priorityscore=1501 lowpriorityscore=0 adultscore=0
 mlxlogscore=591 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504110077
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rg6+7yX1;       spf=pass (google.com:
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

On Fri, Apr 11, 2025 at 05:12:28PM +1000, Nicholas Piggin wrote:
...
> Huh. powerpc actually has some crazy code in __switch_to() that is
> supposed to handle preemption while in lazy mmu mode. So we probably
> don't even need to disable preemption, just use the raw per-cpu
> accessors (or keep disabling preemption and remove the now dead code
> from context switch).

Well, I tried to do the latter ;)
https://lore.kernel.org/linuxppc-dev/3b4e3e28172f09165b19ee7cac67a860d7cc1c6e.1742915600.git.agordeev@linux.ibm.com/
Not sure how it is aligned with the current state (see below).

> IIRC all this got built up over a long time with some TLB flush
> rules changing at the same time, we could probably stay in lazy mmu
> mode for a longer time until it was discovered we really need to
> flush before dropping the PTL.
> 
> ppc64 and sparc I think don't even need lazy mmu mode for kasan (TLBs
> do not require flushing) and will function just fine if not in lazy
> mode (they just flush one TLB at a time), not sure about xen. We could
> actually go the other way and require that archs operate properly when
> not in lazy mode (at least for kernel page tables) and avoid it for
> apply_to_page_range()?

Ryan Roberts hopefully brought some order to the topic:
https://lore.kernel.org/linux-mm/20250303141542.3371656-1-ryan.roberts@arm.com/

> Thanks,
> Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z/kFXDwneQ9yHiJl%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
