Return-Path: <kasan-dev+bncBCVZXJXP4MDBB6EG3K7QMGQE36LO42Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 89C1BA827BA
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 16:26:02 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3d43b460962sf126596025ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 07:26:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744208761; cv=pass;
        d=google.com; s=arc-20240605;
        b=G9PjlhX+LAzJUHz7ofrmQwOkN2njXJ2LDkuWMf+ZhhAjbY1vpY846/w077jdrCeAzF
         4lgkfQY8L4YwMCad/vPs6z6/mz0uhza8bszs4ImwMKmrzyEdxc4b7QLQYCDpSAoCJ6M/
         TGD51mK4aNf6LghQM7cdAfp4+E515mX55FzQ4fIWOa3gcYjJIz7vIECtAqCiJL3lH9S6
         0wVwujDWAUss9MFAbp3UNHHVW49e3xgFKzdzmXRq8lp4F7WmmFUSkelUJKA9mviWdH15
         lnp8bC/4I2HI1scn4eJScLs3qxUTfGZC93YRFxtz6i0Ojkl7HzBOUlnWfPzZO/x4lxQN
         wZlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OFlbs1Y31YjWCLbD6XVQCN5jOYDo7mfHsYx+fPsAF40=;
        fh=wVlsD2OHIq+uodycOTlsYl2Dgp8gPYGfGFP3/gtqoJY=;
        b=EmKTMoJdrIH2zpxw40pjZsZjxInHX/0ykRHDFjKYPZzWh4WB/7ALCdczVkNrEMSRfE
         F7+cEP4hjV+yKAKtBMPUyJufmIbYgrJmUXvBnbUnxaU/lfhroaTvRrcS2ghBkQuUKWGj
         kgOARUojLveYvVa+3pF9D9OWoD/XlCQZm1EXSzDcyn7o3uNNgDMxSaAcPVqcElvXGzOG
         +XQcTKsmnBe4Pikrg3UQq6Y4ugqGXqnZ7nzqW0j9M1zjHsHN4k4EED6+xZAqIOAuJ8bE
         D4Wk5MUpUDgvfZJNQhvYhZJ4UhUYRYcEyYnaLUn5YuOrRDWzOzaemSwVTpgj7Q7SFnhc
         O1Ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IRgQg+p0;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744208761; x=1744813561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OFlbs1Y31YjWCLbD6XVQCN5jOYDo7mfHsYx+fPsAF40=;
        b=JWZOoo+KrK+6t8/MkVOSwXp59O2BRJgbqeCZ+pu1M/AMxx94UvMEcduJho71OT6MC1
         4VZjSe00VqkET0zDiKeoj8EDLnZwXkxfXnIy/R+frQhsCu4ra+fKHOCeDPIT05ajhNf4
         eMR3ESNWeKL5xHC/Rzg8rViqPd3+XTm2nj02p2VVCtU3ZPDl1fpNs845TXexX5/mhp82
         2K+bDg1VSVrtBl3kJjW06LfvW4WckM04uMxl1rI2EyRLEeuUDzmDZLzE05OKGBjzepr6
         cbYHJeuW5Rvi57fClC+iNcsM3JlQRm7f4F4/aybPawSBVPPC85oTHhcfHeckTfodW2AB
         7Xiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744208761; x=1744813561;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OFlbs1Y31YjWCLbD6XVQCN5jOYDo7mfHsYx+fPsAF40=;
        b=NO4YQi6nbtnpBo4h8R/ksX1McqkPrw7APPFGaKsPCHnNd7H8eQS2My/XhUFrG6FMjn
         H+PKDl8r6cC9h4T8x7kyEpEjjL3TNX8EnJasppXiP02pdE5J4IZ2yPnhTdn/peZ8zsEz
         ep5nbKcIBr5pRHWUg5IsEjYWQiqPu+vAvRs5raDLwzQsBxtxzMeVslm6cTGwmSc42w7P
         3kHd1jln6vPflx5RVT5XljQzGvYSnvTOIWJppl8Ntj//BYIK6tSIzJIE99n4TqUznNJp
         NV1j7M52LZ8SXRzvZtLmpst23SRER/vt0abtY72+CQenY0jODTCa2Nw6zl5Z7Q4bmAyI
         7ZtQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6TJCQM2ik7a2oU09ePRoGY4tA4AxFes3/JEU8KN6fSdHUMllotnu4XAKCFhMVLDSsYrXV5w==@lfdr.de
X-Gm-Message-State: AOJu0YyedBqdOkAdlp/Th8SsbBxWL66OGE5tyX0kKsWU6WyleUc3998A
	ZW4WmeYuAVtjq6m3Ie0sv8zz8R81MSb9GifxHpg3UxE0JIB6mCLp
X-Google-Smtp-Source: AGHT+IFwKbTWGWBZ6z7LeHaoty+gng13gPG0Q3SKHR5kAV5nOXcsZO42AmLIECh7f2VJx8H53WAxxQ==
X-Received: by 2002:a05:6e02:1b09:b0:3d4:3c21:ba71 with SMTP id e9e14a558f8ab-3d77c2b15d8mr35684085ab.18.1744208761019;
        Wed, 09 Apr 2025 07:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL/wc2TOZ11xfJOsh6t69Y1PsdYAV1cITRo2fSs82K/bw==
Received: by 2002:a92:c60f:0:b0:3d3:d548:983c with SMTP id e9e14a558f8ab-3d6dc9bbb8dls1786985ab.1.-pod-prod-02-us;
 Wed, 09 Apr 2025 07:26:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzG6umc2HIYdfkBQu5In2cB47MUnaSCCBW+DkPO+dEd2GyEwu0eOSiDZdcGKS0mBzskgHTFb8Rpjg=@googlegroups.com
X-Received: by 2002:a05:6602:2989:b0:85b:3fbc:e55f with SMTP id ca18e2360f4ac-861611a4e89mr438139739f.4.1744208760004;
        Wed, 09 Apr 2025 07:26:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744208759; cv=none;
        d=google.com; s=arc-20240605;
        b=IlbdhfhFQMzcajbkauT5QT6GMxTJGl8oaL04AD+Ugi9b6uHFoQM4UhAZfHQuUBvtKJ
         8KCKk026aWk9XTuLjbWoP42oPeNa96MVJOUYd+3q/nRYLzXriF//oVoIIbNbmGlFYYzt
         ZeR9F20ltvw/egvjIr9t1/lt9RZMobKPLBJ3GpXa8aX2iQ/lkiy0S+a4hjNQLHbj8hku
         Fb3wzgBOlWbImNd/LAcktgMpZAOG1BfI/PptQhFtUYUbub545bpJNnL5HiYL4WUOsJ+4
         kaJo4ZiI63/Ei3XeNIFqQNoBD1Th4rmJM3H295rStHHpvBwgmrIGqxSEYuRAT77bvZ/f
         ZoRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dZ0mp0fbK09n1Ak/UvqxB1GCA8Znz4UQv5qeUc3rPlA=;
        fh=C0IdoAVF6MGGNKoWikjwjM4jVhum/ognX2mcLgnJfMI=;
        b=jUKF1QRSgyjVzdUzzPzYERjYxBi0cTMlMTfQgS07Mxd4G21AFRMJ/rZNkSoDA0AVmv
         +bB0Bs36mewl1EoBUu6fIFk3W4RCmfZE+Quwm+SRwrzbfYer4bn8DEgnUQuo0JwG+Fno
         rrPDqR/cMFASOnzpDLw6VeIceJiRvGxONnHb34JWNvlIYlnum+2giY5rodGSpyWkwcsu
         V6T9Mfqt22NmnRcsM4rkvV1Hx9BnyeSCALmTS9GBRAAd2TxkWEUb7ReqWRU+xYIS5ixi
         iY+Z9oDBemKPHeQmU7aW0uKAtk5ytDsZIvCxCqS9vECzhp3RBvnjaWwOwYS8QhmXDeTu
         8N1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IRgQg+p0;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8616522dd1esi5296239f.1.2025.04.09.07.25.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Apr 2025 07:25:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5397HMTX003773;
	Wed, 9 Apr 2025 14:25:59 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45w7yxd3vs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 09 Apr 2025 14:25:59 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 539EB8On010066;
	Wed, 9 Apr 2025 14:25:58 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45w7yxd3vq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 09 Apr 2025 14:25:58 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 539D3ElP011078;
	Wed, 9 Apr 2025 14:25:58 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 45uf7yr7wn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 09 Apr 2025 14:25:57 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 539EPthu51446068
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 9 Apr 2025 14:25:56 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E2E2B20043;
	Wed,  9 Apr 2025 14:25:55 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A20A320040;
	Wed,  9 Apr 2025 14:25:55 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Wed,  9 Apr 2025 14:25:55 +0000 (GMT)
Date: Wed, 9 Apr 2025 16:25:54 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Hugh Dickins <hughd@google.com>,
        Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH v2 1/3] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <Z/aDckdBFPfg2h/P@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1744128123.git.agordeev@linux.ibm.com>
 <2d9f4ac4528701b59d511a379a60107fa608ad30.1744128123.git.agordeev@linux.ibm.com>
 <3e245617-81a5-4ea3-843f-b86261cf8599@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3e245617-81a5-4ea3-843f-b86261cf8599@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: MHqebilzhsuhaERLi3oJf9wiQWwhiimV
X-Proofpoint-GUID: uhQA63QGysorbXbRGqjCOxWiIF599GSi
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-09_05,2025-04-08_04,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 bulkscore=0
 spamscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 clxscore=1015 malwarescore=0 mlxscore=0 suspectscore=0 mlxlogscore=844
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504090086
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IRgQg+p0;       spf=pass (google.com:
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

On Wed, Apr 09, 2025 at 04:10:58PM +0200, Andrey Ryabinin wrote:

Hi Andrey,

> > @@ -301,7 +301,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> >  	if (likely(!pte_none(ptep_get(ptep))))
> >  		return 0;
> >  
> > -	page = __get_free_page(GFP_KERNEL);
> > +	page = __get_free_page(GFP_ATOMIC);
> >  	if (!page)
> >  		return -ENOMEM;
> >  
> 
> I think a better way to fix this would be moving out allocation from atomic context. Allocate page prior
> to apply_to_page_range() call and pass it down to kasan_populate_vmalloc_pte().

I think the page address could be passed as the parameter to kasan_populate_vmalloc_pte().

> Whenever kasan_populate_vmalloc_pte() will require additional page we could bail out with -EAGAIN,
> and allocate another one.

When would it be needed? kasan_populate_vmalloc_pte() handles just one page.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z/aDckdBFPfg2h/P%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
