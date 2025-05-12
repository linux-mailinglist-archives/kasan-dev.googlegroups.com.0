Return-Path: <kasan-dev+bncBCVZXJXP4MDBBJUIRDAQMGQE36QM5LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 01A92AB3A54
	for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 16:22:33 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-30a59538b17sf4384332a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 07:22:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747059751; cv=pass;
        d=google.com; s=arc-20240605;
        b=AlVfdNsmN0ixUHV4MYsIHJ/UkgMcA5nVzcnnp5v+8za5JWTKWAfY/SAik30bQb69d7
         2IxvX8vbwiIMwNO4BcPGTpNt9JMR1P+XSqVFHMOE8hP94ykuVcHskkaRzV6EXDtzUy09
         qs/WsU0iRZpf301n+bsH6QCdr2IMJCRYMrSON6LMkvBpDN7WAXGEMg5VPrXh56PgDDEO
         qWOSc2QnSUp4/5CQVIX9aELvT5zaFtLMZozc7sVVywdHIJ4CeV5/TSQ5ncsGRAkwNaZW
         yYCMAr6w5KFObWqqncHrH7f82RpytAdRIVYdKUIpOGX9T3+fzxuLBC4G0wg/wgCmNNSB
         mBDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PWFmHgsEbvaq2Q7HKH/ZKl90N5qSMJthLTib1wNElsY=;
        fh=Ox+yAJZXW8rF9ged+2FYktTV6oG9H19kNFqGG/ZSYS8=;
        b=ADF73GiJg3I4EAE4AeDDuYm6SVxZtcaJcH6etjLexOBfz7RqQMKN23E1ug9q+VRAaO
         Dhnj5bNcohXCYd/MYIyGAW9o75fszbEfL+Rfjsam8m5EX4IfIbdhnQtZhi6MI1TsqFTz
         KTCEssGQrLmn9LueGWeriuiPkVERlJUX2L3BD6T28lIxfIWXoaID6fxXbORuRibxmQn6
         OCPksGhT5CD4fDDpYpII/ho4rgUSklRDGr4EYJer/HK8dUrSpy64yruQgXNoZkN8c1JW
         g/y2RGxGK9LMOujdNAIM0TbRKdBGJiiwii4NSlzmgAJ/z5wzSy1F9TvVAOZJlY0ChoXQ
         N1rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cFo/WhMX";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747059751; x=1747664551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PWFmHgsEbvaq2Q7HKH/ZKl90N5qSMJthLTib1wNElsY=;
        b=nxCtqeg3QnxhzIeV/bmj8oKSxaDvzJau65H+Ot5nJ22MIsdu6FrTVTVpAQYc+1U61T
         wGo17/fz9hZRgq83Etx1JHB5S/2HGfsYOhUqPNVuet7qCN9MwFOs/49TcuAUBeQqGkW/
         1dUBwQNVzSiLUhVtEa7QEcTLmRz57pjgdzeWvq2/ExbYFO9Gj+/ZO43hl1iN283BtLMo
         sj5TA3DNLMIwWN20z+B0zd/7Qy1Tc9KZk5hBCI2Q2B5vpvOAQKtPsHdxYdtLzbV/1Ebw
         BCq3HcDRTzCUdGfOt1GiwVw4gGA4HdYrGDkTgg9QMBWVh9j56e81MMRQvWL4ZRpA6jfL
         sBDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747059751; x=1747664551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PWFmHgsEbvaq2Q7HKH/ZKl90N5qSMJthLTib1wNElsY=;
        b=k3jxx2+bmNeVJwz9FZrhjk6paBjwJrbGJT/FMiFAS2h7/PGVXlHnQBwQd1FycG2ONR
         2wc7NONWhIJ7yTARMsqlsXYTOKWI5gZJm4KEnwwp4+u7ZTAubjRcEfwmlEtVcemIecWU
         DiWoGkykZJ/ZnYSS3kCxSMRa6xGpPURlo09fGYsvNVP1tHIM+VSI+ZEpDjSjdCvpke6B
         5YchEtMrgAGQK9yj6Qi5RYtNx413zRHRwK7Fk9TN92s0VxpXRJtkhChGMcLZF3Ep4oyx
         gEiozmYngvmiFTtaTrMdgz5NXVfLrTcXC6QxcT0JD0MSGKreXzQ1NlG8QEioPEad2VWv
         w9vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJfPEFbAw0ouaMHFzNs1XrpUWR0xldCMOKG76EaDXZqXvW6fHqyOBBxTk3gsSdt8pTgm1Ewg==@lfdr.de
X-Gm-Message-State: AOJu0Yz9ywfNOjEEFkZEqNZfKDhbD4hIMdnI4AYYbVCriKdLFUNSqDup
	NgcsctvwG+DLwClyqSYhLq+jJ7Yh3J3t5MlS+PgjxjnTc4teUB+B
X-Google-Smtp-Source: AGHT+IHw0v1gf/fPteWggohqOQCFMyXGiwF7Uw6YWIOpXeQCAu0NMSqjdPyUU0ofp5WBkGVQfFjCiQ==
X-Received: by 2002:a17:90b:4b4b:b0:2ee:6d08:7936 with SMTP id 98e67ed59e1d1-30c3d3e23fcmr19423076a91.20.1747059750970;
        Mon, 12 May 2025 07:22:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGZKWac8+AIphbPqB3WQkjNiY0SU9vDEx1NVbJXbBbEAw==
Received: by 2002:a17:90a:8e83:b0:2fa:5303:b1e3 with SMTP id
 98e67ed59e1d1-30ad8a0632els3049910a91.1.-pod-prod-01-us; Mon, 12 May 2025
 07:22:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7T3tcmXOy+Si+H3aVHVuKXls6JcT+c9aZQogcDHC02YWyowHc3wNm3jA3bimX3v6S3Rp6CawyjrI=@googlegroups.com
X-Received: by 2002:a17:90b:1dd2:b0:2ff:4bac:6fa2 with SMTP id 98e67ed59e1d1-30c3d3dfb4cmr23482847a91.16.1747059749678;
        Mon, 12 May 2025 07:22:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747059749; cv=none;
        d=google.com; s=arc-20240605;
        b=En42XvB63Loluxz0uA0j6yG1G6xdAEqv8vB3H47UMianyP92YA9iyipklUtkjwW4lP
         +426UxMT3DFt6j1oCqGkvI7o9+Yoh8yDvtO4bAS+QPe0xGwpaF2nx2wt4Y8lpVnhySmh
         iUcMUbwAtEMrerflrXcES7gzeldl2eohMaWe/8tQi8aWDSUCZ2su8KZVNHmqTEaItcxq
         M5+k216qVevcZzMYFsGT9B200Rt1tHPKeQYcGiqe6PLIKpDzeEJ1o74MyA5kcjKqeUSN
         dMDsqZAV0ZIUT6ZhSJ4LCwoHIx+RIqJju6WO6cxegPP2NHtbWM5iIzKCWu9k5Mn9VfQc
         ccQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bYTcl/cxzHc+BRnCsqjMP85sfGh2bQzuASBHWbuH1bs=;
        fh=UDdBOzNKXZ7Naie7WIjvPNKc6E4DKPCddYGjM4WKApE=;
        b=Nf0EblBHt7nxFj4asNDYAo8Q1R09rzYq9Nt/VmpYdOAp/h2AS+AgGLkBumQa9tAgHV
         CdY/gbyI6xton2pE459SNzNvCj6KvgN9K9J7zCNB3hCSCuH4CaSzgFbugSO0PuCOLZSQ
         KFnOxToYyOrfqH4GE/xU3akInCKdeMv4+z4egdZf+TOP2eWU4MlbT2Pys6svMmTFW04i
         4awAUIS6P78cF7rDjXuE/zTjzyuDDuD+INkxOknKdbf3lgWiydGUbdlLXTZzc32ZNSbI
         fqlEhatdq6zCqhOM0c3ZGpiRDNiYt784j7nP825G3kzgOF1rL1z8o6OmXXAjrKiC0zOX
         1tIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cFo/WhMX";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30ad4f9fd8dsi384943a91.2.2025.05.12.07.22.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 May 2025 07:22:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54C9Et21015544;
	Mon, 12 May 2025 14:22:28 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ke6j1chk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:22:28 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54CEJB10007431;
	Mon, 12 May 2025 14:22:27 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ke6j1chf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:22:27 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54CCfoDo016955;
	Mon, 12 May 2025 14:22:27 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46jhgyxfd0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:22:26 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54CEMPOJ19792146
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 12 May 2025 14:22:25 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EEC7220090;
	Mon, 12 May 2025 14:22:24 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B20622008F;
	Mon, 12 May 2025 14:22:24 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 12 May 2025 14:22:24 +0000 (GMT)
Date: Mon, 12 May 2025 16:22:23 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v6 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aCIEH5WvkhQreVrV@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1746713482.git.agordeev@linux.ibm.com>
 <aabaf2968c3ca442f9b696860e026da05081e0f6.1746713482.git.agordeev@linux.ibm.com>
 <aB3ThByuJtxMpAXi@harry>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aB3ThByuJtxMpAXi@harry>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: z5zmlcPwAaxOT6dGMJKaE4i4QQ5NgCNF
X-Proofpoint-ORIG-GUID: iycNLknPJ7DkqTOcqNurG9cEEwXlcdpL
X-Authority-Analysis: v=2.4 cv=auyyCTZV c=1 sm=1 tr=0 ts=68220424 cx=c_pps a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=eJIhiymoiUTLQAr0ViEA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTEyMDE0NyBTYWx0ZWRfX0osQ5VCGYDmC VT6/dx+dPlH6iVSL7LJppXlgJAK4JKkNpmBUem/CxOpDQwDPpoevEp4EwH8SMdH5KvAWtZouMuT lSSQear8dwM1EhOgr3tUK7jyo3sPFSG2jB2V8+1zjNHCGpwlfOg2V13D8hwl/Hs7Vio5uFmPAVj
 MCrAFtLcTz+HrLhFTojH7+zoDpzJZu7GQny69Bvt6sGbF9aEpbBKCl2zfbwwQlRqyKkTygaC/xt mU32E1o813SeKsq+yRpd8oo3ih3YcT6Qe+FVvScY4RlKHLxuT2YmFZJvC21CxQ9kVsuLNhFCp10 jAQcrdRlZiqTUYAQyp5XqWkul1GdfV4LKGsjJviXth22jT3TJMcTknNRxyrt4N1cguYoNmRCeuO
 76v++8k7K2qXpf6fV5gnL1CvCV9sCwX726Sv1VCbIO6UeGj3StppL+7l0dGBy7oJhSqEwgDW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-12_04,2025-05-09_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 clxscore=1015
 priorityscore=1501 lowpriorityscore=0 spamscore=0 suspectscore=0
 bulkscore=0 malwarescore=0 impostorscore=0 adultscore=0 mlxlogscore=563
 phishscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505120147
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="cFo/WhMX";       spf=pass
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

On Fri, May 09, 2025 at 07:05:56PM +0900, Harry Yoo wrote:
> > +	while (nr_total) {
> > +		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
> > +		nr_populated = alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages);
> > +		if (nr_populated != nr_pages) {
> > +			free_pages_bulk(data.pages, nr_populated);
> > +			free_page((unsigned long)data.pages);
> > +			return -ENOMEM;
> > +		}
> > +
> > +		data.start = start;
> > +		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
> > +					  kasan_populate_vmalloc_pte, &data);
> > +		free_pages_bulk(data.pages, nr_pages);
> 
> A minor suggestion:
> 
> I think this free_pages_bulk() can be moved outside the loop
> (but with PAGE_SIZE / sizeof(data.pages[0]) instead of nr_pages),

Because we know the number of populated pages I think we could
use it instead of maximal (PAGE_SIZE / sizeof(data.pages[0])).

> because alloc_pages_bulk() simply skips allocating pages for any
> non-NULL entries.
> 
> If some pages in the array were not used, it doesn't have to be freed;
> on the next iteration of the loop alloc_pages_bulk() can skip
> allocating pages for the non-NULL entries.

Thanks for the suggestion! I will send an updated version.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aCIEH5WvkhQreVrV%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
