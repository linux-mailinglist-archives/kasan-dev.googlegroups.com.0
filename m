Return-Path: <kasan-dev+bncBCVZXJXP4MDBBDEF3KWAMGQE2FB74XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 50D8B823F28
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jan 2024 11:03:58 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf1407905ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jan 2024 02:03:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704362636; cv=pass;
        d=google.com; s=arc-20160816;
        b=UVsxtOc1eQ6Ns9yxedWxJCchxeUhxA7pf1QAX0N5lt/XjEqKVrAUBuB3b9a70aybe+
         XSk+ihutB/Kwf2KbBi/XY4fCgEFC7xp4OlbqJgRko6B6DnvUk8ZErDn1nv0PTLSzkaZh
         uvw8C7hwDAlhvW+ku/10YpXkJiH6fc8EFv0un8+xKy6Ssnnu3D5q386c3964cOPqtvVp
         tLI4WIEYAItqkmr1epGr/YHYUDw2OTpk8LtNNd6fVdNqlvEEfHW7hpkxW+aGOMBVieEU
         MZ0e5K9zg3ooXWyuGebgH675RzZr3tadaziwknRvvWmaPl1LB4VL56Dgx1uVxpBkcOiS
         AUUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=14JesNO/6oprJIwmnF0Cit/YZN1yIsJJJ7WJ1NaTPEs=;
        fh=LJM85ck+xcuX9BFa5F0pKdGPbzOKut3aE0o1UEkcJfI=;
        b=PP3106qX1HQqqUBp6LUm3cuNiMJpzJ/fe3O4UJnGZJIhVAbMrSB5+dtE2GvnSBSUnz
         ITnu9pDp5UfaxhsWH878yY/54WwD5ozRWlAbu9+8ydQQ1PMwngurf4qQD3LJdhcbSLVh
         +VKVu8zoVVUUbjEAp9BWpiWzqLwrV2PM3mMCdTh/4ZDyS4N0jVOTLTzXqAzH9HpiRFIV
         qYNh63otxjNIUy2YUCzlp0noDO4JxvCJD/ecZ3ycLXChvOVvBXTQjFBU269ZhrEO70s+
         vUFinAj6sD1HfxjyHhwwP/phbGCT2a/1TxC9uZO9RQc1vnv2BEw4IrZYyeYSPzEvuOFA
         /MvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PwamUfyZ;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704362636; x=1704967436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=14JesNO/6oprJIwmnF0Cit/YZN1yIsJJJ7WJ1NaTPEs=;
        b=RaJs/LW/syp7MvMQy3rlTod4l1Q+khBgoavoexFWWUd4E/VytxVN33QQYmWiTkLu9U
         fWCuMsMnafAC1oAOsE3r6KaAnTfHJ8sHHQc01j4dKueMHfrTP+4TaRJ6DHsh0PI+0v6Z
         1KzxoDFrBakCrK+gH8vOvURR87XEabpVozyYm7mnccJBNT02BmwhZA0/3mTaXaIkfdvg
         b4i7nSJhR5ngAvABKcKgki8/+l6q1xJV/znjYl/2QrSLnRb7kt0wMyLpa+pYkL+cF9kN
         Ry32nYr9H0Bx8V3NUqRhTVT7jnSy3mU+3e89/h37D5GlDJBVsYrbR7KBSRxrXkruTctV
         eUVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704362636; x=1704967436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=14JesNO/6oprJIwmnF0Cit/YZN1yIsJJJ7WJ1NaTPEs=;
        b=LZuRcM/M5Hp7MzyEsc6qP2MQu+Mq3BlrKcSKF47+wHhTeq+Z6YvD4UDS4K/wb+9SI4
         VoqxkOrlJE3O4VodOQf/M4Q53Gnwsim9ThNpoFpqdmi6PwF2czEQTbEsjkbR8Gsq/qYu
         UAOXJAfo7YnSxIIJzqG3lorkk/NL5Zp5tCg49qS4H7hn59R4mNQGeuElhH4yRlIiJvqi
         slGbTW7V8937fr8iRZUteD+fA+iV5Rmpt80oYVQ8ndN9XPIVU/7qqHPI1RYORiohm/2m
         sN2drfjeHDdwLo69XGVyVEZiE7sj2R/I/tzynuK6312HW7OlkRqlYIYSVFwB7YlUy0uZ
         wNdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyAJPxmgEIL4owO4yTDVFszdffRdAJmvywfFP9v9iOWR9FwAew8
	SPBdshQFLEvehSmT2kjuCWI=
X-Google-Smtp-Source: AGHT+IFLXaKahtcY50zeTd+MarFYVx40ZU8GnOulRPlqlXKVd+4gQ4NyRoih8C9oKVgl/N0zPEZTRg==
X-Received: by 2002:a17:903:2292:b0:1d3:c54a:5982 with SMTP id b18-20020a170903229200b001d3c54a5982mr395575plh.4.1704362636356;
        Thu, 04 Jan 2024 02:03:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9049:b0:1d4:95ec:2cb8 with SMTP id
 w9-20020a170902904900b001d495ec2cb8ls1973529plz.0.-pod-prod-05-us; Thu, 04
 Jan 2024 02:03:55 -0800 (PST)
X-Received: by 2002:a17:903:2282:b0:1d4:bd0c:207d with SMTP id b2-20020a170903228200b001d4bd0c207dmr283720plh.66.1704362635094;
        Thu, 04 Jan 2024 02:03:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704362635; cv=none;
        d=google.com; s=arc-20160816;
        b=wuzvv1FtsrpU9qAPfgOYtnOl1zKiPzqka2VXkCwetpWaLHqWASFK7oPfFk05WDIbRz
         jp6vcMMFAj3ku/VWY7HhEUK/B6IABHrRxcvTsEpmfcX7EkSZV0aS5IlNrfMFnm7BOl6M
         2Slzw3Q5sYqCQ1dGZoc7rIN39oUbRyrnL5xebnICy906isV7pT19yXdIlGUnFZRx5xNY
         LXF0UOejjZq81tBCh+p4HLumCyDKaeHkJIzFbdz75EeqTqvwpsYEl074G+yXcI85rKXl
         XCtd91OL3PF7md6A5UW4elDP/0nx2QaiCUBSGp6P9nVEolc+Qeojmd2ut5Q8i4mUgABA
         yA7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mEC9RU/7gJsuNRS5VA9HyG1hQ3z9kUtySW0uefqhic4=;
        fh=LJM85ck+xcuX9BFa5F0pKdGPbzOKut3aE0o1UEkcJfI=;
        b=xGucGxT5lGDJyX1TCgvCCcPv2eD3IzZDHF5q4zkQ7jtilB/fFavdcW5rPCqVp9l9wz
         MdfuDPn/iR0+2giaViiMbQAfw/uI5y7hXvU/0kO5KsNHMuQWw5vA4SRpAirzveqFfoxX
         /MWYA7WC2KCsfAKVOC/a9TVVOvN1SjS0Yqv+aSVJI52s3g5er4uzBLPlCArPy4Jk8jvS
         u3yZBPm+P9cW+CxYJfdAiRdH6Mdxhdmnpj7mKlxRigfl+nh2R/+urxI67uxz8ta6ERt4
         kZpuDC9tkEe3+CP+B3bsPGTp3WNpgnwctYF435XdSebdjQy8h2TcB/alrNXS0I7zkzeG
         ADJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PwamUfyZ;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ja9-20020a170902efc900b001d045f1d86asi789194plb.9.2024.01.04.02.03.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Jan 2024 02:03:55 -0800 (PST)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 4048r1Vv014717;
	Thu, 4 Jan 2024 10:03:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vdsj1a7rh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 04 Jan 2024 10:03:50 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 4048sLms018434;
	Thu, 4 Jan 2024 10:03:50 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vdsj1a7qx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 04 Jan 2024 10:03:49 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 4048PKj3024643;
	Thu, 4 Jan 2024 10:03:48 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vb082g0ew-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 04 Jan 2024 10:03:48 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 404A3jJr5178108
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 4 Jan 2024 10:03:45 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9B53B2004B;
	Thu,  4 Jan 2024 10:03:45 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1D71A20040;
	Thu,  4 Jan 2024 10:03:44 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.45.37])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu,  4 Jan 2024 10:03:44 +0000 (GMT)
Date: Thu, 4 Jan 2024 11:03:42 +0100
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Heiko Carstens <hca@linux.ibm.com>
Cc: Ilya Leoshkevich <iii@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>
Subject: Re: [PATCH v3 28/34] s390/mm: Define KMSAN metadata for vmalloc and
 modules
Message-ID: <ZZaCfsuuODGkdUHV@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-29-iii@linux.ibm.com>
 <20240102150531.6306-F-hca@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240102150531.6306-F-hca@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: nbfM0juIhZleyeD13N0-vwHlSIw9D1PP
X-Proofpoint-GUID: 48fRanwL7QTj7BMTM-SFy1C7v7RSY4Cv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-04_05,2024-01-03_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 bulkscore=0 mlxscore=0 suspectscore=0 adultscore=0
 malwarescore=0 spamscore=0 mlxlogscore=676 clxscore=1015
 lowpriorityscore=0 phishscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2401040075
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PwamUfyZ;       spf=pass (google.com:
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

On Tue, Jan 02, 2024 at 04:05:31PM +0100, Heiko Carstens wrote:
Hi Heiko,
...
> > @@ -253,9 +253,17 @@ static unsigned long setup_kernel_memory_layout(void)
> >  	MODULES_END = round_down(__abs_lowcore, _SEGMENT_SIZE);
> >  	MODULES_VADDR = MODULES_END - MODULES_LEN;
> >  	VMALLOC_END = MODULES_VADDR;
> > +#ifdef CONFIG_KMSAN
> > +	VMALLOC_END -= MODULES_LEN * 2;
> > +#endif
> >  
> >  	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
> >  	vmalloc_size = min(vmalloc_size, round_down(VMALLOC_END / 2, _REGION3_SIZE));
> > +#ifdef CONFIG_KMSAN
> > +	/* take 2/3 of vmalloc area for KMSAN shadow and origins */
> > +	vmalloc_size = round_down(vmalloc_size / 3, _REGION3_SIZE);
> > +	VMALLOC_END -= vmalloc_size * 2;
> > +#endif
> 
> Please use
> 
> 	if (IS_ENABLED(CONFIG_KMSAN))
> 
> above, since this way we get more compile time checks.

This way we will get a mixture of CONFIG_KASAN and CONFIG_KMSAN
#ifdef vs IS_ENABLED() checks within one function. I guess, we
would rather address it with a separate cleanup?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZaCfsuuODGkdUHV%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
