Return-Path: <kasan-dev+bncBCVZXJXP4MDBB2WERDAQMGQEWIE2G5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 977DCAB3D93
	for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 18:31:39 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-476c2d1c582sf90119121cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 09:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747067498; cv=pass;
        d=google.com; s=arc-20240605;
        b=bl1uV71qIq7mbloTlJd+45UZP7dxaZkwxNMF3H4OkULh5xFtX35HfRU6711Rx8a4jk
         NAQA9cmJKawQdaI1ZyZPKwQM86BnMOMwHSmrIjte7f5XLTtuZkQK55dMJt3UWKDpmRld
         nz7rPQXktTpQazqH6J3+KUpEut8SZM5GCeQGSn4H0/Sn+G4Da+2WPaTK0PUn1ya3+KR3
         NAUMpGuJQTc1++N6ELtEKtfEwQHactH6/1ZHgeA0xzrjjZ3GYwJl2x7MKkcXf8cSoGAH
         E4yaEVU05sqAO3QoO4eWAo/j+6tztGWbrx/lPQ34iZiqy3tZFye1h8ZFzWrUQPCYH2ff
         23iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Q1e7qXl9AQweBsyHKkPBfz2bGmAYTVhN8W781v/xLU0=;
        fh=8cw0T9cCVQO8DoXgjp4/r259r0vA2BWC5mv9ePaNE6E=;
        b=hPoUgqUODoHIcK/EDb833UBLmrjx501zFo0hMQ4TSDU2Hh5ni3uYshkaS/fmWphTA5
         TnXxbzVP8PVroSrV94Y/Dm3NHqkX8BiiuH+M2kDox96iiPOEkWGFKRvsqSZTLIGTq6ox
         f2NoTyVL0Ep5NiLmzFQBTDzX+DP/v6T6tWMjPxYB4r+tbpoAPpBMn2/hLgU5UjL4Qal1
         0fD70t8KzdKO4t2qQcKsFF+athVYWtywnn/YxXjpDDh6l2hlbuW1zVVNWMoWmaOzjgJt
         l+4uIRglzKbcXc/TEwR7+nUYufQ8mU3o4XftmHEV5o20Xz9ByrQhG1MHj8G2SovWKNR+
         2uwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fP3ChIBS;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747067498; x=1747672298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Q1e7qXl9AQweBsyHKkPBfz2bGmAYTVhN8W781v/xLU0=;
        b=VbR9oJfM18ibayuNtNl+OxIpvaD14Lem6cZmzk3ISgTnkfRLgDQ9Z4R2lRdjJUvJ6C
         2vF47BKt1gEubR/8ZuImSGVJBsff5s/AvMlQYTWAH3Bj3uAv6mdshoNhtF3WKawMWf7t
         zkgM1PMQq5Iu55a54fRGkCgFrCgN/Y9Qs09ZFnotNNSev82l+SZKsm/KVbKOiCOpcggX
         9Jo01YhB89+pKINFTCkBdzVRD9OCDY48eP1ikqOv/6t/inlqCE36XYNiOJ3jW8f+1ld/
         XGwc443G2p7S4rg/z+SvqhuCnrBps4FjvTYb3S5iC72OlQqaYhPfuzjcp4ilYJ3K1SAd
         CnAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747067498; x=1747672298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Q1e7qXl9AQweBsyHKkPBfz2bGmAYTVhN8W781v/xLU0=;
        b=k/paD0/T2Z3EsGeyntvzTJ8AsJx+JEiRpSExVexTXKf0Zt5DuO+OQIQbuKPU9mGeW/
         5BunR6+eItZdlP1+OKhiy6zE5BxdfgmhIi5SPlvQBVD+5jzaD19ktEVSo8IEoiwzBNz6
         IOlsEsrlgjRhlNdG7Ck3YDrerNYbjst+h0QE/CSL7PmCQRQyAS7ZriXOc5+uxlTPR0b8
         2KDy+Ed+GomtZ2HzCCa0RUyZijjjRCnn3rAqD0Pu/2hYBfBYszQzSFfXtAyER3fKPplu
         7R73ewtB3IvZa9toUlLPbLGhPmCxPO1xFS0miyh3pSic4a4zabgFXxWyIBwdsVUPwINe
         5gXg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWb77RjwsAhmoKVEq/HWinnyAXiZEdEg/LGCPh+iBdvzywQ/qAAdOf2vAZ5RhITsgE6c4YYhA==@lfdr.de
X-Gm-Message-State: AOJu0Ywa3ZH/k/cRG/8dgd3JImyeUxdW64gJhgVVOsp3S+hGrQc9dUCO
	Dk+o9III4s/xUyB+6JMMXMn2e9Xr+/O7WGH/eO7JUtZ0JhsYO2rc
X-Google-Smtp-Source: AGHT+IG4tQwKZC6pqzqz3zOX+DPL0wtfDRPZ4hxPidU/k83HazU0jmClCNTsK2zlYvrVpTZa09BNlQ==
X-Received: by 2002:a05:622a:2d2:b0:494:700a:d450 with SMTP id d75a77b69052e-4948737265fmr1634131cf.13.1747067498492;
        Mon, 12 May 2025 09:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGYWdVJh6BEjEfzEn6FU3JgSfiEOzL+/V5G7++KIsRhrg==
Received: by 2002:ac8:4f0d:0:b0:476:6eec:3aa5 with SMTP id d75a77b69052e-49449385b31ls82376661cf.0.-pod-prod-00-us;
 Mon, 12 May 2025 09:31:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+dne0KKBvOMyMsbPXLRhvEPTqwdOxaQHEnwaF72ZtX4BqT6khknJYF3gaKhcVWamgfC7HblOqWMk=@googlegroups.com
X-Received: by 2002:a05:620a:63c7:b0:7ca:d9e8:d737 with SMTP id af79cd13be357-7cd1debe840mr13589585a.22.1747067497422;
        Mon, 12 May 2025 09:31:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747067497; cv=none;
        d=google.com; s=arc-20240605;
        b=Gt3FoLoGLM5XwnbzDsexAT90wm74f/caWlgGiMb0K7VUn4BdGg9qdXiQz6nKh/loxE
         wVzMerdGff1bSdNSuMKU1wP52SiBggKRS4xXwA2dLjwg2oNiOfiZPpGztEOUoc5KGuoW
         4G7a7KP28yuahSn2Fs6Art20nGptETeZKcMpGTjmsI4w1RZ+Jp1ekgGOx4bmW0bsxc3c
         gzJbXUu7dPPQtORpTyBWPDwy+8OixplAZRGCu402/mLmE433khQDzzVTrIsqyLShe2sl
         0U1NeRmbdboIrGRGWsQRbe7MgcM0A3dNnaS1Ajv+TUUWaEFWgxkHaeRNWjqiFWeVIr8L
         m3Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tGL/LbTAfn0zgVU3c0eZIOyEQsldEMIlaiE0jItqvvI=;
        fh=UDdBOzNKXZ7Naie7WIjvPNKc6E4DKPCddYGjM4WKApE=;
        b=S4NfPnuGTG0D06ojvZIjOdMdMOdH8ZMCO05JX133Rel72IoIgylShBGhbePDz05mAH
         fiEZpQkkCgtzj1KPVUnKafjTenNYi+7RhNfuB/O9h49SwDFGvk1lYjaEGDXqpJg7KFs/
         1sjzmcocKqoFaFP49fGQAxsPyEcDXR7/DFXITZAUWUBQjhSd5A43BoXwzFRfP8QY0j7K
         qx8vAqhSY9TVUhlLcc5UAGR5ITFBJPGYUiav7NBpUnNBjZGXBpVK3SuGxX5D/fTXq9V3
         LJ63qvTBxN8klRiO1ZL6FgVFLer0oJ0ZIhmpfS20/dSEksvnkzOpiXkT58lIWVJn0vmM
         uuKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fP3ChIBS;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7cd00fddb48si32882485a.7.2025.05.12.09.31.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 May 2025 09:31:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54CGFYFB024389;
	Mon, 12 May 2025 16:31:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46kbkstrvf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 16:31:35 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54CGEgRb024804;
	Mon, 12 May 2025 16:31:34 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46kbkstrvb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 16:31:34 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54CCqoM2016337;
	Mon, 12 May 2025 16:31:33 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 46jh4tf0ph-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 16:31:33 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54CGVWjv54657416
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 12 May 2025 16:31:32 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 229C020114;
	Mon, 12 May 2025 16:31:32 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id ECD8020111;
	Mon, 12 May 2025 16:31:31 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 12 May 2025 16:31:31 +0000 (GMT)
Date: Mon, 12 May 2025 18:31:30 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v7 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aCIiYgeQcvO+VQzy@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1747059374.git.agordeev@linux.ibm.com>
 <c8eeeb146382bcadabce5b5dcf92e6176ba4fb04.1747059374.git.agordeev@linux.ibm.com>
 <aCIUz3_9WoSFH9Hp@harry>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aCIUz3_9WoSFH9Hp@harry>
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=DrhW+H/+ c=1 sm=1 tr=0 ts=68222267 cx=c_pps a=bLidbwmWQ0KltjZqbj+ezA==:117 a=bLidbwmWQ0KltjZqbj+ezA==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=dg7Irr5rqVmvLQufYEsA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTEyMDE2NiBTYWx0ZWRfXweJ+O0011/Hs 6Hi4ZRGHDlEuF3MjSp1S3b9ZMbw7IQKKSMaelku9w/b5OsAN8qEomFNf5kouXsH7mtGlnlCEtvF uClj9wJ7drwFXTPRAGica6qa0XtOfr7AfpFn65OU1Qk88AedgaPcZzFgmtyYVTl1gdAOMd5cReN
 7ObWluXXhDlPUzQ8HHQs5PSuD5d2cgz/aoNx7GOtMH38Bg5oEmGMldZdfoberwf7kt4nxgOvDcd yg0cE04WpU+7ZqSJIa7fcet/D87eDR4Byn93QV2FLuyoct/FurVgShuCbiEJIiEXK4sneVy4W1+ OUKx76PhRj/rKDEod/2dQSvFl//4ji1YxiSn+KAogptSpp/IdFODEwhyxNz29TrgwQ2Y089pOFd
 Am9OmqgYtKMWOWD4ynpv24Q55k8wN5Ljbtd+PP9QNcpo5/3rlNXcQgMeLbIfPFNon0jcuU1p
X-Proofpoint-GUID: 13OLRlz25CD_Htxzm0V93LQo7uFLBEqY
X-Proofpoint-ORIG-GUID: _K-rkFkUazgqcTHuIiwz58rCfqji_YEE
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-12_05,2025-05-09_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 spamscore=0
 priorityscore=1501 clxscore=1015 impostorscore=0 phishscore=0 bulkscore=0
 mlxscore=0 adultscore=0 lowpriorityscore=0 suspectscore=0 mlxlogscore=597
 classifier=spam authscore=0 authtc=n/a authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505120166
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fP3ChIBS;       spf=pass (google.com:
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

On Tue, May 13, 2025 at 12:33:35AM +0900, Harry Yoo wrote:
> Thanks for the update, but I don't think nr_populated is sufficient
> here. If nr_populated in the last iteration is smaller than its value
> in any previous iteration, it could lead to a memory leak.
> 
> That's why I suggested (PAGE_SIZE / sizeof(data.pages[0])).
> ...but on second thought maybe touching the whole array is not
> efficient either.

Yes, I did not like it and wanted to limit the number of pages,
but did not realize that using nr_populated still could produce
leaks. In addition I could simply do:

	max_populted = max(max_populted, nr_populated);
	...
	free_pages_bulk(data.pages, max_populated);

> If this ends up making things complicated probably we should just
> merge v6 instead (v6 looks good)? micro-optimizing vmalloc shadow memory
> population doesn't seem worth it if it comes at the cost of complexity :)

v6 is okay, except that in v7 I use break instead of return:

	ret = apply_to_page_range(...);
	if (ret)
		break;

and as result can call the final:

	free_page((unsigned long)data.pages);

Frankly, I do not have strong opinion.

> -- 
> Cheers,
> Harry / Hyeonggon

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aCIiYgeQcvO%2BVQzy%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
