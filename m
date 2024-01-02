Return-Path: <kasan-dev+bncBCYL7PHBVABBBA562CWAMGQEE24GXWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 246D4821DC3
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 15:34:45 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-28bcf7f605asf7809672a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 06:34:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704206083; cv=pass;
        d=google.com; s=arc-20160816;
        b=AfKPY4jcNqEd8An4n/WLN9AnFeUfDk2qymm6ugUO9x9X8pjXTMu3tqcmw47/Tt0tJa
         +R6h7z4uVtRPNizPmGcA8/lns1xFQGt3uM5uE4IFj36+l71gvdSrAzBeXeldMIrDthsK
         L2QV4tunwSbA9Ss7FQrX8hIjh+ZBdYanUqbofbOYQcYQq/Cv5Ao7P+Gyzl1buJDRcZ/5
         j3q5zq+Po2IphPuGnPlZKWKCQHprL4dFukEC/c1nuhInlPRTaAzA/dQSlCdU9Xi13vio
         Cks5lrkiJIcQ4MLupcfFdyBSIm5f0VU4XaBkqsu1TukhTANR3dG4nfuZDd6+wfbKl/2E
         VdIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=u3wLbh81jBQBrW9gdmcqdnmPKU7Gi/h1cHzLL2J/5S4=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=oFmHlXyY4gGn6H1U1DeSzF80BtSTYMhqxoWTgZYs0FKd9zPC61EqfLu3jvIBCLZFsN
         QYLnguIyu5LnwtEdPfBRFotWIZONSQOMXEWpi5umMGicdAo1RpQxFaWN1b/fNAKqdDpy
         BfXxXJKSwkPTcv7izCpby4nA2bulTnA3CUrPXDUDFj047/rV3BTXZ6ZnGcXG/muyGTWd
         LB1fC3f6i1cUHGT14P0IzAJJkANiSc8GhGbcX2Di4t8DVkIjglBcEgbr9FIZMzqehTuF
         szbmrNIjoizHuumpew6jRee729Op/fIr+gXNWHk43y9/3ntYSJWkSHC2rGT2DbftyKqm
         XrrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=j98rMTP6;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704206083; x=1704810883; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=u3wLbh81jBQBrW9gdmcqdnmPKU7Gi/h1cHzLL2J/5S4=;
        b=GUgkt2+JXQY9b9meBrLXKNybXqLe3Pr3sThpyj1fR8nWUxs8DZRI9QDR1rZXFceW0L
         lCLeJXui0qGmhySVmtSjoGQYjOOmXS+g26jSDyE6By6NjTm5nu6ggY4OmZoqzaiK5XqQ
         mkL7QauB0ckh7B/SDVISnxeT2tO6a9mc9G4mZ+gl1LJn0YCcg8MJ3E5TxG2ZQftV9l3l
         FH6IksGyfa4Da84oD6eIuXPRCS9x2jyn/HR+kXxsxUGncJOnLPtUVL9bOch6tfn36SW+
         KaeXqMadge0IEamWARkH/Mnfd/dKF2ikBOTUriT3U51XwgV/AUlRqM8raiN1g6myZ/yf
         IVzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704206083; x=1704810883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=u3wLbh81jBQBrW9gdmcqdnmPKU7Gi/h1cHzLL2J/5S4=;
        b=sre1WwBhZWAPvyjozqEvZcWqeNC2VrccmNX8tKx4LXT99VIvCzR9gw4P1IBC+nt3BA
         IIBH7k7q1ACFDpLy0L1viOKeZWV2cjoDAR78wc8Ggbd+LYMcERSG9L463rO0F8Kn95tm
         6jXMwoaq5+vjjcnaJexz4zdE0cPbGBUwT5ukWvI3MLEQH52xO/LGBRBJv6nj+Cxzl/U7
         T2g2MV7TLiuhvlYTsGRCaElkS1U+n580azs4911l9v9RD2R527OsAdPq2RJUQjvchXly
         mHTv2by70EPwfujGLA4kiSlthi/Xqvyr3VvXt1zUjIE2aF+G2nbULHpawutHHP3CMfA+
         YUPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzWYe7tMM/4pEac/fPuTiQVE/Tn6TKvyug95fANwb3Ki86X8E/h
	GA69VIbTr4MHPxw5bsueszk=
X-Google-Smtp-Source: AGHT+IG5XslczyLZx1QJDuwZJNN5UyQ/6voB1+dtMT2z+CFQhtn+9we3aHLS4+Z/sCBKZx3SBPyjvQ==
X-Received: by 2002:a17:90b:46c5:b0:28c:af63:ea5e with SMTP id jx5-20020a17090b46c500b0028caf63ea5emr8117445pjb.21.1704206083300;
        Tue, 02 Jan 2024 06:34:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3b45:b0:28b:8958:5ccb with SMTP id
 ot5-20020a17090b3b4500b0028b89585ccbls6176663pjb.1.-pod-prod-00-us-canary;
 Tue, 02 Jan 2024 06:34:42 -0800 (PST)
X-Received: by 2002:a17:90a:7d0e:b0:28a:c6a6:6d69 with SMTP id g14-20020a17090a7d0e00b0028ac6a66d69mr21302726pjl.4.1704206082302;
        Tue, 02 Jan 2024 06:34:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704206082; cv=none;
        d=google.com; s=arc-20160816;
        b=cq1eoUQYie17goADAhDZlpVw2UZlqw+BomO1vml3+vxZEcle51Q3sm3SirnFG94rWV
         ZMxdtvFeKaZAYD0c7993tjZbMWV3dFnib96V+rI6UXj7u9kkQkvKqCKNKeWAiljvOXHI
         dTnxUXsx3Cu72dSmvf31fl2sjs25SzgBvsfORbobLIxO/XuD7SP5H7oDgl5VTDXM5GYd
         KybCsjYLTAAvO2J+hhkYyNipWmo2IogaUglcZ8C0hySAQ0htStHDmd4gVbzqbQ8RSwY5
         tjsgdxG/EvzzD4jqszNjzM5TK2/PKAaPj1AxjxkLm2Q9iAPRXqj5CuCci5F5KQW3+viG
         l9gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zy1qZMqGOpyHSQ3Wj0sp9M6cSL2hJ07Te9b4OYnhiyU=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=W58d4lV5601r+PjedwuCQH7CmZOMgViP1XVydDuPTBZPVKYT14oS5bd+5y8u+igWcE
         0QUCnwCoznDkebrAZFaNh7I1Q8ItGs9OxoFTIJ+N7K+IaHqg7eYJ0seGfGUPOERxAh4Y
         2OEg/lur1CiQba0ANpXAh8JKZ1aiJLSnGq0FrNz98UGRIrWJ5gRlC7pZLlz2XzhqWJOE
         cNEf3n++iWQAvyHoaYgkDORM2vKKtvZMB9e4zxXEf/OMJZ0TqC0vbJ1G2AncLaczal30
         tkyAQtdWhRg5JzjZSgChglq7CmtmMxsdn6JKaR7v4ecN2R5nWtayk6TlOtHOqK33RW0D
         1Ejg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=j98rMTP6;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id e8-20020a17090a9a8800b0028cabc27bdasi664946pjp.3.2024.01.02.06.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 06:34:42 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402DiZWY028458;
	Tue, 2 Jan 2024 14:34:38 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcjqutbc9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:34:38 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402DilXq030037;
	Tue, 2 Jan 2024 14:34:37 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcjqutbbb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:34:37 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402Bv3NY017981;
	Tue, 2 Jan 2024 14:34:36 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vayrkcyv4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:34:36 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402EYXeW24904366
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 14:34:33 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 53F3E2004B;
	Tue,  2 Jan 2024 14:34:33 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 102A520043;
	Tue,  2 Jan 2024 14:34:32 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 14:34:31 +0000 (GMT)
Date: Tue, 2 Jan 2024 15:34:30 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
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
Subject: Re: [PATCH v3 23/34] s390/cpacf: Unpoison the results of cpacf_trng()
Message-ID: <20240102143430.6306-A-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-24-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-24-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: kTqZ1PRN-hTiLoJIQyYlJCXg5MKH4SKE
X-Proofpoint-ORIG-GUID: z1yxLgfbHQruE14JYN0FnEq3ruYg6F5g
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1011 phishscore=0
 mlxlogscore=483 suspectscore=0 adultscore=0 priorityscore=1501
 impostorscore=0 spamscore=0 bulkscore=0 mlxscore=0 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020111
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=j98rMTP6;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Dec 14, 2023 at 12:24:43AM +0100, Ilya Leoshkevich wrote:
> Prevent KMSAN from complaining about buffers filled by cpacf_trng()
> being uninitialized.
> 
> Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/include/asm/cpacf.h | 3 +++
>  1 file changed, 3 insertions(+)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102143430.6306-A-hca%40linux.ibm.com.
