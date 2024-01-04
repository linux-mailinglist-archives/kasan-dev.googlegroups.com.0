Return-Path: <kasan-dev+bncBCYL7PHBVABBBQNP3KWAMGQEMQ7X5JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id EBFCF8240BC
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jan 2024 12:34:26 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-28bf98431d3sf353383a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jan 2024 03:34:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704368065; cv=pass;
        d=google.com; s=arc-20160816;
        b=EnhkvqBnTRvVOHy2qDAtqszP4dXmm33El8PFE08dimErbcfWlMW9XFHwOVSI84AAci
         NrFYlo96o90dorT9anESYimptaP1DO06Pt96vLy9Yaq2fiqyANQwFM9nSmRD/7s/UYV5
         CFJQOHiQNSzNieduuhMsUsbAx0BgpXCJ8jrLl7sar82S8SV1WfJQylmiL+c2/cH4VDxr
         s/B4MMZQK/rbmmYQaWaMtl1ZCjQxViPq+ghEwf8k4ShL/meTRFMtkg4FQAcgauETZzeI
         QgSndkNpR06P9j6/Xu/Z7i27VpCYWDml8qAyuUSGzjk//7DxsXOyJ7+9CddgBOEgK1ps
         IhHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5yQWFp3iTsrZTHrKsJfBEQ0MYtzrVryrzWrqqm+q00I=;
        fh=5zv/1k28Cz78IWthD5Q0549Jo3JHhYnPiCDnRz79T60=;
        b=ANs+OiNeuEiQ2g3QzR1LepJATpHc1eHKggcKj54HU8DTKgknHV92QQeonkwH/YD111
         VITWM3r2MNjOgRoFL1Hn5eaPPPc/N2hhOaeEwj848s8AVK5uL00bth8toVZUUW7a4yop
         e8j+9bdFzEveAJvB+79tRPGhF8nV9t0iZPpdfWmu6Ca5mdvIEkm+v18DNQJ8xptaZKZD
         8p3iOyOgqsNpcKaSGTzQTnx5GUW++HvC1H9KRBiKfZeOSXbVyquN7hH+OT8JvZpxrbvL
         DJV+kuyRligLt05Jq1HHaumcG6VI2AfzGX4SV9+q9zJwviLAZjQ6CKcn+RBCBEnS0D5q
         uCgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QtvPnqN9;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704368065; x=1704972865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5yQWFp3iTsrZTHrKsJfBEQ0MYtzrVryrzWrqqm+q00I=;
        b=PSSyA3bCbgNj5cxTekS1Z2axZNHMzZm2rCQ4k8zolMiXQUaghzeudAC6VjxzZRH3Pd
         iOIFNFXkwU2QDzghWDOLmBe3PGmgIWUoDOIlO/WxiHqy8Ck/Dsv3BH8I4qAMdFo3BsKe
         rs+jABk/neZYBYW4pEFSTEmgqEqIVzUzV7+r/V4S1fC/IZQ019vSex3xy1RGY6kepkJW
         2VHcsiwQF8E684jUr6jLoVB4PZ0PVsHRdtRMlcY2LUJEQEF5qkru3kU7xjGtmMqMTuh5
         ATwFSCNOtLBc9XvHErtBlTMmCAt1ukM2Onu9ir6+qZUQ/qyUj0swe2eVawGMb3uu9p9v
         d1zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704368065; x=1704972865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5yQWFp3iTsrZTHrKsJfBEQ0MYtzrVryrzWrqqm+q00I=;
        b=ozdt54QnY2xxyFto2MRRTq+Ahbj5MUJy2pngghzUYbX5cFDRXfmht1QKG/ZgkL9+Pp
         GDzcjtvoYYvTyUlxuifThPiOBoN79YBWNY5XSWTobCc9Weld9Y/+eBqqBeonHrubonuh
         VPxjJH9slrWpHVKdGFy3iYaOO53OWkdMbvshUKJoIwO/WXoH5kp6iVRN9tgunmmnkW02
         yM8NThF44rEup8lF5CKOjZ4wjR28xYGEY4nbJCdz3m5FjIGTtCOlk4BhU77JXv+h9Gof
         TzCl14GsgXUxK18GZWwlaajH4ZjrjgfLuakDll3Yed16JIJ1KnHhxXJ5qmeQ1+2dTU4m
         zgAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yypks6WLyXu/crX8OUPrxHIAWGomGaaHylHnD9vYG+tSPWvT0mQ
	fEmpjQdbmK6sGtFWrijUcQw=
X-Google-Smtp-Source: AGHT+IGlR290vOxwHLeBzivQMbhV5lotEVk/ZGh1oGRwwGNlWKpBAmO9PIl/3t3GqJ101PPqZqNJQg==
X-Received: by 2002:a17:90a:f2c7:b0:28c:1eff:ac45 with SMTP id gt7-20020a17090af2c700b0028c1effac45mr374430pjb.77.1704368065141;
        Thu, 04 Jan 2024 03:34:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bc86:b0:1d4:dff3:504 with SMTP id
 bb6-20020a170902bc8600b001d4dff30504ls151160plb.2.-pod-prod-03-us; Thu, 04
 Jan 2024 03:34:24 -0800 (PST)
X-Received: by 2002:a17:902:c402:b0:1d4:be46:5325 with SMTP id k2-20020a170902c40200b001d4be465325mr381544plk.78.1704368064063;
        Thu, 04 Jan 2024 03:34:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704368064; cv=none;
        d=google.com; s=arc-20160816;
        b=DlnkFjaZopkAolEu2caifU3pJFsM2zzeu+FPrdFv7DpXTRqGq9zPpYWmCuuVsNuD2i
         q7T69kMOeF9EOY51idWSieA4BrHIoX3Sj9Fru4TEjdT3z8SnvaNDkeuiru1MFtJZ9mEx
         ZpzwnWPdIi1PB+BG4mlkXYAvI3N9POsMNszGu2EQ1ak7MCrV9HSeH7MYP+l8cdcP9Yy5
         IlpANfBzSmRuBvW/yK5vC0dgr3xbwE+cgvFa2xfAN2ny+Qj+uHWxRaJdC/4SAIMTUFl9
         ylAkbnJpWdpRhl/oGGHRh1xc2Z+woVetJ5od/yJJ2vRTOJ0gGvLxWjzJuAUSPZtXtC2L
         dLgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DaA85JZ3rfzvuiZT2nU5IqFu1BqiLfSbMwxD/EB8i9Q=;
        fh=5zv/1k28Cz78IWthD5Q0549Jo3JHhYnPiCDnRz79T60=;
        b=VdK/uaEk+NjnztSGcM/sYqWd06ZAffyzTBqmzqyu2Ia4in1RJtF2ddQLgRz7Srl96F
         1dP3pBvGaMmpZ1PjA8+/YHhrU2oWZ9sxMqoASGZy8K106wLYtQhtSaX6sqcIxBhTTeh/
         EdWgt88yPicfgH7hRosZQAQWr6eanca6XozbcExVcmZIuYk+07VN1d7+E1BZir2yBfTb
         /1L03nK8T4sCIdo9n3cK9j+zEHUJpz+U6d+p+0ulj1VcnaJ6zOE1Nf3f+PMouM2rM7Z7
         lI7iDpummaAqwn+1DlomadZUQXXLCJdrGuhjQtgv0vc/ht9kJOIlYKDlJ2lp3EhxOyaL
         n3Tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QtvPnqN9;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id l17-20020a170902f69100b001d39c3be94bsi1542917plg.8.2024.01.04.03.34.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Jan 2024 03:34:24 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 404AHvBh020357;
	Thu, 4 Jan 2024 11:34:20 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vdm4p87u7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 04 Jan 2024 11:34:20 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 404BQTXx032285;
	Thu, 4 Jan 2024 11:34:19 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vdm4p87tp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 04 Jan 2024 11:34:19 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 404AUHJA019397;
	Thu, 4 Jan 2024 11:34:18 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vc30sr1yw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 04 Jan 2024 11:34:18 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 404BYFI428508726
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 4 Jan 2024 11:34:15 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1912520040;
	Thu,  4 Jan 2024 11:34:15 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 347CD20043;
	Thu,  4 Jan 2024 11:34:14 +0000 (GMT)
Received: from osiris (unknown [9.171.1.64])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu,  4 Jan 2024 11:34:14 +0000 (GMT)
Date: Thu, 4 Jan 2024 12:34:12 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>
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
Message-ID: <20240104113412.7040-A-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-29-iii@linux.ibm.com>
 <20240102150531.6306-F-hca@linux.ibm.com>
 <ZZaCfsuuODGkdUHV@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZZaCfsuuODGkdUHV@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: A-r5ni_NxO1svHGVXf-nj62fil3Gwpze
X-Proofpoint-ORIG-GUID: OVn0-Bn5itLqAoOpBhaSOLkGr5KeaBNy
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-04_07,2024-01-03_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 clxscore=1015
 impostorscore=0 bulkscore=0 mlxscore=0 mlxlogscore=678 malwarescore=0
 spamscore=0 priorityscore=1501 adultscore=0 phishscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401040088
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=QtvPnqN9;       spf=pass (google.com:
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

On Thu, Jan 04, 2024 at 11:03:42AM +0100, Alexander Gordeev wrote:
> On Tue, Jan 02, 2024 at 04:05:31PM +0100, Heiko Carstens wrote:
> Hi Heiko,
> ...
> > > @@ -253,9 +253,17 @@ static unsigned long setup_kernel_memory_layout(void)
> > >  	MODULES_END = round_down(__abs_lowcore, _SEGMENT_SIZE);
> > >  	MODULES_VADDR = MODULES_END - MODULES_LEN;
> > >  	VMALLOC_END = MODULES_VADDR;
> > > +#ifdef CONFIG_KMSAN
> > > +	VMALLOC_END -= MODULES_LEN * 2;
> > > +#endif
> > >  
> > >  	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
> > >  	vmalloc_size = min(vmalloc_size, round_down(VMALLOC_END / 2, _REGION3_SIZE));
> > > +#ifdef CONFIG_KMSAN
> > > +	/* take 2/3 of vmalloc area for KMSAN shadow and origins */
> > > +	vmalloc_size = round_down(vmalloc_size / 3, _REGION3_SIZE);
> > > +	VMALLOC_END -= vmalloc_size * 2;
> > > +#endif
> > 
> > Please use
> > 
> > 	if (IS_ENABLED(CONFIG_KMSAN))
> > 
> > above, since this way we get more compile time checks.
> 
> This way we will get a mixture of CONFIG_KASAN and CONFIG_KMSAN
> #ifdef vs IS_ENABLED() checks within one function. I guess, we
> would rather address it with a separate cleanup?

I don't think so, since you can't convert the CONFIG_KASAN ifdef to
IS_ENABLED() here: it won't compile.

But IS_ENABLED(CONFIG_KMSAN) should work. I highly prefer IS_ENABLED() over
ifdef since it allows for better compile time checks, and you won't be
surprised by code that doesn't compile if you just change a config option.
We've seen that way too often.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240104113412.7040-A-hca%40linux.ibm.com.
