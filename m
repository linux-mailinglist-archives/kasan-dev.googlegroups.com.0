Return-Path: <kasan-dev+bncBCXKFB5SV4NRBQHVTWIQMGQEEZIFQFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DF7EC4D1C46
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 16:48:17 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id u191-20020a672ec8000000b00320707d98e1sf1500553vsu.6
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 07:48:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646754497; cv=pass;
        d=google.com; s=arc-20160816;
        b=I6yhL0hu0SNDDUWIYboy4WXDRLrhv6fKZaMbnlAdveZvmA2nDyes1Jx5UFdaJILu8p
         YAHgwkSrmfiTibNtuJ16VI38QBUIybMSB33MQ9RS2L4P9NO9hCeAjqOzUg7+R09tIxeF
         9uRbJS+TE8WFS/3WVZTv1u32FM2VCf++LcS1EbYGXC3zUr0LPAxiNMdRiJ+Gz6PTVTUQ
         S3zZ271tQQRnYaXG0tuvDzU4YePYhGr+j0DOGZU40DzKN/FxkG7NtfMLvLaWOSoPb9jU
         b86ppLsmxTAJdsDXIr/0x+pAQsZH+o7ul4Q2OZMag03zOw0LFXXGrfvFO7vgjuJ05Vxl
         svQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3ZTBJ4+euzRAOjC6GpFAmeeHBr1Udw1BHE9REI/bKY8=;
        b=fRQd2HeMbaC/+Xvz8Ai3t02TkL4f51nNMKqN18u2UJyNXp7eXRsZSSPlRU9iidyfBo
         m3bKZm1hmnBkmZo84QWABng4/iqWrr8jTipiv7Dmf1PIUWVymKx2jpaVsBVbBh2QD6SG
         4Aq3zyw1nSMqZhzviiWETLzYtH6BLS8wfdwHrbfQmvaYB2URQfvgq7Mo4l/z7J5chSBn
         3uu1bXIwDHsZ+WW/jBXy4TNq4IzJzipt+nneLUYhpz3CQEvJbrLn1jDJweFIe3LFCsgS
         E+R4e+3K1g1zNSB2l0vjq+MPH3wTX9arMMdHzYne5pNvRARGx+f3Hslez4IWs8Gb3zj5
         HJLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=k0Rh9qRi;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3ZTBJ4+euzRAOjC6GpFAmeeHBr1Udw1BHE9REI/bKY8=;
        b=tg8CL75DfRoHShyAsc8krP3HRhW2hHIZXjyn2c3yE2WbQGawBvkY9HvVgQSYWzHA3n
         im1Gx3q5dJh7FpIcwyu14trqOeYTQG/9MZSQJsZzWm+bIjxmvuolZ/hvvDe8uLqfrKR7
         cWorE0M//KsTmkwKP+xlO4XvztQOdjv4U0CoABbcTQOgOfaErob1+48EptZdQ6+X2cUh
         dcC1BnECN3HpIhOqO1zE384KZLSjsDLnKgYHZzaOVWSdkN6ShIpBVDO3xmRfi3pNcAQP
         1Xg4WMjyAy7GsA8KL5/yMEm+AvofQ/RmRDeRnjMu1sdjQzB9RKJ+vQtrHbgvQ8eiNdTE
         kePQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3ZTBJ4+euzRAOjC6GpFAmeeHBr1Udw1BHE9REI/bKY8=;
        b=s90CYVNseHwZXZoDgVwS68jdpXcc+shk4Y3oZ9u6Acw2hQ+0+lbBoW+qpjk+uxf7MI
         v7SUBFUncu2waOrYshqRpL7vEuY92FepUGv9rMa/GXWNE1XbFzEkrP99pbGrQcCRTmM2
         fVpewiUSuFFVdqm0k0njdoNurYlN/ihBWW5UXn8tPYEFYjVu5bdqOCbKVQRGVeDv7GEw
         zz6e9TheUjFCrn2WL+uzoSw7zqY5/C8+7hq/mj1WBwuTLqbVVoSiAHAG1EkWosuY3g6l
         9I8PTZ5rFpzL26Y3n+NyknSCS+dLKymn5bVyEUxweFREY+782zE4dx9bL+8LOW0ben9R
         h0fA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532GwWwY1w7u0pbOHW/8lpr5/7CgQDhs9+cauXRtowdtXBPPcoxH
	7OaHEX+K75biaVkcrOmfavI=
X-Google-Smtp-Source: ABdhPJw1TJkf+dTQo5aC5TAp/g0dj2dQ7hgzD9XhTIpBqxM8AHSB2yOSSk2leGafHRQ08pykh44O2A==
X-Received: by 2002:a05:6122:886:b0:332:6a9c:902b with SMTP id 6-20020a056122088600b003326a9c902bmr6650432vkf.40.1646754496839;
        Tue, 08 Mar 2022 07:48:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7409:0:b0:34a:ff4b:9ae with SMTP id r9-20020ab07409000000b0034aff4b09aels1037640uap.3.gmail;
 Tue, 08 Mar 2022 07:48:16 -0800 (PST)
X-Received: by 2002:ab0:481:0:b0:34a:b2c2:6b83 with SMTP id 1-20020ab00481000000b0034ab2c26b83mr6337803uaw.62.1646754496364;
        Tue, 08 Mar 2022 07:48:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646754496; cv=none;
        d=google.com; s=arc-20160816;
        b=JwOnnvuN6ZbHE2CaNmtQ3DszklPUBBYNIw3q5wuSLjiJrmdI0eQTfXkgHCLOD6fib9
         bLzIOUcAQVDzRQci+bWL+g26qBCG4nTYODrKxt5a6RKTWEZdz5tuREhatxmzQURuxRdF
         fzUhgon7pbXghRx4olatja90PyT83MvEb0nOj8VVMIOIBhotvcpXZX02D7Lty1iy++41
         /4LdE5ylz3THEi3YdBImh3c/9Sfzp563auY1PBNEuQP4C6R92uBxpbywIjnwxceMiFjA
         HTprbl+Nts4rjd4qfn2VNCppkCcm73dmb/FmHWohCBLjk8VKH6r8683k6Be6JlLP2F1J
         NJwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=389I0VekDwwKFjdESH9plHsPrSJCLzJsP3F8jIyG3CQ=;
        b=RwqLx0kFQK7fvhJNKH+9+5hIGkcp7euNJQdO8gJ1T7BjvhPVGDTMtmwttSwg9n9Po5
         WN2RF0hAXiMqRl23vHQXXvX2QB8+I4E3ohksLPx/uhc1UUJLmsX5eB01CCNyri0EYeAT
         /GWWTzRHT/OLeRViizSG3E7459uDX6X0TkqXg/RoM/s1x4mlsPZlf6bzu6N7So4HCJqr
         Y7V8ZoGAt2PG+C4DrjFvhnSU1C+Y4TAgDGtlyx3QkV9XRss0UCk2SRK+RuTXzshRe8hM
         xi0k8gTCoyWC1SqaY1gt5In8Vu1NnENIIwgDItWAL4n6gJAFzYbFKzzc5XmTZd5zGip9
         XjKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=k0Rh9qRi;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id f83-20020a1f9c56000000b003293e1f1b21si914459vke.0.2022.03.08.07.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 07:48:16 -0800 (PST)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 228FjCGK012295;
	Tue, 8 Mar 2022 15:48:11 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3ep03vmx3x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Mar 2022 15:48:11 +0000
Received: from m0098393.ppops.net (m0098393.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 228Fit4i026728;
	Tue, 8 Mar 2022 15:48:10 GMT
Received: from ppma03fra.de.ibm.com (6b.4a.5195.ip4.static.sl-reverse.com [149.81.74.107])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3ep03vmx2u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Mar 2022 15:48:10 +0000
Received: from pps.filterd (ppma03fra.de.ibm.com [127.0.0.1])
	by ppma03fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 228Flwmu020523;
	Tue, 8 Mar 2022 15:48:07 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma03fra.de.ibm.com with ESMTP id 3enpk2t7un-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Mar 2022 15:48:07 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 228FatBU37814606
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 8 Mar 2022 15:36:55 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 502074C040;
	Tue,  8 Mar 2022 15:48:04 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A0C7C4C04E;
	Tue,  8 Mar 2022 15:48:03 +0000 (GMT)
Received: from localhost (unknown [9.171.12.198])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue,  8 Mar 2022 15:48:03 +0000 (GMT)
Date: Tue, 8 Mar 2022 16:48:02 +0100
From: Vasily Gorbik <gor@linux.ibm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>,
        Marco Elver <elver@google.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux Memory Management List <linux-mm@kvack.org>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Peter Collingbourne <pcc@google.com>,
        Evgenii Stepanov <eugenis@google.com>,
        LKML <linux-kernel@vger.kernel.org>,
        Andrey Konovalov <andreyknvl@google.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: Re: [PATCH v6 31/39] kasan, vmalloc: only tag normal vmalloc
 allocations
Message-ID: <your-ad-here.call-01646754482-ext-2781@work.hours>
References: <cover.1643047180.git.andreyknvl@google.com>
 <fbfd9939a4dc375923c9a5c6b9e7ab05c26b8c6b.1643047180.git.andreyknvl@google.com>
 <your-ad-here.call-01646752633-ext-6250@work.hours>
 <CA+fCnZdCZ92BxnympNoRP8+3_gGDMZQgTeaUpga3ctuRq8zPYg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdCZ92BxnympNoRP8+3_gGDMZQgTeaUpga3ctuRq8zPYg@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: cnJS0jaZ73zICUKHNxVHC0PllMeIiWKp
X-Proofpoint-ORIG-GUID: SJYIB1z1q2pLAWtXKFCctbL9yPjmQfqd
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.816,Hydra:6.0.425,FMLib:17.11.64.514
 definitions=2022-03-08_06,2022-03-04_01,2022-02-23_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 mlxscore=0
 spamscore=0 clxscore=1015 malwarescore=0 bulkscore=0 priorityscore=1501
 lowpriorityscore=0 adultscore=0 phishscore=0 impostorscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2202240000 definitions=main-2203080081
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=k0Rh9qRi;       spf=pass (google.com:
 domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=gor@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Tue, Mar 08, 2022 at 04:30:46PM +0100, Andrey Konovalov wrote:
> On Tue, Mar 8, 2022 at 4:17 PM Vasily Gorbik <gor@linux.ibm.com> wrote:
> >
> > On Mon, Jan 24, 2022 at 07:05:05PM +0100, andrey.konovalov@linux.dev wrote:
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > The kernel can use to allocate executable memory. The only supported way
> > > to do that is via __vmalloc_node_range() with the executable bit set in
> > > the prot argument. (vmap() resets the bit via pgprot_nx()).
> > >
> > > Once tag-based KASAN modes start tagging vmalloc allocations, executing
> > > code from such allocations will lead to the PC register getting a tag,
> > > which is not tolerated by the kernel.
> > >
> > > Only tag the allocations for normal kernel pages.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > This breaks s390 and produce huge amount of false positives.
> > I haven't been testing linux-next with KASAN for while, now tried it with
> > next-20220308 and bisected false positives to this commit.
> >
> > Any idea what is going wrong here?
> 
> Could you try the attached fix?

Wow, that was quick!
Yes, it fixes the issue for s390, kasan tests pass as well.
Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01646754482-ext-2781%40work.hours.
