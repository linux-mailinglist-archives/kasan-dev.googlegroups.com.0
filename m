Return-Path: <kasan-dev+bncBCYL7PHBVABBBQOJR7BQMGQESSZCFIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 3043FAEFAD4
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jul 2025 15:38:14 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-23692793178sf48496675ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jul 2025 06:38:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751377090; cv=pass;
        d=google.com; s=arc-20240605;
        b=gbyGt40JdJgeQ+AX8KWQWaLfNqEJShwSahs9mEqbjCgS9JGIJS6/99LAIUF3w5cH7I
         yHx8iKQtUKCLXvYEdjlWozosHSnJ4IB7e17o6VBaE4+yiBZLotwptNl1RZZrpI8ski86
         BVMRI1EUL+2ujB/QpWfHkolXQCxw+8GDgII3fQuRrY2zqbhB9TwJrGLOByGiug+IeoHD
         2kOGJryyrzts76W7CTigF0oNVIBRwtxr8PCuZYAskrIj44oTcNdkVZ05fO+TAVX07dIR
         /hvzyd8bQNM1VU6RhtBqwopTRRNqIdPU8u4eI5rxb7TIXu+sRuDnyX9OYrXOpcZ/Y1OJ
         xS5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BPSO4yQmtC7spKkKqjuf1UHMb9bkvDYtlPPM3pyoSzs=;
        fh=UOpY12tC0vWCFLQ2j+hE24Zafb7vvxB8EtC05mdQ1nI=;
        b=ZhqALUZzUCWgDApMEVMSQWzrwC7eCCBk6qD84YstDvfXXbK/jZsKZXQ9h4HOBCFfH/
         562d5YHvOWNwzdXmP1a/H9Ec0c2HsLc0+Cj6lJ9+JzxGE5ZqgNfiU1dvIKZyloJdQqRG
         in2UgS4Yl+l3D53Qd4no8wLGxlGwHy+m9uYKqAOIAfoDy2bdl3vYKVzFRrYGMLnpqcZF
         uAR1B8a/kVmxWsjAj/12GMO9ji9klIb8v45X/lZSRMXzuRE60sOON5nZwy6b8YLrqEuW
         ezH3OtMgZE7Drsjd5os6NAeB0PUT0VUPMHQF8aSVtIYiw0NV8si7b02gXceAGAlPMtJN
         okQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="rlhS3ni/";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751377090; x=1751981890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BPSO4yQmtC7spKkKqjuf1UHMb9bkvDYtlPPM3pyoSzs=;
        b=qZmUJzVA00JSRuka7bgOJ+jD1mcuGpIlYeGYGOjhDAovxxsb/674z5+K9aGdluti/4
         CxY3nFj+of1IuReGml7We5uwAXBdzjg8YT9guMPX27tcIgXNmaEyIZ05A7PPwDwq6nyi
         sM3RIPbEpUsbBhNEak4WAtqU4zJSeGLQusv1V02hdw0yTdjGWVvn+tWJa5OgpgiPj8aZ
         kuEhTlCzAQrKdEhCMk/+RgimKIFxFUXRUSoAF4rErfRNmFBarHRuYO98SzjXolsWvi14
         +9JUJ/JKMi446WWRxOxVbuWFYUriuSO2Bbls8UCkxVpNKUUttKYNRA5iTEXLkxjjZfAu
         B7gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751377090; x=1751981890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BPSO4yQmtC7spKkKqjuf1UHMb9bkvDYtlPPM3pyoSzs=;
        b=WBsr/CcDCIrwaYKWkghvj8RAgal9LCA23tAHft5SHWwKdPRn0cyoByyXB4hT6YwIY3
         e7Ewp0KT0gaQIxdB8MP7IE8zUIvE5v/p1amDPtowqut975BSQV7/XDO1eu51uTGX7BIw
         eUdh3SzlpTpFGfkaeuFfcQyHwEAJwdnEvB7v8/O6Z6erLKiYm+10WPapHKgZsvP16t7j
         6TFICpKnVUey0ig7di7EpuLLuQ4wunXTKT8UzETR3yoNqTeyNHuwsq50yOFYuF2EnsPf
         OKrdVbeVRwW+/k1wWWnVhdRIty+YI368EcWZpNire6t+OJiZn72FjRfIl3KjR5JkZpZS
         I57Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhQGehFIWqMZ6Cx2IBGGs/yQ1cnIaAz1Cbx3rZFZzbh7X0IgLX4rVDLvI2qaN4rgralYwgaA==@lfdr.de
X-Gm-Message-State: AOJu0YzUzIHAD2FJmL9YL5qXcJElebnvLFz6fDCCMlcujyKZ0pqUpYNV
	hTn7ps6YthR0v50kIVF3szNJeNpQetK+/oVP7Jccd24zHrhEPuGio0JP
X-Google-Smtp-Source: AGHT+IFDHdPd/y3mDb2VeHe/caDceS4tf2ZqlwUEn7EH1KqVCK/BoMxJ0rxg6qxzsMKCrriCNCD6YA==
X-Received: by 2002:a17:902:d504:b0:235:91a:4d with SMTP id d9443c01a7336-23ac45ead66mr287728915ad.23.1751377089665;
        Tue, 01 Jul 2025 06:38:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd1D6eRHjCVfFPh1I1orBSlhnLBwYdtl9j8bvYpAvC1QA==
Received: by 2002:a17:903:23c3:b0:234:cc1a:5845 with SMTP id
 d9443c01a7336-23b3565f8a8ls6072115ad.0.-pod-prod-04-us; Tue, 01 Jul 2025
 06:38:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyI3Mzfgh53j7qwndmaXeCcOB3Wiye6fvIfJFmkjsiYQJ59YiiejrOqu+eL8kd3qE5Wn07EthBAZQ=@googlegroups.com
X-Received: by 2002:a17:902:d492:b0:234:f6ba:e681 with SMTP id d9443c01a7336-23ac45c0a2cmr322702095ad.5.1751377088366;
        Tue, 01 Jul 2025 06:38:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751377088; cv=none;
        d=google.com; s=arc-20240605;
        b=JLv0WSTB+DpTwXOXF1xGvP4fBgXZrUXpzw13aKbWhgFiG+RgN2SZtWI7Tkrjij7yGr
         E1qMYd0qeJHh4+onewYy09ictygkJi9HfikfQcDHjN3QfYOI31pvC4+rcRv4GUx43yuh
         u55rAaOZW94qWmtTNs+nVsRvYcVtG4njNQZ0elvQxNbk5gy2GPOjPCL0uF4vCD0sgf7Y
         KXyL3926n+Aa+eX76YLV0w6sciL0aEtXqBPml3cCDd05H+1XwlA8bd2/eA63ADl9keU2
         3dKat5TdiaTbT+WiuWHeYrW4Jj2HGvjTPyNnUICe8wJ6t4WdETcXRgqSrG2cvS5Ldmn6
         dIwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=AJLNXeZBidDlQX/9niKzeIA7RdIQ35aaPXD/kLpTeHk=;
        fh=rln/uaf8EX/fP/qVez5pwQASPkx6YXV3lrSy/MSMw0I=;
        b=BBXtY8hNIueW4So9egco+Bag+8UBWxfv7la9FTojCi1KrVRWWm0zBCDCjGzpVn13z4
         kIESJil+mIA6MvXZznFIm9IeUMudAy8BuJTEzky96/Trs0rOfW/TwbgzJch4lZKx55A+
         pw5rMKayDe+Ep7ykKGpNwxQH8LCE8XldR2ctwHmrnwo6eRPhLx1OlyYm3eDbwGbXgvi8
         Vtua/XFhmpFzrJiqM9gQrarr1ISc4Id3gCyLzbt9/nAX9OLQxt3EDIhyvjDnhCbW58pd
         rYKUp7CWtvdR38pXFXk7klW9iobFMH7QKCb7QfFlUdVHiwxUKRqDNXVwNXEMVFBZF3vZ
         gu7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="rlhS3ni/";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23acb3501e3si4625705ad.8.2025.07.01.06.38.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Jul 2025 06:38:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 561Ao1Lm012254;
	Tue, 1 Jul 2025 13:37:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j7wrfqxp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jul 2025 13:37:34 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 561DK4Af030631;
	Tue, 1 Jul 2025 13:37:33 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j7wrfqxj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jul 2025 13:37:33 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 561CFQo0021945;
	Tue, 1 Jul 2025 13:37:32 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 47juqpju2u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jul 2025 13:37:32 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 561DbRkS39191032
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 1 Jul 2025 13:37:28 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D64A12004B;
	Tue,  1 Jul 2025 13:37:27 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 79D812005A;
	Tue,  1 Jul 2025 13:37:25 +0000 (GMT)
Received: from osiris (unknown [9.111.81.242])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  1 Jul 2025 13:37:25 +0000 (GMT)
Date: Tue, 1 Jul 2025 15:37:24 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
        Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
        glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        linux@armlinux.org.uk, catalin.marinas@arm.com, will@kernel.org,
        chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
        mpe@ellerman.id.au, npiggin@gmail.com, paul.walmsley@sifive.com,
        palmer@dabbelt.com, aou@eecs.berkeley.edu, alex@ghiti.fr,
        gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com,
        svens@linux.ibm.com, richard@nod.at, anton.ivanov@cambridgegreys.com,
        johannes@sipsolutions.net, dave.hansen@linux.intel.com,
        luto@kernel.org, peterz@infradead.org, tglx@linutronix.de,
        mingo@redhat.com, bp@alien8.de, x86@kernel.org, hpa@zytor.com,
        chris@zankel.net, jcmvbkbc@gmail.com, akpm@linux-foundation.org,
        nathan@kernel.org, nick.desaulniers+lkml@gmail.com, morbo@google.com,
        justinstitt@google.com, arnd@arndb.de, rppt@kernel.org,
        geert@linux-m68k.org, mcgrof@kernel.org, guoweikang.kernel@gmail.com,
        tiwei.btw@antgroup.com, kevin.brodsky@arm.com, benjamin.berg@intel.com,
        kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
        linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
        linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
        linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
        linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with
 kasan_enabled
Message-ID: <20250701133724.10162Bea-hca@linux.ibm.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
 <CA+fCnZfAtKWx=+to=XQBREhou=Snb0Yms4D8GNGaxE+BQUYm4A@mail.gmail.com>
 <CACzwLxgsVkn98VDPpmm7pKcbvu87UBwPgYJmLfKixu4-x+yjSA@mail.gmail.com>
 <CA+fCnZcGyTECP15VMSPh+duLmxNe=ApHfOnbAY3NqtFHZvceZw@mail.gmail.com>
 <20250701101537.10162Aa0-hca@linux.ibm.com>
 <0400f0be-6b63-4bc7-846e-8852e1d01485@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0400f0be-6b63-4bc7-846e-8852e1d01485@csgroup.eu>
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=E/PNpbdl c=1 sm=1 tr=0 ts=6863e49e cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=kj9zAlcOel0A:10 a=Wb1JkmetP80A:10 a=voM4FWlXAAAA:8 a=pGLkceISAAAA:8 a=9kVARt_T5sJ8cKZ6P08A:9 a=CjuIK1q_8ugA:10
 a=IC2XNlieTeVoXbcui8wp:22
X-Proofpoint-GUID: RhlQaPOLrhblKhkyaR8lhPAADXtAGdqv
X-Proofpoint-ORIG-GUID: GE-5RQzQLYwKSRuZzvD2Ieha-YyMeWy7
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNzAxMDA4NSBTYWx0ZWRfXzvbPIXoCFjaA YSsHPBvgZlo8uA940MrN2nhmDxVD4yrQC0Blr21wUJpIGCnNlNYIEYn0zUSw91bxc/h5BgvR4PQ 8+gmBbA2hDH7/zlVMxuAui0Eg0eLEMWJxQ2/qxuHFp9hM4UusUMJXT1gcIBCqFiNlncOSMVN5PG
 Ld5QIjM0M/RCgeT9uZc/VoQiigSg/ZOOijWeB0ApYuTWAn6oTpW5uLedkuEa+H9gsqL267RFsh+ hsZlShfTEsI5dV1qJMDiUaZYdjPAHbt+/Y5HPTDay65IxTT2JuvXcJaPY0TCfNXxBXRdcK6cNfg T9ENU2fNsIOPb8h0JhVPWTlgBKUQsNsQrY0goxWlNMztanR3wFR0fwoMfm4Jvvns3yERoc04SWn
 h0O40s/ZVSLp603nO33OhPNgBdCIeQQuKGnHgEsIbQLtMjKZdTC34lQKNuw31VIbsvBRZVlt
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.7,FMLib:17.12.80.40
 definitions=2025-07-01_02,2025-06-27_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 spamscore=0
 bulkscore=0 priorityscore=1501 phishscore=0 suspectscore=0 mlxlogscore=594
 lowpriorityscore=0 mlxscore=0 clxscore=1015 adultscore=0 impostorscore=0
 classifier=spam authscore=0 authtc=n/a authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2505280000
 definitions=main-2507010085
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="rlhS3ni/";       spf=pass
 (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT
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

On Tue, Jul 01, 2025 at 12:25:32PM +0200, Christophe Leroy wrote:
> Your patch below is simpler than what I proposed, but it keeps the static
> branches so the overhead remains.
> 
> I also proposed a change, it goes further by removing the static branch for
> architectures that don't need it, see https://patchwork.ozlabs.org/project/linuxppc-dev/cover/20250626153147.145312-1-snovitoll@gmail.com/#3537388
> . Feedback welcome.

Yes, removing the static branches during compile time is of course
even better.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250701133724.10162Bea-hca%40linux.ibm.com.
