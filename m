Return-Path: <kasan-dev+bncBCYL7PHBVABBBLH5SSNAMGQELKOTCMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A59875FAFD7
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 12:00:14 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-131e72856e0sf6471649fac.9
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 03:00:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665482413; cv=pass;
        d=google.com; s=arc-20160816;
        b=TcrSgNh3q/KHExvN7n5DOUD0NSYkwnEmUbm2bTgnb2dEl0e4zEYp2UAVa6Qux5TKnR
         1o/IK8kwNsNeoyU1lpx9MmbjwtSUi2OTZKKT9fU/+CjBe8eid1++rWE4bzVdcQjR1kL/
         MECU7P8BfhhY3vPjWl91O5XEDY25D3kvznbT9+Ji+An2FoJXVqHbF6H73t5OLaLtRTX7
         lj+gG488HMcZKTaO6+xFlM44ijZaM8UFPleoINLIfOOGmyaBOauWFh71NTE/C7357099
         Etw230My5iS5ijkbVoLDFQu3W1zXK1srmG7cuNPRpRT/0dimaQXTlHK/cTOx27l+rUw3
         6hJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KcZ6yuyscXKQJgV5M9Um+Z6yFgy99RO2JbhPA0ylaKw=;
        b=e8kminRcK1MtbsdpmzPnNncA/xzrXOY8XXZfh/1LgxQ6aLYL6ElJT8ULWDa//wHfoP
         j9E9CTMwFAKwlLnhqEGg0Qs7sVvub1inZfRLbconJYPLZnofpHEwIXTTGxaUEIUAZYAs
         3mt78sFp0KuWhNvKX2RrzXSxW7PwJPixkFr1WmMfQCoXFp8H9Cv1+y2y9RYRX7b9dYeq
         xqA3MK1KouIqnKjY3EBe9DQ+gTwfF1pCXqsEp/zZo50cxJlATapadAzU9ymWNrDvaQRf
         vhCqpmfhpXGe6fwDM5B7GshMLWV1HjAEzFQekNQ7x3UAebwb0QBCYWv14Hw8OjJcLKF6
         51Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MpaqjBwC;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KcZ6yuyscXKQJgV5M9Um+Z6yFgy99RO2JbhPA0ylaKw=;
        b=kdkV9gXrw0fBXWv4LH9xlXnGMXiPAuHXppWc001Cih95qvqUntMZMOeo7aYbi4htS+
         25K7Nra5uwogGziXcNrPSY2pZQrzCyAAiReXs8Vb68s2EgHnY6POFr19utzMPUlI4EtO
         Z/PbaTCDMz82ruDtYNNCR99q+mHb0ayuw+B4egJVQVoYa3r3UjwkwghCptKHeCqHMyUE
         adaqAyszBP37wsibkhwlPxLfifYC+qe0lbbSTPgklW52DLxjZ/lzeNH41bcFTj/HEulZ
         +2XX5XqoAkwZvxcPGjInF+CMkD3rdLZ3lDgWOPL7X5P9p3041rwbyjF3bK90MJvA9217
         ZV7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KcZ6yuyscXKQJgV5M9Um+Z6yFgy99RO2JbhPA0ylaKw=;
        b=FBIIBWK66w62zAK2YuGL8Nj27sEfDZBwJpa0wP2RIpuDttlrayaEod55FKr8sZY55E
         NPRtacPVWDVRJ/49c7XPTSYPNN3W1inJW3iOVPhcJJd4PE/ep1W7ACseDmrorwjjtStg
         zvboakXA4Rhckfd7KhKp0D2OHE/R9uApehtcYYFIKhs6HVuZ61ALILYNKKt4tC2YJupB
         2DqATBaHP1UPfaMWKb54DUwaaEzzKpwKQ0YBWltO7u/3VNznzH1R59D2FiK7vpOOvp8A
         MB6ly94v+Ak8/jS36nZb6BouX5Ojdh4b2mjoMlaRQSsSZxLYdK08fHn1OMD6PZut3bci
         qyZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf16qtnOO7fr2Jr4w/BA4h3tvlzRLEecB8mqLJczkOVC3ySwHw0c
	KDaptiOxoSZ62HEYuWnE0iA=
X-Google-Smtp-Source: AMsMyM46Hcv7TMZRClbDB20yo2Nwdyj3vqq9/AiMawDRPdjC8oSPZVUjM8YJyHm6XNrgy+/3EYELIw==
X-Received: by 2002:a05:6830:3499:b0:661:ae23:35cd with SMTP id c25-20020a056830349900b00661ae2335cdmr923086otu.133.1665482413033;
        Tue, 11 Oct 2022 03:00:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7381:b0:127:568b:5cc9 with SMTP id
 z1-20020a056870738100b00127568b5cc9ls4179605oam.0.-pod-prod-gmail; Tue, 11
 Oct 2022 03:00:12 -0700 (PDT)
X-Received: by 2002:a05:6870:9a2a:b0:136:408a:e3b with SMTP id fo42-20020a0568709a2a00b00136408a0e3bmr8848092oab.41.1665482412642;
        Tue, 11 Oct 2022 03:00:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665482412; cv=none;
        d=google.com; s=arc-20160816;
        b=P//cI27m2NfCqMoe8ddpdsZrWYTDWs73NEK3Ihkn/5xbWVHSKWbxpDGBm76RJsup/O
         DD/SY1v2LQiB+/bQLMrARPFTAySqkdiRmqt3kRaJ+JLLYo6k4Q2UNfLQczKm7n5klE5t
         CQj68lGrMuUSKVzEtvGuPQgxqGV0EmRwHNSDEcD6JJjr4Vn3JfEnsdnJvm8tVN5S9TKG
         3SnxAJoHDNVFdsWxyywSdWdJ1RTok51F7f4mj6cZroGCVKdpz1gQNHeNp60gdGlB9igD
         iB70xCSAyeFdCPOKaliv6cEJIAIS9ur3vsTls3nW1Ufnsh9cYU/3sH4twSTMssKSPhj0
         baMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8TskdJLbpvnFxRnfdNl/vSrXgO12T2EGmWRBhayoU1c=;
        b=NWE0gHl7EcFYBgIlH2oXj743Ar4E8DNRfWg3l5ljbE5rdeaiDJubVMEAgLfCQEoZuy
         c8MDZCPt4gM/9GWmPj2Vq2B3RbzzEG1aB0yvhiq0ye4jxhvI1NUgZEcE4nSa+anHWkZe
         M3TuznzVOejSGDHdi+42vl6mlQ1A8ss61FhDGIX4J9iGHuBPXPhxuz3aQ+AqG39o+s2K
         txTotRGr37j5LgvZ5i7tAT+gnblhf1RgN+r40JqWTSYoEjrdStqoRDG0t1MYinxQ8r4P
         xtv6WGmsuDpIsZMHjJNF3N10K5SyeE9Cg2frc/1wgMMuiM9LA4suUxMKfilJyJRBpIEQ
         3TpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MpaqjBwC;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id y22-20020a056870b01600b00131c76edf09si454340oae.5.2022.10.11.03.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 03:00:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098404.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 29B9tKHc006567;
	Tue, 11 Oct 2022 09:59:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3k569g048p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 09:59:50 +0000
Received: from m0098404.ppops.net (m0098404.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 29B9tN6w007536;
	Tue, 11 Oct 2022 09:59:49 GMT
Received: from ppma04ams.nl.ibm.com (63.31.33a9.ip4.static.sl-reverse.com [169.51.49.99])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3k569g047d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 09:59:49 +0000
Received: from pps.filterd (ppma04ams.nl.ibm.com [127.0.0.1])
	by ppma04ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 29B9otYM003872;
	Tue, 11 Oct 2022 09:59:46 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma04ams.nl.ibm.com with ESMTP id 3k30u9c3jg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 09:59:46 +0000
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (b06wcsmtp001.portsmouth.uk.ibm.com [9.149.105.160])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 29BA0ET842008878
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 11 Oct 2022 10:00:14 GMT
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 77311A4060;
	Tue, 11 Oct 2022 09:59:43 +0000 (GMT)
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 842F1A405B;
	Tue, 11 Oct 2022 09:59:41 +0000 (GMT)
Received: from osiris (unknown [9.152.212.239])
	by b06wcsmtp001.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 11 Oct 2022 09:59:41 +0000 (GMT)
Date: Tue, 11 Oct 2022 11:59:41 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
        Andreas Noever <andreas.noever@gmail.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
        Borislav Petkov <bp@alien8.de>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Christoph =?iso-8859-1?Q?B=F6hmwalder?= <christoph.boehmwalder@linbit.com>,
        Christoph Hellwig <hch@lst.de>,
        Christophe Leroy <christophe.leroy@csgroup.eu>,
        Daniel Borkmann <daniel@iogearbox.net>,
        Dave Airlie <airlied@redhat.com>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        "David S . Miller" <davem@davemloft.net>,
        Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        "H . Peter Anvin" <hpa@zytor.com>, Helge Deller <deller@gmx.de>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        Huacai Chen <chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>,
        Jakub Kicinski <kuba@kernel.org>,
        "James E . J . Bottomley" <jejb@linux.ibm.com>,
        Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
        Jens Axboe <axboe@kernel.dk>,
        Johannes Berg <johannes@sipsolutions.net>,
        Jonathan Corbet <corbet@lwn.net>,
        Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>,
        Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
        Mauro Carvalho Chehab <mchehab@kernel.org>,
        Michael Ellerman <mpe@ellerman.id.au>,
        Pablo Neira Ayuso <pablo@netfilter.org>,
        Paolo Abeni <pabeni@redhat.com>, Peter Zijlstra <peterz@infradead.org>,
        Richard Weinberger <richard@nod.at>,
        Russell King <linux@armlinux.org.uk>, "Theodore Ts'o" <tytso@mit.edu>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
        Ulf Hansson <ulf.hansson@linaro.org>,
        Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>,
        Will Deacon <will@kernel.org>, Yury Norov <yury.norov@gmail.com>,
        dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com,
        kernel-janitors@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
        linux-block@vger.kernel.org, linux-crypto@vger.kernel.org,
        linux-doc@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-media@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mm@kvack.org, linux-mmc@vger.kernel.org,
        linux-mtd@lists.infradead.org, linux-nvme@lists.infradead.org,
        linux-parisc@vger.kernel.org, linux-rdma@vger.kernel.org,
        linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
        linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org,
        linuxppc-dev@lists.ozlabs.org, loongarch@lists.linux.dev,
        netdev@vger.kernel.org, sparclinux@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v6 4/7] treewide: use get_random_{u8,u16}() when
 possible, part 2
Message-ID: <Y0U+jRHiYFXTYIN7@osiris>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
 <20221010230613.1076905-5-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221010230613.1076905-5-Jason@zx2c4.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: jYIdds8I8OnV55xqlHcn_K1Fpf49bihk
X-Proofpoint-ORIG-GUID: nBSabzQRwIftT0z0mh64gqfTqchstuk_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.895,Hydra:6.0.528,FMLib:17.11.122.1
 definitions=2022-10-11_03,2022-10-10_02,2022-06-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 bulkscore=0 priorityscore=1501 impostorscore=0
 malwarescore=0 clxscore=1015 mlxscore=0 spamscore=0 mlxlogscore=445
 adultscore=0 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2209130000 definitions=main-2210110053
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=MpaqjBwC;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Oct 10, 2022 at 05:06:10PM -0600, Jason A. Donenfeld wrote:
> Rather than truncate a 32-bit value to a 16-bit value or an 8-bit value,
> simply use the get_random_{u8,u16}() functions, which are faster than
> wasting the additional bytes from a 32-bit value. This was done by hand,
> identifying all of the places where one of the random integer functions
> was used in a non-32-bit context.
> 
> Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Yury Norov <yury.norov@gmail.com>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---
>  arch/s390/kernel/process.c     | 2 +-

For s390:
Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0U%2BjRHiYFXTYIN7%40osiris.
