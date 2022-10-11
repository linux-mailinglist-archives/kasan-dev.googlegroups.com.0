Return-Path: <kasan-dev+bncBCYL7PHBVABBBEP5SSNAMGQE3DHW7AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BE9D5FAFD4
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 11:59:47 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id z8-20020ab05648000000b003b48415d88csf5188763uaa.10
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 02:59:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665482386; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGW9E86Gl1jpzC+Mz8VTcpuWfTvjPZxayY6MWE/ONmPFU0TGK+Pb8g5ykebopTMXER
         gDboI7ug5woYjliZP+sHs5BlfZyvVTPt84K+geqRk2Jsptgyp9GDmZrP+HlWmCQh+Njl
         MRHdjlJj0J9rbO1s1bVnwpk0Vweco89fhPnwpsnB/CH42BVmoQnretlyez642bMZUSmy
         RHA7AH70FnlDvN3zvUSqmApxiD3VcWmLu6wf/UcMapObFLPwTl6g0yDQIecXcxbLDYJl
         Nf8nl/3JUviOtzM1eKJaG18Nj9KYt4pYCi6ii2rDChRXakK5miR4g+XYzYLK9L+lJej8
         ZmAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=lmuHa5JRukjP0Wl6dup2JolVJA0lpWHWluBzz5H+t9U=;
        b=ELfT/n2/rSPhyDADJVx1RUYQG1doPEFqsG+3V0hftIW1a0jgNBQ6BCoB+i88vaJEka
         Tp/t4GSru9qKmNuLS1dBRPP9Y1eH5rZevSNW28USbc/0mU9413xkmGzY+BVJm9q0tTaB
         MqVcAROGw3SrTqGq1yGn27p3zXJ/EbkzSqntetwZRh6EiASmBfx0DuCIGB4oD0J+BywK
         Xh0VwxunbKtSe26fD6Q9o171/iyqwv09xe3uEJ9sWBnrAlwRF2+BMLMs9fOpKCb+OKOp
         3AEQiFqNU7BqCGrvvn51++x/if+pqkjVxmJgatHL5vzXRqv/327ltimziFOX1drSG7od
         ljiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=b9WrKX6E;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lmuHa5JRukjP0Wl6dup2JolVJA0lpWHWluBzz5H+t9U=;
        b=qRmc1l04a2eYbBTVkXLZrwqkcqKEYWVQXQRweZS8tKA2CdEbBdgJn6pt7+btrsXbwq
         yJK/2RP/GDNVl6mdZ34p1Zjq7tsGvvCMpmU2wifzmSyfJqT1Cnp/HHls5hss7mse9csG
         JuHb48rDfUSZQb0CBxCcBIWRZ8NmT0ChpwrUvYTjmYqwLjFxjf7x/AZnfEjZh0p8hyZP
         sKrB7cZ/pnVFJa/a9TGKGALEyskYAuiXW/5kGxI5EtB4wxSAxzdDlmSGDcwdC+HfHO8o
         wNg+1OtKp5R91qA68HOsONZzP2wvGlzIuLQg4zW70GZ3FVS8OmuSbACM+BA9IFGOhqjG
         ZfaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lmuHa5JRukjP0Wl6dup2JolVJA0lpWHWluBzz5H+t9U=;
        b=hJWl8k+l6c92m62+zlESW2tXeDmLyh14N8IUCWcJ0tHE5AaFULvupp3+SDR5bpSS1s
         eCPjFIEcAxD8LYd4kv1GNNbOJdbUjVk8sodVGela2NqDoRAxJvkDqNp06tpl6w7PnalD
         4azbv+mUM8Ip+VQLAR8WAzRtsm4SbR3PWyjRT6sX72Z+uwTbHEbRJz4HQ325L4wsAHZW
         o3qLMgu+pwzh1/gcXOMY2RZ/6JVZc286EcH3RxtEicKqaMYLaVmHiuccHTBp+N11gzhB
         vJ8gPvtJlveJGsZm46WHLetDJQbBeDGnvb/E9xehAwCN2PQfd3PHXa2ZU5K3ikOMhsqk
         OIqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1hS/sIqPIqBY75uvMkwtHWPCTrJuVFXnDaWetv4jUmO5ltaL3j
	JdJuxezzhmot9AKgCnggnD4=
X-Google-Smtp-Source: AMsMyM4N6AklHWDBWofWNiZXVVpF02zYWz7B8g8a0xdi74i6mssgYyQhg3KxfyEruEJwh2+4Eg3BmA==
X-Received: by 2002:a1f:e444:0:b0:3ab:2991:56d1 with SMTP id b65-20020a1fe444000000b003ab299156d1mr10505161vkh.16.1665482385981;
        Tue, 11 Oct 2022 02:59:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7588:0:b0:3be:7b4c:e320 with SMTP id q8-20020ab07588000000b003be7b4ce320ls974237uap.8.-pod-prod-gmail;
 Tue, 11 Oct 2022 02:59:45 -0700 (PDT)
X-Received: by 2002:a9f:35a9:0:b0:3df:a108:f5fd with SMTP id t38-20020a9f35a9000000b003dfa108f5fdmr8566143uad.4.1665482385503;
        Tue, 11 Oct 2022 02:59:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665482385; cv=none;
        d=google.com; s=arc-20160816;
        b=SE+XzF8RVU9aeCXdDsqAek7xF9+/LBPmXMvC8SyRSzWtsrdHlZg9LffOnEsVPg4glt
         q3ECCopx4MM1YOc/tTBya2AmP5GqZTV+vQAubPTmJxR5jMxDEicHzibEM8nki5B185QV
         PQMDOShMmqHsSzTSR6nDueBYER3ZBKWQLHvrxyd61n3v2uDRseLM/g8rvjRzpk6Dlqla
         4VgOU2wXts6pozmkLDKWnMS36fnhdaugyaIuoGj+xoo4TfW5rB8E2t1J0d6C1H5zr2Y3
         RvidhkPBGNmYg6sJ3cyatR12hB8TJuEgSufD4XU6cltZENykn/DwVkCYe++RzZnEc71c
         ZQfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=rsi++8Kv70P/yyaG5N63ukoqzzaV32xXultfsAN+sgY=;
        b=rwzMNzV20uSGyrbqwaQzj4E/egFR204onwPaMAtdNsN/+DcftK6YlNbNv+wDwf80oj
         TfuOHf49eJqK+gFiE/s84jJLkwWSRIR0goES48TmA/coJ7hXxu4/d6gYoHwmudG6Le7J
         SCZfJofeseb6GTT/j9qTHLzFM1ozhdAgI1nhQtP6yu3L01eYbTemv39kYq/bI9P4PHtx
         m0Myk2ZLXuoPHaW3H6mbtTLHVCaMxniI/shsxX80pyl9El5V3I5LVRoqHyuEGPKY+3WV
         VjIyNvXW7/hdF8EgWq7jqX7KqhzteLMgJaaK6c73hL19mBHqc5l+zCW7TI9oh9URPmod
         36RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=b9WrKX6E;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id az10-20020a056130038a00b003b38a9f6c6dsi1597165uab.2.2022.10.11.02.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 02:59:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0187473.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 29B95O0I029402;
	Tue, 11 Oct 2022 09:59:08 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3k55j4he2w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 09:59:08 +0000
Received: from m0187473.ppops.net (m0187473.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 29B95aAH029805;
	Tue, 11 Oct 2022 09:59:07 GMT
Received: from ppma04ams.nl.ibm.com (63.31.33a9.ip4.static.sl-reverse.com [169.51.49.99])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3k55j4he1k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 09:59:07 +0000
Received: from pps.filterd (ppma04ams.nl.ibm.com [127.0.0.1])
	by ppma04ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 29B9oZnZ003829;
	Tue, 11 Oct 2022 09:59:05 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma04ams.nl.ibm.com with ESMTP id 3k30u9c3hv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 09:59:05 +0000
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (b06wcsmtp001.portsmouth.uk.ibm.com [9.149.105.160])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 29B9sJie47120848
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 11 Oct 2022 09:54:19 GMT
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 10739A405B;
	Tue, 11 Oct 2022 09:59:02 +0000 (GMT)
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 30E5BA4054;
	Tue, 11 Oct 2022 09:59:00 +0000 (GMT)
Received: from osiris (unknown [9.152.212.239])
	by b06wcsmtp001.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 11 Oct 2022 09:59:00 +0000 (GMT)
Date: Tue, 11 Oct 2022 11:58:59 +0200
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
        netdev@vger.kernel.org, sparclinux@vger.kernel.org, x86@kernel.org,
        Jan Kara <jack@suse.cz>, "Darrick J . Wong" <djwong@kernel.org>
Subject: Re: [PATCH v6 1/7] treewide: use prandom_u32_max() when possible,
 part 1
Message-ID: <Y0U+Y+VBqefDAZRG@osiris>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
 <20221010230613.1076905-2-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20221010230613.1076905-2-Jason@zx2c4.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: TTro46mI91bs851nCMcm06VmbEuVu9s2
X-Proofpoint-GUID: 7jolh1dfZQU53Ghsw2G__g5RiD2MLnMM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.895,Hydra:6.0.528,FMLib:17.11.122.1
 definitions=2022-10-11_03,2022-10-10_02,2022-06-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 mlxlogscore=399 mlxscore=0 priorityscore=1501 bulkscore=0
 spamscore=0 clxscore=1011 malwarescore=0 impostorscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2209130000 definitions=main-2210110053
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=b9WrKX6E;       spf=pass (google.com:
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

On Mon, Oct 10, 2022 at 05:06:07PM -0600, Jason A. Donenfeld wrote:
> Rather than incurring a division or requesting too many random bytes for
> the given range, use the prandom_u32_max() function, which only takes
> the minimum required bytes from the RNG and avoids divisions. This was
...
> Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Yury Norov <yury.norov@gmail.com>
> Reviewed-by: KP Singh <kpsingh@kernel.org>
> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4 and sbitmap
> Reviewed-by: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.com>=
 # for drbd
> Acked-by: Ulf Hansson <ulf.hansson@linaro.org> # for mmc
> Acked-by: Darrick J. Wong <djwong@kernel.org> # for xfs
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---
>  arch/s390/kernel/process.c                    |  2 +-
>  arch/s390/kernel/vdso.c                       |  2 +-

For s390:
Acked-by: Heiko Carstens <hca@linux.ibm.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y0U%2BY%2BVBqefDAZRG%40osiris.
