Return-Path: <kasan-dev+bncBCYL7PHBVABBBVX5SSNAMGQEZX5CQTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 92FB85FAFF1
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 12:00:56 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id s2-20020aa78282000000b00561ba8f77b4sf6984982pfm.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 03:00:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665482455; cv=pass;
        d=google.com; s=arc-20160816;
        b=fzlvB4LLOq4bBhkvguaqsjvykIT4sMtOEFyOP1jz+3djiF+BvBwQHI5JXmW+cqYfz8
         pSLmHum13ebsZDZFrh5l7hKmIcF05XAtNt0OlIP0T6/cihg7qCVZJoBBqOzKu1zrcpXI
         CdFBOh2kchIT7UgY1v7rAJDjK3XBy7de3D1fhOkJuFN47ZtR7PNLkJjt5SdI8cWZD0TQ
         trDFcDJXO3B11Yj9xrJyTbBkV83olL16lp4felge+DHvvsD+GOMfmyj6ZxfMiwq4UnxC
         Vcmze5hpUVXp4XYIp8Xu8ywQDP0t8dsJny0qT5thnR3+Mgb4L6E6v1xvlq9eGzUR3VrS
         ZocQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Q/0NR46IhoPbiWSIvFm5GVCeAHXV6aVo5A+CW9e7fmI=;
        b=nry/kNg9AqIBqwdI3hrgjIgc0n+lrXKRZJFv5qq+sEme8Ip2Z3l2vgmJPLdC2joN/j
         ymWj5HGqSXlYMpc3i4DSKkkaEKLBjAd7uGDaYx8Mr1Wdgvn65tBibP1AtFYgXq5Fn2EV
         GXVYnXT8h4JaCG72zOQvBPc+cfq1+MwCykB4JROo9tWLlNipesL3Gx1yOSlGi9T+rLGI
         KXgq9KtISLJsAsGgmoXzh4l9LQ4+qGqon+VtmxZdC0Ml0crNR3TVCM16Rvag1/Ymr2k8
         UAftpOW2+eHePapVFwzPyhln5bVAzFDTY3N0m7BelnUhfpwHEKlVjVkgXraWNCgLO3t8
         //yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OOL8Hxcl;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q/0NR46IhoPbiWSIvFm5GVCeAHXV6aVo5A+CW9e7fmI=;
        b=jilfEfm0c3TV2eSwsSPdkvAcYNVArkJxSE2QyeTpWcrKyxpzeydoQY46niL7oo0J7y
         FVQEP0D14Fa0FPG5SfBCHDOiI4knjMuPaaMKrqNc6CKa0EBxKYuBjx0hZXBu9KAM7QgW
         KKy85U84RRhG29Ogp0N6eNbd58nXtEO08ghC5ZESsw7TVjmYHRblhta0qEff0SYdhM1M
         ULBAjx3mxlKWpCNA/PO0V/x7F1BgGeOExy1eWz5cqMNWVDhd3CmW6yQr/IccTkXhhOu7
         NJroKf7Zf2px12cK05UkwhlLAuNCJwLy0kyNyOwmhc3U+x9FiFM45jeNOQeliFWAq/ZK
         VnCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q/0NR46IhoPbiWSIvFm5GVCeAHXV6aVo5A+CW9e7fmI=;
        b=oPK38ww2TFu9961fei3SjCXzUb1EbZ8PYneEFMtlrbFEYkiPyLKEfKh/wAbcBaCZN3
         WX52HRU7Ob3p8G+09lgaXR8K8I/ORB1/KzBjYqNIWvbvQd2SshHCp1+stK87fQ9a4IjG
         i4BcqPN9PjK5WST8fCTGL3wA9JOo0zK/fe8O7SwJ2wACjjGOsN/qtipkQy6eO4TkkCID
         VyRqIvjZVCZjgnSSH8E70WTvOGwf9R+V+JUb2iIG5H77KZtQBih7J24s1fPXXb8TMW+x
         pdYIF07p1Jeavw5BZsBxop9TFgOCG46Eg5P1xb/WnlP1Je04Mli904lUiLPW93MNzL6g
         M53Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1ooMTdYCTE2QC+3qrucsVOzGKo1fbEhNEEoLYvT7aVk3UUQwDd
	1mLkIJtFFEpLM6mTbUkvHgA=
X-Google-Smtp-Source: AMsMyM6eoqUelI/oTgijGp3PIJZO5dYcsW1wnQ5j8oZMSB9X/lq3JMwXcDDsNqm9tSAiSbYA05C2SA==
X-Received: by 2002:a17:90b:1c09:b0:20a:d962:5beb with SMTP id oc9-20020a17090b1c0900b0020ad9625bebmr37559971pjb.81.1665482454788;
        Tue, 11 Oct 2022 03:00:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d38e:b0:1fa:bc38:b125 with SMTP id
 q14-20020a17090ad38e00b001fabc38b125ls493513pju.1.-pod-preprod-gmail; Tue, 11
 Oct 2022 03:00:54 -0700 (PDT)
X-Received: by 2002:a17:902:b692:b0:176:d346:b56f with SMTP id c18-20020a170902b69200b00176d346b56fmr22975252pls.140.1665482454016;
        Tue, 11 Oct 2022 03:00:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665482454; cv=none;
        d=google.com; s=arc-20160816;
        b=Ud0vb3triGJg+duuQ/Sch+s0OhSHOBUUAsLUMcKiLGhZ2KMEdjrVwSss/K5RfdmlO1
         YzD/+fh3k55lSXojsAUxhrfIsqUs5mBVVvWjXgk8Dy7iU5cGBzUFKbYLwSw3YXvjcBIv
         VY8ldlrGE9xCTXMHwpfDf2+clICeu/cDaFKHTVNaHDrv3ypfpAx1awGOuXGY24cW1sxo
         DE+Bx3HneU2jzR6tj8m6MW3TtMGLKXX/b9xDTG/vreVN90i2GIUZhkLy+q4NapJR+s29
         ssj7I8BiawJYvy3YLI2eqDMWV5A1gotn/thkDoa5x4FvaQfCy1bsjQOu/gg5oNPr27f0
         HLDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=cDUY+1vkbBQhdXB58PoxjcuGNo/DQDfRq3ZaWdWqAzc=;
        b=Vc7ET8YCDrE3RPo5girA+3uYARpJ0LiTV8b8jN6WKlCuXrd+obBl+zhvJRUSwcsjjj
         vFWPoJG632XNYKI5niH06uClIedC+pRGumTH0iqxYOPOjGsuuI2gpkxCKKMGYZCoGhQ1
         jK6l7wtvl7kZNAcremdLYETNmPk0eLHUYOUG/7XE034MsWhslaEYas6dPSew9+KBbe/6
         fJu6GqvMRu/U35VmU9YthvfTX+yZaEEf1Nz+0Uyo/FMUFV1o9L4Tlx+kb8qiXEaajwD9
         LqULcTWKOjpS+DYM7Z5XOgpbSG26bBPLY7ASxASMQoymzyjYTxjBsIaIwivx8PiSUQc9
         JZgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OOL8Hxcl;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id i4-20020a63b304000000b0042ba5b4bd9asi424373pgf.2.2022.10.11.03.00.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 03:00:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098419.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 29B8RZ75032170;
	Tue, 11 Oct 2022 10:00:30 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (PPS) with ESMTPS id 3k4wya5aeu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 10:00:30 +0000
Received: from m0098419.ppops.net (m0098419.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 29B9uxZh014981;
	Tue, 11 Oct 2022 10:00:27 GMT
Received: from ppma04ams.nl.ibm.com (63.31.33a9.ip4.static.sl-reverse.com [169.51.49.99])
	by mx0b-001b2d01.pphosted.com (PPS) with ESMTPS id 3k4wya5aay-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 10:00:27 +0000
Received: from pps.filterd (ppma04ams.nl.ibm.com [127.0.0.1])
	by ppma04ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 29B9ok2w003853;
	Tue, 11 Oct 2022 10:00:23 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma04ams.nl.ibm.com with ESMTP id 3k30u9c3m9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 10:00:23 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 29BA0LdC58196252
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 11 Oct 2022 10:00:21 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 32F1DAE051;
	Tue, 11 Oct 2022 10:00:21 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 26CF8AE053;
	Tue, 11 Oct 2022 10:00:19 +0000 (GMT)
Received: from osiris (unknown [9.152.212.239])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 11 Oct 2022 10:00:19 +0000 (GMT)
Date: Tue, 11 Oct 2022 12:00:18 +0200
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
        Toke =?iso-8859-1?Q?H=F8iland-J=F8rgensen?= <toke@toke.dk>,
        Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>,
        Mika Westerberg <mika.westerberg@linux.intel.com>,
        "Darrick J . Wong" <djwong@kernel.org>
Subject: Re: [PATCH v6 5/7] treewide: use get_random_u32() when possible
Message-ID: <Y0U+sluE4MidMk8M@osiris>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
 <20221010230613.1076905-6-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20221010230613.1076905-6-Jason@zx2c4.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: xxTAUpkGdY4i3BSgCBDzJ0Hjxpj-WCth
X-Proofpoint-ORIG-GUID: jfmCKEudRO9C-x9PZSooVyIQeTri0ZJ_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.895,Hydra:6.0.528,FMLib:17.11.122.1
 definitions=2022-10-11_03,2022-10-10_02,2022-06-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 impostorscore=0 mlxscore=0 suspectscore=0 spamscore=0 adultscore=0
 priorityscore=1501 mlxlogscore=403 malwarescore=0 bulkscore=0
 clxscore=1015 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2209130000 definitions=main-2210110053
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=OOL8Hxcl;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender)
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

On Mon, Oct 10, 2022 at 05:06:11PM -0600, Jason A. Donenfeld wrote:
> The prandom_u32() function has been a deprecated inline wrapper around
> get_random_u32() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function. The same also applies to get_random_int(), which is
> just a wrapper around get_random_u32(). This was done as a basic find
> and replace.
>=20
> Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Yury Norov <yury.norov@gmail.com>
> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_cake
> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
> Acked-by: Mika Westerberg <mika.westerberg@linux.intel.com> # for thunder=
bolt
> Acked-by: Darrick J. Wong <djwong@kernel.org> # for xfs
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---
>  arch/s390/mm/mmap.c                            |  2 +-

For s390:
Acked-by: Heiko Carstens <hca@linux.ibm.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y0U%2BsluE4MidMk8M%40osiris.
