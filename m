Return-Path: <kasan-dev+bncBCMMFP7V4IARBJEIW2SQMGQECDFIGEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8539674F551
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 18:32:38 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1ad34f55a63sf6595574fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 09:32:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689093157; cv=pass;
        d=google.com; s=arc-20160816;
        b=ewPel2LAyTLgJDF8cJYTK/eM1ajKJkgmnVlNkAVPBtTy/ZoIqE8phME47uRTjUt6+I
         MS6MA8839WdiZOiDoPLso8dd6/ynK6ZlUbrk243/wKpaHY0F8aKQQv3XTlRVVzGgxfOp
         M1ztCa8mut1O64kD6p9QWT+YwmdOFFtVmLaS9eugpSuUZ4QQb+1V9eOnFgLpSu24kYgh
         dLhu+vcev76lJCwJd7OOOYPX3m+ajVYSluXJ258DSOt6RW8WI36SCCro8+XVaPTMNVyr
         qNmC5SeFVyP6lVZCSOckvVPWF+5U4LUc8TlNH6ziy2EmTwFZgsCM+mSyFYwZiMpNBW1+
         UiMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=K8XlqBL4R4pkclG+2xF1kcBpkPv5LnWXHi22Q2A49tE=;
        fh=9l3WlPrJiKe0VE01dwZLc8FZUO+QwrxdBFb1JVM+yEc=;
        b=wNuwZAD8M9JRxp+ReTHtbwHPkk5A2rwfNKzZwjoKsGrhGOtK4EFsnLAz4z7LiDQ7Pm
         zIKX5zZuzDM37wmfS9I80x3kO5sAN5eYIsQ65ywAKsyGMJ0wTy9HxNuKf/pdeKvbM3vX
         v1RKqjwYTubeJY+Wv1arGg1ZCVWtOxiSPVVeU6gYYcUdj/aqAW/sp6ZoP8Wa8m4mrbe9
         6UcnU32/zOu7FCImQlD+h9VyVBWPwFcAic7E6JSyWA4jHrjpip7O2vXcEX34a6o2XH44
         CK9lVTzNNAQDAKqHDWMVuHtp6GAImB/YNTZOU2M8EbUC58cl51SWa+DDK8Tgt1iUV7LO
         ultQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=ymbOEdbz;
       spf=pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689093157; x=1691685157;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K8XlqBL4R4pkclG+2xF1kcBpkPv5LnWXHi22Q2A49tE=;
        b=WP0y7oHhvAW/AMGhzOLBH9VE7q2uYcP6/jVYqp4JG+qtMIH4/PkIje8PJaWG0Xsrnh
         RYO7RwtcXbwVaUAvhDI9xFs0bbpnUe9oqidZs5UJz6r1jM8v8kqKhIMYDNKCdqPc34zl
         swhXNAvBq1Z3EQWAn8XvDhGy3lisBrflWj19s7xLHx8AnnCJAibzapjJ8IcviQ6lPobI
         8Wb4+NRp51+9INk6VsikOGpENJwzG6Ty2kmi7SdUs+8C8vfnrI8HXPEXc7p2kgUjktvK
         B/l8hWm40Ed3wPnihBjNXlf2OEJDYGSujraBjyrpysMAIuRjRKqynks39GGTRgPOBd55
         uXUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689093157; x=1691685157;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K8XlqBL4R4pkclG+2xF1kcBpkPv5LnWXHi22Q2A49tE=;
        b=L8tWuHRAakva5M5CUKZOMVCntgXQGv+7tPApMEdQBXDLfGjFYJ6V39Ws/eG4Aapv7o
         mZLp8KIZS5pNYl0G3jEXs/SXpwPXUA+XXJZsox59qMnXX5R7uSIbUrPnyWF5HgiGgRml
         K/b50TezoVTOTi5/MJeme77BLx+5hKhex3xQXciNnCsdOT+U+jF7qHgMdlq6xI8TSJ3z
         EHa/5+2nNztZnpMv+0DtfRcGXiHW2YJZutq1JSQ3thJmMM3PugMa33Dns6iIGEkiJCNB
         yd9dnorOa1/NIH8TXcES29q+Qsv9NwtXbHU/crJq6tsjLVNf/yS1HZMESYMAjYmYi5Dj
         H/xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZExRK63+JFeOUPqaVv5ublMjNVb1bGX+7yFND6hDPgJwk6n1kj
	a9NarWljrEn2ZD/rM4DF54E=
X-Google-Smtp-Source: APBJJlF1FoK4xH6dqdYbXnhpGH6UyeMu9RESx0g2uhBkLsFBSXmjrdlA2hejJKoUhnWEKglHrOAZhA==
X-Received: by 2002:a05:6870:f10b:b0:1a6:987b:f09d with SMTP id k11-20020a056870f10b00b001a6987bf09dmr18616022oac.51.1689093156988;
        Tue, 11 Jul 2023 09:32:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:61f:b0:565:b612:7f77 with SMTP id
 e31-20020a056820061f00b00565b6127f77ls1308143oow.2.-pod-prod-02-us; Tue, 11
 Jul 2023 09:32:36 -0700 (PDT)
X-Received: by 2002:a05:6808:1986:b0:3a1:d656:21c with SMTP id bj6-20020a056808198600b003a1d656021cmr18546932oib.21.1689093156487;
        Tue, 11 Jul 2023 09:32:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689093156; cv=none;
        d=google.com; s=arc-20160816;
        b=eVlKg+7s6j52nJrcoFFIrjtmyPM+iEt0/svrrakUJDD1TNXJAgMYToAF3GPJChpTa0
         efew1ilLCA0DzbUkmaUW+QZEscwDBv7TJkIOG+Ft/3yw9GyQr0hjWKrFgrF3N7jiRTyY
         ExZyHDXbxTivkZraZwJUUdyvRgrW8WPS/j1N9tYld6Qfe8nXgWmzvhfZd/+mDMqUH/2F
         Js64fyqcauY0Z75gB1Hbl9QfdTrIi29XhZS/wSK93DjvPqrN1rhhNMovJfce108Xc8c5
         LNNAaSHIyt5Pip1GeeLfgDxGsbVuFKYis5oZiUn9v+gwLoPQ7GAnGdGhmAsE0pRafqsg
         Iq1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+4V1nFRqwTelDtAcI310e7e7t3xc9C8kzlyU277DNxs=;
        fh=9l3WlPrJiKe0VE01dwZLc8FZUO+QwrxdBFb1JVM+yEc=;
        b=pp5up3TdTOelFcuhM47tm0SE2xJEFs+wo+TkHnSikNeAq4SNPnVONCObMJvmfLzL9C
         Ni8LlC+hRkg9npzltXyh1OFCKOkUtAMCs9k0aACzqHjCKprNyhm8xE04YOBir0egi9H9
         LzFo4E0p+Oe+w/kzkZ2nFLeBkTt2X55CzIYDwt2eaJKkO6JnL76REh9hoTgqVdcR09KM
         fMsgG24xssap+pcJt+sTkbQzoH7UnzKrao1tlGFuCIpr06mMvCKZeKvSaQKnwRriPT3P
         Y0B1wlTNs7cOzdzhZCL916IG2HdoPCKwaDbjgvylnCg/yFxBlaodewKB1C4XoM425ELZ
         lO7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=ymbOEdbz;
       spf=pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id bf34-20020a056808192200b003a1ee7b28acsi215649oib.1.2023.07.11.09.32.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jul 2023 09:32:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 36BG3O1f022902;
	Tue, 11 Jul 2023 16:32:04 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3rpyud5e6f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 11 Jul 2023 16:32:04 +0000
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.17.1.19/8.17.1.19) with ESMTP id 36BGUtBm007087;
	Tue, 11 Jul 2023 16:32:03 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 3rpx854cdv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 11 Jul 2023 16:32:03 +0000
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 36BGQBXP019529;
	Tue, 11 Jul 2023 16:32:02 GMT
Received: from ca-mkp2.ca.oracle.com.com (mpeterse-ol9.allregionaliads.osdevelopmeniad.oraclevcn.com [100.100.251.135])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTP id 3rpx854c4h-4;
	Tue, 11 Jul 2023 16:32:02 +0000
From: "Martin K. Petersen" <martin.petersen@oracle.com>
To: linux-hyperv@vger.kernel.org, Julia Lawall <Julia.Lawall@inria.fr>
Cc: "Martin K . Petersen" <martin.petersen@oracle.com>,
        kernel-janitors@vger.kernel.org, keescook@chromium.org,
        christophe.jaillet@wanadoo.fr, kuba@kernel.org,
        kasan-dev@googlegroups.com, Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>, iommu@lists.linux.dev,
        linux-tegra@vger.kernel.org, Robin Murphy <robin.murphy@arm.com>,
        Krishna Reddy <vdumpa@nvidia.com>,
        virtualization@lists.linux-foundation.org,
        Xuan Zhuo <xuanzhuo@linux.alibaba.com>, linux-scsi@vger.kernel.org,
        linaro-mm-sig@lists.linaro.org, linux-media@vger.kernel.org,
        John Stultz <jstultz@google.com>,
        Brian Starkey <Brian.Starkey@arm.com>,
        Laura Abbott <labbott@redhat.com>, Liam Mark <lmark@codeaurora.org>,
        Benjamin Gaignard <benjamin.gaignard@collabora.com>,
        dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org,
        netdev@vger.kernel.org, Shailend Chand <shailend@google.com>,
        linux-rdma@vger.kernel.org, mhi@lists.linux.dev,
        linux-arm-msm@vger.kernel.org, linux-btrfs@vger.kernel.org,
        intel-gvt-dev@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
        Dave Hansen <dave.hansen@linux.intel.com>,
        "H. Peter Anvin" <hpa@zytor.com>, linux-sgx@vger.kernel.org
Subject: Re: (subset) [PATCH v2 00/24] use vmalloc_array and vcalloc
Date: Tue, 11 Jul 2023 12:31:45 -0400
Message-Id: <168909306205.1197987.4062725942946508296.b4-ty@oracle.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20230627144339.144478-1-Julia.Lawall@inria.fr>
References: <20230627144339.144478-1-Julia.Lawall@inria.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.957,Hydra:6.0.591,FMLib:17.11.176.26
 definitions=2023-07-11_08,2023-07-11_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 mlxlogscore=801
 adultscore=0 mlxscore=0 spamscore=0 phishscore=0 malwarescore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2305260000 definitions=main-2307110148
X-Proofpoint-ORIG-GUID: VdiqWRAD5JOoA45uglvHtoSxe29wDWJY
X-Proofpoint-GUID: VdiqWRAD5JOoA45uglvHtoSxe29wDWJY
X-Original-Sender: martin.petersen@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-03-30 header.b=ymbOEdbz;
       spf=pass (google.com: domain of martin.petersen@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

On Tue, 27 Jun 2023 16:43:15 +0200, Julia Lawall wrote:

> The functions vmalloc_array and vcalloc were introduced in
> 
> commit a8749a35c399 ("mm: vmalloc: introduce array allocation functions")
> 
> but are not used much yet.  This series introduces uses of
> these functions, to protect against multiplication overflows.
> 
> [...]

Applied to 6.5/scsi-fixes, thanks!

[07/24] scsi: fnic: use vmalloc_array and vcalloc
        https://git.kernel.org/mkp/scsi/c/b34c7dcaf311
[24/24] scsi: qla2xxx: use vmalloc_array and vcalloc
        https://git.kernel.org/mkp/scsi/c/04d91b783acf

-- 
Martin K. Petersen	Oracle Linux Engineering

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168909306205.1197987.4062725942946508296.b4-ty%40oracle.com.
