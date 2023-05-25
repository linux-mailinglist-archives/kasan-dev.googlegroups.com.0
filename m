Return-Path: <kasan-dev+bncBCG4ZMWKSUNBBMOLX6RQMGQEP5OAHAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id AD058711A52
	for <lists+kasan-dev@lfdr.de>; Fri, 26 May 2023 00:48:19 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-53b9eb7bda0sf51001a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 May 2023 15:48:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685054898; cv=pass;
        d=google.com; s=arc-20160816;
        b=z4rD2ixwIgu7wK4+/ZxPRjDoRphCkeMeAjavNYuU2UhjcHwFDMYoOXtz/Otzlg/nsO
         eD/lIRAmYeXi2dEfcDA4ro00ikJ8tQIgECJDPELz73xynIsx0ybQ5Yd+cvkHIHmzqgi9
         ydbZdovLoAuLsjfT8OYqGBs4KiAhaqzy89j2Yj39OMLBb8LO5v6FSSYotcLz8cybsiy0
         bihVESeefAMGHIW3LgwVP41XzTzm5TKxE4smsbex35ve1cUWEDbwzFbw2etQNl09TvnS
         CLUla6q6JuPZ5NI7H+EDDeTHUFc9OiCIoOAbL3W1uLopNGp23G4xTTHnrmuLrsCZul3e
         SvqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:dlp-filter:cms-type
         :in-reply-to:mime-version:message-id:subject:cc:to:from:date
         :dkim-filter:sender:dkim-signature;
        bh=l+0J38s9nPCSQ/PtMbyj4YbhlhFmkGb7GVOO/4i+yWI=;
        b=XNaRW4fTLkRfwJOBNkqFRn/LyKVuMDtiUOWpqV6WEMspL9eIeSiH7YJvi3Y3WrMxM0
         9mTjOM18hKzXbGrvhHFTM4Z2rI/GmrpBbr8fcyIBLfTZpmpCOb6l3MyuDd84zreWVLyy
         obk+oZ0sO5DQ/gXl9K8YqlkgAzIc5kRQ7Efp7lgCTAMEoIW7mibb5ZSIpspiSCIASmru
         yrPtBUxAyZnwbklFbNbcuuU6ZOD03Ye6tpzHAzNflkKrkcFl0sg9HnlSZVXenHz82Pek
         yfDtDcXnCz7ABSpm9DZlADtVc3rVVHsCxqyYEMmz7VKOB1v7e/OkZWXE1zURK9u5Gxmz
         GxFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=asOch4kW;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685054898; x=1687646898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:dlp-filter:cms-type:in-reply-to
         :mime-version:message-id:subject:cc:to:from:date:dkim-filter:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l+0J38s9nPCSQ/PtMbyj4YbhlhFmkGb7GVOO/4i+yWI=;
        b=YSNqcF3vtKHwmVf6YMGw2qZObpgQ+zD/GTBKIe1g5JgcsH4gGc0gwPwCkSHGsMB/e8
         4ZfaIzYTtxz+CRuRN3x9SH5GlrHHXBg3pG/8+yjTJItm3y/c6WILOfVKTJfpKn0Nujfz
         EHu3L2EG4zKMl4dxjQYzaUDClrZ7VPbCl6BlVDR+HjFianUCL6ode9CQR53cdvGtLzlL
         4SxOqlS+LB5PY+kuCQBrIj6t8h7L9t1Ab6l3G2Xyhi3dBokLuk+bMH0PWU3ANGjvzp3y
         KJmaucO1HG2d+6+Q4+wUpx21RUyuVvBy9JJt5QZm1/tGN0IXxxZHBaGKpD4cBGT4y8v4
         MaCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685054898; x=1687646898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :dlp-filter:cms-type:in-reply-to:mime-version:message-id:subject:cc
         :to:from:date:dkim-filter:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=l+0J38s9nPCSQ/PtMbyj4YbhlhFmkGb7GVOO/4i+yWI=;
        b=FtaInRC5EwA/2fdzpp+5MeaLzhRo0V8Z39f1IzjM2iMwPs2JK+UvJcfoVOWn5yaFWu
         nI+XzGrvyU2PL8t59Dz5OV2bu1HJ+uV5aFUkENcBn7I7GHaaw5N+ciAgIif5J/gXX5G/
         pQAJBxg8wTa4VofJu+WXKCsUu+47zxMX/Fl3LcbMJhNa+q0ykzHJxFOsDw6eEJUC5rEb
         tf7deYASylYYuf1H7UY3l/ZyClI+LkHlLTZ92pb2N/lP8xcYN5jLuaiIBP8TmHQ4n8Xq
         ICHOdDDC/G1mAHBNl1YZ4X9JKbBoitDOEx5B8Pc2diTQD2YBIyw1CRFRTh+rrgWE3+zP
         7H7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw6XKmvM82FnYIh4UcC+DMODQ3l+ycpg0XNS0yaZPaaPV7GZJ7x
	tTJweuIjf368EXiJzn8dx2o=
X-Google-Smtp-Source: ACHHUZ7yy8IJjn5iq/EgPc6ig6sdHV+hK34wXnKZlWTAKJ6MRCvGvZ0wXUsOfGPO4Zp5MXfrW44ALQ==
X-Received: by 2002:a63:541f:0:b0:52c:b46d:3609 with SMTP id i31-20020a63541f000000b0052cb46d3609mr52440pgb.12.1685054897805;
        Thu, 25 May 2023 15:48:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:db03:b0:250:b790:c2fc with SMTP id
 g3-20020a17090adb0300b00250b790c2fcls1712153pjv.1.-pod-prod-02-us; Thu, 25
 May 2023 15:48:16 -0700 (PDT)
X-Received: by 2002:a17:90a:72c7:b0:255:4635:830c with SMTP id l7-20020a17090a72c700b002554635830cmr160411pjk.40.1685054896771;
        Thu, 25 May 2023 15:48:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685054896; cv=none;
        d=google.com; s=arc-20160816;
        b=nDKUrs2pdAB6OP9+4C2WI4wXuRU9DJAdLWle1hIWfAfPsDNaBM2nbskiokaMWkNi8j
         mHKZTD2QLk+pv2JWQh+zcE+A+evbzMLv2S9Iq1Vp9Y8SiMDjQkE6IHqN/PBrbG9Rsj7V
         kkgl2CcrhNCo16mTYA0/sMbs07SvVjwdkt4QgDeXaiE8CCfxt4QIDlhfjSaCbMheqHFl
         xdO0qca00u4FtyOJl0qWjm6hg4k4loW87rH6DFD+MdGBsNjZxG5Ef9OhU+pVRqYT5dSi
         96l7nJpaHQixLz96p37tIbInuv2D3OzRgKK1ff5tjq6maA6ROjwuW8cCLhjU2VG6uA8S
         7RYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:dlp-filter:cms-type:in-reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-filter;
        bh=cuqiYyGVTSNlMib7a3dSbg6Z3ptpKNFLw5h4StleDco=;
        b=aP52U2MP6v9K7DMMYh1+H54AQ/0KtPBypBtfXaZY3Vhpy0As95w65HaDhs1tdew4tj
         cDBIiP72VBtTnb693nBteuXZH575161Bx6fodYgqvSStAgdEzemrkILt3Dhj8aUR3POJ
         myvh12BQmbxwQ3brlnpqeOq6Ee0Z6SqxZAFWBZZ+P79pyrFvGzCJBJbJ5kfU1FsZMQPm
         OT3oyWEKB0sI7Q8fBWGVXghobvT4kkfSJEEtMsxWTGJI3gmIpRH/NjKDbsflCvyq0YO6
         kmUfVICTf4ch0CyRvY4iyX2Ec47EH5YDPufhuzf3HknggtvdAA5Bwa3IsIlRt50spKkT
         HXZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=asOch4kW;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout3.samsung.com (mailout3.samsung.com. [203.254.224.33])
        by gmr-mx.google.com with ESMTPS id pt13-20020a17090b3d0d00b002504e396db0si257613pjb.0.2023.05.25.15.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 May 2023 15:48:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as permitted sender) client-ip=203.254.224.33;
Received: from epcas2p2.samsung.com (unknown [182.195.41.54])
	by mailout3.samsung.com (KnoxPortal) with ESMTP id 20230525224814epoutp030b0d916e383c7452cf9dc37d41292120~ihH_aVRdD1478014780epoutp03Q
	for <kasan-dev@googlegroups.com>; Thu, 25 May 2023 22:48:14 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout3.samsung.com 20230525224814epoutp030b0d916e383c7452cf9dc37d41292120~ihH_aVRdD1478014780epoutp03Q
Received: from epsnrtp3.localdomain (unknown [182.195.42.164]) by
	epcas2p3.samsung.com (KnoxPortal) with ESMTP id
	20230525224813epcas2p3969793adae63ecbdf613b1d4dbcfdea6~ihH9fHqPz0772307723epcas2p3t;
	Thu, 25 May 2023 22:48:13 +0000 (GMT)
Received: from epsmges2p1.samsung.com (unknown [182.195.36.99]) by
	epsnrtp3.localdomain (Postfix) with ESMTP id 4QS39m647Jz4x9Pr; Thu, 25 May
	2023 22:48:12 +0000 (GMT)
Received: from epcas2p4.samsung.com ( [182.195.41.56]) by
	epsmges2p1.samsung.com (Symantec Messaging Gateway) with SMTP id
	23.78.11450.CA5EF646; Fri, 26 May 2023 07:48:12 +0900 (KST)
Received: from epsmtrp2.samsung.com (unknown [182.195.40.14]) by
	epcas2p4.samsung.com (KnoxPortal) with ESMTPA id
	20230525224812epcas2p4a554e246fb54c91294b209977c73e265~ihH8rlsDU1037410374epcas2p4Q;
	Thu, 25 May 2023 22:48:12 +0000 (GMT)
Received: from epsmgms1p1new.samsung.com (unknown [182.195.42.41]) by
	epsmtrp2.samsung.com (KnoxPortal) with ESMTP id
	20230525224812epsmtrp25979228577d3670b5f8237fc82b16308~ihH8qr90t2708327083epsmtrp2h;
	Thu, 25 May 2023 22:48:12 +0000 (GMT)
X-AuditID: b6c32a45-1dbff70000022cba-3d-646fe5acaea6
Received: from epsmtip1.samsung.com ( [182.195.34.30]) by
	epsmgms1p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	48.6E.27706.CA5EF646; Fri, 26 May 2023 07:48:12 +0900 (KST)
Received: from perf (unknown [10.229.95.91]) by epsmtip1.samsung.com
	(KnoxPortal) with ESMTPA id
	20230525224812epsmtip11695bab10cfe82146e0cc79bb0fc319c~ihH8bvmxk1534015340epsmtip1U;
	Thu, 25 May 2023 22:48:12 +0000 (GMT)
Date: Fri, 26 May 2023 08:20:36 +0900
From: Youngmin Nam <youngmin.nam@samsung.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: lexandru.elisei@arm.com, andreyknvl@gmail.com,
	anshuman.khandual@arm.com, ardb@kernel.org, broonie@kernel.org,
	catalin.marinas@arm.com, d7271.choe@samsung.com, dvyukov@google.com,
	hy50.seo@samsung.com, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, maz@kernel.org, will@kernel.org,
	youngmin.nam@samsung.com
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a
 default
Message-ID: <ZG/tRDjl4uR7C0dD@perf>
MIME-Version: 1.0
In-Reply-To: <ZF5gmBz4NbDseDHp@FVFF77S0Q05N>
X-Brightmail-Tracker: H4sIAAAAAAAAA02TbUxTVxjHc3pL7y2meldRT4o6dvcK0tJiS6+b7CUKNoHFJmZbJFvqtb3S
	pqXt+rIhH6abTUFkjKpA6BbW0cmQ4sbKS6QFtiBZ6ZwfJgQMCqOCLmERZkEmZNS1XFj89nv+
	ef45/+c852AIP8ARYDqjjbYYKQPBSWZ3X0snhW33TBrxvZCI/MdVj5L9Q2pyeXEekLWRGQ45
	31wFyNE+F0rWRJwo6fNOscmW+3+wyOEzlSjpnx5NIi+N/c4ie74KJ5GOOzLS+3MUfXOLoq2x
	DSh63BOowuO3K3pdYY7C33qWo+j49pSiurMVKNEi/X4tTWloSxptVJs0OmNxLlFwRHVAJcsR
	S4SSfaScSDNSJXQucbBQKczXGeKpibSPKIM9Likpq5XIen2/xWS30Wlak9WWS9BmjcEsN4us
	VInVbiwWGWnbqxKxOFsWbzym13ZMNLPNIV5pQ7AOOQ2uJ1cCLgZxKfT6HrArQTLGx68COHdp
	fr2IAuidml4vlgD0X+lCNizNLRtdfQA+Wu1EmSICYE1bL5roYuMvwhvXb64xBxfC7qEYSHAK
	/jKsCiyuuRF8mAUHPQ3xAsO24u9A3yxM9PDw52G4NgAYfgaGG2bYCebimfBhnRNJeCHei8Hw
	0gSLiXQQlkeq2QxvhbOhTpRhAVyY6+MwrIe+lZvreiksn6xaH2cvdN8vXzsMwbXwzOe3kUQe
	GA8xOM5m5M2w4toqysg8WOHkM86X4MrFdsDwThj0tqw7FdDdkcZcSRCB3uUpUAN2u5+axv3U
	YQxnQk8wynHH7QieCr+LYQymwx8CWR6Q1Aq202ZrSTFtzTZL/l+w2lTiB2uPOCPvKrjw4G/R
	AGBhYABADCFSeO0Gk4bP01Any2iLSWWxG2jrAJDFV+NCBNvUpvgvMNpUEuk+sTQnRyLPlonl
	xA5eam5YzceLKRutp2kzbdnwsTCu4DTrjfxeTuTHsd82SYss25WG8xX5E4cMyiOO9O638ho/
	5BW173Q495x9n+p+NhCJbi58XHZ8SLkoALHmOudt5+VUh/AuDD55N0+s2UIc/ylzrunov2OT
	hws8Hef/rFXpu5bkHx8rqBi/85nNtvrFCw2/FEaXHUu6/l+znqt9++6jr0O7RLsOI7wRbmz4
	RLZct3xq73tAz1VLW6f5m5SXG2ukfQ+D35eTsT23Rq4siEx/wRMLlPPTyW2fZLCfnJv1pMwS
	IZ+xfOSoqGm8p5g4WRjpulgdDPWUHqibsX/wTe/yKzeQL6OuliaTvNPQXzbucO04BOqHR0bP
	PR7cfStQX/PawArBtmopSQZisVL/ATENBQBNBAAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFmpkkeLIzCtJLcpLzFFi42LZdlhJTnfN0/wUg9ezuS2+T5zObrHvRLLF
	zy/vGS2mPnzCZvF+WQ+jxbW9E9ktJjxsY7dYvfgBi8WKZ/eZLC43d7FbbHp8jdVi6fWLTBY7
	55xktWi5Y2qx+MAndgd+jzXz1jB67Jx1l91jwaZSjz0TT7J5bFrVyeaxeUm9R9+WVYwB7FFc
	NimpOZllqUX6dglcGdPuvGAvaOeu6H/wgrGBcQlHFyMnh4SAicSyFe9Zuhi5OIQEdjNK/Ny5
	jgUiISNxe+VlVghbWOJ+yxFWiKL7jBLbPj5mAkmwCKhKnD19iR3EZhPQldh24h8jiC0ioC7R
	s+sL2FRmgctMEh1THgAVcXAIC4RKrH4lAVLDK6AscXLqLkaIoQeZJX7eWc4MkRCUODnzCdgV
	zAJaEjf+vWQC6WUWkJZY/g/sak4BHYmP09qYJzAKzELSMQtJxyyEjgWMzKsYJVMLinPTc4sN
	CwzzUsv1ihNzi0vz0vWS83M3MYJjSUtzB+P2VR/0DjEycTAeYpTgYFYS4d2Qk58ixJuSWFmV
	WpQfX1Sak1p8iFGag0VJnPdC18l4IYH0xJLU7NTUgtQimCwTB6dUA9NW8etHLuWw1bFuvDKv
	xUWZZaZY/Z7P2mLaHAtrGybdnJW2crWz/F+5STxO13ZdWS3BM+VQeEp2cYZQa5FkSMm/JXr/
	71WG+ih+zLnvHzvhYN+ZPpFt6skrfBJObZJcrKyv6bmQN2BN9awfRS9fy3MseGq2n+GaU/RV
	S+bWrZ48G9b/kXhr+traODv+UeEUsYMddz/9TJQSXlt/JfKZXT3LOr1ymU+vm1eUf//wa8Hu
	hYyhTz7F7nTaXLXgvEeO3owjGo+eTZ8dxv722pyIvG/rDypk1oeGrue6LclSlC1yNu+LifqW
	i2UTJv/NP9mf6zzLXz2Fq/mvyuOgnkUrZpWqXfy6Jmnqx6g7fnPnskUrsRRnJBpqMRcVJwIA
	HfeopRQDAAA=
X-CMS-MailID: 20230525224812epcas2p4a554e246fb54c91294b209977c73e265
X-Msg-Generator: CA
Content-Type: multipart/mixed;
	boundary="----Y9bAoTVPo7TEjNVVx8BuVeRnQePgNsPKB0hZTbOgiEUDqOwX=_3b99f_"
X-Sendblock-Type: AUTO_CONFIDENTIAL
CMS-TYPE: 102P
DLP-Filter: Pass
X-CFilter-Loop: Reflected
X-CMS-RootMailID: 20230424003252epcas2p29758e056b4766e53c252b5927a0cb406
References: <CGME20230424003252epcas2p29758e056b4766e53c252b5927a0cb406@epcas2p2.samsung.com>
	<20230424010436.779733-1-youngmin.nam@samsung.com>
	<ZEZhftx05blmZv1T@FVFF77S0Q05N>
	<CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
	<ZEZ/Pk0wqiBJNKEN@FVFF77S0Q05N> <ZEc7gzyYus+HxhDc@perf>
	<ZEfYJ5gDH4s6QJqp@FVFF77S0Q05N.cambridge.arm.com> <ZEixUYKPr3F0Y8Xn@perf>
	<ZF1+cLp7Io7L25yG@perf> <ZF5gmBz4NbDseDHp@FVFF77S0Q05N>
X-Original-Sender: youngmin.nam@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=asOch4kW;       spf=pass
 (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as
 permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

------Y9bAoTVPo7TEjNVVx8BuVeRnQePgNsPKB0hZTbOgiEUDqOwX=_3b99f_
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Fri, May 12, 2023 at 04:51:52PM +0100, Mark Rutland wrote:
> Hi,
> 
> On Fri, May 12, 2023 at 08:46:56AM +0900, Youngmin Nam wrote:
> > On Wed, Apr 26, 2023 at 02:06:25PM +0900, Youngmin Nam wrote:
> > > On Tue, Apr 25, 2023 at 02:39:51PM +0100, Mark Rutland wrote:
> > > > On Tue, Apr 25, 2023 at 11:31:31AM +0900, Youngmin Nam wrote:
> > > > > On Mon, Apr 24, 2023 at 02:08:14PM +0100, Mark Rutland wrote:
> > > > > > With that in mind, I think what we should do is cut this at the instant we
> > > > > > enter the exception; for the trace below that would be el1h_64_irq. I've added
> > > > > > some line spacing there to make it stand out.
> 
> > > > I'd meant something like the below, marking the assembly (as x86 does) rather
> > > > than the C code. I'll try to sort that out and send a proper patch series after
> > > > -rc1.
> > > > 
> > > > Thanks,
> > > > Mark.
> > 
> > Hi Mark.
> > This is gentle remind for you.
> > Can I know that you've sent the patch ?
> > Actually I'm looking forward to seeing your patch. :)
> 
> Sorry; I haven't yet sent this out as I'm still looking into how this interacts
> with ftrace.
> 
> I'll try to flesh out the commit message and get this out next week. You will
> be Cc'd when I send it out.
> 
> Thanks,
> Mark.
> 
Hi Mark.
Sorry to rush you. Would you share your patch for us ? We're still waiting
your patch. :)

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZG/tRDjl4uR7C0dD%40perf.

------Y9bAoTVPo7TEjNVVx8BuVeRnQePgNsPKB0hZTbOgiEUDqOwX=_3b99f_
Content-Type: text/plain; charset="UTF-8"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZG/tRDjl4uR7C0dD%40perf.

------Y9bAoTVPo7TEjNVVx8BuVeRnQePgNsPKB0hZTbOgiEUDqOwX=_3b99f_--
