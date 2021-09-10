Return-Path: <kasan-dev+bncBDN6TT4BRQPRBS5N5WEQMGQE4U6HJTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-f188.google.com (mail-qt1-f188.google.com [209.85.160.188])
	by mail.lfdr.de (Postfix) with ESMTPS id A6EAE406C94
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 14:59:56 +0200 (CEST)
Received: by mail-qt1-f188.google.com with SMTP id q19-20020ac87353000000b0029a09eca2afsf9766967qtp.21
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 05:59:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631278795; cv=pass;
        d=google.com; s=arc-20160816;
        b=w/ex9+5FZYYTl0uYdqAzyJ0/0M2ZIqFqUp1p9snYh4zZPIYoXGmdrP93YSz9ygWhX9
         Lz1y0Hy+wiZ6FO8PoI+Ff//BoqwNQo6emIv4Zaef+j4v5t0hBaivyrSmCGalr8lXKX67
         +rgtdCDPIyKDhIMZdMTmtWYRHEtOrkjRt7N1EiL9U9jeXcTKGELm4gfgVvKRot6AgJx4
         YwURmFbEl6CFOFtlV2orwDFKK4JVydYoVOvJ4moSFt4W3ZFLWBI2V2azkpQfFhzrnaRq
         TaU/y9F+taNvLKXnuxoRUV47Xb+xLN7f7jb+VUx1MIprN2dQXYJpJmMp7MTqUzHOalM7
         RecA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type:date:message-id
         :in-reply-to:cc:to:from:sender:reply-to:subject:mime-version
         :dkim-filter;
        bh=w9ThFZFERZe9oN5myYDmFfEIsXxUz/4B9M9oFl2S2OM=;
        b=gavzMWTs+B9z3/nv56gTLq8OGePJR6tHydyVwJW2otn4f6s/AU8O8IebZ9YUqaUBcU
         MV4aUWKTifopku3s0h3RLjSRggQ+BjC+G4JFl19yeEoV/Ioo/HFiEzdLqGBLaibB9I+8
         Z0NtnrtJrG9/mFdKA7lGLkDMQ6VQN0cgv17KRRSsnvIpW7f/CTfvIFYIoIQZB6cgFypO
         uOWnzIhTX5Npo03SCfn+WAm9J045mJjnj2H9gsCc60TX/+HOYADDLcYTiugQT3QPinHq
         FezDypwW3cJwVuPItSR5ngj+OKZozp8QhprpekngahRXljJka6qezyvgOKtwllHgAS3i
         JSYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=iSQr58NN;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:dkim-filter:mime-version:subject:reply-to:sender
         :from:to:cc:in-reply-to:message-id:date:cms-type:references
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w9ThFZFERZe9oN5myYDmFfEIsXxUz/4B9M9oFl2S2OM=;
        b=2Ibx+hxIo7rAF6rG3j3HjxtuGFKkexwDYWZZaHtl7Zz8k/XyT1Fg96mZPnYbca6irj
         UpvaJuoPJ+izBtzQgoYvlOintKfrL7G6P71tYVFJ7nLG+zBFJ1+xRBeRuAIZw4SWUnFK
         5EZUCzj9BnUo/nsDCka11KaqR/67jrLkvE58+CWqPQO7XNx9slMUvlaIw8iWEMu+YmYH
         crWUBvOnvRwxhz1JES++Txz2NhyCipb57U3PfH5xbyhnFdqbAtwOkt7BJea1d8DwLx2D
         aeA6Y4L3ydehclXBT5vlH9h2/rO/PpcBVt4jFwPg59ufp0MbFihUHKUcI9Qa485Y5EYU
         804g==
X-Gm-Message-State: AOAM532/Gptq+xa/2HkaA+xYhC2WceWfyj/aNqnawMst/UFZ8IfrMCc1
	UXsjWoWMgX6yjmZ7QLk7pS8=
X-Google-Smtp-Source: ABdhPJwXuNeGaSjuJUJtlOAPI3mplbkcDdSYmm9IrD+IUjvKnfgv5Jyu348uNjGm/Z7nwm1LTFDIlw==
X-Received: by 2002:a37:6451:: with SMTP id y78mr7227065qkb.427.1631278795531;
        Fri, 10 Sep 2021 05:59:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e303:: with SMTP id v3ls3557841qkf.5.gmail; Fri, 10 Sep
 2021 05:59:55 -0700 (PDT)
X-Received: by 2002:a05:620a:f8a:: with SMTP id b10mr7581404qkn.424.1631278795087;
        Fri, 10 Sep 2021 05:59:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631278795; cv=none;
        d=google.com; s=arc-20160816;
        b=wKT3yhT15gRPPsi/HxiQG/cmYj1yfIRiWzjefHwkj2UewCU/BKg3LK+bs5056PYrbK
         3Xig3FMU+CDJMJKNI0zuiLzkujGgNJkcJ3I9O8oTby1PKqHcC+WoQzR3Lewzq6Gsnk5z
         MPK7RyaIAgjPojnxXJMtI32kCjE3MR7PlI2/fjbmZBz4wlGcazbSlFJn1+JhrfSIWlMl
         oBom7LL/w8sE4/MQHMvp998YVWPMkCPVIYG8QbjRNDutJntIolyceFt3XYNHxvN7K5My
         B1WYd5e4bdSwgds2YJ/xOC14GaVoSB4pBte2lKifZ//Nqr39MdA+1z3m2icRIhvvrY3s
         ZzTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-transfer-encoding:date:message-id
         :in-reply-to:cc:to:from:sender:reply-to:subject:mime-version
         :dkim-signature:dkim-filter;
        bh=jZAIRI5syEH1dQgQ88ZbFitr00/kCWSSVpXDzAa4vzw=;
        b=qZNMqZEP2N3Y+DNQE/6VOszGnuWR722Yqs2/SDMmdu2nIxbjVfAlvos9Vg82BuDRYb
         9zAz4RuTMPi2ECstySBiuR0ey2uS5eEpBtHqy1yjf1HV2AlTAzspK903iUV7rJYPBTJt
         JTgUtYlv9o9hkzLGk+gW+hyf7zC2YoFWS9GnV5qICSE+cMSQZS6Ii/bHu3H8jENNcDPP
         Tq8hG5c1NPH2hEnRHNsBqT10vKZr266Rayq+jvVwqD0bPV2+GMPeDfydDBnVUm5sqbis
         VlTac3xak73SXH3ry73bgXY2NkSMfd9xBluJLA6JDRZW5AHkEKmL2U7Ggkv0scEJfy1w
         QisA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=iSQr58NN;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.samsung.com (mailout1.samsung.com. [203.254.224.24])
        by gmr-mx.google.com with ESMTPS id d201si424294qkg.4.2021.09.10.05.59.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Sep 2021 05:59:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as permitted sender) client-ip=203.254.224.24;
Received: from epcas5p4.samsung.com (unknown [182.195.41.42])
	by mailout1.samsung.com (KnoxPortal) with ESMTP id 20210910125951epoutp01412161938051c71bcf70fea0bb8eb614~jd2sSCvrg1266612666epoutp019
	for <kasan-dev@googlegroups.com>; Fri, 10 Sep 2021 12:59:51 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.samsung.com 20210910125951epoutp01412161938051c71bcf70fea0bb8eb614~jd2sSCvrg1266612666epoutp019
Received: from epsmges5p2new.samsung.com (unknown [182.195.42.74]) by
	epcas5p2.samsung.com (KnoxPortal) with ESMTP id
	20210910125950epcas5p2990404d76736db2ec3116cc6986f6d9b~jd2rQT_BH0368703687epcas5p2g;
	Fri, 10 Sep 2021 12:59:50 +0000 (GMT)
X-AuditID: b6c32a4a-b2dff7000000287f-d9-613b56c60c64
Received: from epcas5p2.samsung.com ( [182.195.41.40]) by
	epsmges5p2new.samsung.com (Symantec Messaging Gateway) with SMTP id
	A8.C4.10367.6C65B316; Fri, 10 Sep 2021 21:59:50 +0900 (KST)
Mime-Version: 1.0
Subject: RE: [PATCH 1/1] exception/stackdepot: add irqentry section in case
 of STACKDEPOT
Reply-To: maninder1.s@samsung.com
Sender: Maninder Singh <maninder1.s@samsung.com>
From: Maninder Singh <maninder1.s@samsung.com>
To: "Russell King (Oracle)" <linux@armlinux.org.uk>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, "glider@google.com"
	<glider@google.com>
CC: "catalin.marinas@arm.com" <catalin.marinas@arm.com>, "will@kernel.org"
	<will@kernel.org>, "mark.rutland@arm.com" <mark.rutland@arm.com>,
	"joey.gouly@arm.com" <joey.gouly@arm.com>, "maz@kernel.org"
	<maz@kernel.org>, "pcc@google.com" <pcc@google.com>, "amit.kachhap@arm.com"
	<amit.kachhap@arm.com>, "dvyukov@google.com" <dvyukov@google.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Vaneet Narang <v.narang@samsung.com>, AMIT
	SAHRAWAT <a.sahrawat@samsung.com>
X-Priority: 3
X-Content-Kind-Code: NORMAL
In-Reply-To: <YTYQKgKspSPORGH8@shell.armlinux.org.uk>
X-Drm-Type: N,general
X-Msg-Generator: Mail
X-Msg-Type: PERSONAL
X-Reply-Demand: N
Message-ID: <20210910125949epcms5p40ddb337f000a5fe46bb6e59f48452060@epcms5p4>
Date: Fri, 10 Sep 2021 18:29:49 +0530
X-CMS-MailID: 20210910125949epcms5p40ddb337f000a5fe46bb6e59f48452060
Content-Type: text/plain; charset="UTF-8"
CMS-TYPE: 105P
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrFKsWRmVeSWpSXmKPExsWy7bCmhu6xMOtEgwm3lC0u7k61mLN+DZvF
	lA87WC3eL+thtJjwsI3dov3jXmaLL81tTBYrnt1nstj0+BqrxeVdc9gsDk3dy2ix9PpFJoud
	c06yWvTfuc5mcXzrFmaLQyfnMlq03DF1EPRYM28No8flaxeZPXbOusvusWBTqceeiSfZPDat
	6mTzODHjN4vH5iX1Hn1bVjF6fN4kF8AVxWWTkpqTWZZapG+XwJUx+9I39oI3LBVXf8s3MH5g
	7mLk5JAQMJFYdq+XrYuRi0NIYDejRPOWd4xdjBwcvAKCEn93CIPUCAtES2w4e40dxBYSUJS4
	MGMNWImwgIHEr60aIGE2AT2JVbv2sIDYIgKTGSVmvTMDGckssItV4su6m6wQu3glZrQ/ZYGw
	pSW2L9/KCGJzCphKTFpyA+oeUYmbq9+yw9jvj81nhLBFJFrvnYWqEZR48HM3VFxGYvXmXhaQ
	ZRIC3YwS69/thXJmMEr0PJoG1WEusX7JKrCpvAK+Eus23AGzWQRUJfZeWwV1nYvEyp7vYHFm
	AXmJ7W/nMIN8ySygKbF+lz5EmE+i9/cTJphndsyDsVUlWm5uYIV57PPHjywgrRICHhJL1ipA
	wvYvo8TeK21MExjlZyGCdxaSZbMQli1gZF7FKJlaUJybnlpsWmCUl1quV5yYW1yal66XnJ+7
	iRGc3LS8djA+fPBB7xAjEwfjIUYJDmYlEd4TGywThXhTEiurUovy44tKc1KLDzFKc7AoifN+
	fA2UEkhPLEnNTk0tSC2CyTJxcEo1MCVuEIt9JPnkyFXd2yWLUh6tlvxRnrzs29o/rfLXryX9
	+nHo8llB08O7LspxJ/JO5A7pr5lRWvTnxpmyVd2xBVfNNtmaVb/32ujE4H1x64JTJgv1b6+z
	DmC86DfpWMHRruVOlQwsHqaK+yQdbO91LdETL1r6631f0OP6a8mbHT/tzLrVe473lV/xMisX
	b42CfR075geonC/Jv+7SK9MsOnPbPpVmK5trqgmfXrdP/HfE+92yL3e+75jP94K3ReK7pW2m
	qeLkBIl094xJtW1/w5R6V106YHbkXllbcKRsZ5pPq2GrvP/2U7eCF+/geVMvHTPhbqie+Le6
	RIflulOTdL8Lxt06lvS3Sfu49+G2lUosxRmJhlrMRcWJALDpUcPdAwAA
X-CMS-RootMailID: 20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a
References: <YTYQKgKspSPORGH8@shell.armlinux.org.uk>
	<1629270943-9304-1-git-send-email-maninder1.s@samsung.com>
	<20210906124351epcms5p6020fbfe5f885f1e8834a72784b28d434@epcms5p6>
	<CGME20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a@epcms5p4>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=iSQr58NN;       spf=pass
 (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as
 permitted sender) smtp.mailfrom=maninder1.s@samsung.com;       dmarc=pass
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

Hi,

>No, I've not heard of stackdepot, I don't know what it is, or what
>it does. It doesn't appear to be documented in Documentation - case
>insensitive grep for "stackdepot" gets no hits. No help text on its
>Kconfig option.
> 
>How are arch maintainers supposed to know anything about this?

ok.

Added reviewers/maintainers of stackdepot and KASAN(filter_irq_stack) code.
Because on our ARM H/W it was causing memory issue, and without this change
purpose of filter_irq_stack was gone as it was not filtering irq stacks.

If anyone else has any views or comments for this.

Thanks
Maninder Singh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910125949epcms5p40ddb337f000a5fe46bb6e59f48452060%40epcms5p4.
