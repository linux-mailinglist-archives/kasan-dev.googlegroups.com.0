Return-Path: <kasan-dev+bncBCG4ZMWKSUNBB2XN6WRAMGQEFPGATHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A266FFD0E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 01:14:52 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-645538f6101sf29940166b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 16:14:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683846891; cv=pass;
        d=google.com; s=arc-20160816;
        b=XlQmyj+3p0LSZG4SMjirsTzDmj0nMtdkuhgBfvZwse36ei4ueY2jpQEhq1NrIUmyPh
         j8B+EP30rL6FbHoN7k5/KA1fhm4nqZ9WmxRs0N/SwhKueiMgR00jPX7P8Y1j1fTkXBnW
         pqbRLSy9tn2klMRczNXmYwmB2oig/NVq4yv3MRKsYlBsib5Hc27TEADWz89FxX7jISXP
         khHpxMiOkaVsI6zhxV2pAv+ZJIuJ51gxOmR4LqdOhCC4ciic9UXGBjxcUOki2lInfXSd
         uxwRtvmazt3ipUH2SWiKBzwdLnXUKMkWnpVkwFpMwJd1OcjYvpAMDi4KSxtXo6p2ZCaT
         N1Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:dlp-filter:cms-type
         :in-reply-to:mime-version:message-id:subject:cc:to:from:date
         :dkim-filter:sender:dkim-signature;
        bh=RpqsOPC0h+dDHyVRDJ0lApN2Yj7D17wSZE3iwyUS0xQ=;
        b=ABuGM/9v6wkWeIvfa/VptFz70O0FqVEFrI9ghcs1HcLlA4gXFsMTRoDzc+RaT750w3
         oGZltPiBIWYg7ilyxO01CYbMOXHCXzfx5lvbb24yIeD6224aa8R/MbRveVQ7w0nfdySU
         TkkwwH5kvSMqOvjaecpxijo9WBipxaxU16wOeGSCVaCLEryCICelgaSQ0QB35zHza7CM
         rz1XLSXrcICoQfSpY6wYKJ0JqTkqc889GGu4rhJi8t5VUSfSO+MF6Ld2qvhMagxHWyin
         yoMHsR89vRNFh3opdV7vQlWveqKDjfyzfd1MUmHFwDskEe45/DqtHgiP1ZA8YKDliAzL
         j9ZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=qVcWIxZl;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683846891; x=1686438891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:dlp-filter:cms-type:in-reply-to
         :mime-version:message-id:subject:cc:to:from:date:dkim-filter:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RpqsOPC0h+dDHyVRDJ0lApN2Yj7D17wSZE3iwyUS0xQ=;
        b=IoqbWLu/3UrFzNzfACHSmLES8E42DkyHpFyLzyKigzDn0ERhQIYbsP/krw7l4qD7iI
         OvA33FmWCz39XEenG0AKcd9R98s0SRzDUYkCFegkFlnHpFetQZjusfrcEMlKVQMQOCXP
         stsS8XO3ErJjA6BWx5hO0kn5ySRiZOBA+1cS9rYFhjHw+ps+u2GehIvuuvSqWSb7QSwc
         C5LCcr7A8+tJSYk0PDChNYWhNOwpHJPS0DDzt/eCR5MgJMWw8g0y4mouBdtT8pkMysA3
         aP90FY8S3h0uM7AU3QHmxDwQHP7XJUZHzW6d+2HLY1zqt6pHlgCBVrYaAYqy/vTtVsrI
         8U1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683846891; x=1686438891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :dlp-filter:cms-type:in-reply-to:mime-version:message-id:subject:cc
         :to:from:date:dkim-filter:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=RpqsOPC0h+dDHyVRDJ0lApN2Yj7D17wSZE3iwyUS0xQ=;
        b=H46uyefTuj0I9iMlUmiO0jztvY4wjIBNOtMMVoedzBAkOvSiK5VQN/p9u58MjH1ayV
         9mhOIYCEz9ko3KNELrcF9rgIs6iAcLzcO6p0CWGK9HzyfkpdtnfK5eyi/QtABNRq7EX7
         5EBgLqZW1QhQlLH/7yasWBgRTrXNOxuee2ZlRYhEGezijhEQek17QaZesGkFFnXqdlCG
         uUoTpWjUJXjliDjgtXmCd1rqZ0HsfR/L4LhfW8+cpJE2vj3+Nz1iXa5x9cDi/ZhxlQq8
         mMZ7/Aj44zAKrQ8Ecm2fv0vJiUnbnWcja6Ynt+cs6Jis7C7X6RB3myxCPf2RIj2KSIv1
         R20g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxu6o8sP2+JBqTPpC7vICh3huVw8FSYu6U+Xja/lv/sPxejJ0EX
	nc/8O08Lk8stwKPRDZWjbDo=
X-Google-Smtp-Source: ACHHUZ6HiOJZhP3gup4f16sC2XSuUhd64whB91lmBb6vNuwUyAMXFako8IucFyZa5e7kUfhj6uvsXQ==
X-Received: by 2002:a63:2806:0:b0:51a:7d6a:65c9 with SMTP id bs6-20020a632806000000b0051a7d6a65c9mr6437136pgb.6.1683846890695;
        Thu, 11 May 2023 16:14:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e1cc:b0:196:751e:4f6e with SMTP id
 t12-20020a170902e1cc00b00196751e4f6els2904pla.10.-pod-prod-gmail; Thu, 11 May
 2023 16:14:49 -0700 (PDT)
X-Received: by 2002:a17:90a:b007:b0:24d:f880:5192 with SMTP id x7-20020a17090ab00700b0024df8805192mr21485585pjq.19.1683846889725;
        Thu, 11 May 2023 16:14:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683846889; cv=none;
        d=google.com; s=arc-20160816;
        b=TAiBC7rSmFwRym+0qfwZZ/CwMuZnsh1mwqEzOWJY+Q7iJQDkraj4ST5L/dTSGs/7XY
         Z0EytBFaLYHEImnK6+BGLjjynbKG/dcLdJr1UttTARb34LEPWJQzYwILMqrtsTScy1lt
         f6LVn0lcEVg61jkDZxQhvesBb5OGTHA6Nx5YgE1Mfffc63uRfNhn6Rk/9SdyJsYDOf1X
         rUEuNrxqChetcco6JFVZZQTwTOOnY15y9ljeCmORdSv1OZULQ1DkFJA71mdhnpObBZkO
         1osXAas45ix1nBRSc96HZP+g/2kx3YSYSJId41qDDPhza4oLHRBzIpyO2ot17OeN832T
         B2ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:dlp-filter:cms-type:in-reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-filter;
        bh=jlCwTX7bTofIc1nCkwsfm7hSTJ5JzJRR44AmY2dCDXk=;
        b=AlwRC8Aa10KEm6ghXDrEG8+8bJwtcFmGEV5ht7R3QQY5n/i9W11ngXSvI2A86qCOjX
         Kg5LcrmM9xhbfBlae7dHEuJzAnVFKWGQDxwbJj9YMUrWE7mUvaLwgcMB9wwZ0ii6dljL
         2lRU2mrYnx7PovwzY0rHqXzmBeFCppy1ar4Jy7nnesCIcChzOnUt1waQsUwcmS7zl4n/
         B2QvFdkB2krR8+y8jEuVc6PtEGCYIfD+Ojtz3bHBYdiSi0HH0d1ngbv/vlEF6zpKsLxd
         M2P7DQ9iqv3flo1833hbkPJ8aD0D5n4TG13mrQygV8FoWryzHVnGEkm1QdANCKAwWDms
         69kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=qVcWIxZl;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.samsung.com (mailout2.samsung.com. [203.254.224.25])
        by gmr-mx.google.com with ESMTPS id kk11-20020a17090b4a0b00b0023f99147cfdsi420179pjb.3.2023.05.11.16.14.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 May 2023 16:14:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.25 as permitted sender) client-ip=203.254.224.25;
Received: from epcas2p3.samsung.com (unknown [182.195.41.55])
	by mailout2.samsung.com (KnoxPortal) with ESMTP id 20230511231447epoutp02391a452e3ba306577c4f6024e3132c8b~eOdKdgnAY3229632296epoutp022
	for <kasan-dev@googlegroups.com>; Thu, 11 May 2023 23:14:47 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.samsung.com 20230511231447epoutp02391a452e3ba306577c4f6024e3132c8b~eOdKdgnAY3229632296epoutp022
Received: from epsnrtp3.localdomain (unknown [182.195.42.164]) by
	epcas2p4.samsung.com (KnoxPortal) with ESMTP id
	20230511231446epcas2p44649b9ae40d06ea6d0ced86e364c210c~eOdJlv-sa3162731627epcas2p4g;
	Thu, 11 May 2023 23:14:46 +0000 (GMT)
Received: from epsmges2p4.samsung.com (unknown [182.195.36.69]) by
	epsnrtp3.localdomain (Postfix) with ESMTP id 4QHSQs6KgYz4x9Pp; Thu, 11 May
	2023 23:14:45 +0000 (GMT)
Received: from epcas2p1.samsung.com ( [182.195.41.53]) by
	epsmges2p4.samsung.com (Symantec Messaging Gateway) with SMTP id
	31.5E.22936.5E67D546; Fri, 12 May 2023 08:14:45 +0900 (KST)
Received: from epsmtrp1.samsung.com (unknown [182.195.40.13]) by
	epcas2p1.samsung.com (KnoxPortal) with ESMTPA id
	20230511231445epcas2p1dc064af79f66fbdd459e0ae9a2c04d1c~eOdIXAJ4d0582405824epcas2p16;
	Thu, 11 May 2023 23:14:45 +0000 (GMT)
Received: from epsmgms1p2.samsung.com (unknown [182.195.42.42]) by
	epsmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20230511231445epsmtrp18d829b6519c1136ec1effc594766800a~eOdIVlP0n0792507925epsmtrp1D;
	Thu, 11 May 2023 23:14:45 +0000 (GMT)
X-AuditID: b6c32a48-6d3fa70000005998-b8-645d76e5afeb
Received: from epsmtip2.samsung.com ( [182.195.34.31]) by
	epsmgms1p2.samsung.com (Symantec Messaging Gateway) with SMTP id
	15.2C.28392.4E67D546; Fri, 12 May 2023 08:14:44 +0900 (KST)
Received: from perf (unknown [10.229.95.91]) by epsmtip2.samsung.com
	(KnoxPortal) with ESMTPA id
	20230511231444epsmtip22a5127fb0147d70d8230a88c800c8437~eOdICZOmD3172031720epsmtip26;
	Thu, 11 May 2023 23:14:44 +0000 (GMT)
Date: Fri, 12 May 2023 08:46:56 +0900
From: Youngmin Nam <youngmin.nam@samsung.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: youngmin.nam@samsung.com, alexandru.elisei@arm.com,
	andreyknvl@gmail.com, anshuman.khandual@arm.com, ardb@kernel.org,
	broonie@kernel.org, catalin.marinas@arm.com, d7271.choe@samsung.com,
	dvyukov@google.com, hy50.seo@samsung.com, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, mark.rutland@arm.com, maz@kernel.org,
	will@kernel.org
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a
 default
Message-ID: <ZF1+cLp7Io7L25yG@perf>
MIME-Version: 1.0
In-Reply-To: <ZEixUYKPr3F0Y8Xn@perf>
X-Brightmail-Tracker: H4sIAAAAAAAAA02Tf0wTZxjHffvj7sCV3QroO8awHkijWUsLHD1F1ERcLht/kC3bHzOOdfTS
	Etrrpdcy9Y8JugCrqDRuMkolOBwgiCOFVH5tIpDNbmL8QRyCzJEV5kAjIBGHDNdydfG/zz3v
	95Pnee+5w8RyHxKHFbB2xsbqzQQSKfENbCZVk0X7DJrnfi1Vde4WQi26qlDqxyv51D8LjwD1
	9UQAoR41VADq9g8ulKqcKEWplvo/JFTT1D0R5f3ztpT67rcbIqrL45dSX9wlqfq+eXTXq/T5
	2vOA7nKPo3Sd10H3uvwI7W3+EqHbzx6ij3c0g1z0o8LtJkZvYGwKhs23GgpYYxbx7vt5u/PI
	DI1Wpd1K6QgFq7cwWUR2Tq7q7QJzcGpCUaQ3O4KlXD3PEyk7ttusDjujMFl5exbBcAYzp+PU
	vN7CO1ijmmXs27QaTSoZDH5SaGp9dgbhnDv3exrZYnA9zQkiMIinw/JAmdQJIjE53gng6YYS
	1Amw4MM8gHO4UH8MoL9qTPxCuDa8AkIsx7sBbP2GFEITAHpGL4pCBxJ8E2y65l0NIbgK+q4I
	QgyuhBXdC5KQIManRfDYg1Yk1C0a/wC2TMNQRoYnwsClSYnAr0F/dWCVI/Ak2LtUg4ZciPdi
	8NRgZ3iibOgqKQYCR8PpnztQgePg3ydKw1wIW5Zuhnk/LPu9IuymQfdU2aorxk3w9EqtNDQP
	DA4xOCoRylGwfOBfVCjLYHmpXDCT4dJXbeGu8bCnvkksRGjoblcIr6REDH3VM0glSHC/dBv3
	S80EfgvW9cwj7qAuxt+AjSuYgJvh990pdUDaDNYxHG8xMnwql/7/cvOtFi9Y/YC30J2g5uGs
	uh+IMNAPICYmYmQPz+41yGUG/YGDjM2aZ3OYGb4fkMHVuMRxsfnW4B/A2vO06Vs16RkZWl0q
	qdER62Vz5YkGOW7U25lChuEY2wtPhEXEFYv62mcddSfX3cqqyvrrcnP0e55fPFE755a1vcf2
	TRx6fGSNUtWXLMl7Z3FkqKsi9tujOitXWH8JLIv61RtzYgLVYGiPcfKnxl+HR2rIO9b1tcsB
	/yQxcVR5cppeq3iS6Dk8NvpgxGO+YQJHZg9IqMiD128qT6nUhz+9uPHp2Czq47lzOQ1Fb/aM
	lXFDSScSzhBX9w5eXvs6+9ki2dDLKe/HZz7/UEnfa7nq8MxXHl/4/GmUJb6JbnZiFLdpV1TC
	8uCakTbbQKzrTjRNajbsKcieeWV+vKRnZjz5/o6OKVlZ8sdDDkvayrPMoeELbU9YMrslJX+k
	LSnz7oYLkSvupG1aQsKb9NotYhuv/w8+nAjHSQQAAA==
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFmpkkeLIzCtJLcpLzFFi42LZdlhJXvdJWWyKwfnV1hbTV15ms/g+cTq7
	xb4TyRY/v7xntJj68AmbxftlPYwW1/ZOZLeY8LCN3WL14gcsFiue3Wey2PT4GqvF0usXmSx2
	zjnJatFyx9Ri8YFP7A78HmvmrWH02DnrLrvHgk2lHnsmnmTz2LSqk81j85J6j74tqxgD2KO4
	bFJSczLLUov07RK4Mr7c+c9ecMqm4umsuYwNjCsNuxg5OSQETCTOXfnH2MXIxSEksINRYmPH
	EmaIhIzE7ZWXWSFsYYn7LUdYIYruM0rMeveGHSTBIqAqseLcJkYQm01AV2LbiX9gtoiAukTP
	ri8sIA3MAq+YJK52fwXq5uAQFgiVWP1KAqSGV0BZ4sn+pywQQ1uZJZ5uvMYOkRCUODnzCQuI
	zSygJXHj30smkF5mAWmJ5f84QMKcAioSe37NZp/AKDALSccsJB2zEDoWMDKvYpRMLSjOTc8t
	Niwwykst1ytOzC0uzUvXS87P3cQIjiUtrR2Me1Z90DvEyMTBeIhRgoNZSYT37ZLoFCHelMTK
	qtSi/Pii0pzU4kOM0hwsSuK8F7pOxgsJpCeWpGanphakFsFkmTg4pRqYZv1nMlH4toBF9EHG
	2X3yHq7fHJk9Ehb4JzxvnrdSliXKYUvks82m6o55u5L/CtXYXLG/uJh7meTci586Bb5I/5x+
	YaXcBa5AaZk2p+MXmZed+H07zU35x67/XjoKE+dtTDxz9riho0q5+MvpMkvS/rfuSrxwpa05
	/0BYk41SbcvxA8e2T5XamCR/6lgsO3uzrlJ+mGzAiTKnHT/21uuKTY+tnnfuTriVqeq7H6Yn
	bsTu1Y+S2aaamVGw6H/NLUEPnqiJ6hPfXqi6dSSwQJbj9/KQP+mnXDawPdv+ueuOWaVNjQ6X
	LSPTsgfFQXdzPJ5J9nLlp0SKuZrvWtPbFF9RwH1o79mA/+F2C3fO8rqkxFKckWioxVxUnAgA
	xIh3uxQDAAA=
X-CMS-MailID: 20230511231445epcas2p1dc064af79f66fbdd459e0ae9a2c04d1c
X-Msg-Generator: CA
Content-Type: multipart/mixed;
	boundary="----z2p9DfUg.12UdV-1HGm7AiXlN_kW1MICQ4MqlFGlIKeVCcXh=_fd1ca_"
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
X-Original-Sender: youngmin.nam@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=qVcWIxZl;       spf=pass
 (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.25 as
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

------z2p9DfUg.12UdV-1HGm7AiXlN_kW1MICQ4MqlFGlIKeVCcXh=_fd1ca_
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Wed, Apr 26, 2023 at 02:06:25PM +0900, Youngmin Nam wrote:
> On Tue, Apr 25, 2023 at 02:39:51PM +0100, Mark Rutland wrote:
> > On Tue, Apr 25, 2023 at 11:31:31AM +0900, Youngmin Nam wrote:
> > > On Mon, Apr 24, 2023 at 02:08:14PM +0100, Mark Rutland wrote:
> > > > On Mon, Apr 24, 2023 at 02:09:05PM +0200, Dmitry Vyukov wrote:
> > > > > On Mon, 24 Apr 2023 at 13:01, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > > >
> > > > > > On Mon, Apr 24, 2023 at 10:04:36AM +0900, Youngmin Nam wrote:
> > > > > > > filter_irq_stacks() is supposed to cut entries which are related irq entries
> > > > > > > from its call stack.
> > > > > > > And in_irqentry_text() which is called by filter_irq_stacks()
> > > > > > > uses __irqentry_text_start/end symbol to find irq entries in callstack.
> > > > > > >
> > > > > > > But it doesn't work correctly as without "CONFIG_FUNCTION_GRAPH_TRACER",
> > > > > > > arm64 kernel doesn't include gic_handle_irq which is entry point of arm64 irq
> > > > > > > between __irqentry_text_start and __irqentry_text_end as we discussed in below link.
> > > > > >
> > > > > > TBH, the __irqentry_text annotations don't make much sense, and I'd love to
> > > > > > remove them.
> > > > > >
> > > > > > The irqchip handlers are not the actual exception entry points, and we invoke a
> > > > > > fair amount of code between those and the actual IRQ handlers (e.g. to map from
> > > > > > the irq domain to the actual hander, which might involve poking chained irqchip
> > > > > > handlers), so it doesn't make much sense for the irqchip handlers to be
> > > > > > special.
> > > > > >
> > > > > > > https://lore.kernel.org/all/CACT4Y+aReMGLYua2rCLHgFpS9io5cZC04Q8GLs-uNmrn1ezxYQ@mail.gmail.com/#t
> > > > > > >
> > > > > > > This problem can makes unintentional deep call stack entries especially
> > > > > > > in KASAN enabled situation as below.
> > > > > >
> > > > > > What exactly does KASAN need here? Is this just to limit the depth of the
> > > > > > trace?
> > > > > 
> > > > > No, it's not just depth. Any uses of stack depot need stable
> > > > > repeatable traces, so that they are deduplicated well. For irq stacks
> > > > > it means removing the random part where the interrupt is delivered.
> > > > > Otherwise stack depot grows without limits and overflows.
> > > 
> > > Hi Dmitry Vyukov.
> > > Thanks for your additional comments.
> > > 
> > > > 
> > > > Sure -- you want to filter out the non-deterministic context that the interrupt
> > > > was taken *from*.
> > > > 
> > > > > We don't need the exact entry point for this. A frame "close enough"
> > > > > may work well if there are no memory allocations/frees skipped.
> > > > 
> > > > With that in mind, I think what we should do is cut this at the instant we
> > > > enter the exception; for the trace below that would be el1h_64_irq. I've added
> > > > some line spacing there to make it stand out.
> > > > 
> > > > That would mean that we'd have three entry points that an interrupt trace might
> > > > start from:
> > > > 
> > > > * el1h_64_irq()
> > > > * el0t_64_irq()
> > > > * el0t_32_irq()
> > > >
> > > 
> > > Hi Mark.
> > > Thanks for your kind review.
> > > 
> > > If I understand your intention corretly, I should add "__irq_entry"
> > > to C function of irq_handler as below.
> > 
> > I'd meant something like the below, marking the assembly (as x86 does) rather
> > than the C code. I'll try to sort that out and send a proper patch series after
> > -rc1.
> > 
> > Thanks,
> > Mark.
> > 

Hi Mark.
This is gentle remind for you.
Can I know that you've sent the patch ?
Actually I'm looking forward to seeing your patch. :)

> After applying your draft patch,
> I checked System.map and could see irq entries we expected were included as below.
> 
> ffffffc008000000 T _text
> ffffffc008010000 T __irqentry_text_start
> ffffffc008010000 T _stext
> ffffffc008010000 t el1t_64_irq
> ffffffc00801006c t el1t_64_fiq
> ffffffc0080100d8 t el1h_64_irq
> ffffffc008010144 t el1h_64_fiq
> ffffffc0080101b0 t el0t_64_irq
> ffffffc008010344 t el0t_64_fiq
> ffffffc0080104d8 t el0t_32_irq
> ffffffc008010670 t el0t_32_fiq
> ffffffc008010928 T __do_softirq
> ffffffc008010928 T __irqentry_text_end
> ffffffc008010928 T __softirqentry_text_start
> ffffffc008010fa0 T __entry_text_start
> ffffffc008010fa0 T __softirqentry_text_end
> 
> And then, I confirmed callstack was cut correctly as below.
> 
> [   89.738326]I[5:NetworkWatchlis: 1084]  kasan_save_stack+0x40/0x70
> [   89.738337]I[5:NetworkWatchlis: 1084]  save_stack_info+0x34/0x138
> [   89.738348]I[5:NetworkWatchlis: 1084]  kasan_save_free_info+0x18/0x24
> [   89.738358]I[5:NetworkWatchlis: 1084]  ____kasan_slab_free+0x16c/0x170
> [   89.738369]I[5:NetworkWatchlis: 1084]  __kasan_slab_free+0x10/0x20
> [   89.738379]I[5:NetworkWatchlis: 1084]  kmem_cache_free+0x238/0x53c
> [   89.738388]I[5:NetworkWatchlis: 1084]  mempool_free_slab+0x1c/0x28
> [   89.738397]I[5:NetworkWatchlis: 1084]  mempool_free+0x7c/0x1a0
> [   89.738405]I[5:NetworkWatchlis: 1084]  bvec_free+0x34/0x80
> [   89.738417]I[5:NetworkWatchlis: 1084]  bio_free+0x60/0x98
> [   89.738426]I[5:NetworkWatchlis: 1084]  bio_put+0x50/0x21c
> [   89.738434]I[5:NetworkWatchlis: 1084]  f2fs_write_end_io+0x4ac/0x4d0
> [   89.738444]I[5:NetworkWatchlis: 1084]  bio_endio+0x2dc/0x300
> [   89.738453]I[5:NetworkWatchlis: 1084]  __dm_io_complete+0x324/0x37c
> [   89.738464]I[5:NetworkWatchlis: 1084]  dm_io_dec_pending+0x60/0xa4
> [   89.738474]I[5:NetworkWatchlis: 1084]  clone_endio+0xf8/0x2f0
> [   89.738484]I[5:NetworkWatchlis: 1084]  bio_endio+0x2dc/0x300
> [   89.738493]I[5:NetworkWatchlis: 1084]  blk_update_request+0x258/0x63c
> [   89.738503]I[5:NetworkWatchlis: 1084]  scsi_end_request+0x50/0x304
> [   89.738514]I[5:NetworkWatchlis: 1084]  scsi_io_completion+0x88/0x160
> [   89.738524]I[5:NetworkWatchlis: 1084]  scsi_finish_command+0x17c/0x194
> [   89.738534]I[5:NetworkWatchlis: 1084]  scsi_complete+0xcc/0x158
> [   89.738543]I[5:NetworkWatchlis: 1084]  blk_mq_complete_request+0x4c/0x5c
> [   89.738553]I[5:NetworkWatchlis: 1084]  scsi_done_internal+0xf4/0x1e0
> [   89.738564]I[5:NetworkWatchlis: 1084]  scsi_done+0x14/0x20
> [   89.738575]I[5:NetworkWatchlis: 1084]  ufshcd_compl_one_cqe+0x578/0x71c
> [   89.738585]I[5:NetworkWatchlis: 1084]  ufshcd_mcq_poll_cqe_nolock+0xc8/0x150
> [   89.738594]I[5:NetworkWatchlis: 1084]  exynos_vendor_mcq_irq+0xac/0xc4 [ufs_exynos_core]
> [   89.738638]I[5:NetworkWatchlis: 1084]  __handle_irq_event_percpu+0xd0/0x348
> [   89.738647]I[5:NetworkWatchlis: 1084]  handle_irq_event_percpu+0x24/0x74
> [   89.738656]I[5:NetworkWatchlis: 1084]  handle_irq_event+0x74/0xe0
> [   89.738665]I[5:NetworkWatchlis: 1084]  handle_fasteoi_irq+0x174/0x240
> [   89.738675]I[5:NetworkWatchlis: 1084]  handle_irq_desc+0x6c/0x2c0
> [   89.738686]I[5:NetworkWatchlis: 1084]  generic_handle_domain_irq+0x1c/0x28
> [   89.738697]I[5:NetworkWatchlis: 1084]  gic_handle_irq+0x64/0x154
> [   89.738707]I[5:NetworkWatchlis: 1084]  call_on_irq_stack+0x2c/0x54
> [   89.738717]I[5:NetworkWatchlis: 1084]  do_interrupt_handler+0x70/0xa0
> [   89.738726]I[5:NetworkWatchlis: 1084]  el1_interrupt+0x34/0x68
> [   89.738737]I[5:NetworkWatchlis: 1084]  el1h_64_irq_handler+0x18/0x24
> [   89.738747]I[5:NetworkWatchlis: 1084]  el1h_64_irq+0x68/0x6c
> 
> Thanks for your work.
> Please add me when you send the final patch so that I can test again.
> 
> > ---->8----


> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZF1%2BcLp7Io7L25yG%40perf.

------z2p9DfUg.12UdV-1HGm7AiXlN_kW1MICQ4MqlFGlIKeVCcXh=_fd1ca_
Content-Type: text/plain; charset="UTF-8"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZF1%2BcLp7Io7L25yG%40perf.

------z2p9DfUg.12UdV-1HGm7AiXlN_kW1MICQ4MqlFGlIKeVCcXh=_fd1ca_--
