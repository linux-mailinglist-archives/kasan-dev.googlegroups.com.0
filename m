Return-Path: <kasan-dev+bncBAABBR5US36AKGQEXL6SKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-f64.google.com (mail-vs1-f64.google.com [209.85.217.64])
	by mail.lfdr.de (Postfix) with ESMTPS id 8434E28CDE6
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Oct 2020 14:15:04 +0200 (CEST)
Received: by mail-vs1-f64.google.com with SMTP id d9sf4648911vsl.12
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Oct 2020 05:15:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602591303; cv=pass;
        d=google.com; s=arc-20160816;
        b=vMEiaPoO3QDMJZsqymP3ceN64LymN/YXmbX9ArQyXmIw6TrYLQV8HophTztIAkPVoX
         ygB9KroevKk9juIecm2/KQLNjMkyJDb9lbs8edudt4Izwuhjwhz7hb3moO1Y9Z/wSf2A
         Sw3f7F/YtIKzOE0F3tVQ4H+5MMASbexdc0VCq2HNTdAUE9IgAQ3cyaWb1KRL8EW9mU6Q
         u95pQ4gJKNwNc6q0J+7xJYt/vCUp18o3REJQqgjONQR2XGv6ifgTSgJBBaxMmTyMUjwk
         g7XMJjLPjwjbsW6/sgjY+D3A5k1o5D/ohCQeX05lCTOeh32yrOxUmysv6Eq2QdAplNGO
         forA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from;
        bh=o+ClDlJVVeOzcmaeHN29PMqfwYQaIUDc8k4v/5kW2CU=;
        b=nXSK3UxpDLM8uAFH7hcdZYLISfKaU039OTa3sDi98YsSKR1/5pkhIzmezW3RJykkgW
         afpl0glRCNL68lRugzPjQOqp10bEkNxJBn6VsMx07FhHXYUaoNPUhcSJSYl8KRD3i2aQ
         plvVI2EVImHDipjqjD7JEfOFCX4lUksApyaJZ9AUomfsTI2bK3kPdobSjm6wQhAukvHY
         /dIoUZ1rTen7CCpHbRFojCEsTDagMYyZFHnrbWKviDn5b9DR4T09/YBhk+3W6/fpWx5b
         +T9WcUGJolbFDeJ5JP4BFaxUpNBXs3TNNaodtviPbEmQQUp82ctr32pdbv3xUHOZGJy/
         pz9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZTYMaspF;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:sender:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o+ClDlJVVeOzcmaeHN29PMqfwYQaIUDc8k4v/5kW2CU=;
        b=m6T+KGXLuyGR15+SdJYzfkozF2HrhmahSmY4BA8C0+Gxt8vOLWJG39ulsYMC7DYPCr
         ESprof9xWVduUbTKTB6Den5R/hzJXPP7jFqTSrQWDLIFgD/NfEPTjdc8dV0MlJG9oi04
         4g0OmzT0HImozPzg/Np6808TOnQizJL47RifRhbHigYNb761WFix0vXphcnNDDIalZpE
         ZFpUvoqDMPh2WEMAoHjebEJXHxjZ2xD+2b5C/KiC0GQ1Cm8XAU6fKcACuobXmmWl+Y8b
         zX/kZpmjfco7CLYt4zgO9Ff5SU6hHCJq4d1XWW/hfmj72fgo2a2bDViw01d2D2YPmPPc
         9EAA==
X-Gm-Message-State: AOAM531HBJ/1+sDHxFGSUoyWF42N3hP6B/o8Y3pAmvjN9eDovVq4XKFi
	m26oSBMQdoFiKcaXCbsXClQ=
X-Google-Smtp-Source: ABdhPJwvTTemkYfUYoOz9XQIGXwsPQHJ79qhuU7kKjM6ZE4b1cX9WRIgBg8hEFEnyM3510d+6/277Q==
X-Received: by 2002:a67:d005:: with SMTP id r5mr16356570vsi.13.1602591303416;
        Tue, 13 Oct 2020 05:15:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:edda:: with SMTP id e26ls2256484vsp.5.gmail; Tue, 13 Oct
 2020 05:14:57 -0700 (PDT)
X-Received: by 2002:a67:8002:: with SMTP id b2mr1493425vsd.22.1602591297363;
        Tue, 13 Oct 2020 05:14:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602591297; cv=none;
        d=google.com; s=arc-20160816;
        b=0SXJ+DiCvwq4SZD5O3h5TONvde8rPRVnxspkxL4tpEWNLOMwjZjtmuBOOMvigJl3x0
         VTipYMDEebLVScVtIlE7yDMURGpRAibDJuozuuK4w++45EeLJvBINeSa2ie5HzCNCQQq
         cZwkcVPyfdDxCwAexIAHTL5pSzF0iKAjo1X90B33Ms3FM93RbHOQD3pur9r4E9+22ByZ
         fqQ1s8U0gNAQWrxtLjvnIGMcirlpq/8MGv7b7Xso/0jR6zo4S1R/HWJ4ZKdKRkU4YJ7d
         te7eSLwlv1DXqkj31GFmquUdJ8nWaOVuFh0+UuejUYbgDrkCEEt8Wufxzse3A8bDmq8W
         xpIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=VjyfrCRdtpFGYB2Yo66fT4YY0ayYElgCncNCHIGB/8c=;
        b=KkhtQx4INpTfAbCR4TXdjDgIVBVJiLMbkx4CuL3VlnRba2pls84tRhRG/UhaGp7z6s
         ln17GZIWUhfBwoL4V7KZGMyDkAjRKCzwis5+gFDM6N7l++QIoKt3M9M3DslHTBZafrlK
         j4iqNXLdbMxmIir8g0s0Im2pv+VikbQyukxWia2jk1p1xuia9MlsVzrdOhnkTNAb4y3N
         hkjs9123On2i8XO4EKoTzUwuH0bEBuAOh2vwQDO3J3+PMvlo84K4maAGlzjWpjhVwA4w
         inN40K2A9b1kWqs99C9gELFvJKpBCE3nhHeC12ZEBZXCEqfop+pZ+JBLdCK9zWX8V9e0
         ClRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZTYMaspF;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g23si1101606vsa.0.2020.10.13.05.14.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Oct 2020 05:14:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (ip5f5ad5b2.dynamic.kabel-deutschland.de [95.90.213.178])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1C8C822265;
	Tue, 13 Oct 2020 12:14:55 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.94)
	(envelope-from <mchehab@kernel.org>)
	id 1kSJCe-006Co9-U8; Tue, 13 Oct 2020 14:14:52 +0200
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	"Jonathan Corbet" <corbet@lwn.net>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 09/24] docs: kasan.rst: add two missing blank lines
Date: Tue, 13 Oct 2020 14:14:36 +0200
Message-Id: <48293b76fddce2b2914592677bf5efdbb5b34859.1602590106.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <cover.1602590106.git.mchehab+huawei@kernel.org>
References: <cover.1602590106.git.mchehab+huawei@kernel.org>
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ZTYMaspF;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

literal blocks should start and end with a blank line,
as otherwise the parser complains and may do the wrong
thing, as warned by Sphinx:

	Documentation/dev-tools/kasan.rst:298: WARNING: Literal block ends without a blank line; unexpected unindent.
	Documentation/dev-tools/kasan.rst:303: WARNING: Literal block ends without a blank line; unexpected unindent.

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
---
 Documentation/dev-tools/kasan.rst | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c09c9ca2ff1c..2b68addaadcd 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -295,11 +295,13 @@ print the number of the test and the status of the test:
 pass::
 
         ok 28 - kmalloc_double_kzfree
+
 or, if kmalloc failed::
 
         # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
         Expected ptr is not null, but is
         not ok 4 - kmalloc_large_oob_right
+
 or, if a KASAN report was expected, but not found::
 
         # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48293b76fddce2b2914592677bf5efdbb5b34859.1602590106.git.mchehab%2Bhuawei%40kernel.org.
