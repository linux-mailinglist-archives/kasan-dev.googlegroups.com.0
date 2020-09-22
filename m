Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBU44U75QKGQEUEAD4AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id C6680273F4B
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Sep 2020 12:13:40 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id a14sf15531751qtp.15
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Sep 2020 03:13:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600769620; cv=pass;
        d=google.com; s=arc-20160816;
        b=jtwva1L0du37acPNFqu2OrTu8yze17xBaxnAjGb7MpPwxyWWkJPkUKLVg8/wVS2KZy
         wzRc6OejVFs95Q5yV18jJk0lFwEfNwjsqeFEFXHzOm2Eje3/jc/Xc3JSk6qGukdmUWhQ
         m7I2g4ScsT0VXjatSVj0oEke5fFf5k/Udui8yD8o/MDq6Flkrg6wLVDPpXxIHwq1MxgN
         cJCKL7W+g/ARkTzmCHXciZPd7iIZXBQ66kRfhhSiHdutgcp4LNO5+GsCawCVJ/Apalu2
         OaqoNsg4vHzT3BkZw9vqOIcMY+y1cwZn+qzL4ncIjaVQ6zbnj76C80gBLDgMQVjlFEEk
         bIFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=xy4I8QJNQwaVMN0PhMQHpVQxuPlra3wIg4ICsFveAuo=;
        b=QJAA7U2A4JoQ4wMofvzDarqeNKyAeGRHxBWhsk+DCsi211D8FTq40f2myBgacmcUtj
         9lFFOI2zhtrYycJEg2FJTFsuRGw0gOazOyo0ivbv/SPEUZkKRuFqbY+Ys2injWX0vqya
         vgVXFo9lTcmWbvdn4cnVyqzKZ4dO0BxzmuoSXFOqtMkbbgy18sjD/TyADe0JbTuCcq9T
         iaGwNNeMlgty9K++KI3eMGB3RSgKecXU+Ll06NkQSEMUkUfM/aefGkk9fKKl54xSQ2Yu
         srsqVz9X9MR18OzD4gwLiw9H/AQPeq5ZDP64ro6iTfIKCPIZbsAdB6n3AtPgkwUhuVmA
         vDAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xy4I8QJNQwaVMN0PhMQHpVQxuPlra3wIg4ICsFveAuo=;
        b=VPRcRp1PGNM1bdkQsUrunh34pNw0vdCHI+OZCkiThqFpXdA5OVF8MpG1GBfZkmJfQ0
         /mYpC78FfDokgMfzCM3igD5IZ/jm6u4ePBAMIZVE2pdhVID4tNU0myq+C24pE37jh2Wp
         M+l8/K8VI3h3EMbv0cNQ1UY9E8TJxf7/cN2anX2L1QMbOl0njb7ZMntZsN1jUy/3VaxZ
         jz0b8r9MCfMOzl5yJZ20ydRIL8T9q63quFVxESuixkO0gh36Nwr50gwzZ2lQnyPCRphg
         yLZvju9qYOwXia/ja8MiVR3JyLVJPxVtnUgVCYNfaMWSMsLdC0OBua0m6am93pzB/Ugk
         HWdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xy4I8QJNQwaVMN0PhMQHpVQxuPlra3wIg4ICsFveAuo=;
        b=GUFD+DC1fSHIY4zMkoeF6+ne1Edq9k3e0g+Cu7+Pwr8lmNSYm0ONC9iLcmwFo+Kntj
         IzhDr/yxhnOvVCjxrXowSCSyp/FErPR3gXh9kPzFidoovpUC5I7sT8Yzcv4IuKsKZtUc
         2W7KYjGJjXVqgjGQFl1nJMFPItSJzutT4KiopobMBH69bEic5eVVJHJeWf4wYmCJso7E
         Da4YpE9giocRlRp2CsEaKq68HBegj4nRrn//CwyOalcCTlX6txNDBVZQ3e4Nl5VtUFTe
         BoSFsVL7LL9g8QRB7o6O3pLdbb6W9IUxEvieJur1YdzQYa2mtDnrHEcPWa6KOuzeckie
         Z9tQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MT8qf7sD2koVBNWuckR3cyrDASxgZn5MOfFzM2jBJm8sH/Y3h
	HRbhRnLZw+ruEGXQCDrXYUM=
X-Google-Smtp-Source: ABdhPJwhkS/foMN7fFcHq24lD06bRT3LzwPb/T0NHcVn89S47gqHgmzcuQZewHQtN906HFd2huU0mw==
X-Received: by 2002:a0c:dd8d:: with SMTP id v13mr4918065qvk.22.1600769619931;
        Tue, 22 Sep 2020 03:13:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:136e:: with SMTP id c14ls4059675qvw.10.gmail; Tue,
 22 Sep 2020 03:13:39 -0700 (PDT)
X-Received: by 2002:a0c:e188:: with SMTP id p8mr5031437qvl.9.1600769619566;
        Tue, 22 Sep 2020 03:13:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600769619; cv=none;
        d=google.com; s=arc-20160816;
        b=JmmAGzo1RQjTxPxyIhgk3DRNibaSVMSespsSSiKUubhNcXFOPaIvYrIzOkMB88AP33
         U3M0Q2ET1RVWcI4in3e8ZiY3RrE3vthR3PbC9pkgAPaiS9p231fL6uiHVyQkI0NcOj0X
         eo4KG6/0sH8OAdiOOf3O28el610xtMxsuvI9yGBxJM+mcJ6jNONMzPIg7BbmItQEAVy8
         SEf/BsxreogNEyO2kTEqGDwltqDuajljExHa9HBvl1ucrKzBL+TRuqvlwbd0EG10qLSk
         HCUpJgiKq9ikZ9DRYBfU+WsN0pZF4lT2kp6stRZNTBvGGnMKloAI6D5wSgdH3w+6iDla
         Knmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=3wjkPS4t+GN2qQg6fKYdla0SOyJpq8expC6yITqibF4=;
        b=0esRwl1gvatgyuT7WAbE5JcYOj3Bj/m3wD8OOlBXqRxzRboWRCbvj0jjJN8Xmaj7xg
         +33EVNq/q6UVjxgdVpVrdJOQB9zDrJSULuXz5Zh1hMc5o4AMZKWRGBILk1ERetIJ2FnA
         pEUMAxp/ZYp3i3cUWq7S5EzLk6xeGhb0RUYo8mTJaGBDiAQcZfXITW/WfN1vGFzHrvMG
         c265Of9C7WAIfXLXJHtS3iFhMCHG73pXBJP1ofY6XJj7ajVkRygyUmOH5VOmzHu7AumS
         VBFKs96vDAuUsK0Y/OJ9HBW1xR6qOsNdtbmlUWW/ev1KQULSDYLpx8Anb7ocDdJKAh6q
         KD7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a2si800632qkl.4.2020.09.22.03.13.39
        for <kasan-dev@googlegroups.com>;
        Tue, 22 Sep 2020 03:13:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 90D4F1516;
	Tue, 22 Sep 2020 03:13:38 -0700 (PDT)
Received: from [10.37.8.152] (unknown [10.37.8.152])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CE4853F718;
	Tue, 22 Sep 2020 03:13:35 -0700 (PDT)
Subject: Re: [PATCH v2 22/37] arm64: mte: Add in-kernel MTE helpers
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1600204505.git.andreyknvl@google.com>
 <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
 <20200917134653.GB10662@gaia> <7904f7c2-cf3b-315f-8885-e8709c232718@arm.com>
 <20200918093656.GB6335@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <392180d4-95cf-fed9-5650-bbf52ec5c087@arm.com>
Date: Tue, 22 Sep 2020 11:16:06 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200918093656.GB6335@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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



On 9/18/20 10:36 AM, Catalin Marinas wrote:
>> Same as above but I will use the orr in the next version.
> I wonder whether system_supports_mte() makes more sense here than the
> alternative:
> 
> 	if (!system_supports_mte())
> 		return 0xff;
> 
> 	... mte irg stuff ...
> 
> (you could do the same for the mte_get_mem_tag() function)
> 

This would have been my preference from the beginning but then you mentioned
alternatives ;)

Anyway, more then happy to change the code in this way, seems more clean and
easy to understand.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/392180d4-95cf-fed9-5650-bbf52ec5c087%40arm.com.
