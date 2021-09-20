Return-Path: <kasan-dev+bncBDDL3KWR4EBRBSWSUKFAMGQEFVD2PYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id C52E4411838
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 17:31:23 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id n3-20020a17090a394300b0019765b9bd7bsf152730pjf.8
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 08:31:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632151882; cv=pass;
        d=google.com; s=arc-20160816;
        b=eyXQhaV5OAENIxgfGveT6uZwngONJjQjHZjyASbtAu3Pcg6XioxV//O+HgZLklish6
         7MClULX+ULGqQ8qGcAnhvF8H++CDB172F9MQBqs1pTjQq7Fo2s3nsCjW27tH9vErKfRD
         T2iYm7VVqt9/EgpUPSir2NWbXEYRSSFaXNgiMQopqwx6ae9mUCv+PhIloYVIWcUSu4nv
         z50wy8DugI1XQJ3T4pp88j8cKrfX3LvRXMUvNoLe1dd37gkvBWRB1B7DYdrMOhQ9i7NW
         RboR68oQmQWai9mAEeEcX5EhUoy0GXZjURSnNC3tj2Glb+1xak8Mx/FLmj+EMmDgMBwW
         PVag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MHDWosx0xlHV5O7kkm0MjzYdT5hQQoxibdFhoPVDekI=;
        b=aeCt+0edA25aZIYhwonAA7y0Fg9sEjlZnA2gLk6lVkpHpoIVWiRAQC3cf9g0hQqX3g
         alumhs0vat8ZMGkuv4w48WCxOSb/1gKxYGpny7gIWCtv6qvxCUR3zUMWtOb5vJIu0YvL
         xx6Sk889m5+GCGgVMrrLKjsNXjzJBkaPLa20fXQIVHksLr+TaJ77ccs6OekD7K1ZkA8T
         /hw6FF7sdBtHILkQQqnUz+uK2zXasvfXhnVgoC9s+DFlm/4T4FsgToIFRFnocXtDzvSl
         Eq1/nU2drPRbaWVI/G55KzJBKEg2IDLRPeX7JJarId524XEhY7ySqqxQ76dGKcoZszjY
         bUHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MHDWosx0xlHV5O7kkm0MjzYdT5hQQoxibdFhoPVDekI=;
        b=cIeUQ+uJxJLvAtiMI9Q8qhF1DUShIeDxk6sdItaRGMcmduol+nXO0aWnsF9Jnty5I4
         oRuOyCrbE2MfJaDJIRaIxGX74UgcJMQweqyICaTTuJ06omYb/lWbzYKcbLZmKKFn8OE/
         f1y3ICOGmRDP2ilOCzjxWi6Pt5frvIfRa/VuNtXASEzln1YW7CyTkXNwP43GCjzKn5WA
         6XxxgQ9VRNspNJKoBA2iwGYul1J+saYVbjgkqRnmtGDRgVaBiY8bv4DW1kjVhRK+ceZZ
         rSaDS7dgi5adAlSttAd+EJXsunuOY/MJflbs7Germ7DiU4LE5bE2IvXnBDjq+zW92Vhc
         i56w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MHDWosx0xlHV5O7kkm0MjzYdT5hQQoxibdFhoPVDekI=;
        b=DXHMe3drflz5bxag5EWON7Kom7204ibdREgzjcaHuq4kK/deobDsc76eDGDrBZGB66
         6rdxc5YI9SmVByMqoO7ERXzYfV6zO+7r6GBJ2tpXNfE+A4OQ9NODbPA/IVJoP07MQawC
         5YapTL9F3Si3b2GpIOhmRVlzOOXqLrI3w6OzvqZsxOD+BOoYc6rTBT9CvHfTD10jotWh
         b0dgeaAN+QBG7wF8sMpaLxz60z1eogMmTYk4W2KFO6Fw50HYtCWwk+CpOo4lyA7vZOJF
         3+cNlwj54klZ9EAwx+CvtYv83bC+9kEYwxc1LEri9Y2Xvr5jBDRZjmyIe8dLYbotn3+y
         NMOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xOOyXMIcoxlQuWJim2U7DKhvau4ULSaSv1j+pch9+vpxXrYmV
	IfeDpbKR6F46Y/r28Zc0Z34=
X-Google-Smtp-Source: ABdhPJyuyGipUu9o0kbU2CmaC5rezGLwHcXTDa9j/AYCQ+MFKj+//STDsIQdZk3skuGuKSRytMzBPg==
X-Received: by 2002:aa7:9f9a:0:b0:445:10b6:5a6e with SMTP id z26-20020aa79f9a000000b0044510b65a6emr17002893pfr.70.1632151882222;
        Mon, 20 Sep 2021 08:31:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:20cc:: with SMTP id i12ls8225097plb.8.gmail; Mon, 20
 Sep 2021 08:31:21 -0700 (PDT)
X-Received: by 2002:a17:902:cacb:b0:13a:5f28:e4cb with SMTP id y11-20020a170902cacb00b0013a5f28e4cbmr23417702pld.37.1632151881455;
        Mon, 20 Sep 2021 08:31:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632151881; cv=none;
        d=google.com; s=arc-20160816;
        b=yzCWobNrTWr2lwiOSqvBNsXQU8r6xRR2+CHKRC9VmYYv7jk+LIbL76Je0GnqxVUqqa
         dwQD/9BqJgDcniiQ4Cz5bgXMKxQPLgN1lS28Y7xAQwDbWqNhTFjsTy9TJnObdGynnQmK
         WljZd1eI+s09EdLJNrvUbMnMGWeuP0vwnG9jJegwB3OYqKyr/wMiUA8M1ObV+LqagUIJ
         u6fZDDgCarxQv1pwFPhS513EghIjZv6cI0wM1Y6mqqnyHi3sl9FAIKB09oI2SQdPqONj
         KOWvmVlEsFOIH4stMwKJ1fydDqy1ssb78ffmks2UdhWCYY6EGhWagOPwbi9JRRW7+0i8
         BSIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=HlfAjS2+iA0LsltYMPFv1/wfPfQbXYzjy3Ar9ac59sc=;
        b=OWtcCfCs/a84tGx7IfftAW74Bt9ubmQr4cfLiv9hlJMhzck+h6u/dcBuSNsAwGg7SA
         uXM7PQ8xTsOFbPRJ74w/wwL66RBRTGXEBzdstvDL/NtlHH6pf2qABLaGTc3vCK05srU5
         IiG4gd46V+WoNCjVnBDRQWFkGHoKS4ZvLu9tgeumbdDq22MCgs+tZLdzdRQroLSXEuhg
         nHwvCD0vvy9ZfmNA8pxdqfnmQ1xEziFKTtQl89S1OO4YE3UtY0CRUQkQkLavfLpJlBHt
         dc3q8GGqOSHDYeYN8GxmqX2kCWvSkIAC9s7rVsujAQVpEdV5oW9tWibxVmJ8uP1C08XF
         Hlyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i22si11361pfq.4.2021.09.20.08.31.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Sep 2021 08:31:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CD61F610FB;
	Mon, 20 Sep 2021 15:31:18 +0000 (UTC)
Date: Mon, 20 Sep 2021 16:31:15 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH 2/5] arm64: mte: Bitfield definitions for Asymm MTE
Message-ID: <YUipQ3WBk0LrgdMV@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-3-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913081424.48613-3-vincenzo.frascino@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Sep 13, 2021 at 09:14:21AM +0100, Vincenzo Frascino wrote:
> Add Asymmetric Memory Tagging Extension bitfield definitions.
> 
> Cc: Will Deacon <will@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUipQ3WBk0LrgdMV%40arm.com.
