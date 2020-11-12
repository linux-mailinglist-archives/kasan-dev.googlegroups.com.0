Return-Path: <kasan-dev+bncBDDL3KWR4EBRBFEJWT6QKGQEWI36SUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id ED7F32B0239
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:47:01 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id i19sf3449739ioa.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:47:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605174420; cv=pass;
        d=google.com; s=arc-20160816;
        b=06oVnQUTuhNPwJtaWvaEkvmivCpIKcXrbxuwCG/kbsclTlvpRy3GcR53EOJyOxL5Ib
         x5vbGsgj3WIGGjBFbmpwA+/gq8tD3z1xU2aPz/CKwwbv+YiKpYYgQ33zrN6AVH9sjbjs
         IFW7FaxVpZSmmuumlN/TqQjE9xr9tm2sr8UA1rz5Ditf/y34CY92e0crxpV+TiHg6qaU
         ttIYpbQKQsiMl3/SPnlXtOfCa1cORbcbiRmYPvb5TJKMr7sjK7lciZ+kIs8d3nURy3vG
         dofmuZbYyQlNl/Z6fy9uinfDJX+OVtIp9BMkjB7f8u7sdoFz3ziLwl3mFGmEXN3tTupO
         AVAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=BMkBoUB2HoSTCbgGnFfePAHtN36RsFC4CjDzyulUVB0=;
        b=PsA4715h+S6fpwG/LB2nU4MRb6axj9PhN/2EbUGDharJkd6DFPr+2PwLPMAr1LpLpT
         IvbGNBoWs3X2BJAEfwlYn+M/NY0L8GGMlBFIgRQnWP47qmlOnfHqiA3B1wvTEoijV7FK
         /BY+clkUHK9pmbbfj6xtOCIwFgzsvXOVaQyfKTI3fN3IhzKe2wKKdCLu86t6KneXRQbD
         cCTRMFzVLab/Bn2YyUEP2c60BOIL+IljPuDbT2PH0BZwIQ7UlckE9eDu94fTI7msfNU+
         4U4kMZW7waDhLDLsUmdQ/kzN+BFgPwEY5Aj26e0lTzS8Hi1bg18RZihYbi76xvCoU6yc
         oJzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BMkBoUB2HoSTCbgGnFfePAHtN36RsFC4CjDzyulUVB0=;
        b=Xp1f4l0xu9Xd2RaenLIu3tdc1r/OgPFCMy65DPtsiRydURDo3MmKe3wrLC+ffldJrC
         0PjbQCuTMD00ofljT+8oJvs/SWzeRJcj+PPr7qey8XMee89uSe6QDwdCK+D/CyPC2YgT
         30celjx0M2hbhnJ66gYZ9KwcCre/fyRWeNu0QoWLNGAW7XSP+m0bxbsyiVqizqy5+S92
         V6JCFLx1ripUkWUNTK008DzPfd1HsHXPjESTBLQFCO1PpUoBdB3ZrffZaZ10R7pEPqkg
         VVF/A2TheMyfkZ6zd3Xbnm9H/YIeccXw8QBOO9jr0DiGxDfmITjyDtkL0W+wbATWXQlf
         Oi1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BMkBoUB2HoSTCbgGnFfePAHtN36RsFC4CjDzyulUVB0=;
        b=IfTYvtf+BXR9g55mjtDIIKLLmIyb5KXsSNsvlqW9gqijxf2oOxA7z66yO+ILoeKDf+
         5opqfSMWPL3YdtG3OJ/dJXLRATK8+pR355fyNsrFGo5KwclhadYxFgiuRKs88onuJMvE
         7XHhqjfbBc1zLY2VtQJiT42YhEdjWLYu1pZSRxBhWar7QgbMdtIYonYMntiwLEIegOcX
         wm01q8JdJafguH/3yXCkeYGSzZU39Hghus0o8OLkGMLrbiRdW5Ib8SVT+nBYQd+RUhyh
         Zx0DqdEyRFsFPBn69X6St9k4F4bR+A2ZUL5iYxIKsDUpkAKgguoJ4n4noPKOhvAsDNc+
         D9gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533708JEIidPdlW5G7kD0aqfTYUDRTn5eLHB6EH/8NirHw1md1r+
	VpEmEfgFHUGy3JcyfKMbnXk=
X-Google-Smtp-Source: ABdhPJxdjRzm/fImo5VeVtYLKcdfrOFVTzJ2+NWHxlRTYq6jWTH0f3i9UPnugVWFhX71eSW+NbIt2Q==
X-Received: by 2002:a05:6e02:1388:: with SMTP id d8mr22629789ilo.272.1605174420422;
        Thu, 12 Nov 2020 01:47:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:140f:: with SMTP id n15ls619456ilo.4.gmail; Thu, 12
 Nov 2020 01:47:00 -0800 (PST)
X-Received: by 2002:a05:6e02:689:: with SMTP id o9mr6924597ils.47.1605174420072;
        Thu, 12 Nov 2020 01:47:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605174420; cv=none;
        d=google.com; s=arc-20160816;
        b=ygHEMQL7zZ1eWUcDcsC+XIxobWC/MCpKFgYld7VmG/WtascY3RetKJrh2Bw8rKCsnk
         dUCiUCAiSCLFs7DGOiAAHAHAymILpzT4zf0VxPFzl7DtS+IYTAXrymAwiv1uyAxb+ptl
         3PZbRZfuGYKMecmpiHqYHJDKkU1pXrT/AtFtSqW+vmK5wbwJcSYhF3LckR5A0+6Eq56l
         dCxbGnSd545QaB2h0naBBL0IEvjrUpFgVpoGGCHiWxrMbOPjEXa+02jS/zcF7RdSm3yc
         X9yRHedhWnsJaHjupYHBm21pFUkWWSu2JX9uXXRyr2mBM61slSOF98DPi33GbZ9Zgzq4
         xccA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=gicXUzNI/9yhIwbya7ixxl5KwJr3NLoHmLyhcODq5L4=;
        b=WwNFPGvoiZmDjd+bDcjj+XO4BXr2v8NjB+YZ3GqDDInq/HoAuI0HE8UXPGvUPisweQ
         k/m+sUp74DlJF3ZeP4MtgsZZhwR5/O8c/DFCAQbPczx+Pq9N29tBN84I3Z0zquLR2G07
         mOLJTiKH5EPmZ6PqSNYQPSeCdfQ5IYjL0Ysc3AShsgfmcgW+LqMUPwFPY1/UdDbk2OZo
         oV9jD8tVb8/gIOCGHWWnYaZ6SemZrqkHrtbZqIy9LW/3U2cOkgeH2Vu5HzRFhFXwLeIr
         ysJF0Xr5yGNfBcJ7gZOCWcLzSQJo4aD3YM+Ccs7bGnqoPnQK0cNLkHS3AyUW+sz2yBdr
         EkNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z10si9045ilp.1.2020.11.12.01.46.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 01:47:00 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 946DE21D40;
	Thu, 12 Nov 2020 09:46:56 +0000 (UTC)
Date: Thu, 12 Nov 2020 09:46:54 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v9 44/44] kselftest/arm64: Check GCR_EL1 after context
 switch
Message-ID: <20201112094653.GH29613@gaia>
References: <cover.1605046192.git.andreyknvl@google.com>
 <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
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

On Tue, Nov 10, 2020 at 11:10:41PM +0100, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> This test is specific to MTE and verifies that the GCR_EL1 register
> is context switched correctly.
> 
> It spawn 1024 processes and each process spawns 5 threads. Each thread
> writes a random setting of GCR_EL1 through the prctl() system call and
> reads it back verifying that it is the same. If the values are not the
> same it reports a failure.
> 
> Note: The test has been extended to verify that even SYNC and ASYNC mode
> setting is preserved correctly over context switching.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112094653.GH29613%40gaia.
