Return-Path: <kasan-dev+bncBAABBJMORTUAKGQELHGF5QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 93F7E451E9
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2019 04:32:07 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id e7sf699636plt.13
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 19:32:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560479526; cv=pass;
        d=google.com; s=arc-20160816;
        b=qjgSx0rC/01IxhZXqf1Qlk8pz1gCP8E26Bg3nam+CnsMMZ62eiUCyNk8Mrr8KUgiy9
         BjWhlyOEYM+Yx+7zl6KcheGjEzCZdpH1hHKumQTBoJqL/iWjo4pkcCCfoQleKpM65k1b
         KeNB/os+k80xy3i+vT0w+cmMyD9BrONg8JrdM2EKNDbJM1bhxxESeY7XwQjsOayXz321
         f86h+D6233VOZEUDcCLWMfdv7/jHZX/bD0oRzr8Hum1bFOgWpLDKX8wL0/xMcFo6fmOj
         KInTyPWJ/2X+PvdbUNOQsaa+KtgO6u1nDVMHtDZKDVP8aW4TgBW2l7SwLuE9sSYxLzpb
         OwhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=2E/m9fft1+aTENQjQr55yvnsllDYlUJN1QahSuOsaog=;
        b=F7bXjYSarmktcZ4Vdq/6itvPBjkpUgN6fjlZp5yoqfvkIfPEfmFWCq69YZO2KZ8EJS
         dS27PKEW1Vz+eGZOaNUfxyTsix0w9g6FJL/YV3krGjkzxvrnrrSVLeNytnjlZovcFRei
         unsRHgsvbfTL78G9AkttdGlkGoK0Q4ZKPeXsprGkOJRI0AHogkqg61KaSarXNDL7Kysh
         ci99yRVoX3BH7717nXQAKKGneQjIsPOP1M8mBFIQpXn6Zh+qz/zRGPKrZp5tW7TPjoW9
         UVCy90+xDJjTJZyWNh9BFXKRbMZmvVOJJacy6fC3cqUykTcLnqEEkZ7VW7Xjo31HoXBN
         lFtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2E/m9fft1+aTENQjQr55yvnsllDYlUJN1QahSuOsaog=;
        b=UL6DDou1DFRwp7+Ba7j5H744RrKm9QeXlTWsD02hw7AmP0adQWJdG5iTGqbtCP1moS
         qqYl5gt+A8ij0UB3PWF8Z4bqcnFwvU6tf9Ue9DBTEv0yabUDnsg3a/5UijzunogX56oJ
         QUnXVqbyf5JWvFLo1Xfjk1rSszEL1WwGGnhY9rM1Fd9VN0ISoV6V1UzGvN0ZAwFfzV3y
         BJSaLW3RlndF8THLDqnzlniqe1EPlwIvnqzfljDmVnBp8PF+xj1tWvur0YJfW2HRc9z6
         WBiA9L5mllEzJHx6guKi2VrExh4eRKSrt6ncfO3KtbNMdbI0vhGGEQSRX2I0V6hp4alC
         XCtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2E/m9fft1+aTENQjQr55yvnsllDYlUJN1QahSuOsaog=;
        b=YBowNZ1bSZMwc30EAbxm6GBPLN5EJLS0F0d3JX5HVkk2/9xqiBif709lA2D9nPLFyd
         1J0LpXx5aJXxvHc9P0pY5zL2XoGB55KQyBbbtsAB22HqN1M9OPO0ImuKMst1KrkLcjQA
         UaCtDV1SZ1Kslzhc63rcaucfrwgsHOyS40ShaKla4DVauNJXKxJTE7XKdSZVicnPEaO9
         8FYxLVz70zYoFueU57XfkdvJD/pigLMwNbJ8BD0idoerbo4oHd8NXOUx9iPmeTo/wYm0
         6fZaJ2C/3Vhvms9pn28PZlrGmmRArVOhzbw2Zh6PZ0woT867KCf4zv6sxgVr2KVWXEgM
         l/4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWfWW/f2beRUrSkeFb+kVVpX4dTJJueaBrYuFKn8nOIAVnPki4C
	zA+KbW9CFDKXeziE3pEm2YM=
X-Google-Smtp-Source: APXvYqwdygPsoW+xyitykJbWaLfY6o/xli7E77LDkeKMaeZ9xPtMHRBUMnoXxLStEbD27fgMJJtuqg==
X-Received: by 2002:a63:eb0d:: with SMTP id t13mr34329787pgh.37.1560479525846;
        Thu, 13 Jun 2019 19:32:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b703:: with SMTP id l3ls1870571pjr.2.gmail; Thu, 13
 Jun 2019 19:32:05 -0700 (PDT)
X-Received: by 2002:a17:902:2a29:: with SMTP id i38mr63249525plb.46.1560479525586;
        Thu, 13 Jun 2019 19:32:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560479525; cv=none;
        d=google.com; s=arc-20160816;
        b=LpdJs8xUx9AECPXzIk/41IDD9dMc23TORS1SlhipNhHR1tqJ6IS0iapTvxyTQOQFwQ
         CPZSA6+YOdFRvYRjffBBq2xe6zoXgUUaAcpo6VfCYj9U16TMYmzLvScefcr0UMiggFeX
         IIsEzkSd1yxXFkZlHKW8Dr+OBCNLKg/eFzr8wXm4qWlARib6WX/GDgejC24MWIcUtDSZ
         F7fasF086GiOcuvOTAeM2Fz7llUshO1eto3o1TFvpYtz5vHa+o6Xm/JAwtqmc3UVlZ/D
         +DeDEkcLabxIg3NTE/872rZ2ySXSAbFsOnP+95BEvbeAVYjLm0IO7R9SImwo/09LOYhu
         sfSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=kTe2vZV0xSZQ1ioxOtwYAy0bK8GedKZIxNZ5CKd9JJs=;
        b=jF0ohicYXzIngPJ85c1/GsnR2nTk+x5RIO7tTw/k4eYCpMTSqMS4Zn8d6suqd7gIG6
         Cw0K6Tr1uAXP7jUk1keYqIi16ZQwsaSVDrFgfjCO5r8i66k0lgIZfg0aJh9ARzaIie1Y
         xFKEepuSS4si16h206CeF43+4MC2sQiKrc1yGTdEhN0I1REWlF82CFtEC8v+25+YiZvc
         ReD0TFBaJEOXqY7q3giYant1zplXbQauuqd0+2Zv4lz579zp/X/rU+drPxUVN5FsRJmB
         s54FEGcWijrC077LeQEQGk5rtNDQ62ZpO5SfApXwE/5h26Q+fuz51kvVDGzSbe1iAIav
         pItg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id o30si136210pjb.0.2019.06.13.19.32.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 19:32:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: ad556f1f2e36417abf74c4de3c3953c3-20190614
X-UUID: ad556f1f2e36417abf74c4de3c3953c3-20190614
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 589143347; Fri, 14 Jun 2019 10:32:02 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 14 Jun 2019 10:32:00 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 14 Jun 2019 10:32:00 +0800
Message-ID: <1560479520.15814.34.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Fri, 14 Jun 2019 10:32:00 +0800
In-Reply-To: <1560447999.15814.15.camel@mtksdccf07>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: C34F4A9FF25B720FA8D264905C1A23CE1B1F2B5A1E4DE450A529D5CDAA5FBF8F2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Fri, 2019-06-14 at 01:46 +0800, Walter Wu wrote:
> On Thu, 2019-06-13 at 15:27 +0300, Andrey Ryabinin wrote:
> > 
> > On 6/13/19 11:13 AM, Walter Wu wrote:
> > > This patch adds memory corruption identification at bug report for
> > > software tag-based mode, the report show whether it is "use-after-free"
> > > or "out-of-bound" error instead of "invalid-access" error.This will make
> > > it easier for programmers to see the memory corruption problem.
> > > 
> > > Now we extend the quarantine to support both generic and tag-based kasan.
> > > For tag-based kasan, the quarantine stores only freed object information
> > > to check if an object is freed recently. When tag-based kasan reports an
> > > error, we can check if the tagged addr is in the quarantine and make a
> > > good guess if the object is more like "use-after-free" or "out-of-bound".
> > > 
> > 
> > 
> > We already have all the information and don't need the quarantine to make such guess.
> > Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> > otherwise it's use-after-free.
> > 
> > In pseudo-code it's something like this:
> > 
> > u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> > 
> > if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> > 	// out-of-bounds
> > else
> > 	// use-after-free
> 
> Thanks your explanation.
> I see, we can use it to decide corruption type.
> But some use-after-free issues, it may not have accurate free-backtrace.
> Unfortunately in that situation, free-backtrace is the most important.
> please see below example
> 
> In generic KASAN, it gets accurate free-backrace(ptr1).
> In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
> programmer misjudge, so they may not believe tag-based KASAN.
> So We provide this patch, we hope tag-based KASAN bug report is the same
> accurate with generic KASAN.
> 
> ---
>     ptr1 = kmalloc(size, GFP_KERNEL);
>     ptr1_free(ptr1);
> 
>     ptr2 = kmalloc(size, GFP_KERNEL);
>     ptr2_free(ptr2);
> 
>     ptr1[size] = 'x';  //corruption here
> 
> 
> static noinline void ptr1_free(char* ptr)
> {
>     kfree(ptr);
> }
> static noinline void ptr2_free(char* ptr)
> {
>     kfree(ptr);
> }
> ---
> 
We think of another question about deciding by that shadow of the first
byte.
In tag-based KASAN, it is immediately released after calling kfree(), so
the slub is easy to be used by another pointer, then it will change
shadow memory to the tag of new pointer, it will not be the
KASAN_TAG_INVALID, so there are many false negative cases, especially in
small size allocation.

Our patch is to solve those problems. so please consider it, thanks.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560479520.15814.34.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
