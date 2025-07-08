Return-Path: <kasan-dev+bncBDG6PF6SSYDRBBHFWPBQMGQEYFNLCLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 5091DAFC855
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 12:27:18 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-32b37b118a3sf14472471fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 03:27:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751970437; cv=pass;
        d=google.com; s=arc-20240605;
        b=DqTbF7+HDYtKBlugsOvNlKHyCzVVeZ6WHEN9ZUKYs17jut6r4ZNnTBGioL4p7xwQFK
         gyIvXceU9YlqiyhQ7UeuYsEOggH68jXRPCxlG/EtTgPnlgo6tkBMcux2FXkhAjL8Qp2T
         rbjS2KdkdQpF6KiZfqrCAI99ND6lk9ds0xEWG1FK7Bw6b19xz+3pfhByQOXHS7FJqy4f
         jXIO2NLx1kArb0IjugyFY2nyTTDUXJCx3eevfdOxco7X3HMBG/EYwXJebcC6YaWT8Mkh
         oX4zZQAwnySitmfPbJRJNiDXK1JSnXPkA33wXiEn6jeui/gViD49BpgMWeGTomXZj8bO
         ejkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=4TNSSo39Go8azwAlOdwWyX0pTKOXUND8t16okLDZhrA=;
        fh=1aJjc9IJ2E3daW2DDqca1sStq12xpMWIk80notiFLUg=;
        b=E5DKyKMcjozjzj1UWzg7F5aPoEUQaBgZJ61oh4hGZ2R10eade3iPul7O/wFLv0Omoa
         lYClt4cFXu+qHr1S4vcYLE+7bZzq6G5lHmDPGdaLY9HgTV6N+EPW820aesEiryjt8/hr
         eaqO/qqdYpYTdRJnIVd+Qi7HXPFYoLuR9LEflV3f6kdTFJdamZhAW4dfRGllpZaqCpJx
         Mc0+T8czdgJkQ13fSzBQs4FqY7v4aavTmWcTyjv/gg8rARZmEEFv0+9/2qSUmYHesOli
         nSS6yRZyDqV+AgSWxmGCCLginFwzGx/nzuuqnBgx1HFgRwRCSa2miIbige/wOkuYlXCj
         1eYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=F008LidY;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751970437; x=1752575237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4TNSSo39Go8azwAlOdwWyX0pTKOXUND8t16okLDZhrA=;
        b=mI+A5Jci4GEIzfUd12UtwNjscN/3Is8r6/v64vuQW4x050ug+z9MKsB9tPJUnEmQnI
         No3edImSOCsB0VpPC4X5SMAv/5Vv5ubtPVor+sWOs/N6FW1CRniO90KRlRYEsVdCbK0I
         9z+rzF56XOcPCMldBRElnChb1NoXL9ZzH4Ka7Nj/N2KXUYlV+LrFgL11fDTIMZi3cU/q
         MmX7RyCwGLJR0lfjEBtjuBNkLvfJFQaZbIJ6Ff8wjne1zpg2tJK8yKENRk1pYQNGhviR
         vCsVxTCvNJuKDGm4fSVtgej6Yygh1mJUyRIS3tmRhB1fvBXEMf9kGze34V/LD7f4Lj8b
         es0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751970437; x=1752575237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4TNSSo39Go8azwAlOdwWyX0pTKOXUND8t16okLDZhrA=;
        b=MQM7fAOlrsqopcadchkeSgQzyHcCG2WOXJ8uSJVnQE1r79/RhaV8PkG4PeBCeUxtJJ
         9pyV4PAz/D8QywQ4zikny6XHwoGbZZgcIeRWlJEWS+OQgRXwG9iz7dqSmHQXeQTHat2p
         fooweO9uP/zMW5PFjlBPGPeuRcjVIh8dMGjI1I4gPxFgj1+znCTrwONOUuxBifGef4fL
         oHzN3+cx0rm6Rj5tuJU25NawrQnvjvfFyCjODqjDyDDmiWn2wJDivteu3TUtOHCtxfJO
         E0URkUqfudk0wQLus8/spLC2wuaDQJYwdEPLoW3ed0yBPujB+C+Rg06q+yckwkWcN7EK
         9DZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWp7qtqOUoqqQbxvdFKNL1MxzWFodbOWGps5IbFLPVNtvdSyAjxpvULWtQl9zvfhsqyyNJ0XQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzk3JiDibIHvmBN8aSOFJdbBph2uUcyI5Az+tsetDWnwa8h5kbw
	rgLu2mUkbGZJQYf1hVFr4vrh0+eidy+BT3fvbc34w4aaVBNzz89kyBqJ
X-Google-Smtp-Source: AGHT+IED1q0+LB7fq6Zy9nRxB++wLLu6Yz+Jpe3ZK3siH6b1rlcZVi66B7F4/NCyqEVVIbgaLZm2SA==
X-Received: by 2002:a2e:a99f:0:b0:32b:5de6:89c6 with SMTP id 38308e7fff4ca-32f39aa3b68mr7168211fa.13.1751970437206;
        Tue, 08 Jul 2025 03:27:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdJX9WqJdRGDKx9gs1Ik5WZQZ9zwScVV+4IgGf2vfSlwg==
Received: by 2002:a2e:ae16:0:b0:32a:5c14:7f1e with SMTP id 38308e7fff4ca-32f11458b02ls4452071fa.2.-pod-prod-01-eu;
 Tue, 08 Jul 2025 03:27:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9u1YbUhNEiPzFDrmUHPUDi6sNWW9tzrB745jTNFSeFqyaw/IzG7NIt/koha4bx7+2MbFG9jGLb/o=@googlegroups.com
X-Received: by 2002:a2e:a549:0:b0:32b:2fba:8b90 with SMTP id 38308e7fff4ca-32f39aa3b50mr5922261fa.14.1751970434305;
        Tue, 08 Jul 2025 03:27:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751970434; cv=none;
        d=google.com; s=arc-20240605;
        b=iK8Z+0WRk4RgKTWDQFVngk1pyv13SbR+hOu/VqYWfa9Vqf/JlVknSvh8RIuhIYlN8n
         LMOB1MpalZBtCz4kythEStXQWo/db2PENicBQO1/67yxi8v+8iXSHSxs+Sv6GuP6HWvJ
         4RYUmLLyn1rM9JPlwfREx14KdbFeW0RYfVCy01AuBuPLsqQDD9ci8VAPcp0eLuWtG5lY
         WON3YDdkMab/mcvfzk/z2fNqvn2wowBQhe6SutgXllm5eoy2witZjY6ztQJnDKdCv7ph
         UE5BbTq7JT6o7nNQaDTTc6fGEKMAdbIN0p2WvKAlnbX7qxFE9jv+cFv9a/Y5woxYMxK8
         WzeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=CvHwMYp2XIGbJnf/9QWS8C8NtBZtZV/va6aW8p1Pd0k=;
        fh=Vybu629c/t6Bxguwm0ZzA/B2Lv/TTdklcjG7jdpoXn8=;
        b=JLHfWfe8PdO7xz6mR9TbqbOVdmU6UoR00nofsDK1k5IuSy1z7xn4+pppgJS/T/a3ay
         akzXT8ZlIDq/wjNRZXWueamjAkRrkLkTNxogAZ5qCo2dHFDHxYThRhkSF02/5FStGx3z
         VLKlQcW2O+aJ1vMgWEqY7ocSITtZLfq+odRV2euElFy46WfXvL+BL4gLBzKuZY4WxFS2
         mC1mRpLFvT+V2NuT+4Rt2HD+ZU+bfIHZQXo0IZBVHyzF5WSigyS/7GRNHLHbgn0BL8vt
         gdve+YA+QI2rnp2Q4DjhVFWwc4FZB/jLpn8Ger2bfRz7Ky6sA7I9HKAxlHyQaN5gKKvX
         AuwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=F008LidY;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32f13e3031asi1990481fa.8.2025.07.08.03.27.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Jul 2025 03:27:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20250708102712euoutp02b3d8674c35b8169adb57fa6eaae42cea~QP9OHtL232034920349euoutp02k
	for <kasan-dev@googlegroups.com>; Tue,  8 Jul 2025 10:27:12 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20250708102712euoutp02b3d8674c35b8169adb57fa6eaae42cea~QP9OHtL232034920349euoutp02k
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250708102712eucas1p1199b906d3c40b7ff5066a92aacd7b14c~QP9NsRWhM2715427154eucas1p1l;
	Tue,  8 Jul 2025 10:27:12 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250708102710eusmtip12ad336592b93f91919ed398faf3d4122~QP9LytFDz1124711247eusmtip1B;
	Tue,  8 Jul 2025 10:27:10 +0000 (GMT)
Message-ID: <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
Date: Tue, 8 Jul 2025 12:27:09 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
To: Christoph Hellwig <hch@lst.de>, Leon Romanovsky <leon@kernel.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Madhavan Srinivasan
	<maddy@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas
	Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>, Joerg Roedel <joro@8bytes.org>, Will
	Deacon <will@kernel.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang
	<jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, Mathieu
	Desnoyers <mathieu.desnoyers@efficios.com>, =?UTF-8?B?SsOpcsO0bWUgR2xpc3Nl?=
	<jglisse@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org, Jason Gunthorpe
	<jgg@ziepe.ca>
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <20250630133839.GA26981@lst.de>
X-CMS-MailID: 20250708102712eucas1p1199b906d3c40b7ff5066a92aacd7b14c
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
X-EPHeader: CA
X-CMS-RootMailID: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
	<cover.1750854543.git.leon@kernel.org>
	<35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
	<20250627170213.GL17401@unreal> <20250630133839.GA26981@lst.de>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=F008LidY;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as
 permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;       dmarc=pass
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

On 30.06.2025 15:38, Christoph Hellwig wrote:
> On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
>>> Thanks for this rework! I assume that the next step is to add map_phys
>>> callback also to the dma_map_ops and teach various dma-mapping providers
>>> to use it to avoid more phys-to-page-to-phys conversions.
>> Probably Christoph will say yes, however I personally don't see any
>> benefit in this. Maybe I wrong here, but all existing .map_page()
>> implementation platforms don't support p2p anyway. They won't benefit
>> from this such conversion.
> I think that conversion should eventually happen, and rather sooner than
> later.

Agreed.

Applied patches 1-7 to my dma-mapping-next branch. Let me know if one 
needs a stable branch with it.

Leon, it would be great if You could also prepare an incremental patch 
adding map_phys callback to the dma_maps_ops, so the individual 
arch-specific dma-mapping providers can be then converted (or simplified 
in many cases) too.

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/69b177dc-c149-40d3-bbde-3f6bad0efd0e%40samsung.com.
