Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZ5DZ2AQMGQE4HA2JUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id E7B073214DC
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 12:13:44 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id cn7sf4923363qvb.18
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 03:13:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613992424; cv=pass;
        d=google.com; s=arc-20160816;
        b=xkxtjShlF5rjSSi5VjA+9QvDdYn3g/zuJl51T9TM9C6kdDxNmrZwYurMr6lix58/bz
         jaMf+NR9IbgMeUsTceTUeMZqSnrkW+SraK65Uz/RUl4tvMpXBcil38pv/HZ1ulXtMn3A
         3l93X+U28D+1lcBDAzHuyY+7vndAwkDeyCCmgu4xNqGzE3IpyPE65diMuNFawGHDcx+H
         9sYYbNJNFIy4d3pDhn3oLpuTjYD9pY6Dp5swuhgwPYeYFtE38efxSqMhOmJDtguqQ3Fw
         ftQ4Dki1jUbab47rRjRbsIJEWnxLp9bXTA+J4e6wuwhtK2txfbiqhORl0gZeJmNbd6E3
         IH8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=F6OnHTk7aO2urEMgzZsmX3Z5MNBDNKDkwU9tkBCSZMA=;
        b=zvxzW/ERNHtWuibSuLS6nvckBlgu0I1v/AlMC0LMOSd8pStgIiGrmL0udRLsP7CLjr
         0Lj1SIWlerWNftGalgnPR5aqYD3lF7yqyUDWLd4NfmO7npq8wyW2yYI+JI+8f2ucs/Hd
         oKm5pixIY/QImRPSll/sdcR4n7R+/zZHX6nlJejUfuRFG+zcIt14OLCrIlaU5DjeiYWi
         Bo34y7YodCj8UwZHPjtOQAv/KuYXDgcuh33WLEImb+xAMn3H7uQBX9rsHvO5AOIYUJlG
         9uoqujKgXrvAEjNRJ3iXXS8RJ6dRYDhXW2mzCmS/THMmQSL5ccbbZ8T+jcfN9FfhWVMF
         lj0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F6OnHTk7aO2urEMgzZsmX3Z5MNBDNKDkwU9tkBCSZMA=;
        b=MDxsTbW4fDDxUtpQsyrh1FF+7bMxPHNHFx6bd0ZlietJP+bk5R3JcPnzP7lHkYgGuR
         TvxP336mdAJpSihpL4g6hP2JI1wU3lHFIbARjQlTfBJ/tm36c3M1BstefEcNsw5kTU5C
         9lf0IyDnU2A41FJMqbSWP92N8z2d3JSE6Dwui9Om0YZ79D25oIQ5mIZBhcuDoesiDvPf
         azGqD44OlTOIQL8JsRXyI5H8xookNzKuj88Jv+4NDNeFvOwPw0eDTUb5I0i5sx9FQzLf
         Uvd+VzDedPTdfx+V8sxXBTQr7UjtFcIvA33gRvjVn524UqiEPCB3IGpqc+rr/Bs5epEi
         2bHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F6OnHTk7aO2urEMgzZsmX3Z5MNBDNKDkwU9tkBCSZMA=;
        b=fU/cx4gMNdFoV2GXfJlPg2yTrpVGraDm8IB60SVlpqw9RGpyethcb/TDBoX+YxSvKn
         7glKMrrLpE36aX2z0fvIiWyYrTUtkgQfj77k0M008TsWsm+o6kCkiwAiXwSXk30fs3Im
         AIR1qq0rWbiCuWL9qkHDJJRVtyz9lMtYp1LXYYWnzLV6+AmejNyHZmqyARju1uDeSXXm
         3GyeaVWfyyZXMMcOPFr7vgbqFhhpvIx8hNyxraFsn3XoOT7Cy/cBzS6tFXx/m8NMNx35
         X/m0VSPIPzjTDr+74DRHIDnIhPulUNN3EyVEduXrhW8RVF53mf6C4rHdoCkkP6sbYTss
         9yyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533w7UN7zA4Saepv+m7jTvaOfD+v+qhQTn1VnQWYP6UbDMthekBq
	L/C6uQRzW+OfQkrun7Hyfyk=
X-Google-Smtp-Source: ABdhPJymWBuA6W8nimg8cd+1UdBbR8jm1DRfBh+p0JtuCvkIH5i4dsDGhb32l6zCfiryaQn8Y21CCw==
X-Received: by 2002:ac8:1c92:: with SMTP id f18mr19257799qtl.234.1613992424060;
        Mon, 22 Feb 2021 03:13:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:d2:: with SMTP id p18ls6253480qtw.3.gmail; Mon, 22
 Feb 2021 03:13:43 -0800 (PST)
X-Received: by 2002:ac8:5d45:: with SMTP id g5mr19422038qtx.247.1613992423702;
        Mon, 22 Feb 2021 03:13:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613992423; cv=none;
        d=google.com; s=arc-20160816;
        b=KPrgml+Stnw4dEGhm5HpFwvMWOEI8GwVXW1B5STR1BUkjNiGI9APnh2fvH5v/O0Z+W
         43XGOn99g1Mthrg6NLmwCrgVTjPpEtQT4azmXMKy83oqIL90iVmfhuByDl1sh6OlgxYR
         95ixVNzMT4bg75VfnEyikptbBT6z4vNzXbud0YCHuPBmo4hYmUJQvR5eBddj4egj3701
         4/CesJxjAhQ4SHoVhKfQplIB/yPJJMZCW8bGib6JRJzivKHZRdEqcmHsHtOl8S/o3mGM
         25S+Agd4W59hJwePkMeLeGO9ktNkxK+DV54Bt6l/vP1TvnZINtQq8+NiY2xFFf3TcBHa
         EiLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=V7uGidTIRIReV4qcrLjnQqayOTIPEWPP7Br+8x9Ylgo=;
        b=VMOY2UF6hLAO57pChowwxS7I5BTHvZXAv9K0TPKr4fQ3vI8MJf83+xBBFZuAsIp/Rf
         tXBhgwytnjR3u3WFJtl44yXhRSAiVuapz34zpfPSPIZ96Q59ngtT9Zbs9T6dED5IjFR/
         D3icSTEMV4RGvfQclVoSmOvUddWGljAY05Cwbg4BL725xyQpNfJHd2PmYj3Js8A+8MNk
         9jW4KGXuC7/C1ycJSZTE77vyEsUqmsbu0TvTK84+8HGdq9DNCgCWYeU8IO7QtAztq3qj
         MmVXn2oGLrdE4cYTde65bqiPc5DMG3qQh3h6+FHJZATS+ypiR4WAY3Nlnl52U5KWYb9g
         o2Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p6si932754qti.1.2021.02.22.03.13.43
        for <kasan-dev@googlegroups.com>;
        Mon, 22 Feb 2021 03:13:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 07FDF1FB;
	Mon, 22 Feb 2021 03:13:43 -0800 (PST)
Received: from [10.37.8.9] (unknown [10.37.8.9])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 226B23F73B;
	Mon, 22 Feb 2021 03:13:39 -0800 (PST)
Subject: Re: [PATCH v13 7/7] kasan: don't run tests in async mode
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-8-vincenzo.frascino@arm.com>
 <20210212172224.GF7718@arm.com>
 <CAAeHK+zg5aoFfi1Q36NyoaJqorES+1cvn+mRRcZ64uW8s7kAmQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <fbc215de-82f0-cc6f-c6f3-9ea639af65d2@arm.com>
Date: Mon, 22 Feb 2021 11:17:53 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+zg5aoFfi1Q36NyoaJqorES+1cvn+mRRcZ64uW8s7kAmQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 2/12/21 9:44 PM, Andrey Konovalov wrote:
>> I think we have time to fix this properly ;), so I'd rather not add this
>> patch at all.
> Yeah, this patch can be dropped.
> 
> I have a prototype of async support for tests working. I'll apply it
> on top of the next version Vincenzo posts and share the patch.
> 
> Vincenzo, when you post the next version, please make sure you rebase
> on top of the mm tree version that includes "kasan: export HW_TAGS
> symbols for KUnit tests" (linux-next/akpm doesn't yet have it).

Fine by me, I will drop this patch when I will repost in -rc1.

@Andrey: If you want me to test the series all together, you can send me your
tree before I repost and then I can send the patches as single series. What do
you think?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbc215de-82f0-cc6f-c6f3-9ea639af65d2%40arm.com.
