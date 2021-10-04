Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZFV5SFAMGQEHI754GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C295421276
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 17:16:53 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id z62-20020a509e44000000b003da839b9821sf17460218ede.15
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 08:16:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633360612; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQbfPptv1tHXGpB6YeVUHyQROpzCgmKfzjUMPRTMl4LQj3Uc8v7mj5u7WTXLcp92fQ
         4csbOASC/tdK7YDYYsb+MEZEh7L2DJ/YecG3hSESyageopbmI3epyN0gd8+1Pc9I4J7U
         WCeL81M+i+w5/33hmZCO/AmcxwlzyHO1MYrsRXfPXJTTroR6WzsYzEqzWupwLpwffR5x
         +FBwz3f3isjL0RMq7MVeO8T33i8tbBmWo04VdkenaybDvw8DhY7svWGwIIO4PX94X/Cm
         Ek+yUMBey08WIqTxge55BD6KAX18MB+kg80HnGqNSK1UH/xhnD3BTFRDWh16A46M1gNq
         hw+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NZsx/dZMOBfVs0j7sEdx64JrxXsFsAikXvh2bOeny1Y=;
        b=zu7tCBScZHzWFYpdT6tu5TDXkZPpzTONx/cxWs81W79FRTO+L3g6NKBJQwsjPDmm4k
         /rv3NBmvcoe/nspmBpF5tH6riQXIw2vZSmmF92+n0klH5gxUMueI/TNC4O6FMv+ej3pz
         MIRoLQp3BX4/oeOErvKeIo3KR4JguQXpyZ69rvr7w6VxNufMDqc10TWotSrcSnTH2SJD
         EfoDifWmHu6TRdUSd9+OTjvZskJxXXIzS4gXTpJPe+PeEeAMWTXEZX2xtdZqjEs/NvtM
         Sn94i/qwe1VGVvNnD7Rqf6o7Rb+fc8U/YYxXUE/GvbIYgic2ThA0sjb56cW8bY+KcbFR
         HYfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NZsx/dZMOBfVs0j7sEdx64JrxXsFsAikXvh2bOeny1Y=;
        b=rm1P8LaJVTfzXqJXsTUcEb+6JL7XXEjoZqYgpc9GKy+IR9u1iOamxbYr5YIBoUP9Kr
         V9hawJN6of8J3uwLLVVt59MHb2U8oSJxRGp0HzXcaiIPFaDNcljzEAnz+0q1eaTqBL4r
         FsNz65eq97+jYSlKfZyQqF6UdLfHjvzH7HbChANy2Obhhi2kP6SqM0BONE/C0UgGgpzX
         FQ/+2/LNuuxRJhAXpydfALADPTFRyfco6L8QvxmCYcSGrIJAom+GDMMBWA6/DnPmdi0P
         fPsaHD3eC0W6z/wppmNdZ4KUEQ/vy3aESFkkJIYcLG9BFvJEcOMZSF0b88cXEf+PoC1b
         nOXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NZsx/dZMOBfVs0j7sEdx64JrxXsFsAikXvh2bOeny1Y=;
        b=WPIfHbryMNK5Eo3z6utpe9l3WQauEX6Oybpp12blO7qmhUsjvcXyW8A/ax9eNN8mL4
         n9OI06dwWlD2kiflSMVElwhyrzAqjpTHWuWu8ayOEm8NLXyl24oIxwiuHnPLuPg+VdyO
         6DKkllb83wnL/SiakL2b8m+k2LF2HbMxZ+G2EUB68PJnhI+xiS9uQCaSObQrqERB2s9k
         +DdXg/mQ0S98vjr/t4HnlZl6JAmJOppRGL0rRtrNGsBM5/Qo0RsgT1bK4p5pfZisbbjo
         3DhCpl1ifr7Xv4ELw7YumTdQ6D8mfptE+PrE25WxsR/aslmJvDuRZlwlXzShbMCz4LWM
         RG3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ynMU75LEtNQa/kfrR4nxXeAXPr1Sc/zz0Yi7lsWS0o+nhQK2d
	Pl4Rb17DO2UmwlmEy4JM2CQ=
X-Google-Smtp-Source: ABdhPJylVefbZ3dp+BZXg/l14Lj8YxiDD5P3Sgs1+bbTR78VKtp5hOeWi2paj0ZkbDV05Qk63PTMYg==
X-Received: by 2002:a17:906:2b91:: with SMTP id m17mr17519240ejg.202.1633360612759;
        Mon, 04 Oct 2021 08:16:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1484:: with SMTP id x4ls2745450ejc.1.gmail; Mon, 04
 Oct 2021 08:16:51 -0700 (PDT)
X-Received: by 2002:a17:906:d54f:: with SMTP id cr15mr17911327ejc.300.1633360611897;
        Mon, 04 Oct 2021 08:16:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633360611; cv=none;
        d=google.com; s=arc-20160816;
        b=W8AOrBfo7898wwaNLJxUMVeyu86jZ+hny9ZAFX5X78vHGFDM6bTgRGFo65Drz//d/v
         B2mptKEyL6QhaPiig3CKkujTnLw8TT5tWcZWYJDdO9CVSDV7wRVzICoRJAnTVaBldCUW
         2ez31WYaGHjYN6WQUYvu8JjDGUwA8g87dxn7uZXn0JO42a8Xwb4hZzhfjK8tSvb+t1on
         REe0w9RVegRJcjOgSXEEWGZnQryGTm/X6gmWOhMgk8bQ/R5DVpAeXjQYL8lEs137tA3q
         hGX7JcJa+28H/6hsoeVBDnS5aS17ejH+O0LT1nCFtqfO4Tx8CWbYBIjq8XBmohj2vZ7R
         ly5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=v4FPmS3RZa/xH+ZZYDYX9Gnmvo+kaU3beqNrQd7cnds=;
        b=JvqCQrnBPePEDSF81CHUkiU16B0Nvn8jhuZJh2o45SlEQRRpUxiLvZPdPxJiEhIGNK
         AVVWPQ2+q/nv+WESUr6XfsVq2Pbzg/quUmKkhpOaHs87df1H5r5NePg1wSrsezKv6zjQ
         49p0zjSctSBWY1SSdfwY9ez4BqgNfZGSZ8lQYQ12uzO45rdrZ5QD/I79ebKJug+cz+Pn
         cxNFNCqCpKT6k5Lx1YKLREUdFYZV71BXBfGENTu0SG8GdBOyINz3Wg2Rb/5rK5lQVszA
         hz2Vr5CEEcjJS4sqRc7axnmKImrXNXTD0rJfjB043ka0d7KiLXoAZctPRoSTzd7EkVXT
         FP6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m23si263761edb.0.2021.10.04.08.16.51
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 08:16:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 16716D6E;
	Mon,  4 Oct 2021 08:16:51 -0700 (PDT)
Received: from [192.168.1.131] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F21133F70D;
	Mon,  4 Oct 2021 08:16:47 -0700 (PDT)
Subject: Re: [PATCH 0/5] arm64: ARMv8.7-A: MTE: Add asymm mode support
To: Will Deacon <will@kernel.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210929154907.GC22029@willie-the-truck>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <90cb5600-44cb-1ed5-de4b-d19919090622@arm.com>
Date: Mon, 4 Oct 2021 17:16:49 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210929154907.GC22029@willie-the-truck>
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

Hi Will,

sorry for the late reply but I am on sabbatical :)

On 9/29/21 5:49 PM, Will Deacon wrote:
> I'm surprised not to see any update to:
> 
> 	Documentation/arm64/memory-tagging-extension.rst
> 
> particularly regarding the per-cpu preferred tag checking modes. Is
> asymmetric mode not supported there?
> 

The document that you are pointing out covers the userspace support, this series
introduces the in-kernel support only for asymmetric MTE. The userspace bits for
asymm will be added with a future series.

The confusion comes from the fact, as Peter correctly pointed already, that I
forgot to mention this vital info in the cover letter. Sorry about that I will
make sure that this is addressed in v2.

Thanks!

> Will

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/90cb5600-44cb-1ed5-de4b-d19919090622%40arm.com.
