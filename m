Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBOVXH6QKGQEF2KELJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 85B0B2B19BE
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 12:14:14 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id c2sf3891158ooo.20
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 03:14:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605266053; cv=pass;
        d=google.com; s=arc-20160816;
        b=o62Lfl3wDL4U7e+8MelBReO5EplMo3W7NyY+vkxc2HUEptJIPRqF5wla+7Xfb0xAvY
         GuTRlZ9G3WdajRbwwVcF4F+cERobvMirVdIVJt0AiI3lNHp/SnWVgbnnfikrshsUgExI
         NqcISLt5gGwA+o3ljVCGg0CkTxifUalnhtZyilKtaxTXmdKS0i5I/r1+JwF+WZciqcR2
         cWhh6EpRaRxTLYVMTLnFQEzqm8lSEgi3qz7UZ0wRmSJo5vesGlkrPYKx3jSIw87gi/bf
         ZGbmSZIevU6+XeOiNVIfiYpnPqo2pJdI7hVZdvEFdMap9lUDN7IW07jkuORxqsEg3myg
         5lRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=qh8jvnCnajfODPtySBl9E5dDRygLhuXg+0W4FjvAivI=;
        b=t/8NkEukLkdmAHsx4SRggZX7Rj93U01z6TJO7d3JxF5Mqs02RmsY+I18eZ4wFSMJRP
         EqHoM4iNpkfxSusylbPRTry8Hh29kb6X3q9mixjVt+rgR9dFnwQ6UBI+z4NK/D+NlVg+
         H2vH6/eunS0bZ0ARgG3SOeWg4q7K8lu6LoLNb9lGmTOF67br6qh8qx7PvXvKofqYeFgY
         LKG3h2B6GOP3X9bFpiLOt58gnI00fe2IkSayhAQHrstZzFJ1k2TwuGBFOA2PDg0Iz35i
         DfQPSQNqdhXlAIrKOueDNxsBGw++NAtgTiwyG+YBCNoUei0iTwbtUvQmKB9ChlpZOjXO
         jW+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qh8jvnCnajfODPtySBl9E5dDRygLhuXg+0W4FjvAivI=;
        b=oCTCiB01smRxVrdRvNet0Ppna+M+HkTe6JR0TVFjlriRO/0HimYC7oggQHUHA3HY1y
         rrSlF35blGzPICqwjcTW1VJ4BXWcz+n0pUO7jbHw2vIgyNsPUxTEs4x7ixO0hnt2GUkB
         mzAEdxjWPpmDBZJvS/09u5/duwrauo52yAnmTaFdiV8dZzrAi9mYns/5R67pgbGflm3X
         mIhqVxWCZv0gsJT8g/GaZdANBkLKyH6lWiH4JmUfwubObCzR+4JDCWSH92gSQtytRSrT
         3inx8AwNP0qtG8a4g9qC1ITpvMU9trSF5oNnBKvEtc4exaAO4poOOunAbXPH43dzqZXB
         b1vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qh8jvnCnajfODPtySBl9E5dDRygLhuXg+0W4FjvAivI=;
        b=nNtDcLLIlb9qwFtOicSNydgcewpR0SynNlOxp6MQOrxQhqgs/kL8cn9WBKMwl3j29y
         ItZgQ34A6CjzNmF7C6YCI8ib/VIRVsl6yoV8eO+xIDHs3/CFkou766o8zu95/IgcDLy9
         /JhAhiYtbYuyCg+aCP/BvU3UenZMBmSHWL1PLi1EOHpP1eqjSJHpM62CUiY/Gb/bPHbo
         bZGr9FHs/yTRgeXnkn5Ar4JC3G96XF53QHVHnHKVTVgZlrIIcy/DAp1IHw3hNJcv+lGD
         dvEis6o+IYeWlw4AiWm8+tftDsk2N1srYERg79k1xdye9co3D7O7sKhzbzqzk0Aw9nX3
         RxMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Su5BatT9fOtqW8ZeXKAeKnnQIXYCfNFd+T5OBtPXMH68XYWBC
	m3UtTQ1Ax1iuigLIpcriTNg=
X-Google-Smtp-Source: ABdhPJyZDroIKz7qCQTSG2OhFHWoRoXDQVWoGVKDSLwJz1BWSpOYT+6de/5bvQ4hZa+MwLgoysh1kA==
X-Received: by 2002:aca:ebcf:: with SMTP id j198mr1063188oih.154.1605266053514;
        Fri, 13 Nov 2020 03:14:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b784:: with SMTP id h126ls1399497oif.3.gmail; Fri, 13
 Nov 2020 03:14:13 -0800 (PST)
X-Received: by 2002:aca:c3d6:: with SMTP id t205mr1094937oif.10.1605266053088;
        Fri, 13 Nov 2020 03:14:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605266053; cv=none;
        d=google.com; s=arc-20160816;
        b=UFJqoYFVk/PUmN2dfrO9WVlbnViLrxSuR5c3F9xgqZPz0p5GThUEicW4ppMbFDysn5
         zb82cfHanNahRY07cVV6fc1QbUaadILeYsOf3QAbB7S/FzkBGqV8O1lh+hz/R7QoFT2c
         1s3NPU5bVHs0dRpBiZ3QEO3rliRqjqAyoBfRsaPot5Ts8Q5MgmGVKLJbmplC3WBWr8R3
         7ZE7K0+o0H3oZz+AGPGmAipUwfzzpRVw/G6JA5tOc8BVVzfe5fQHvzOvm0PX6r1qqQLu
         8jDHoo1ajUkpuYCmwVgGjlMjIHOW3WeFtySJruMrVk3RY5vmmrCUfPLQT+izZBmT7ydc
         lDFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Su/97YBgAuXukGx1LwV1dgtAOx6zcfV18cq2PmS5AmE=;
        b=jyjd/gYcFIuNfteXrZayzssDnlL2cw/DS5djfjW/ueRLQsxA5MeS4PHIMVPaSlXeDh
         5L7PJq9M6Exd+8/yyGMM6ZIn5MIM3E/0Q/kfWetd0pWRU5kRQQ9em2P3UYoDLjOLVKJJ
         Sq1xmEbpMuZkeb5+dsOaJKH4T6ilbE6iEnVrM0MpKU6gClZyxq/8V6ZNC2PJH/GCC9l2
         C8qk49auo1ztzM2iAOgG1RSVwAS0IrXQ1S2daev8Kw7NzSeSgE6WCKlVs+cvkiYlhhdv
         Tmoh9WC9xCDF7UtOjpwZbzHIK1lPLFwB4G/fai+LZfVyfu1WQwMGKHeoxIhGcPukj43L
         8yag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d22si809143ooj.1.2020.11.13.03.14.13
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Nov 2020 03:14:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B40081042;
	Fri, 13 Nov 2020 03:14:12 -0800 (PST)
Received: from [10.37.12.45] (unknown [10.37.12.45])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 568CB3F6CF;
	Fri, 13 Nov 2020 03:14:10 -0800 (PST)
Subject: Re: [PATCH v9 30/44] arm64: kasan: Allow enabling in-kernel MTE
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1605046192.git.andreyknvl@google.com>
 <5ce2fc45920e59623a4a9d8d39b6c96792f1e055.1605046192.git.andreyknvl@google.com>
 <20201112094354.GF29613@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <66ef4957-f399-4af1-eec5-d5782551e995@arm.com>
Date: Fri, 13 Nov 2020 11:17:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201112094354.GF29613@gaia>
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

Hi Catalin,

On 11/12/20 9:43 AM, Catalin Marinas wrote:
> On Tue, Nov 10, 2020 at 11:10:27PM +0100, Andrey Konovalov wrote:
>> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>
>> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
>> feature and requires it to be enabled. MTE supports
>>
>> This patch adds a new mte_init_tags() helper, that enables MTE in
>> Synchronous mode in EL1 and is intended to be called from KASAN runtime
>> during initialization.
> 
> There's no mte_init_tags() in this function.
> 

During the rework, I realized that the description of mte_init_tags() in this
patch refers to mte_enable_kernel(). In fact the only thing that mte_init_tags()
does is to configure the GCR_EL1 register, hence my preference would be to keep
all the code that deals with such a register in one patch.

What is your preference?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66ef4957-f399-4af1-eec5-d5782551e995%40arm.com.
