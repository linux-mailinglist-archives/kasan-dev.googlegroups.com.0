Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIUHU2FAMGQEL6G3HLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 56E9E412EFB
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 09:02:59 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id s14-20020adff80e000000b001601b124f50sf1190961wrp.5
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 00:02:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632207779; cv=pass;
        d=google.com; s=arc-20160816;
        b=bg8kWq4uizt8H1P8/rgrovM/mdAL5DP6sKVAcJZsXqu6m08kxg2RpyzGOFXeuwmu2Z
         CaBWXkbH77iyATE6NLv0Pfy7mXy5aS7E7Um5s95non7s79Eqz0AwgdZ6YdWzSITgiWNy
         1140j/78/JNETvLqonjxjgn7d4k+/T9ZNqODs84/clPlBvlTNU8eCk+N3ottzMwi5ns7
         34ntpByBQU5wFPNtfVWodiLIkjvrowjcX3K28FQ+3TatcNTpyXhPk1QJyaoc+FS6wSro
         ARhQh8nWbzGeIpB73H1z1+j1z/udU54IO5ozbptKA8aGg7THnYcfGddZLa2GZdDZbGYe
         4joA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=QDAUsPEWa0CbEHKSuIBH7COX2NfnnDjroYMwVoLac+Q=;
        b=gF8Cd9MNa6/wSZCfzVLSP5HGQUr8O1vYOTUtrjKFlPUKA3DZu1Hwv3SYYjaMeOvcbs
         lZjqKICqg0adcRM76Y/XuyVWNYd6ytuftteGEnzlPuB+nKKIYIwlRpWaKKKkfqs2YX8X
         77o06ZttZYKUzr87fLEw2oDrqmijjSA2HyHPQJAS3TjkZIalM7UbDTvvEzdEwugVf5GW
         aE9O2suuZq4DAwpNS8wH16yGve/sxm/wGu6hn0RC5ZmlAhxl6J17/enUog4FahOLq9vz
         S5cOqy6mxJkqp7GapdfnCu6rdqJTavrHPwpO5RDWy38NklyDzcr+EEwKKYiJobWgQoIg
         pEzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QDAUsPEWa0CbEHKSuIBH7COX2NfnnDjroYMwVoLac+Q=;
        b=IZLkSRC8wTTGJHMlC3rU8EVchMJ2A8I6dYLMyeu3xLfmMzedxZb5c04Dgqnxc8FlS2
         POPAhdcdnVUlQVQDW3ZtqVsXItk/dOajHLccpRJAtB4lT4ZMKc3DFSJd3YLcm7TBLiCu
         8qQ7CnywE/v/OeVcVX+sBaUdhwNCRSELxeexOkh4unkaVpV6dhNenInZxn7VZbpFv/pj
         m9hqyj6Kdl0FK20pCU4EGZN5lfHDapi0ILHa8rgnT3YhVwvM/B8POQW+5pWQW4k6AA2l
         MAsPNOWZvXFjVAF++b4AoVJWNuWUBCKsaFYDHG6O+wmK4mW9VlX322OZmhBzsjp9r7Cp
         CWPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QDAUsPEWa0CbEHKSuIBH7COX2NfnnDjroYMwVoLac+Q=;
        b=aC7xhIGheHwF5g8Uh2VN9csL9iVU29Tagtva0nNVKE8PM/rGEXzKWwPtEoVrPoW1Uk
         RYQnfrSyoyHT209qtJtAVkHzBdrMhBWr5cQQf03/j3jQsvHpAdqjL8WqSRnoP58ccXh0
         MKry1CQ8xNxq0xsVdRTOylYMHoe/+ls0/hUVpPWpQHe0oYApF8MsGUQk3MFoycSrFJRz
         fPIushQU/4URG8dpmqWgwvHl/85tQv5+nRsxCW7Rvw5RvQYJrBaWjabYh3OFDV3HBBd7
         zFbYufPSiIXtO901PnCMmcaT7u7SpeEsXrHP3BURRQfblOlEJxMnsVLTgFT9x/rVd7sn
         Jy5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YMAMksTRwfAJ/1s9BJVh3sxFjiom28xjgfnOZmiuRVrWfIKWv
	oT19kLH9eGbivVm9s9gVeEU=
X-Google-Smtp-Source: ABdhPJwtXVTZLNuyGsbOTaVls2+3eIgeA440Rtj+Z7+0vvsu7AOy9WlJbNsRXJJyCW8WajAYBm42+g==
X-Received: by 2002:a05:6000:18ab:: with SMTP id b11mr21025032wri.131.1632207779036;
        Tue, 21 Sep 2021 00:02:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a285:: with SMTP id s5ls1425825wra.1.gmail; Tue, 21 Sep
 2021 00:02:58 -0700 (PDT)
X-Received: by 2002:a5d:67cc:: with SMTP id n12mr32352347wrw.381.1632207778234;
        Tue, 21 Sep 2021 00:02:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632207778; cv=none;
        d=google.com; s=arc-20160816;
        b=Unz6Qz8v+DtWOahfZQI79jn6RHJLYqq+Gh+nN+/bFKWoMnFuP9P2+7UOiPJZkBwLf5
         SvhBj3ca5fd+e7EPeH0DfFnZZ6acG18LXF/z/VelaJ+4PDB4fIGsdBMr/94kvcXdI6ZD
         bvRULrYlEAC0yCIlslFPNc9JR7ibwfu7/0rOHjOWA2wVtAq+A3VnkofUulxUgJiD30Vz
         ukPpcHJyuvWp2Hft5pOJTJVe2AGv0DdDR2JwRInXXyatQYTKMiwyyFTIiyUkZ/x1GEoV
         aO5pTKtvsKsRmJENiESAcVKMhtTDqrUETQdeHrbf2AQ998oq4yyLp7epgIvqZXvSnHrG
         JDuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=MCjc13MxIW/UC6PQhj8cgwe4d4hLjCmc2Oz+B3S+ehk=;
        b=D6IEI000OZlJOyy2539MmBMAHFrtWwN8Y903cm0H4a/pvGWSTA2HXWH3vBzpu2VXKL
         7HbZrzKaIbd1iwLXr7oWx/x8EQNwZO4Ll04LA2WTtgkQhMUiVHbAQclHfk6huIdWy8pj
         Ak2FgZAO9VnNogFcuEwj1k91r+G0KGp0nf8jClLM0obQ7h7y5CJnGNXYSZRPIMWP/IKc
         zcyYDWSNJ3maJiu0UbLU+X8fvyBewdo1ki8PpdbqIO0Jy6EdMRBxHKpsLFDLSnSJJgS5
         fwsZmdXCaLMQVj1JZZf03NhkJC09P4QVzBJ5LcnJlVfSGH4fDHFNe4u+78v7LnWAOC5v
         vmSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f5si1291732wrm.5.2021.09.21.00.02.58
        for <kasan-dev@googlegroups.com>;
        Tue, 21 Sep 2021 00:02:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 67C2D106F;
	Tue, 21 Sep 2021 00:02:57 -0700 (PDT)
Received: from [192.168.1.131] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1C4BF3F719;
	Tue, 21 Sep 2021 00:02:53 -0700 (PDT)
Subject: Re: [PATCH 0/5] arm64: ARMv8.7-A: MTE: Add asymm mode support
To: Peter Collingbourne <pcc@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <CAMn1gO5sUhDkx4w-Kk8hw0xLbXmr129xeJa6YhxOeJ-v83hp6w@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ab5615ef-b4f4-28be-3e2b-2b592e11580a@arm.com>
Date: Tue, 21 Sep 2021 09:03:01 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAMn1gO5sUhDkx4w-Kk8hw0xLbXmr129xeJa6YhxOeJ-v83hp6w@mail.gmail.com>
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



On 9/20/21 11:29 PM, Peter Collingbourne wrote:
> On Mon, Sep 13, 2021 at 1:21 AM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> This series implements the asymmetric mode support for ARMv8.7-A Memory
>> Tagging Extension (MTE), which is a debugging feature that allows to
>> detect with the help of the architecture the C and C++ programmatic
>> memory errors like buffer overflow, use-after-free, use-after-return, etc.
> 
> Unless I'm missing something, it looks like this only includes KASAN
> support and not userspace support. Is userspace support coming in a
> separate patch?
> 
> The fact that this only includes KASAN support should probably be in
> the commit messages as well.
> 

Good catch, I forgot to mention that this series is meant only for in-kernel
support. I will update the cover in the next iteration.

Thanks!

> Peter
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ab5615ef-b4f4-28be-3e2b-2b592e11580a%40arm.com.
