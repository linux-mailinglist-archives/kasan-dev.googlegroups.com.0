Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKXLXH6QKGQEWZCQ2GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BBC12B1A6C
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 13:01:48 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id z28sf3569008pfr.12
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 04:01:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605268907; cv=pass;
        d=google.com; s=arc-20160816;
        b=VP+sENpQPUAjP68lnBDKejaXF7eMUKxPBOxozv5g7uXCwpp7XL6ev91Ig6iAYL2s3U
         TEVeqdK6p4XjDAGRUJbIWjkAHhF/hCdJucSKsEo0Q/dj9IKOjJtw9Re5E0xKhCDKtbej
         XHet+oigYVLB3UcxPUH2BVypaTybnOirplQye3T88xuk1OFDVm2CBr86DJUyqXddkUza
         7h/U/psMM7ILA3Ti3whfgWMSeoPvGu6ipbECe34p4HUmOzl8lfDmQ52m7YJ/hCIA7uNj
         UCE5fjWKiJk0qic5g1Pc5XQlPSQevbu/Cp4ItY/vR+WPW2k+ibA9XfA2fqN/jXIfmOuj
         Qmtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=sZohgdrYlqrAeelTYaX/8+VAfMKfDf/DL0Rm/IcFRyg=;
        b=yq5YqZnatiH6j3Q+HzOv/rW36HLuXz18F8lrRWfUx3eKerj7m0jsiuKA/EsJyoqU7r
         9nva0QrGuGMt/EIxqUhrzQQ19CCSGIskWVD39q5BrC4tYjjZD7zoGfXUFkt9Iaqjl0LL
         I3ygjJLDyCHRGAuamY9VYWa1eFeNTX/YgN5BtbSlH4CuxX0BJ6WEUGX7Mlss1JbxOxwt
         Aq73kZ67+C8shsTLVyLC2knC3zUKuiqhKyerj5vQrbqiQ89i/VtwDMVTpyhM5R9omgpY
         qR4mPgD1D4OzJ+k3UDna1Vqfq/Ygm1Iiou33P0coEY9K7lvT41OqHEBuFWz79UUcy7pI
         CTLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sZohgdrYlqrAeelTYaX/8+VAfMKfDf/DL0Rm/IcFRyg=;
        b=EyMNgmzsIFu+3Y2ZPbCO4y99wFXWdKiUlS84QUbQbNbKXKfSQgtm1mcSe+SpHhAf3k
         nFCcDIDC6KVN1V/ZR3NJPeTqCIo5Z9N/2ymum8qfvqxwrFk3twAsnYETBLqcnHp7+8RF
         Ikkd3gEQAi1hz9zGoPBxEIm9NVALw3RgEi0/9r36Qj7g5jzCk801pkb5ZGK/GDi/xKhW
         VOoaRFWTi2ghktfTL5X3mDA7ngt2oqZ6ox3ZlM/T4L6qRTkym5E0Y5mkFbKtKqFzegv3
         GyuyOovzI/zXMM7F8OOIQCaLsoG6k044rm+bYI46NHlRwW/BdquIQGlt2XKwN3YCxL4W
         PVFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sZohgdrYlqrAeelTYaX/8+VAfMKfDf/DL0Rm/IcFRyg=;
        b=t5D3e5BTinBVHQ2JHmcUEeCtdJE8dKghGkDKwTzehvPWpNLDBIXrVgDBDWwRwF+khs
         IHFkzmVGYwDGCRYxFQ62FaE0BCH4WVKIqv4oj0ELQ8duCpXNObnQSMPeGK8cjzAQ6wDa
         2kiR+GbFtm/rx5b7mw0f+xcXE2cdYFbnwerMN3y2mtknle+NSuyf5DkXiCblEr/AA/CY
         rLu9Q88Kg1j30nziGOofe1l0nDW76Z6iNQ5ZDpUG+eT8NWazPkJwNRirPe2AvMsYMaML
         UZk/ZM4CGCpTnDw+N1N037EYjT1KM01HUTzlfFxbpI0l1zyixICjKOoTjr49qY5adY3p
         P3gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327UFr8yuqKorzFpRKk2H+c7eo6Lh7Qg09xOwZRJvPC5+uKO6fT
	yKXdpjb1J3MG7II2Bh8gXdo=
X-Google-Smtp-Source: ABdhPJxPQfmHdW3/RqvBc/d5LR6buxv5selalcfLy443Ikow8BX4TquUiHQMPJ7xqJnixVGe9IIIfQ==
X-Received: by 2002:a62:ee06:0:b029:164:20d:183b with SMTP id e6-20020a62ee060000b0290164020d183bmr1829832pfi.4.1605268907023;
        Fri, 13 Nov 2020 04:01:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7745:: with SMTP id s66ls2199322pfc.0.gmail; Fri, 13 Nov
 2020 04:01:46 -0800 (PST)
X-Received: by 2002:a63:c644:: with SMTP id x4mr1842190pgg.421.1605268906496;
        Fri, 13 Nov 2020 04:01:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605268906; cv=none;
        d=google.com; s=arc-20160816;
        b=EA1C6d8nk+Fou9MdnZR/lurHIQimgdhxHF6TyKLrXJngrKcZsE5Iwm0xjZPa3ExQD4
         PdcQsA16ANFxShlhIZu8mTikCW4SNDNQhQtCCLGwMwaJtvzmS5W8Z9iYVWipjHjcmi49
         MD03VRlcZMBiF2MDU9PdyVgE5jAwu7JUIYzVXU4WCeJYidxkmzzYg0uv3xUwg7GnPJFc
         jB+tTJ+ov/IeXZpHgDRAGlyMY8x8eqeYCdecglNO1TWXkyMufaOjCZk4PotLR6voAM92
         /qF5dBxLsKPBeUH22f/7tFalJaEDVmn2d/UQ9QypDquWkZVcPyb+HAzXkxQVHIH4HZpu
         DpQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=aTKH6nzg5J1K/VNYkUpPbFKMNJ9WbBnDEsPk2ML/iZI=;
        b=t8T1BaGoeiQPOtUlVdoyyE/ZD6OHlxnvCBGvvSCwAWPHYWV9coEdmof0GEuoh24pYc
         sIReuqCBVeHWA1Cl3mQNAAfuPVH4iDZemx8wDPKGZLfz7nLO1vQU1zQb7SpsBZqKWXhj
         ZeQCoZUXDCtNV1t5La2MWBv0sguVmF20SHg6eqC9gX/5hfuuIBKrpM2KB1Rw6ty4856c
         n+wUDxU+LFWLFWYqUGISnf7gntOX60ZZYz1Ny+fTC9HtFm8harixeZ2jgQFxXvVCqWix
         fLkw6D10q3JZi/0ILgdSmX4m7ssJPU/owwLgig0LfCOxs47CoG1NxTCfiaBUMXKHSsui
         HgNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t130si507582pfc.2.2020.11.13.04.01.46
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Nov 2020 04:01:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D440C142F;
	Fri, 13 Nov 2020 04:01:45 -0800 (PST)
Received: from [10.37.12.45] (unknown [10.37.12.45])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D4BE93F6CF;
	Fri, 13 Nov 2020 04:01:42 -0800 (PST)
Subject: Re: [PATCH v9 30/44] arm64: kasan: Allow enabling in-kernel MTE
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
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
 <20201112094354.GF29613@gaia> <66ef4957-f399-4af1-eec5-d5782551e995@arm.com>
 <20201113120000.GB3212@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <0ab166e6-9087-6d3b-fc66-ce9909721a86@arm.com>
Date: Fri, 13 Nov 2020 12:04:47 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201113120000.GB3212@gaia>
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



On 11/13/20 12:00 PM, Catalin Marinas wrote:
> On Fri, Nov 13, 2020 at 11:17:15AM +0000, Vincenzo Frascino wrote:
>> On 11/12/20 9:43 AM, Catalin Marinas wrote:
>>> On Tue, Nov 10, 2020 at 11:10:27PM +0100, Andrey Konovalov wrote:
>>>> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>>>
>>>> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
>>>> feature and requires it to be enabled. MTE supports
>>>>
>>>> This patch adds a new mte_init_tags() helper, that enables MTE in
>>>> Synchronous mode in EL1 and is intended to be called from KASAN runtime
>>>> during initialization.
>>>
>>> There's no mte_init_tags() in this function.
>>
>> During the rework, I realized that the description of mte_init_tags() in this
>> patch refers to mte_enable_kernel(). In fact the only thing that mte_init_tags()
>> does is to configure the GCR_EL1 register, hence my preference would be to keep
>> all the code that deals with such a register in one patch.
> 
> Fine by me as long as the commit text is consistent with the diff.
> 

Done already, it will be in the next series. Thank you for the quick turnaround.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ab166e6-9087-6d3b-fc66-ce9909721a86%40arm.com.
