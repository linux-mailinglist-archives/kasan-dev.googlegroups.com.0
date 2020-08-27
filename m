Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBPNLT35AKGQEMUGFEBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B0B8225442C
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:15:10 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id n1sf3915609pgi.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:15:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598526909; cv=pass;
        d=google.com; s=arc-20160816;
        b=rSRK8bMYqbeiBkrAC9kx0lk6KFM+yMbL3NFloIe6hxUWHpp/flpeuk22UYdIB3Xq+o
         CGUu15aQbJTryIFRnW1ejG2AqwwRY354Srom0ylC9LDtXTPFVn2ptJumtzNrl//n6xQO
         tw657Buuv+1aiV50xveFY4REXyolT32WfIoNial74TYqsCzn7sf+oKzl2lxTVZ1XwriU
         J4rHvDMwu6EjJsL/frAeK14wYc24KNKuCoE6hfIKTXwJAdjZjBiAOG4DMI4+2X/HVy6A
         ezZXcgN9p/mKL3ukypXUnV3PHC2ydG2SQnVmdYlHIrtX2lTQkoTSZXt/sF97nZ3ul1gN
         8wrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=mVz/OgOtygExUU1YLc6I370yCv/UuJZDL6H5oTIwWKQ=;
        b=d0xhtdykYQMGgYxSNAg7MQBOTvdTXmvYq+AUY2z5V3HqkgIr26IaBtJon6oFvsQwuq
         ISO7V7aes+afv8+ULIHNRxdb+0EJkeEP0Qt37WknD9Wh9id67pdrTyz8q/UAqKXk6Tky
         wkjfgI/Yb3vj0wdeNPaUfrz1k4epIjW1NjJ+eEdhAyLZ2dS49gMMllOClCzfxWjT/yrQ
         BBKuUZYXjsRcR3gmUF6oRoTi4aGQi1Gu5wGgeSrVVHOpZOlwktxX3TPDPjE3mL8+OEHs
         +o+oYwYsUPoYNFdX9iS9z4c4KwA3sqfPAiCEevN4QpNhZaZ2POmplN0D+uLUzxYKGfUT
         14wQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mVz/OgOtygExUU1YLc6I370yCv/UuJZDL6H5oTIwWKQ=;
        b=r1XdX2k1RA15oS6Jrjm5LT7if9L4g9tnQBM6N93x/LZ+wtGWvQhEN2CJLX3s/T78S1
         4PpZmw6u2xuepcCTXFR1/19nYhkgiW4RXpvt4/9Cqg3ROs69vF5MyfeTzovgC56DsYx1
         p5SuQqvQ7oRTLgrKM6myBo4Psy0bSFq9InkbO5wazsDWR9+9co05ZM4gUiwAF3wd7c+r
         65SocY9l4VD+MxQ+1zJKkAnOCijshKyq3XCaQPYq4D+EGZwmeRCvayUEHkrHFfIMg5f9
         tgJpkCf5bfEWyfx4SxUyHhyK4XioQixZOtJ2iGfT/sWVxOjqjisTiXsnuC7yayMVtYgk
         qduw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mVz/OgOtygExUU1YLc6I370yCv/UuJZDL6H5oTIwWKQ=;
        b=l0cj1bJIxQJTppqbPtA6Nrzv/nnO6Enf3LR4vXVxvfnf20n6T5TdD8Dcl5dgH+BIbs
         eSYKUR29PQW/toa/NOOGDHa71qb/KQoGFcrs3zweHHqj2/+0va7RcXYLaauTb2PD48bV
         Thtb8ZtooPN1g9ddqRJooZDSXSB7ckmpkhHje+NVuH+TDt5l7kv+kRgsNqqt7AU0ij93
         lFFwJGMRV+zRbK28t5pzvlvFgXKuylEOjTupXrHGtfyogvnBvdMTXzBORG8qC9/NRCXY
         58aoE4DGio+njcPcg4686VTNLI5mRF1eo45VoQwzcwpKo6p4dVZC8cARybQ0qWVE5O0g
         buzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Oli1kid0IDW2j/Shw+paU4uFim2kxBmiIaNtaIYzOmHvUL+WL
	fQ60PJLkNOit08e2sNpZ900=
X-Google-Smtp-Source: ABdhPJydd3QFMuG8lteWzf1gNrue1n0tepwNOCmO9YormjBC5fdS1fyUFn91/RAMl/Tcpiu9aQF76g==
X-Received: by 2002:a17:90a:1992:: with SMTP id 18mr10138761pji.135.1598526909481;
        Thu, 27 Aug 2020 04:15:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8682:: with SMTP id g2ls1064598plo.10.gmail; Thu, 27
 Aug 2020 04:15:09 -0700 (PDT)
X-Received: by 2002:a17:90a:fc98:: with SMTP id ci24mr10454793pjb.101.1598526909063;
        Thu, 27 Aug 2020 04:15:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598526909; cv=none;
        d=google.com; s=arc-20160816;
        b=pjrzIc3PfPVT3FfeHLCYCRddagd4pl4OHoVPR8ju6kXW0GYi6ts6OSRFpzE42nxC6r
         F5Tz12zVZxBULN+Wtm/sDjZoOX+AvdVQvXlc5G1kqGY8vJNTFjKUPpcZ553SU2ttX+CS
         GlHPvOaJRTUDMrLxBdvuza/ZrQM35dVWzzDjbduxcOVxZ1hJrtTODMCIm4BJaS7OHjwX
         IL4lLBKxwYT4VjQrv5kvsMsMP/0HvO0pgTgcuJI9zqQqB+Re7WThuXmn/AHPbn9O4J93
         MGvdArG5DJfV79RHMQnEogq7jpjz6jhnuJTtRTIAg+qkxoNkdREGxKPDrcCger4WmCp0
         2/nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=JQAJMCiuUhZeOeLYWHt4ZHRrrpEQM6lcImSQJX2KP/4=;
        b=HSrEdIZxsK0VHbFDDWBQLV+DSNWskd2QvnMgpGNNEGi8ssL0WBrcXi6NX1dWlGViN+
         +5ChItRi15wG7ol1u3EO9HtqOkfQXOfIeNHXCJ8a6tuH4ZMIQMejai2K2OXRPQmWOTXT
         DptqfHS0eA29EiBl7942mk0kkzrooaaqz8MKJ2TD+oftBpAzeM3QIECGSv85spbghr59
         3T9xRMiMtm/MC6ywa+3jFfVC/xC1iFenHOyZ0icXcTSA1ESDZLEk63qgR0k74Ze3ZUxN
         Ijy2iL45LLMlqYvYb3CveCZ/KFTxa6CDnfCLZNtbCAVT8rb6FRWGnh4EfWWZD23hBVwZ
         3ARw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s2si92469pgh.4.2020.08.27.04.15.08
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 04:15:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0E8EF113E;
	Thu, 27 Aug 2020 04:15:08 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F18283F68F;
	Thu, 27 Aug 2020 04:15:05 -0700 (PDT)
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
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
References: <cover.1597425745.git.andreyknvl@google.com>
 <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia> <9c53dfaa-119e-b12e-1a91-1f67f4aef503@arm.com>
 <20200827111344.GK29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <d6695105-0484-2013-1012-fa977644e8ad@arm.com>
Date: Thu, 27 Aug 2020 12:17:19 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827111344.GK29264@gaia>
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



On 8/27/20 12:13 PM, Catalin Marinas wrote:
> On Thu, Aug 27, 2020 at 12:05:55PM +0100, Vincenzo Frascino wrote:
>> On 8/27/20 11:40 AM, Catalin Marinas wrote:
>>> On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
>>>> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
>>>> index 152d74f2cc9c..6880ddaa5144 100644
>>>> --- a/arch/arm64/mm/proc.S
>>>> +++ b/arch/arm64/mm/proc.S
>>>> @@ -38,7 +38,7 @@
>>>>  /* PTWs cacheable, inner/outer WBWA */
>>>>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>>>>  
>>>> -#ifdef CONFIG_KASAN_SW_TAGS
>>>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>>>>  #define TCR_KASAN_FLAGS TCR_TBI1
>>>>  #else
>>>>  #define TCR_KASAN_FLAGS 0
>>>
>>> I prefer to turn TBI1 on only if MTE is present. So on top of the v8
>>> user series, just do this in __cpu_setup.
>>
>> Not sure I understand... Enabling TBI1 only if MTE is present would break
>> KASAN_SW_TAGS which is based on TBI1 but not on MTE.
> 
> You keep the KASAN_SW_TAGS as above but for HW_TAGS, only set TBI1 later
> in __cpu_setup().
> 

Ok, sounds good.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d6695105-0484-2013-1012-fa977644e8ad%40arm.com.
