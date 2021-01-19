Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZOUTOAAMGQEPAJSDDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 37CCC2FB6D0
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 15:19:20 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id p24sf4043957otl.10
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 06:19:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611065959; cv=pass;
        d=google.com; s=arc-20160816;
        b=WyGeoEKmtHiMfWiNydZ3V7iQHoaUtHS7eppYJF/Yn40MnDxk4heTX5cu6o5LbVB3yE
         tJWvp131YG3/OPoU4RUxlWHvS1UrFjIG8gce3AOdOuP3Md8sOE7noXhS15UDpiBrW4Oy
         8Us52o5YxOw8+hMx+yE/ECy/9FnydoP01wCDEn0H/7LQqU4+eYZtNxG7YKkcw7uzn/t6
         LJoF+pt62doHHa64M7lIEZObcr7m3T8uSwcSTqOheATBDcJ2xno0a37eqrUeRFdvdOaL
         jtxWkRfPTrARftXVQcPhXHyI17BeIW8Ko2hxpeXI0uPwQccBm7/BtRmehWjod3noOqYy
         F96A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=gSHLopyXz1qCsgoEX+Q7k/CqKr5OvgosOYD3OTsO7go=;
        b=AYIqsi2jHUmhmVJbGrjb/QKrYduovQ/JFaX2Qys9dsxxU7g0zlHM7oOttL2+SsOkZU
         Z68bvkdYp5Wjrg+eQZBKHdf6MOq6K3isO+va4uhxC7pqXI9J/o9lrAObn0fkFbzJsuyk
         oN18IRLUDN+zjTzneyKWheRzRC7xsbE7QQfjypCXianG68DuApsh9fNOOh+kSTbE4rVH
         2CMiXiOYkl/iwBI3OxbULkfgvIPLO/geaUVlD4wlOlW07kWlCdhmpzoICyXac3EAAQl+
         lu5Z8pMO++Qm2xLzhZ+AC6sE1PvgEH2nmgixGDQ9zRq8LW9NqMufwHODjt94Nz8KQF7X
         wPTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gSHLopyXz1qCsgoEX+Q7k/CqKr5OvgosOYD3OTsO7go=;
        b=VTbjTNlf/YmDhke3qVkDux4uV64qXLmdIeTozq/nzMAFDXo0Jl184RI70U21Fg8fAI
         hOXsHojb4aWKZDT5OMBchbPPmvuuNze3QR2YFuC3yeLWzIpMWpavU3Xy4dYaAc4WPWVc
         6QJhoTU/msgDWHF9g+kd16VtD0JMygKR3amFAU0ZSfH5v0OoH8F5C6VD4/3hE2Vw6SWE
         zA4b6wn6L3ctG6E+F89vFuJgi2Q6McUr4bm3To82mCvVG4afEAALFGqgzmsK2OZnX22q
         jc0BjfnlSUklfRzOokJqOF3OudQOyTeQYBbHXl2KkpIiTnD7WLfVyRECsWilRuSeUjDk
         ofbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gSHLopyXz1qCsgoEX+Q7k/CqKr5OvgosOYD3OTsO7go=;
        b=ZqThFwutwG9+MYWnqTApBkV7F+JAlJhuNvZ0+Z5Lumd3HHTsHnb02fAcjTuAqgqZ2m
         RIFJUEq3CAtHTr/WCLgEZsw1fDfnVqKvJHETBLYoCf/aSlZ1bAf46vEwj0hdJX9F/yV3
         DjfU8AWic7k2KJlvx7VYsjRju939s/voCRpxPDM7NwM2xYLQf981zLVO4pw6IvjEQkg/
         YNmHiw4TcqiIKGvOynMnj8GL5Z9XoZH2VgEJGLye+shCvN6eIDOZZ56HF7wwVu2sNapc
         AZ1vsra2FeIhiMkjHoKJiFi+AU58mgvqMiHN6w+H68ucqrWVlmcOIj1LcgPYzAdijfVk
         EIjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ckWiHOYNG+0h44sEWz1zRbX8nPmgIkGSfIB2JBpfxA/falyGn
	axUxJ0CZ6Paa7wPOb9AmBzA=
X-Google-Smtp-Source: ABdhPJyhUZlFI7aSJfacJK6ZwIy1D/LefSmbAlMP8wwWa06rLJdiZqu6IbeDKTMkR25tt5b3EnZD5w==
X-Received: by 2002:a9d:4e8d:: with SMTP id v13mr3718479otk.12.1611065957551;
        Tue, 19 Jan 2021 06:19:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:14a:: with SMTP id j10ls2785318otp.4.gmail; Tue, 19
 Jan 2021 06:19:16 -0800 (PST)
X-Received: by 2002:a9d:6c9a:: with SMTP id c26mr1773424otr.96.1611065956647;
        Tue, 19 Jan 2021 06:19:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611065956; cv=none;
        d=google.com; s=arc-20160816;
        b=cF1GzyUaNBzXIYI+H1IiDdsx1A6lEkhNl+h5QK6cbLZFJ9lo+zA3IkxxzCspshm4Qq
         D8eGddish7uhPaWh9qy+Wv1q7UbhoxoBTencVy5v3Ix+4RXqerxurBJkCTBwIWrOojtU
         gCeDVDa3DGPMdOJ3KuNYz/BfwRcAiyDtz/o4Yy2L3RERwMVo6Mo3v6oSsS4NHXbZRimU
         +4Bej1z+xnrdV9+xGyEqLWjxwK7cJ6sp4CBLvoWkvp75wc4MuRMiNNaiSNlbmYVvS7/S
         3vmh0BV9JK+ScGVdoCMzeNh8uPSMiMr111nJL5SVDWoVySjJO5rtUJ3UDitB+05gEbBO
         W2Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=htKxssdEnZG+T/dq4TwOeS21MaIh7ly3xXvd102OBlQ=;
        b=OXC/Gzp0kfHMUVG0vrRQjGwDSBDnwbxhUs0quAJHHF3ZnUT5R2UIvbF3kXLDnpS9+t
         3vHr/0p5HlU/K8fMGOCyEAXEAJUJJIFMjoSAVVzn+o2lY0EepEPt1n9df4yvh6pqd7Pw
         ygJGkKJAkN7wAGjNiw2Xcda0hvjKh+PLdxkiZ60Cj0Swl8o/3lp295+3XkSoVAaJGSmw
         UcNNA82vLkZwL7lV/Bje/TOBsDt7i6NUl7lhZrMzPMNoFFmfeU4hLwnTY+etYUMLBjJs
         e8Y0DqflNwsVlK0+NHOAea6zDlssGXE51CcwNoD2IcdlEDmN4obM0SJ1xH2wSTrix2tZ
         9SEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i2si1139414otk.1.2021.01.19.06.19.16
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 06:19:16 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0DACDD6E;
	Tue, 19 Jan 2021 06:19:16 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1A0743F719;
	Tue, 19 Jan 2021 06:19:13 -0800 (PST)
Subject: Re: [PATCH v4 3/5] kasan: Add report for async mode
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-4-vincenzo.frascino@arm.com>
 <20210119130440.GC17369@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <813f907f-0de8-6b96-c67a-af9aecf31a70@arm.com>
Date: Tue, 19 Jan 2021 14:23:03 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210119130440.GC17369@gaia>
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



On 1/19/21 1:04 PM, Catalin Marinas wrote:
> On Mon, Jan 18, 2021 at 06:30:31PM +0000, Vincenzo Frascino wrote:
>> KASAN provides an asynchronous mode of execution.
>>
>> Add reporting functionality for this mode.
>>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Andrey Konovalov <andreyknvl@google.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  include/linux/kasan.h |  3 +++
>>  mm/kasan/report.c     | 16 ++++++++++++++--
>>  2 files changed, 17 insertions(+), 2 deletions(-)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index fe1ae73ff8b5..8f43836ccdac 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -336,6 +336,9 @@ static inline void *kasan_reset_tag(const void *addr)
>>  bool kasan_report(unsigned long addr, size_t size,
>>  		bool is_write, unsigned long ip);
>>  
>> +bool kasan_report_async(unsigned long addr, size_t size,
>> +			bool is_write, unsigned long ip);
> 
> We have no address, no size and no is_write information. Do we have a
> reason to pass all these arguments here? Not sure what SPARC ADI does
> but they may not have all this information either. We can pass ip as the
> point where we checked the TFSR reg but that's about it.
>

I kept the interface generic for future development and mainly to start a
discussion. I do not have a strong opinion either way. If Andrey agrees as well
I am happy to change it to what you are suggesting in v5.

>> +
>>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>>  
>>  static inline void *kasan_reset_tag(const void *addr)
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index c0fb21797550..946016ead6a9 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -388,11 +388,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>  	start_report(&flags);
>>  
>>  	print_error_description(&info);
>> -	if (addr_has_metadata(untagged_addr))
>> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0))
>>  		print_tags(get_tag(tagged_addr), info.first_bad_addr);
>>  	pr_err("\n");
>>  
>> -	if (addr_has_metadata(untagged_addr)) {
>> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0)) {
>>  		print_address_description(untagged_addr, get_tag(tagged_addr));
>>  		pr_err("\n");
>>  		print_memory_metadata(info.first_bad_addr);
>> @@ -419,6 +419,18 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>>  	return ret;
>>  }
>>  
>> +bool kasan_report_async(unsigned long addr, size_t size,
>> +			bool is_write, unsigned long ip)
>> +{
>> +	pr_info("==================================================================\n");
>> +	pr_info("KASAN: set in asynchronous mode\n");
>> +	pr_info("KASAN: some information might not be accurate\n");
>> +	pr_info("KASAN: fault address is ignored\n");
>> +	pr_info("KASAN: write/read distinction is ignored\n");
>> +
>> +	return kasan_report(addr, size, is_write, ip);
> 
> So just call kasan_report (0, 0, 0, ip) here.
> 

Fine by me.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/813f907f-0de8-6b96-c67a-af9aecf31a70%40arm.com.
