Return-Path: <kasan-dev+bncBCZP5TXROEIPNDWGW4DBUBHYUR5A6@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A735997EE04
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 17:21:28 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3a19534ac2fsf28963995ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 08:21:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727104887; cv=pass;
        d=google.com; s=arc-20240605;
        b=MZcm1L7hgUwBvhKb+W3IiwLIYosucQzH3CVQfWVLzVkRN8O2dlASl7SFYAD0plNOWR
         38/Ua2B6c4mX8jv3K3CNQVxMZkW4CNUKFap9w9txtQg7pjY+h45cwb6YfDzGbFjfpl47
         ytRkSo043hwvzlmookth+yOx4tA9qfWg4TFdmI5p4XxMyWbFvFYHxDd/ZaYTxUff7LD8
         OHwGT4l28kLGerPsQW2SK17Vp2GH/W08tipg1G6kK7QrSjeWw3my/xpJS1GQC4FBAhKG
         XjtmdmPxdQP+U5QqWdbQYoM+xbI4yah8WlUlw29xbYyq3Y86FqRzq0WtyCRMbvGhcua1
         5SPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Ru1yVp1Ubk8mk+6pRBSGgUvrIQBoA7rkpZq3ZnfbXgE=;
        fh=j5HHdU+tuZJw/W9JIsvh9zfQtMnASpNAftWHUg6bmUk=;
        b=lC5Btl1HxRyrDATOx2LYuo9l8e3Zb7z9evlEIXdtnJsI3xxT+BpWm9Fh2c4XEbYYmM
         Xkw92gH41bgPIyGs7HS2vP2VYkxdzLeXB0PF9zPY0aheIgaeF7txKeFbE0rfrhwIDsfU
         Wp7DwvNGQr5YEwozttdErMfL6SqaMEo/1+83gVViodi8YKe1NJuGkhy0AICe3w7pd2c2
         2JQYhkwVvMB2LKe29abBUatRrV4eXaTkiYtxb3C+FSAn88/57AOx/wPuCyrjI2ZEoeA3
         +B4Ac/X8MY4MD7ic0L7b391nDTU5IJbU6W+lFckKyPM9+xh0cmdBn0ipDH6rc9e+bhQK
         +YCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727104887; x=1727709687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ru1yVp1Ubk8mk+6pRBSGgUvrIQBoA7rkpZq3ZnfbXgE=;
        b=C7h54iA78guWFDOlKafvSgJysN4ytYVRmYlwO1dR6NpRKQDCKUWYTRyzDAQIW6ze6d
         oXxMQboxShEl/zLHBcg7+wnTe8fGsiRyvLNn32f6qggWh0FHChDakahwiW3QTskADOY/
         DU1/KsB0RV+LZJ/9C3GDbNhRtbHgm5BEb92vm/hGIQLxbRhY82pzvujvg/M+p4Bx+mS3
         4dIKoTZB/voHFfwmD8XR4JcYh2d4JGGDaeDFpw/i9Svyijdy/GqVWiFhyawJtP3cUIoM
         vwBdvSk3jrU/1jH9I2SxNWnCa+UwKOmllhvzcTUo6xYMLgp398VjfGCmurCz0qCxzfeY
         uUHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727104887; x=1727709687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ru1yVp1Ubk8mk+6pRBSGgUvrIQBoA7rkpZq3ZnfbXgE=;
        b=V71TRaqrv5k5zorbTBj69701Dhm8tO8RoxpqPv0nRrvGXutKLK+RY9T7WisHv5PaiJ
         qnQsE+tZKxUDWt9O0axqrqQoiNNJLFk6rOygB0z3crQ+VR1i6jGLlhlp1TsS+Ef9T9Ls
         v8kFH+Ub+1DfU1m0KLtfqViKKbk1yvueuQBWWe0rgizkgY4Wo6BlZYYKj3/I14/r3ZlA
         MqXC0xuSUj0Kn5edQVluqeSRZ5dr/g92kqQ344Mfw3LATm3jr1yLEkgpkNN5xQqs8HLd
         NE07S6/Etsv5mJ3j4jREUNXzLiN7dt0gLVt0LQWvMuYpvLmKpwgwYum26jVEFhah3WLM
         thHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX55M2tROejgOTknthAiT8CFuUZMfJsQi+eL0oLwlq9/xmC4yhiMWEkZq2xdKhNxWAwUN8a0A==@lfdr.de
X-Gm-Message-State: AOJu0YyIYBFgAT0LeOmTxTdA5Nn0WI5KPexiHkqcpzjffF4XHflNka6J
	c7sbNW9ibi6lBgV8sA+RCznblhH2Yc9gpBXwBYO7piIXXejnh7Oh
X-Google-Smtp-Source: AGHT+IFN1NYesdVPEldibNrA7LUXROKgFsBjHTAMQaXkUK0i6UHb8J+h8B+NHWQ+8Kebzv8bitB9/g==
X-Received: by 2002:a05:6e02:1a43:b0:3a0:a070:b81 with SMTP id e9e14a558f8ab-3a0c8d2ea34mr114185415ab.23.1727104886697;
        Mon, 23 Sep 2024 08:21:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1945:b0:3a0:bc59:71d5 with SMTP id
 e9e14a558f8ab-3a0bf1664ddls22743895ab.2.-pod-prod-02-us; Mon, 23 Sep 2024
 08:21:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3/k0p9kTGq1p65TzMm71r0gjHxre1oc6m3Ng0VxJT+XKrnFf4F8aUGOTkpZm8Vr7dbAFqaTwJLEQ=@googlegroups.com
X-Received: by 2002:a05:6e02:2162:b0:3a0:b384:219b with SMTP id e9e14a558f8ab-3a0c8d4282bmr92064045ab.26.1727104885209;
        Mon, 23 Sep 2024 08:21:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727104885; cv=none;
        d=google.com; s=arc-20240605;
        b=PB2ORGjYp5yUBmrPR9HrQP3YwDBbEIbYPwBroIgAPRcdDYc5DxKvoz4q6C/CS3fOea
         OkU3Ns4N+x87hq75wXO/meRI1Qvo+sJtP4zVYnRLyU4BUBGli0p0ZK+7sJnVEgodDz+s
         M6fXy+wrE+8quICXmFxs+1qCCAdxeggoOSXP94KobvfAOleORYb4JU/6M7j+6N+3ceIo
         iMYZWKPn68WOCmuqiw0CiVjtPhK8rSpD5w6pH2JOyU8efBVpkeQv5MCKSoF/vtUkYMrP
         rQODwEcvwIlIfg6D0m6KFYmsjtZ01WwUcPlQzDqLHy/uylBFjLOcn5f+FXikdOpp2Edr
         +F4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=1q2jz1CK7eOsJJb0bvYMQalo6dVdgNgYBjoqos/dtys=;
        fh=GF0OURt1aobVVYo7M3iRXWSqWc1A5XkS9a4tiebN1YY=;
        b=RVytHFWdITbhSy/CHDljS7dDJc/9iKRiuBdRAUsdoqRO6gR0nFoeKiSMhEmqGzSaec
         v8G/AM9TQw1Wcuvqai94pawYM+SPdEh99sfMmpdYCEWou/9STro3sBQUWMMx6O5COzSC
         jv/kspwf7eBWjnjKXn2hNOboRktQSAxzFEs+ogZn0wQze6phhImyuO/DBw2YdEmQNq8q
         1yB8bD59kHiSnrkqQcuIpMb9tJmkSU+7Zec8WHkWpNcTxMsmpdgPpDTYdKXcCWB2RQJs
         GAiy34SfsIN9Cer7Ps+A5HE1/Vu3NdljYFQQ4HClNO82eJnOr16FsrG9xcF0yF5Rv/eE
         RtKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 41be03b00d2f7-7db49a17343si940421a12.5.2024.09.23.08.21.25
        for <kasan-dev@googlegroups.com>;
        Mon, 23 Sep 2024 08:21:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 80143FEC;
	Mon, 23 Sep 2024 08:21:53 -0700 (PDT)
Received: from [10.57.84.103] (unknown [10.57.84.103])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B4B793F64C;
	Mon, 23 Sep 2024 08:21:20 -0700 (PDT)
Message-ID: <ebf8d9c6-867d-4e50-9e98-5d7f854278d8@arm.com>
Date: Mon, 23 Sep 2024 16:21:18 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Content-Language: en-GB
To: "Russell King (Oracle)" <linux@armlinux.org.uk>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
 kernel test robot <lkp@intel.com>, linux-mm@kvack.org, llvm@lists.linux.dev,
 oe-kbuild-all@lists.linux.dev, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Dimitri Sivanich
 <dimitri.sivanich@hpe.com>, Alexander Viro <viro@zeniv.linux.org.uk>,
 Muchun Song <muchun.song@linux.dev>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Miaohe Lin <linmiaohe@huawei.com>,
 Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
 Christoph Lameter <cl@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
 <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
 <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
 <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
 <ZuxZ/QeSdqTHtfmw@shell.armlinux.org.uk>
 <5bd51798-cb47-4a7b-be40-554b5a821fe7@arm.com>
 <ZuyIwdnbYcm3ZkkB@shell.armlinux.org.uk>
 <9e68ffad-8a7e-40d7-a6f3-fa989a834068@arm.com>
 <Zu1EwTItDrnkTVTB@shell.armlinux.org.uk>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <Zu1EwTItDrnkTVTB@shell.armlinux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

>> Let's just rewind a bit. This thread exists because the kernel test robot failed
>> to compile pgd_none_or_clear_bad() (a core-mm function) for the arm architecture
>> after Anshuman changed the direct pgd dereference to pgdp_get(). The reason
>> compilation failed is because arm defines its own pgdp_get() override, but it is
>> broken (there is a typo).
> 
> Let's not rewind, because had you fully read and digested my reply, you
> would have seen why this isn't a problem... but let me spell it out.
> 
>>
>> Code before Anshuman's change:
>>
>> static inline int pgd_none_or_clear_bad(pgd_t *pgd)
>> {
>> 	if (pgd_none(*pgd))
>> 		return 1;
>> 	if (unlikely(pgd_bad(*pgd))) {
>> 		pgd_clear_bad(pgd);
>> 		return 1;
>> 	}
>> 	return 0;
>> }
> 
> This isn't a problem as the code stands. While there is a dereference
> in C, that dereference is a simple struct copy, something that we use
> everywhere in the kernel. However, that is as far as it goes, because
> neither pgd_none() and pgd_bad() make use of their argument, and thus
> the compiler will optimise it away, resulting in no actual access to
> the page tables - _as_ _intended_.

Right. Are you saying you depend upon those loads being optimized away for
correctness or performance reasons?

> 
> If these are going to be converted to pgd_get(), then we need pgd_get()
> to _also_ be optimised away, 

OK, agreed.

So perhaps the best approach is to modify the existing default pxdp_get()
implementations to just do a C dereference. That will ensure that there are no
intended consequences, unlike moving to READ_ONCE() by default. Then riscv
(which I think is the only arch to actually use pxdp_get() currently?) will need
its own pxdp_get() overrides, which use READ_ONCE(). arm64 would also define its
own overrides in terms of READ_ONCE() to ensure single copy atomicity in the
presence of HW updates.

How does that sound to you?

> and if e.g. this is the only place that
> pgd_get() is going to be used, the suggestion I made in my previous
> email is entirely reasonable, since we know that the result of pgd_get()
> will not actually be used.

I guess you could do that as an arm-specific override, but I don't think it adds
anything over using my proposed reworked default? Your call.

> 
>> As an aside, the kernel also dereferences p4d, pud, pmd and pte pointers in
>> various circumstances.
> 
> I already covered these in my previous reply.
> 
>> And other changes in this series are also replacing those
>> direct dereferences with calls to similar helpers. The fact that these are all
>> folded (by a custom arm implementation if I've understood the below correctly)
>> just means that each dereference is returning what you would call the pmd from
>> the HW perspective, I think?
> 
> It'll "return" the first of each pair of level-1 page table entries,
> which is pgd[0] or *p4d, *pud, *pmd - but all of these except *pmd
> need to be optimised away, so throwing lots of READ_ONCE() around
> this code without considering this is certainly the wrong approach.

Yep, got it.

> 
>>>> The core-mm today
>>>> dereferences pgd pointers (and p4d, pud, pmd pointers) directly in its code. See
>>>> follow_pfnmap_start(),
>>>
>>> Doesn't seem to exist at least not in 6.11.
>>
>> Appologies, I'm on mm-unstable and that isn't upstream yet. See follow_pte() in
>> v6.11 or __apply_to_page_range(), or pgd_none_or_clear_bad() as per above.
> 
> Looking at follow_pte(), it's not a problem.
> 
> I think we wouldn't be having this conversation before:
> 
> commit a32618d28dbe6e9bf8ec508ccbc3561a7d7d32f0
> Author: Russell King <rmk+kernel@arm.linux.org.uk>
> Date:   Tue Nov 22 17:30:28 2011 +0000
> 
>     ARM: pgtable: switch to use pgtable-nopud.h
> 
> where:
> -#define pgd_none(pgd)          (0)
> -#define pgd_bad(pgd)           (0)
> 
> existed before this commit - and thus the dereference in things like:
> 
> 	pgd_none(*pgd)
> 
> wouldn't even be visible to beyond the preprocessor step.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ebf8d9c6-867d-4e50-9e98-5d7f854278d8%40arm.com.
