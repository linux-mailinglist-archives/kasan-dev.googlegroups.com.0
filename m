Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBI56UT7AKGQEHMGWDBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A1852CDC4C
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 18:23:49 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id x20sf1828255pfm.6
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 09:23:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607016227; cv=pass;
        d=google.com; s=arc-20160816;
        b=CYwjjp4CteG+uFWT+O8ISQWy7jd5+UWjTJaoiItx6yhtNcqYSkzgdikKn+DPD7c9Oy
         EyJi+ofUhvqLvRjRfnOH3al6obsCerPgqfzpUKks7m3HBfEukF3ME5aMHv25P/mVFJ37
         8XZ1N2n65p0IcOHUyQFQupVqkzcjfPhch0hZ31WrdvGZodxcwKu4DEqJ3blfgNDseTEr
         IEW+TzkQSR5Gwiu54BK58nPjSqrzCEAfOfrts2SKvBOJPM9C3QSY0QAHcnP5Br2jwc0q
         N2PkU31IQwsD8gKJjBkyLkq608HfNOL24up+QWSyZ+9kdM8Yrl8OEZe9/H1qYfK2sC9d
         Ob1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:sender:dkim-signature;
        bh=pvEd8OlhmojPJ3+c+dfnJLpAsgbmZ2S+nb9U4TvGQtg=;
        b=Fr3maehZ06hSy9XVrO+xS8jQKDTltWLy6ZOWL/UiYGcup0l42csfA3s8V7ufbUWAfC
         h9yZpg2VNeMmN20N095d+GELsipcyrBDwofH9HPZnXo2Ku+nSSG3bsFvVKEgwUsniS6n
         xmz39yV+ELm0ytsTvOE4WOb627mt/eOimgbaRUOa6wTPZ4NMhOanLxVzrkD/M7xuZ1hL
         E4OLd8t9VK9y3up7hogm15VFqEWkE382OoIVTLnNb5ZGc5Ly6n2UzLQCC9/DNyzYrM+W
         2/93+/mY3K26F4pdPkPPPafdMc/XjH8+Ye+fDU+5GctTNNcL6kJyitozTFP6MHZEBkdl
         AUwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pvEd8OlhmojPJ3+c+dfnJLpAsgbmZ2S+nb9U4TvGQtg=;
        b=PAMfCdtF7NaKYWsmHErDijB/NN+bhZpx5alZQsPGEzwqSHUgGEx3uz1msi+6KAkSUW
         zyu2EWSQ4RUIENnmcsTVZK9XgGlMLVNVctceyl20DqvRUA1OhARgExFqc63taeXDhy9k
         +ZgBgmJBUJorsGnahq8klvMGD0XdyLy/8wNgQ85Gvil0uJjKaJUGvyN0amJZd1l3DD0R
         4SSkhDhcIHHItf2KTa/fLwjA/iDn7s5gT7zgO6R0tsrdrsaC2V9nkjR+w/CHOXFuX6uS
         zg8BJwfxoRaO5104tUz/SM8D0wi/mMm+SOwk/YwaO5MWORmZXl5RjgGuFkAlMpt+13jV
         PuxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pvEd8OlhmojPJ3+c+dfnJLpAsgbmZ2S+nb9U4TvGQtg=;
        b=FQsTEynlhCfDH/ySyoQxt/3W8hE/CjoUpGBmVhBaLHJxR2gZXKtoK7U9HtIHQEXAWB
         ncGLe0CzAIKGEurHRNRvAykzJsHn3sGzGVy1PRX27iAmzopwIT1dm9piFUG7tLbc9717
         UwnZQ3ciShrWq1AvqZ7LBYpjBXSGjsdiTt+/ThryEyKrifRPIapKfEfBQc47+q5cuD4q
         cFgNg4yF4bs/qttWJ/xCUEQyCXxwI0kmoMKBRJn7h+4+a/aFDD0Lxn3Es4ysTnLtCSWx
         9uHXEVfmObRc4zCT567eg8ciIYiOrzdwukz0U/K4IhdpBdYu4ouNV2NRRcfkYefnYukS
         qqOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321y9QWCEyF2vv5PsBZKhRWOD0NsugA08KGdpHLMAlVq6fvpXNc
	m9YE7CaNAVl/r8Ce5wQ4Uy0=
X-Google-Smtp-Source: ABdhPJyhOLhpK2k2dx9ZGOrtlOzQgEETBXNJLscTEOjxWPAaknDEucW0nwbHuQizZgOahy+gun5QJQ==
X-Received: by 2002:a62:2ec4:0:b029:18e:f566:d459 with SMTP id u187-20020a622ec40000b029018ef566d459mr4122954pfu.80.1607016227416;
        Thu, 03 Dec 2020 09:23:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c205:: with SMTP id 5ls2934458pll.11.gmail; Thu, 03
 Dec 2020 09:23:46 -0800 (PST)
X-Received: by 2002:a17:902:6b48:b029:d8:e603:75fb with SMTP id g8-20020a1709026b48b02900d8e60375fbmr34782plt.6.1607016226871;
        Thu, 03 Dec 2020 09:23:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607016226; cv=none;
        d=google.com; s=arc-20160816;
        b=nl7s8xKcnV363w1FzSVmwazrUaGwJyFgLLA3nnvbF5FU2lw360MfbtC31zJr1WasZY
         6Y1fziBJFFNC4ojZkvoFcKa0W3fMkKwME5N5W0zaDOgp+yisXOLWxYA1BfBgjhUJqQVr
         l38IFWcxJ3equH8PzFg1eakgOgH0T/qD7xCpu70EzhpmCm8PtlHGv+wrFW9S19wpcpwL
         Nj1G7LOtNGZh8dhxRakyeD8OewWAOHRO4ds/ErZ62/FMHwBZ4WtimXOQjfD+a+m60IpG
         MP5P3IZ+J6ToGB/+a+pq01iYNaLrAbj11mBxYDR1hofrqwr2pTtceDWVAtR0oNqKmbmI
         QYlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=c4tbpitkcYj8qfBGHYVBBb4n6ULSQJeM2bPM8KAMifk=;
        b=DDDvBsbN+f63Xb1nohHrnPji+YdraTt4uOefoy59TBxPQnkzh/94jh/PYH/sRJPQYl
         HC5RxcKGiYBWFrD6+ZgcXBebSBHcqGDHdrchF0lpvk8rzLzBSq2yiZ2AhA+n+Tng24c2
         s1TcZTOv5/x3YqkBhVe3ve4g+Se96C7nEJRwLGfLfJTQML+y7V+M55jLvuz+iPQvH52t
         la3Z9OEAbXIH9jA5aAX5q+Ea4VWohdnjnolOoO96+39TDN7X9lU52kWzUQo5KqTV85Tt
         VPg2PxUFqac+47sjNWne6kJaiZjzB82NoClKWyrRfmYTOliBG5DHRRM46uMn+qQKZArW
         K6Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d1si8806pjo.1.2020.12.03.09.23.46
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Dec 2020 09:23:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AC90511D4;
	Thu,  3 Dec 2020 09:23:45 -0800 (PST)
Received: from [10.37.8.53] (unknown [10.37.8.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 14A7F3F575;
	Thu,  3 Dec 2020 09:23:42 -0800 (PST)
Subject: Re: [PATCH v2] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: vjitta@codeaurora.org, Minchan Kim <minchan@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Dan Williams <dan.j.williams@intel.com>, Mark Brown <broonie@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, ylal@codeaurora.org,
 vinmenon@codeaurora.org, kasan-dev <kasan-dev@googlegroups.com>,
 Stephen Rothwell <sfr@canb.auug.org.au>,
 Linux-Next Mailing List <linux-next@vger.kernel.org>,
 Qian Cai <qcai@redhat.com>
References: <1606365835-3242-1-git-send-email-vjitta@codeaurora.org>
 <7733019eb8c506eee8d29e380aae683a8972fd19.camel@redhat.com>
 <CAAeHK+w_avr_X2OJ5dm6p6nXQZMvcaAiLCQaF+EWna+7nQxVhg@mail.gmail.com>
 <ff00097b-e547-185d-2a1a-ce0194629659@arm.com>
Message-ID: <55b7ba6e-6282-2cf6-c42c-272bdd23a607@arm.com>
Date: Thu, 3 Dec 2020 17:26:59 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <ff00097b-e547-185d-2a1a-ce0194629659@arm.com>
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



On 12/3/20 4:34 PM, Vincenzo Frascino wrote:
> Hi Andrey,
> 
> On 12/3/20 4:15 PM, Andrey Konovalov wrote:
>> On Thu, Dec 3, 2020 at 5:04 PM Qian Cai <qcai@redhat.com> wrote:
>>>
>>> On Thu, 2020-11-26 at 10:13 +0530, vjitta@codeaurora.org wrote:
>>>> From: Yogesh Lal <ylal@codeaurora.org>
>>>>
>>>> Add a kernel parameter stack_hash_order to configure STACK_HASH_SIZE.
>>>>
>>>> Aim is to have configurable value for STACK_HASH_SIZE, so that one
>>>> can configure it depending on usecase there by reducing the static
>>>> memory overhead.
>>>>
>>>> One example is of Page Owner, default value of STACK_HASH_SIZE lead
>>>> stack depot to consume 8MB of static memory. Making it configurable
>>>> and use lower value helps to enable features like CONFIG_PAGE_OWNER
>>>> without any significant overhead.
>>>>
>>>> Suggested-by: Minchan Kim <minchan@kernel.org>
>>>> Signed-off-by: Yogesh Lal <ylal@codeaurora.org>
>>>> Signed-off-by: Vijayanand Jitta <vjitta@codeaurora.org>
>>>
>>> Reverting this commit on today's linux-next fixed boot crash with KASAN.
>>>
>>> .config:
>>> https://cailca.coding.net/public/linux/mm/git/files/master/x86.config
>>> https://cailca.coding.net/public/linux/mm/git/files/master/arm64.config
>>
>> Vincenzo, Catalin, looks like this is the cause of the crash you
>> observed. Reverting this commit from next-20201203 fixes KASAN for me.
>>
>> Thanks for the report Qian!
>>
> 
> Thank you for this. I will try and let you know as well.
> 

Reverting the patch above works for me as well, and the problem seems to be the
order on which the initcalls are invoked. In fact stackdepot should be
initialized before kasan from what I can see.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/55b7ba6e-6282-2cf6-c42c-272bdd23a607%40arm.com.
