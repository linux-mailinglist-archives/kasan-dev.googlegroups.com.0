Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLF3Z2AQMGQEJKBETIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FE3C3215A7
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 13:03:57 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id o4sf9186750ioh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 04:03:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613995436; cv=pass;
        d=google.com; s=arc-20160816;
        b=JGFJesss9aMXdCJQFOeBNfLyCiO/B/ypPf/hxuL6IOal8z6HKxPLFzfwGJ1HXUj9eC
         FJGU+FqFKM2Z5+NCoc2xolQuGAAtoJi4LJ/JlUNsos0ePTqRwZVmfL9SS8zP42ctDI2e
         O5Y4fpD6NP8dXyM4EZchWO8TR7OxvZ5qDZ9ebeIIergCqjKFzHJSajNtfUeZfzG6xEUm
         tSMw57UAuHAHsBm2u+BTR3kKapmijXQN8x5JXeEx5HbUcKRWNlvgCSblZ3TVJ4p12w81
         RvAoRlZewt23dVST8IeyQUWcoPOPNxlrqkBsa+crNT3NLRueYCSZYEYwhEVGtPvrlj4m
         c1ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NM2xactue30MZXdDAwiF8noSeR/yoAK1R7Az0eeBgXg=;
        b=BNtBPvJAQAF2yRVE2R/mshbtN261iXddkPmlpNikFMZJILWLiKvP4KNS+hqIxg5JTa
         9iINzIgwQuxCw1Klciz6gCvkJOeyGpQ5YaatwAGoWV9Es7hou0CdoxwSR9lf/PjM8pKO
         lq9AEjdldWqYJ4trrfEnNpI4Im5ZJeEnGVyAp+ebv6StSZYtSspFB/ET1MqC4hgmMoBc
         zxwT1qqsa01WmdmtE1UARUYmjMBsw9NMEJc9GpksjxHb+IhL6rDaY81z4wPU2PCcFy35
         8Exv1rAauhIZGlHew7k9qCp89EBg2Kvs3y1g+Kvd99QRy6SbqXBR5DMBT7hN2roEyZc/
         fjLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NM2xactue30MZXdDAwiF8noSeR/yoAK1R7Az0eeBgXg=;
        b=hnm3VzaGZxs6lgvscR/Ua6sxmjUanY3u5rzvsgXibJ7/l5Z1yD6rnDC1ksrIvjiWai
         mCsdcB56vJb+sLUJP/ATT64VJGzm5VJPqiwrnH3Qhe9IJusuKnaieJngfA/tzf1rHVRW
         HxK9CInzyJzHVn9i2EdAlQi0AyBxjyOtJKSuPkbHSetMohZUxSIuvmFB6t05BgbciQPr
         v+xXOPBumds+rbUZZobt7Itu4dPCo0C6bJVRKtBw5SB+tSJ0jUZtiukWmUQhUOO9iTs+
         Jnoi6IRfIBKK8b/U8SfcpTsWjGruTwreUmFb1MLTmtqynrQ8NBlI/3iA9/clpV9Ceyp4
         pufA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NM2xactue30MZXdDAwiF8noSeR/yoAK1R7Az0eeBgXg=;
        b=ObqvABTC56iB8y7OHGKp088a97BsM6L45eelwaewI53BAXyphPZNf+PdA9i9DaIakT
         38xhqXYtKtY7z8e5Vdgsglc2Q1VRkQp9DiGQX1M4Wb76/FOYYu00EdwrdQmyvThWlsFO
         mNC9EMmH0uz1mteeISojx3q17mqiZuRRHmvK971rNDCavL7SBDSLSjt36/St4QG6wKJm
         Q5DXDCCPFkpt5pcySu+ekfDVFJNtC1eK7It7qpjle5LXdFyXK1ksI4v+7pdXXgs78Fpz
         NolIQoQ1rimTqBJDtKgGcV4euBwy0FMnmU4Os1u69Z98wj7xMix6h9DPN2HIlEVer7KN
         H1TA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ToLIt0ZQlCOd0FDjMnoQo864JxNyNQEYLS78pBhclbyA/eYpn
	lSY3wIUtWw9L+2fzdbWS5Tc=
X-Google-Smtp-Source: ABdhPJz2MPn9GRG1Dqg7RYbx48kclPgbxrJvDeETaKm1S9cLsNfme+sOUHpllrGle7KZkYb7jQNEgQ==
X-Received: by 2002:a92:3306:: with SMTP id a6mr14565746ilf.55.1613995436614;
        Mon, 22 Feb 2021 04:03:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c0c7:: with SMTP id t7ls4250362ilf.2.gmail; Mon, 22 Feb
 2021 04:03:56 -0800 (PST)
X-Received: by 2002:a05:6e02:1bcb:: with SMTP id x11mr14041809ilv.226.1613995436202;
        Mon, 22 Feb 2021 04:03:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613995436; cv=none;
        d=google.com; s=arc-20160816;
        b=OpnPJG6Kw1jjD8KsXgmBuG/bsAuuIv472p/lsoNc04hbE/4n8AzGYXFuIF39A6vvBs
         Az9UDDgtBkcRv8ClAq1teR4tXUHFC/aopZOB7fQBmgw4i2z7BF7TuRCKmZGbvdb4rS4+
         gbcBsitnLR6UyPaQu6YOCbNZL4NDwBUnxBY/WNQQkuPDp4tWv0oS2l58O7IPle5vMK47
         babJttzNbUJ5azLgoCGfiiEYUVAYeRHBz3LCo5klQAm52W0IGE/AgxUsvyKC80uK2R44
         g1mLJg5ntfZOrhIQMoSHgFm31VW9PkDppRe0dF2KHqJww6XPUt0DNmRbogL8UGAHTtry
         S/OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=6I8dmAvwfywsSuR2OL49RQgP9MGNLljDub8LfbFUEk0=;
        b=VJ807nnaMTL2B1oW4roKCEFkKRopaW8UzEgHvCX2mvSWXkMAnkr5T1oud1jpojoE9o
         eKcgrjpQfoqSlngtrP6msN7fUcpTOa296qz6DtVxZjCJJjb0IV58HZFbGyK3PxzpPzlL
         NVAe8Ls1LiMZEtPGnN06W5KJSDYYukj4bagxmJf95hlufPugHPEKEqMrYSXrDjrgMxRG
         yrmSqJvcoo964or4tVkVmX/obKZpRfjJ7W02gpf5jRk1a3BzAr7rwlAjILzHCb4SpDqz
         I3Q9HNC68wRzUCslQoXIFRrOte/hsWl695oNKNHBDWzjy7czHqHyBh4xX4S1otrB5H3m
         9a4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u12si1204608ilm.4.2021.02.22.04.03.56
        for <kasan-dev@googlegroups.com>;
        Mon, 22 Feb 2021 04:03:56 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 699E71FB;
	Mon, 22 Feb 2021 04:03:55 -0800 (PST)
Received: from [10.37.8.9] (unknown [10.37.8.9])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6D31F3F70D;
	Mon, 22 Feb 2021 04:03:53 -0800 (PST)
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can read
 beyond buffer limits
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
Date: Mon, 22 Feb 2021 12:08:07 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210212172128.GE7718@arm.com>
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



On 2/12/21 5:21 PM, Catalin Marinas wrote:
>> +
>> +	/*
>> +	 * This function is called on each active smp core at boot
>> +	 * time, hence we do not need to take cpu_hotplug_lock again.
>> +	 */
>> +	static_branch_enable_cpuslocked(&mte_async_mode);
>>  }
> Sorry, I missed the cpuslocked aspect before. Is there any reason you
> need to use this API here? I suggested to add it to the
> mte_enable_kernel_sync() because kasan may at some point do this
> dynamically at run-time, so the boot-time argument doesn't hold. But
> it's also incorrect as this function will be called for hot-plugged
> CPUs as well after boot.
> 
> The only reason for static_branch_*_cpuslocked() is if it's called from
> a region that already invoked cpus_read_lock() which I don't think is
> the case here.

I agree with your analysis on why static_branch_*_cpuslocked() is needed, in
fact cpus_read_lock() takes cpu_hotplug_lock as per comment on top of the line
of code.

If I try to take that lock when enabling the secondary cores I end up in the
situation below:

[    0.283402] smp: Bringing up secondary CPUs ...
....
[    5.890963] Call trace:
[    5.891050]  dump_backtrace+0x0/0x19c
[    5.891212]  show_stack+0x18/0x70
[    5.891373]  dump_stack+0xd0/0x12c
[    5.891531]  dequeue_task_idle+0x28/0x40
[    5.891686]  __schedule+0x45c/0x6c0
[    5.891851]  schedule+0x70/0x104
[    5.892010]  percpu_rwsem_wait+0xe8/0x104
[    5.892174]  __percpu_down_read+0x5c/0x90
[    5.892332]  percpu_down_read.constprop.0+0xbc/0xd4
[    5.892497]  cpus_read_lock+0x10/0x1c
[    5.892660]  static_key_enable+0x18/0x3c
[    5.892823]  mte_enable_kernel_async+0x40/0x70
[    5.892988]  kasan_init_hw_tags_cpu+0x50/0x60
[    5.893144]  cpu_enable_mte+0x24/0x70
[    5.893304]  verify_local_cpu_caps+0x58/0x120
[    5.893465]  check_local_cpu_capabilities+0x18/0x1f0
[    5.893626]  secondary_start_kernel+0xe0/0x190
[    5.893790]  0x0
[    5.893975] bad: scheduling from the idle thread!
[    5.894065] CPU: 1 PID: 0 Comm: swapper/1 Tainted: G        W
5.11.0-rc7-10587-g22cd50bcfcf-dirty #6

and the kernel panics.

Note: there is a look of msg drop in between enabling the secondary and the
first clean stack trace.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3d565da-c446-dea2-266e-ef35edabca9c%40arm.com.
