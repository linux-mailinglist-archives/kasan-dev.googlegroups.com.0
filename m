Return-Path: <kasan-dev+bncBCN73WFGVYJRB6PKTGSAMGQEQ4LFPTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5976B72B51A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jun 2023 03:31:39 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-3f7f4dc6ec2sf24932895e9.0
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Jun 2023 18:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686533499; cv=pass;
        d=google.com; s=arc-20160816;
        b=K6Kn2MCayHsm/llygii9uRxsvxPF8FwklcnPXOXV7X0VWFdkxbAVzkAtg3qcaCNjvm
         KHItGOg/OOkiFcChMnAPaMD2FKro3vFZEu4QDX3twJYFTWHdkHyb5COXYmpG+QMnmtI2
         9wHR3WAMsIsHw0zml16zocv/yDtQ0wxYpd2WiEE60ae7L07zRGd2n+IPwrTmqE8GJwsq
         uq8FRONGYOoPmC0LU/7rzhkGW/Cr5X+WXcOdOv41EjiC1PAn+Aul3elH5GBHtzKXYk5K
         zoNO8CDKyzAjShaLKcZF0/2dUCoCvdUyFQVR8jg/oQO8JGV2ZMQ85y7F06s5fJroBg/t
         yXXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=Rr8+i8IsTLU0F0FbFb81Ez/TP68yRQE7FJTSqTsbE40=;
        b=jOrw+0mzKFNmzb16AowaWRH1517xxLKTYhlBoc1Z4zFJGBPFHgbqAfRfYP264e4KbZ
         Gy8AZpkccQtGx6vumKiRdkud3jaXWoN93f+8vuWzTrr+goDgD7KmApqP2ICnXaIzWtmP
         KUU5p96el49P8p7DHy+/WT3ka+ubRM9TuXYRpbtHLFThOTIzwJosNVHIbYzc6kYrdoO0
         JGqtlWOyBFmP3n0xvRuRzmRxexCY0owCsov33KGbryGMsIpHIrYrO9gJGIPEO5KTywR/
         7hPwlxVQ/ptz13zQkRFXo66n3MRskyQxyYfeYvoRwM2ICEaWERIy3maHNXHc/2fyh8mf
         QZKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BczpxA7a;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686533499; x=1689125499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rr8+i8IsTLU0F0FbFb81Ez/TP68yRQE7FJTSqTsbE40=;
        b=n7YM6c1fXV4el5+5zZ1YZN4vUMb83NaNRfbGwBWVTOWi/DpbKw9Bb35965ZE5JCwm1
         4ixW2tzXjK5s9Sqm4EMcpU1YRMjmsybQNLeHX1PadyHPii+m8ZMG5xgx2CylUExc84MR
         5EAw0sSCWwR2wU3FwZjNfR1IqWOCa0h545Y1tZ1MHoiyMaStJl4UsNUkN2nIyl9KUy7q
         BB9+F9xcg1zCjMC2WeYkFBhD/Pa+7irE/4Ytm2DuImnjYsCt+gWzA67j2sRaNY2cduRG
         WTp2UCHq9R8BvVo7SLpuPA+pH1UBMMaRJ6EH3xUceShzNfieX6jUgXlKu9S158N8GsnY
         xYMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686533499; x=1689125499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rr8+i8IsTLU0F0FbFb81Ez/TP68yRQE7FJTSqTsbE40=;
        b=FrPiZI9UiO1+Ffn/4TShoi7ugDUztnkqzZQbaPMAqDqNQmnO+ToqeAjZF+Kj4pA7bj
         DxM92vRHkqRLiWVdWhxlG7UCJqKfnwqepxbkVC7RIv+3Qk+L95ejENudS7hRCIQI2HW1
         mNMjncNGeXYKegk9GhOy4T/B46sNujXLT/BXn00X51RdwPjRY5+GV5+dfFKjp3zjHbym
         8eoLQ0xZW0GjjWuwhvBj3u7SZYi566aqhx6CCE8+HYVWAbsMKI6BTzvBT73SsAuHDd6/
         SESeLtaOeQY4AXL6JLBDshravTVYiCgmhLH3Ef1ybquBOqSczzU3BEmKBtwGmT9zs9H5
         E2tQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDznNKaEy0wTp2H3IHIPh0/hcJNjiTIhD0m3+PJUjPYm3ffyn4vN
	45o36C72x74Idmjd5huHWJA=
X-Google-Smtp-Source: ACHHUZ6f4W6UwFZ0wQ12DI+0ZGwauztViNmFYya4SEIcvaPG7WsyxgTlcAQxDqhGnEJC9nPCK9a9QA==
X-Received: by 2002:a05:600c:3793:b0:3f4:2255:8608 with SMTP id o19-20020a05600c379300b003f422558608mr5722541wmr.31.1686533497947;
        Sun, 11 Jun 2023 18:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9b:b0:3f7:ecbb:40e7 with SMTP id
 bg27-20020a05600c3c9b00b003f7ecbb40e7ls661388wmb.0.-pod-prod-05-eu; Sun, 11
 Jun 2023 18:31:36 -0700 (PDT)
X-Received: by 2002:a5d:6347:0:b0:30f:bafb:246c with SMTP id b7-20020a5d6347000000b0030fbafb246cmr2259374wrw.61.1686533496409;
        Sun, 11 Jun 2023 18:31:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686533496; cv=none;
        d=google.com; s=arc-20160816;
        b=QiEVsQBSnzyBd+zsfnjdLnuG1agV0fI4okSUr6OUKwbfhIo4lHKvxZBf0WB1VDYhu9
         PPY8ngPI29pU99T5C2vDuqPewPg73ab3Nua3BLbq1OIJ+NkRoR69NF728JvA5njnWc45
         0eTLriZDKaMYbssfXN332Bqbm63ypFFoAhiluqQnb3j1iq0cMi632XkilcOdOdy6ah8l
         a2AxXT6TzGQnrEa8XqBafDFKQ1kEtpGhVO3GdwtbMrOsMLbkLj+MwoODbs8PX0l2djEH
         HlntLQbKuaiV+VBalkwFtjZZJwunRK2jqEIn4mF2LIsYdaYPBUdg0yT421XDxbJsvmy6
         Wp4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=zb+VyWArCJzEWCyQ0Yq1Nh1fslyQBkR3uFLjC1f4htU=;
        b=jg2Dl/3o9dYnDz6VihNhg1PHd99AhNdQE63ofHK4yrENWS4LzgjTpSL+d6wqbAr8fV
         35zBB/mTOXnkV4S7/BgFlOOM8yHZjsr0Ks4beykX35/YDkWqD0Ge/lsBzaWO075vkFNk
         MPZCDqkh30nYesjX46jm7Vo1m1WZgZ1uLscVXXMUlpD7IkrLcZ4zMJC/ICc6Z65s2K79
         aVKfTQlqWVQ2UMUf49Ojhd3oPp1DzWzPPIEdUTNCa1By6eUcnqUKm+XwWOnkSAwdUSRj
         VEm1qsEKFNnMb2td7+/ao7drwioH7clgvyFXMdOpY/KfjSPsIdFIRpCF4dMLVp88h1Hz
         IRDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BczpxA7a;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id p29-20020a056402501d00b00510cd4eed58si675915eda.2.2023.06.11.18.31.35
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Jun 2023 18:31:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6600,9927,10738"; a="357916471"
X-IronPort-AV: E=Sophos;i="6.00,235,1681196400"; 
   d="scan'208";a="357916471"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2023 18:31:34 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10738"; a="711024244"
X-IronPort-AV: E=Sophos;i="6.00,235,1681196400"; 
   d="scan'208";a="711024244"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by orsmga002-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2023 18:31:30 -0700
From: "Huang, Ying" <ying.huang@intel.com>
To: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: Andrew Morton <akpm@linux-foundation.org>,  Alexander Potapenko
 <glider@google.com>,  syzbot
 <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
  <syzkaller-bugs@googlegroups.com>,  Mel Gorman
 <mgorman@techsingularity.net>,  Vlastimil Babka <vbabka@suse.cz>,  Andrey
 Konovalov <andreyknvl@gmail.com>,  Dmitry Vyukov <dvyukov@google.com>,
  Andrey Ryabinin <ryabinin.a.a@gmail.com>,  Vincenzo Frascino
 <vincenzo.frascino@arm.com>,  Marco Elver <elver@google.com>,  kasan-dev
 <kasan-dev@googlegroups.com>,  linux-mm <linux-mm@kvack.org>
Subject: Re: [PATCH v3] lib/stackdepot: fix gfp flags manipulation in
 __stack_depot_save()
References: <000000000000cef3a005fc1bcc80@google.com>
	<ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
	<ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
	<656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
	<87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
	<CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
	<20230609153124.11905393c03660369f4f5997@linux-foundation.org>
	<19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
Date: Mon, 12 Jun 2023 09:30:27 +0800
In-Reply-To: <19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
	(Tetsuo Handa's message of "Sat, 10 Jun 2023 20:40:33 +0900")
Message-ID: <871qiha2mk.fsf@yhuang6-desk2.ccr.corp.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BczpxA7a;       spf=pass
 (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as
 permitted sender) smtp.mailfrom=ying.huang@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp> writes:

> syzbot is reporting lockdep warning in __stack_depot_save(), for
> __kasan_record_aux_stack() is passing GFP_NOWAIT which will result in
> calling wakeup_kcompactd() from wakeup_kswapd() from wake_all_kswapds()
>  from __alloc_pages_slowpath().
>
> Strictly speaking, __kasan_record_aux_stack() is responsible for removing
> __GFP_KSWAPD_RECLAIM flag in order not to wake kswapd which in turn wakes
> kcompactd. But since KASAN and KMSAN functions might be called with
> arbitrary locks held, we should consider removing __GFP_KSWAPD_RECLAIM
> flag from KASAN and KMSAN. And this patch goes one step further; let's
> remove __GFP_KSWAPD_RECLAIM flag in the __stack_depot_save() side, based
> on the following reasons.
>
> Reason 1:
>
>   Currently, __stack_depot_save() has "alloc_flags &= ~GFP_ZONEMASK;" line
>   which is pointless because "alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);"
>   line will also zero out zone modifiers. But why is __stack_depot_save()
>   trying to mask gfp flags supplied by the caller?
>
>   I guess that __stack_depot_save() tried to be as robust as possible. But
>   __stack_depot_save() is a debugging function where all callers have to
>   be able to survive allocation failures. Scattering low-level gfp flags
>   like 0 or __GFP_HIGH should be avoided in order to replace GFP_NOWAIT or
>   GFP_ATOMIC.
>
> Reason 2:
>
>   __stack_depot_save() from stack_depot_save() is also called by
>   ref_tracker_alloc() from __netns_tracker_alloc() from
>   netns_tracker_alloc() from get_net_track(), and some of get_net_track()
>   users are passing GFP_ATOMIC because waking kswapd/kcompactd is safe.
>   But even if we mask __GFP_KSWAPD_RECLAIM flag at __stack_depot_save(),
>   it is very likely that allocations with __GFP_KSWAPD_RECLAIM flag happen
>   somewhere else by the moment __stack_depot_save() is called for the next
>   time.
>
>   Therefore, not waking kswapd/kcompactd when doing allocation for
>   __stack_depot_save() will be acceptable from the memory reclaim latency
>   perspective.

TBH, I don't like to remove __GFP_KSWAPD_RECLAIM flag unnecessarily.
But this is only my personal opinion.

> While we are at it, let's make __stack_depot_save() accept __GFP_NORETRY
> and __GFP_RETRY_MAYFAIL flags, based on the following reason.
>
> Reason 3:
>
>   Since DEPOT_POOL_ORDER is defined as 2, we must mask __GFP_NOFAIL flag
>   in order not to complain rmqueue(). But masking __GFP_NORETRY flag and
>   __GFP_RETRY_MAYFAIL flag might be overkill.
>
>   The OOM killer might be needlessly invoked due to order-2 allocation if
>   GFP_KERNEL is supplied by the caller, despite the caller might have
>   passed GFP_KERNEL for doing order-0 allocation.
>
>   Allocation for order-2 might stall if GFP_NOFS or GFP_NOIO is supplied
>   by the caller, despite the caller might have passed GFP_NOFS or GFP_NOIO
>   for doing order-0 allocation.
>
>   Generally speaking, I feel that doing order-2 allocation from
>   __stack_depot_save() with gfp flags supplied by the caller is an
>   unexpected behavior for the callers. We might want to use only order-0
>   allocation, and/or stop using gfp flags supplied by the caller...

Per my understanding, this isn't locking issue reported by syzbot?  If
so, I suggest to put this in a separate patch.

> Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>
> Closes: https://syzkaller.appspot.com/bug?extid=ece2915262061d6e0ac1
> Suggested-by: Alexander Potapenko <glider@google.com>
> Cc: Huang, Ying <ying.huang@intel.com>
> Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
> ---
> Changes in v3:
>   Huang, Ying thinks that masking __GFP_KSWAPD_RECLAIM flag in the callers
>   side is preferable
>   ( https://lkml.kernel.org/r/87fs7nyhs3.fsf@yhuang6-desk2.ccr.corp.intel.com ).
>   But Alexander Potapenko thinks that masking __GFP_KSWAPD_RECLAIM flag
>   in the callee side would be the better
>   ( https://lkml.kernel.org/r/CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com ).
>   I took Alexander's suggestion, and added reasoning for masking
>   __GFP_KSWAPD_RECLAIM flag in the callee side.
>
> Changes in v2:
>   Mask __GFP_KSWAPD_RECLAIM flag in the callers, suggested by Huang, Ying
>   ( https://lkml.kernel.org/r/87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com ).
>
>  lib/stackdepot.c | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 2f5aa851834e..33ebefaa7074 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -405,7 +405,10 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  		 * contexts and I/O.
>  		 */
>  		alloc_flags &= ~GFP_ZONEMASK;
> -		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
> +		if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
> +			alloc_flags &= __GFP_HIGH;

Why not just

                        alloc_flags &= ~__GFP_KSWAPD_RECLAIM;

?

> +		else
> +			alloc_flags &= ~__GFP_NOFAIL;
>  		alloc_flags |= __GFP_NOWARN;
>  		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
>  		if (page)

Best Regards,
Huang, Ying

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871qiha2mk.fsf%40yhuang6-desk2.ccr.corp.intel.com.
