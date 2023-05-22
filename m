Return-Path: <kasan-dev+bncBCAP7WGUVIKBBZVPVORQMGQEZRJXOLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AAEC70B34D
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 04:48:08 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3351e9dbf1dsf90436015ab.2
        for <lists+kasan-dev@lfdr.de>; Sun, 21 May 2023 19:48:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684723687; cv=pass;
        d=google.com; s=arc-20160816;
        b=nIJG0kBUjB8fYCukQiVm0KfPIpMeSrJqfrnDh4Ebml59zBiyComiVU/GJuTdEATRtD
         CrvoshK7Sh2vdPXFFrixlN8yC/YEmzLPbYyIjBkFWxJgBe1SU9t1+9jDNUYAyGZDPAn9
         fzWBLSMErGoci9M6I5O2JU8qEOZepaHiQcWvBMOPYgxx4MB2tcf/9l2auJRI9ltahfpq
         Ffm/Iv/+uQutErjRGPbtqwr6t3TKzEZk+Wp7sx4AHaMmlKH2qvBGz/v3gWHZqqZCDuOc
         1ZXDnHHt1vE5qNM8ezrQJlME0mfM4fIwj3rizYZB01G+98jpnHHVQNCUq5PfsApoLoDa
         rQRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=tFFuOUsLs+xg0f8a7C0UP96DiJxqkVfztOhc6qThOcA=;
        b=gV7f2qDVul8xQrqiqVmNH6dnxjugXoPg5ZNNFNVJsEVJZwcelbeNB/kC4CW2SRK8Gh
         oD5SHDgAz2optzQF6cyKhveyplhfi1OxzKX04n5n+wTrY4Ca0RRUqI5e639CdpXKYPQG
         xxLUSfrijNmDJMp/ktsc6TYG4yDQg6NvfF5DqKqhTiI7SUq3p6EMiQaOnCvvesxIed/1
         dJbg9++sGXhuksSLVHrv3tntFA+PupYT7oarJCusAwSTNljk8t3ZLi2YqkN3IMQgS7pv
         tm4bsMts5MBciCYqFKXpUoeb89Ocs8i/kTaHzzMX2iTqwG0XYXiFTDuIOuBw3C00wb1V
         DT8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684723687; x=1687315687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tFFuOUsLs+xg0f8a7C0UP96DiJxqkVfztOhc6qThOcA=;
        b=iVdBBQDkRdYBacMAXUDMfdYECi/1TbONX/+TgEbcVbLszA6smqe8lyLLgJZ9f9815i
         NP1uuTKzK0RbkV2c7b8DqJ+5ixxJ15lrPQqP66Ch3NCy4MqJ/BaSGOkHnFOCS31aS9sl
         TrC6EsXKfjwe+hyXhz8l8gCIcj7qsB3F3nWft6IdeJJ5xlJ0Z+Hhy+AbZAFh3uv4nvwx
         QuR6wmnxkxF6Wc45ITENFjgQ+w0YNKzETk+RkVKeyPp1+8eGGyAE4bTw7QzOvYeHeSvU
         2e9DU+FNQdaGvHLzyOdEWAkV0e0qPgBDtuxg4GoxHH5rEfjIJ8aD0lgtghuy1hdv1DT/
         2AhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684723687; x=1687315687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tFFuOUsLs+xg0f8a7C0UP96DiJxqkVfztOhc6qThOcA=;
        b=ILT5nn+0A4MlDRGTgGluCZAbIhoWuOsOcliB/HT9fFmBpxTi93ip28g7VffzKjTc17
         olQRIhRrz3PcQVweQTk5quqCCw5UZ7HUbcw4l5N+IPnoT4OoDZOxkdgMFgOXes7ZYzkR
         zsB/3sGVvO8YTtkvBPCnOJ4wj9VQDPDPGbwCe24PM3xYirdhITTdiAUMnManLJIh84/6
         uADhOWv5VRw/cbDvSZ58miD1FtwoGUREy/6YANJqV6NKEcxqS+yhj9ci79RAZCRYWwm9
         TRE6Z8k+2TyljRYVOcbRU1g9ew5afYvG7WP7AP7afY6/+OIxsfUflkX/tdaimnwaFR4N
         S3ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDygQBqQ2DM7fS+g/gk/Y/sqJ1nJqPsP6sPvELDu2GLvsEt9CMtU
	9VYHmABPerEZbfhEsg5N2MM=
X-Google-Smtp-Source: ACHHUZ7NsyAg7gw5oUlFCqJQ01InteARomOi+GCRPWCzKTkQdu0lkYP6/uLhMybrRkCpa8n9ypEN4g==
X-Received: by 2002:a92:da0a:0:b0:338:7da7:fd27 with SMTP id z10-20020a92da0a000000b003387da7fd27mr5291382ilm.5.1684723687156;
        Sun, 21 May 2023 19:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1085:b0:332:70c1:2b3c with SMTP id
 r5-20020a056e02108500b0033270c12b3cls2854384ilj.1.-pod-prod-00-us; Sun, 21
 May 2023 19:48:06 -0700 (PDT)
X-Received: by 2002:a05:6e02:6cd:b0:32f:752d:4a4e with SMTP id p13-20020a056e0206cd00b0032f752d4a4emr6931613ils.1.1684723686324;
        Sun, 21 May 2023 19:48:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684723686; cv=none;
        d=google.com; s=arc-20160816;
        b=XcAjQ0NplHoS1eIorWVTIgBYEEqhY8bD20KKZ/hVSFXYGyM3+RSuJf6uWQKwm3HgS8
         qTyiQScbSuOJzXdHlSIYWuOicM9jnIu/NoWp0TliHuymGJB5BW3Jlg1cehOVKf0ev5d0
         juOQB2XXjPU9GPBKz1zdKaSXz+JqDoaYQaTfZRRY//dFyR0zcLtHdHoyA16rsH/9QefA
         /iV3SkgjStho2MLGDXfH4dOSIOd5qJLhXmK1wt1KBFkUXqvR2Xtg7CouMMJAkS0+Tse5
         ZQ/5psyGNdh89woo77CX+RWfvfkm7n8G/psjTBt9cWhWCWgKnr7XrOkjcw1A/zmwV9wz
         5BZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Po77XwJlzEoDvhdeUaCormRHekdIFY4Ge0FQa88HJrg=;
        b=qVNcdDJBeIGUnUop5M0NAtbqA3GERfYhHmNl7E4GwIHOtk2B5/RAJzNMopSKdmopRl
         9GuxFwZtuHRh21sJYvbaOaJl4FeurWcVYllcNn0//IjReA2jn8XIGfUu7+VeBfCeDI3f
         IrV+G/GRZ8uJXwg67NeRoX9xOz0uyQcas270a66J+Dz6EsNxCuPBSifUrGizSIeCL5bS
         rAuZi7ha/zvAKEcU6ad2uOEZIw4knDF9vq8O2NAy0MrbjkUFZJSKzpQ9tKSi/fE6lt5U
         varaFRQvwKok+pMx9H6sZiqJehpeNe/5bk/DI9HiJte4ahs1Yjn6IuG1kPasenJ2eZcA
         CulQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id j27-20020a056e02219b00b00338270e1bb5si289830ila.5.2023.05.21.19.48.05
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 May 2023 19:48:05 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav118.sakura.ne.jp (fsav118.sakura.ne.jp [27.133.134.245])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34M2lpoq021800;
	Mon, 22 May 2023 11:47:51 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav118.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav118.sakura.ne.jp);
 Mon, 22 May 2023 11:47:51 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav118.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34M2lSTW021710
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Mon, 22 May 2023 11:47:51 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <0471c62b-7047-050a-14f5-f47dfaffaba7@I-love.SAKURA.ne.jp>
Date: Mon, 22 May 2023 11:47:25 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
To: "Huang, Ying" <ying.huang@intel.com>
Cc: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>,
        Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
 <9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
 <87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/05/22 11:13, Huang, Ying wrote:
>> Any atomic allocation used by KASAN needs to drop __GFP_KSWAPD_RECLAIM bit.
>> Where do we want to drop this bit (in the caller side, or in the callee side)?
> 
> Yes.  I think we should fix the KASAN.  Maybe define a new GFP_XXX
> (instead of GFP_ATOMIC) for debug code?  The debug code may be called at
> almost arbitrary places, and wakeup_kswap() isn't safe to be called in
> some situations.

What do you think about removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT?
Recent reports indicate that atomic allocations (GFP_ATOMIC and GFP_NOWAIT) are not safe
enough to think "atomic". They just don't do direct reclaim, but they do take spinlocks.
Removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT simplifies locking dependency and
reduces latency of atomic allocations (which is important when called from "atomic" context).
I consider that memory allocations which do not do direct reclaim should be geared towards
less locking dependency.

In general, GFP_ATOMIC or GFP_NOWAIT users will not allocate many pages.
It is likely that somebody else tries to allocate memory using __GFP_DIRECT_RECLAIM
right after GFP_ATOMIC or GFP_NOWAIT allocations. We unlikely need to wake kswapd
upon GFP_ATOMIC or GFP_NOWAIT allocations.

If some GFP_ATOMIC or GFP_NOWAIT users need to allocate many pages, they can add
__GFP_KSWAPD_RECLAIM explicitly; though allocating many pages using GFP_ATOMIC or
GFP_NOWAIT is not recommended from the beginning...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0471c62b-7047-050a-14f5-f47dfaffaba7%40I-love.SAKURA.ne.jp.
