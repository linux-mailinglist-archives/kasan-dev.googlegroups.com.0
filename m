Return-Path: <kasan-dev+bncBCN73WFGVYJRBIEIWCRQMGQE7TIJYQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DC8670CEE8
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 02:09:05 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-307814dd87esf2822928f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 17:09:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684800545; cv=pass;
        d=google.com; s=arc-20160816;
        b=dMZFlK5JV4ZE0T71Cqd1gwUoyrHLFRgHzTSqN5oKE3pNZqUmSIqCH82caoWbX0hmi/
         7Hy75GmiL7YxqyZ3Q9jWO1jMdtnmPZ6mV7M8HfT4sdd3tMc7igg/NP03Qo1D2FYV/G/W
         0xLCxejYYURgbyynH5FcGZp/CjjGDEHA9pZ1S+Ctf30QefZ/EwUoZJg9OPuSWRU3uoIG
         laK0a3fr8LL6mUVso5D6IL1Hbr3mIg6L6W74UCHBBm8nbZzGRUv3g89JBuQsiuCqPp6j
         xsxMzQwwOIfNqYFtVa5I2HliF/Dcu1/JC0ZrnFyEp2c2nwOPsid2Q0KZK9WZWTtl4bF7
         fc1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=CLwwe8gE1Zfpf00l0F84oJvZAlwcZIQquEF4aHsRbsU=;
        b=eZiYzaOvQ8V0mrGheIsGhThWMwNxN2N/yHpr/iP15uWHWu7Oh5IZHLNrOQWjhXUqpW
         CwwR7E7/5rv2a4hYdlH6YfA2GNn0V/BeDMDXE7tj0FRheRHoy/t2VLDY4MQX8Uetc++u
         eCEI0ZUUyNIxai+0FSsKQvQ2nDi0tBe4gRaeo2NIv3XMO0kWFkyYXm85c3zbhx+9gS9R
         6iJjKebMgNxp/PjSAaLAgCFl7Kza0oijizCOvFBEwU1JMsDJjcyh4vQqSkIICJKbLOuo
         0f3y3BeP56UM90JDiH5IKt8m12g5Jw2ihlzGdTN59xk7/MlNbAE7bmAGRdxCfweR0JGZ
         hGuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dqbgoTyD;
       spf=pass (google.com: domain of ying.huang@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684800545; x=1687392545;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CLwwe8gE1Zfpf00l0F84oJvZAlwcZIQquEF4aHsRbsU=;
        b=PADEtjeGubKScKJgTDPYHPLLpeoG9q0ALhiwUMRcLNlrQQcwq39XB6Z8oDegBVhGAj
         7Bebpkrb7iAyTsV2Uh3KAveuvoY7a9h9yfoVnMX7+Vgk4hHcJmJpPwktqx73J5S4kkH+
         0RY66V96h6T05TjZS1c4A4uSK3lsSTbbX5PySP10zuuNqv7EsFibGsIIl/bGVC919R+D
         YWu1G5WRGokDnOsWEhd/jPMI482gnnBetrDxfwXU+p1wk1+vmeD+NkClrLxPKeS2WI3M
         0EQoYIpON5mI9KCD81ZnL8sDXMTZIYz6rR2LoqwWDGjieNEJKoJX4OUnbGnayJq3JKtt
         +YkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684800545; x=1687392545;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CLwwe8gE1Zfpf00l0F84oJvZAlwcZIQquEF4aHsRbsU=;
        b=VzTXBs56qL1i0CL0yEDgKEFIhoTpBl+DQ68qXTinOdm+CNjwTdbM2qf9yo/fWK5mgn
         hy97D5B020IMOU45PxaNmB7Xm9pa95RIT6vf5c9aJLVS+rfjFdOKO49PRA2xElU/6R5E
         wNkVfOoxQg86H1z2WlDPcT2zH8a8ILwFJ8J27+vAp3AEfWieJrdORPFq1J+rXzMMz6n4
         XYJ9o+MxMVs/G6JdwuM+HbVTrHzWfw8Z5yHV/EcbhYvMUOBLd9mNyXUNDiW1nyqgfg3L
         U8VbIYWuF9Ec464QWKhfLQ6cvXx2SvKXo9Iyzfqv/G9FpgWB4PZ4PiRvxP+lOmU4fJVT
         BlFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyj3snhcR/Zyf8StIoprdmFBSTmkkJVQC+ZNbHU9Rba/IfCi10x
	YJyBH6YZDBnVoTyN9wk5OY0=
X-Google-Smtp-Source: ACHHUZ58nh2o53glo62hHoH6N0+DxC6/GBzG6S0/TA4zg9z609NEnuTK9KPqtrTj0MmYewgV+E+Qow==
X-Received: by 2002:a5d:6543:0:b0:2f9:b454:1fc1 with SMTP id z3-20020a5d6543000000b002f9b4541fc1mr1974852wrv.0.1684800544604;
        Mon, 22 May 2023 17:09:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f83:b0:30a:8dcd:fcbb with SMTP id
 bw3-20020a0560001f8300b0030a8dcdfcbbls1029983wrb.0.-pod-prod-03-eu; Mon, 22
 May 2023 17:09:03 -0700 (PDT)
X-Received: by 2002:adf:e8ce:0:b0:309:50e7:7d0 with SMTP id k14-20020adfe8ce000000b0030950e707d0mr7953226wrn.31.1684800543160;
        Mon, 22 May 2023 17:09:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684800543; cv=none;
        d=google.com; s=arc-20160816;
        b=oAyVEXQI0BPBmmz5Oirf33YZ/vr5kXpv7BcEczSj1VfMM1GQzIttOV7CHM3Ge9hNgS
         uJz0bEcEbzIxBGRSvNRtgOzNHgCXEQIY6ccNI8OLRAfnzIdCfANpaAXWbQZKvKLPQAxm
         cM6OEjRqp9FawfpJECmm0ky41b41lYZBluM5TOnY9DFsxu5CKaUSga7n9lrh5KOb9S8F
         Rm2lVyHg2vJBiMXd7YgNoBXHkN31XVItai104BkFSDttTEW+iyReBwqbT31hl+iCOO0r
         1vgKS2ezPOgDq6MSsY8S9o1PHCpBvqvc/5uBzmnYKy7NYhCaz5PCMYD0Lc4Jf9ZPrYk3
         LxXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=WpzNURW6NGvTWyKiQwgw/9T+89+wqu7OptNQSdR7V3Q=;
        b=A25zFgska/DZj4lETjEioSXH0HZh6hlgSSaAvM6Cl1boV7b82b1b5hMqZZkCO5OcbH
         PxERdRN3gmH9qQ7HnoR2SkRqN/y6xfL6t63QumxaU2ntVMcZjSSSbgBYXcdOU0V92wde
         mmDUSF/waQe/zRy5fzvaKdVNTjaXzuXhAfGSqwlU7CmZsQ1v3wfv0dHfL1X4ycjerzM6
         0L92pLj1YNRJh+CYefN0MlMdwYr5T0zxxcbit5PdcMeZF7ENBeEn3K2R+DORastWtbFL
         7QpFi03lhoy15kwBmBuFk++4VoIGhoTssJ4JZ/hav7VmA+depc81VPPqdE0zc+TPVicE
         g+uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dqbgoTyD;
       spf=pass (google.com: domain of ying.huang@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id bq22-20020a5d5a16000000b0030933d3af7bsi501216wrb.8.2023.05.22.17.09.02
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 May 2023 17:09:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6600,9927,10718"; a="355427847"
X-IronPort-AV: E=Sophos;i="6.00,184,1681196400"; 
   d="scan'208";a="355427847"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 May 2023 17:08:53 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10718"; a="734534410"
X-IronPort-AV: E=Sophos;i="6.00,184,1681196400"; 
   d="scan'208";a="734534410"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by orsmga008-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 May 2023 17:08:50 -0700
From: "Huang, Ying" <ying.huang@intel.com>
To: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
  <syzkaller-bugs@googlegroups.com>,  Mel Gorman
 <mgorman@techsingularity.net>,  Vlastimil Babka <vbabka@suse.cz>,  Andrew
 Morton <akpm@linux-foundation.org>,  Alexander Potapenko
 <glider@google.com>,  Andrey Konovalov <andreyknvl@gmail.com>,  Dmitry
 Vyukov <dvyukov@google.com>,  Andrey Ryabinin <ryabinin.a.a@gmail.com>,
  kasan-dev <kasan-dev@googlegroups.com>,  linux-mm <linux-mm@kvack.org>,
  Johannes Weiner <hannes@cmpxchg.org>,  Michal Hocko <mhocko@kernel.org>
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
References: <000000000000cef3a005fc1bcc80@google.com>
	<ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
	<ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
	<48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
	<9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
	<87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com>
	<0471c62b-7047-050a-14f5-f47dfaffaba7@I-love.SAKURA.ne.jp>
	<87a5xx2hdk.fsf@yhuang6-desk2.ccr.corp.intel.com>
	<b3a5b8be-8a45-a72c-334d-0462cdc582d5@I-love.SAKURA.ne.jp>
Date: Tue, 23 May 2023 08:07:40 +0800
In-Reply-To: <b3a5b8be-8a45-a72c-334d-0462cdc582d5@I-love.SAKURA.ne.jp>
	(Tetsuo Handa's message of "Mon, 22 May 2023 20:33:49 +0900")
Message-ID: <871qj7zz8z.fsf@yhuang6-desk2.ccr.corp.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dqbgoTyD;       spf=pass
 (google.com: domain of ying.huang@intel.com designates 134.134.136.24 as
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

> On 2023/05/22 12:07, Huang, Ying wrote:
>> Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp> writes:
>> 
>>> On 2023/05/22 11:13, Huang, Ying wrote:
>>>>> Any atomic allocation used by KASAN needs to drop __GFP_KSWAPD_RECLAIM bit.
>>>>> Where do we want to drop this bit (in the caller side, or in the callee side)?
>>>>
>>>> Yes.  I think we should fix the KASAN.  Maybe define a new GFP_XXX
>>>> (instead of GFP_ATOMIC) for debug code?  The debug code may be called at
>>>> almost arbitrary places, and wakeup_kswap() isn't safe to be called in
>>>> some situations.
>>>
>>> What do you think about removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT?
>>> Recent reports indicate that atomic allocations (GFP_ATOMIC and GFP_NOWAIT) are not safe
>>> enough to think "atomic". They just don't do direct reclaim, but they do take spinlocks.
>>> Removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT simplifies locking dependency and
>>> reduces latency of atomic allocations (which is important when called from "atomic" context).
>>> I consider that memory allocations which do not do direct reclaim should be geared towards
>>> less locking dependency.
>> 
>> Except debug code, where do you find locking issues for waking up kswapd?
>
> I'm not aware of lockdep reports except debug code.
>
> But due to too many locking dependency, lockdep gives up tracking all dependency (e.g.
>
>   https://syzkaller.appspot.com/bug?extid=8a249628ae32ea7de3a2
>   https://syzkaller.appspot.com/bug?extid=a70a6358abd2c3f9550f
>   https://syzkaller.appspot.com/bug?extid=9bbbacfbf1e04d5221f7
>   https://syzkaller.appspot.com/bug?extid=b04c9ffbbd2f303d00d9
>
> ). I want to reduce locking patterns where possible. pgdat->{kswapd,kcompactd}_wait.lock
> and zonelist_update_seq are candidates which need not to be held from interrupt context.

Why is it not safe to wake up kswapd/kcompactd from interrupt context?

Best Regards,
Huang, Ying

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871qj7zz8z.fsf%40yhuang6-desk2.ccr.corp.intel.com.
