Return-Path: <kasan-dev+bncBCN73WFGVYJRBQFFWCRQMGQEQLPU7DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 8120670D036
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 03:11:30 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id 5614622812f47-395f6709591sf4658678b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 18:11:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684804289; cv=pass;
        d=google.com; s=arc-20160816;
        b=uW5qUja4EtpHm/YXKiKUnIDSuNJgkGIhzRXUW/p+iWwB3I2xsmqUevvIvmXJE2fNxU
         KQKDq29xlVTnWlOtSeurZIziOxBzNjaUzSUTfN/7SFno59WSLtKtDJCSeN+v+VRcWMCq
         OAylzSOPQo00i/R3kKGOJFbxaoIBO5y/5Us9Eq8bv7h0sh1Jhk33I3XUsX9V9pWbCbjf
         tDZsOsrGY8Uhq8OoXxVJ1Q5Im7cMqcyRWWKqUHYdE2I0+46JAQbuH4tOntroT5h9VDUx
         +17biKy5zwqXf76Bz/Lt0I0JNjTHk4JpSzNf+0SoYLpbEMRSiaaB9SBFwKIPpagc3WQG
         DRzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=szXK2FVvN/NwtG5PxhAZcOTMAoNLeTYmviWM/vGX7Yk=;
        b=l1brsNn0BxFyJtYwvPTIAo243zT51y0M7vh6QnWU3KvwXOSWGndSq2N5th49b8Qdda
         pZsidZ9teyotcOOOTFnyYRqWRukUGYmuLeR5zNSPmq1/JhKIIcFr7AsIaQBxCpBk8imb
         hC/6/+JlNX8/vlTfEbIXK9rNZoHjqX8kqax2kqQIEPjMcgNW/q4Vgs9XWszM/zjl139x
         Qw/FH2J5w83gscuzIbjTFOYWk6+R4yRrKI8TRZHMAP0T70V5GjGc3zmarUl1aOrzeLDR
         n5+785hlgsApw+hU9/bA3MW5NIFozQe8I1LHeJYOHr2SGjivENaOPR4YTxxHdsmyp1aB
         vXRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jFeNWzpH;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684804289; x=1687396289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=szXK2FVvN/NwtG5PxhAZcOTMAoNLeTYmviWM/vGX7Yk=;
        b=dIFRxPBqQ1hAD5WPVHzCelHIv0x2aH+e2LrUQypuUIbe97uWnzL4zCUOLoW6Otsf1Z
         //p8lZJ3RDil+n6aQrW09NiX6EnULZfIHH2S1/tI7M6HW4EunUe8WCpq93D2XAO2yuUw
         YLRY5IrzRFIX1/hKcDp+puosfCaaqd6a+JwRPYyJvUeg6FxVErD54rMQe07kvqqCNtq/
         phIu64/IeQwGjot4Qs1haQjhSoM2GiGrbU4mwstPF6022Cel+MWwqpzZnLuVBIzSk+Fx
         Zef/aPWb1fg864QvOxk/xwsd/uz7NBOxyAcHEXVhbxz6MaH4rt5H84BnJ3A1AR19c6yL
         5gSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684804289; x=1687396289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=szXK2FVvN/NwtG5PxhAZcOTMAoNLeTYmviWM/vGX7Yk=;
        b=Tyc4vOYXW1mWeNEFfVmCFU+cB1RqrUl3gPrzNOocM0821KLT9F/ArIz97uGsvY1ct6
         P34sp2hq4fLu8vREEBIl8niH26P2Zua10MgMO+jcI/1DEj0zLRnqHXGRE5DAxTZjBxEx
         4h0FjxuRzpQADrD41mYXWSnectrlDjvRjQanOn7Ey/22mWmkJfR7Jpws4FMCro2ss/fp
         lwh27pgclvXztVvPsERX3bHbdqOc7D4z7NgQTmTaJ3lQ8ec8ru9csjnRPAzXZA+HL39Z
         nDPApwF5nnlrv0koV9lszTTpq/DL3/pazvLdLILIZIHgUfRi96wg6XBS1z7PXUi6apQZ
         jnCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyADevrm/gNyAlvvDErGHqfsHi4yUe0V5Y26peqy4IbtuS4WeJR
	TSkRAxfxKuEmLjubFzu53sQ=
X-Google-Smtp-Source: ACHHUZ636e3Dp61YCyU8S9F4LrBxc9E4SLQvpmYbYe9ObYQTACdqBBXF/9hwCHxikDNrJxgMCrKyvQ==
X-Received: by 2002:aca:f109:0:b0:387:7fe1:a5 with SMTP id p9-20020acaf109000000b003877fe100a5mr3404088oih.6.1684804289065;
        Mon, 22 May 2023 18:11:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:38d:b0:54f:bb81:ba59 with SMTP id
 r13-20020a056820038d00b0054fbb81ba59ls549037ooj.0.-pod-prod-02-us; Mon, 22
 May 2023 18:11:28 -0700 (PDT)
X-Received: by 2002:a54:4799:0:b0:38d:fdf2:962e with SMTP id o25-20020a544799000000b0038dfdf2962emr6486399oic.23.1684804288546;
        Mon, 22 May 2023 18:11:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684804288; cv=none;
        d=google.com; s=arc-20160816;
        b=JU4axoPDQILhHmENSrZftEyGsTFwasyaujMFE5dCLPwHEnN4pc6MeD6a3z7eM/yvyx
         +w54XtvPwfDly3ItOGeWjoLelLvOl+Z3rc0PpNeLKrGjoOAWqY6NY66GRdRc8/dfe/rG
         y1ksRky5XuMwoY5SxsnbkcVRAn4HKQQfO3oS4NmlNvadWp999RutTFYSqCMLv/4ADLZH
         Plgh/x08id5yoA/YZbzFQR7FZ786R+5lUeGdWZqeU6K3EbsUBvtOrtnhz/mfpyQ6xKMR
         PUWX8PV/HEys9EnaZsK4Nt5sH2BDIuBLB9Q9tPHHrhn+QBuiixMyrgrQu/v/idbOmHy2
         0Hpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=C6RfMwDzarbcKVcCAAmlwwn9MSUBhRls1C47MYjQR+M=;
        b=rcqWJ22NzUc+VLgEHfUpc5cv4xRHvbhL3kDmJNp2YfOzVS7zvQz0DO62IKtXpeGHbE
         lyaHxqLQcuSAcoOMbFXCPTKowJR9pAri82pkEt1nxw8xFpA1zWF01is2Sn7vbUTKILa7
         I7oBOAdgtE7r4ClhjRMuO356naxM3axr3cmPA/e9Nt22I3lNX4hj2OSXUwAUG3ZQ+VpQ
         zXIMW0q3TsxjxSt3ge7DFu5rTr60qhkZ3uoPWnuA9rhFi4//9CgXS86H/jP1ASIEhWUc
         PHdLrbtF6oIwHe4G7IACwKfjopkq42R3Qo98N3pAgX9oV2vivilmD+6ZpnZhSb1U/DnI
         6yDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jFeNWzpH;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id q13-20020a056808200d00b00397f916323asi313279oiw.2.2023.05.22.18.11.28
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 May 2023 18:11:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10718"; a="351937607"
X-IronPort-AV: E=Sophos;i="6.00,184,1681196400"; 
   d="scan'208";a="351937607"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 May 2023 18:11:26 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10718"; a="734559964"
X-IronPort-AV: E=Sophos;i="6.00,184,1681196400"; 
   d="scan'208";a="734559964"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by orsmga008-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 May 2023 18:11:23 -0700
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
	<871qj7zz8z.fsf@yhuang6-desk2.ccr.corp.intel.com>
	<dc660fa4-1d0d-75e1-5496-36bef9117469@I-love.SAKURA.ne.jp>
Date: Tue, 23 May 2023 09:10:20 +0800
In-Reply-To: <dc660fa4-1d0d-75e1-5496-36bef9117469@I-love.SAKURA.ne.jp>
	(Tetsuo Handa's message of "Tue, 23 May 2023 09:45:02 +0900")
Message-ID: <87fs7nyhs3.fsf@yhuang6-desk2.ccr.corp.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jFeNWzpH;       spf=pass
 (google.com: domain of ying.huang@intel.com designates 192.55.52.120 as
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

> On 2023/05/23 9:07, Huang, Ying wrote:
>>>> Except debug code, where do you find locking issues for waking up kswapd?
>>>
>>> I'm not aware of lockdep reports except debug code.
>>>
>>> But due to too many locking dependency, lockdep gives up tracking all dependency (e.g.
>>>
>>>   https://syzkaller.appspot.com/bug?extid=8a249628ae32ea7de3a2
>>>   https://syzkaller.appspot.com/bug?extid=a70a6358abd2c3f9550f
>>>   https://syzkaller.appspot.com/bug?extid=9bbbacfbf1e04d5221f7
>>>   https://syzkaller.appspot.com/bug?extid=b04c9ffbbd2f303d00d9
>>>
>>> ). I want to reduce locking patterns where possible. pgdat->{kswapd,kcompactd}_wait.lock
>>> and zonelist_update_seq are candidates which need not to be held from interrupt context.
>> 
>> Why is it not safe to wake up kswapd/kcompactd from interrupt context?
>
> I'm not saying it is not safe to wake up kswapd/kcompactd from interrupt context.
> Please notice that I'm using "need not" than "must not".

Got it.

> Since total amount of RAM a Linux kernel can use had been increased over years,
> watermark gap between "kswapd should start background reclaim" and "current thread
> must start foreground reclaim" also increased. Then, randomly allocating small
> amount of pages from interrupt context (or atomic context) without waking up
> will not needlessly increase possibility of reaching "current thread must start
> foreground reclaim" watermark. Then, reducing locking dependency by not waking up
> becomes a gain.

Personally, I prefer to wake up kswapd ASAP.  And fix the deadlock if
possible.

Best Regards,
Huang, Ying

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87fs7nyhs3.fsf%40yhuang6-desk2.ccr.corp.intel.com.
