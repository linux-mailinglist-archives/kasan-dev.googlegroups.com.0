Return-Path: <kasan-dev+bncBCN73WFGVYJRBU5ZVORQMGQEFNRUNQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CC5270B379
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 05:09:09 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2af1ed9514bsf18501821fa.0
        for <lists+kasan-dev@lfdr.de>; Sun, 21 May 2023 20:09:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684724948; cv=pass;
        d=google.com; s=arc-20160816;
        b=00prmKgu6eSwEYHHNQFLi5sVq+f7Zb271Y1vxviSOUzfSLMBDj2pQUVLmvobVXEc/p
         SJ/g8EAoLR4sVgqdcJcBNhW7gOx1N9ANuMPmJ7I7a8hp2yDBXVXKPchMw83R+uJnzJXg
         QygaANz8BIttZIJ29/N3Cvaa6UqaX/f/zfyg9QpA45KpPJrB3jg0oJEeCftD5lwITg5C
         EjXqejj1XUfej2pF+xigrVScvIiZOyOprqmaWUU51XhgGEyjjoXRjB89McEFT2m59G7v
         U9k9GdIhwjrfjMvqNpE0hcBz6pe8rsPf+O95hDnQAdO0ILXbPLHQe8ZCCLDYEJ8TaRuK
         WObw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=byJTlBF+OzWRupxkMqaB1Sq7rDC0QZgIxkMWRg0WVNo=;
        b=QL6ZEYqFZ/2edEJ+ri7lGJOrQmRLEH+QuIToucI4DpLXQjI1tf0gYARgKKdJlhj77l
         ppVl5jFTECOx8f2676rdyMh9ZNeVZDBj/h+qQNrYyrVHzt1kRZJbydFmCXYA+04OLZNJ
         Mos4vACm4rHgn57GPvn4fvqvHQXoUh0wJBCizGHnb5iDa4S37/Irzznc9lWyY3kbm8nN
         Ibs2F+1fiyuBB5um0YGQVGUILdwKzKaB0KCtr1fvCPhoISsqNKo9s7D/OKoGQEsBTGdB
         H01Bw3pu/omxpnT5r+0eLPPlNvfXS7Pd1M6AkTDfSff1qexTuceUx6+SEjTEjefNJBIc
         LcAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=amVE8uj2;
       spf=pass (google.com: domain of ying.huang@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684724948; x=1687316948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=byJTlBF+OzWRupxkMqaB1Sq7rDC0QZgIxkMWRg0WVNo=;
        b=YeE9aBbexUQJV+oclNPjl04w4sBanDB+0uCuKGFRtGeagJPY82HDd+cb5UYHQ0IEiy
         HW7k5dLVtywy4f7+o8pTUpMYbbC/zvGWk6ldJdjizaYB/qwzOpa2BZwDvFdKTdXcAocV
         HzMYb2eR7BEwkHV5B7hZPNjb0UbWpnf1OalJQBKdYdxEoAEVdkk2NKTOkLGDKasdvdKw
         LBg84cOUKKKUEXrWSAD9tyZ+RFpxVOEMJ9olEFuBEbkHPNiKzDEYheyyfufviId0/nIM
         rMjMJUQ5xDSQRa6S4QOaqagopyi/zoBeiVoZ7e8jyMjS3NoyGmNolrx/ZMVui3etA9DE
         hxMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684724948; x=1687316948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=byJTlBF+OzWRupxkMqaB1Sq7rDC0QZgIxkMWRg0WVNo=;
        b=RQ7y9HeKeO0jlqe3G2WUJzXZhqVB5IMk5aRNU/IwF0rYZv8eYfL7oREuj3GtuhKJTX
         yHY6a1K+cL/heRKbu4CXgsSLklA/fIqrhnHYUJz7tndGHGTcblGLgMuPKu5qPeovCRlE
         GPF7ASJoQI+CMwAXVz3h0aDJplL1BWyb2nC2jDw6Jd4B7n2BkcTamAKCdkeQtuECcYRD
         KE6ZdaTQbP66YY8W4GFOj7mt2ZnObEERfeuYSQTuUOc/m94/fdupcMCtAAYnsuLiC3hZ
         JEvmNkAwcSwPw3rT84+aMf12O9x5sfkHHynYe9ycfgV2gWxOTxJU2FpDRSY0Year8c4n
         zWLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx6CVuWy3hIxDHxQ2CScuZXUoz+MUiZiUyQA9CFVQvnOXBueIWA
	RKiVbTxauZ5NMMVXjOu7YRI=
X-Google-Smtp-Source: ACHHUZ7BYG/EMMegvtZP8OMr4GVAucmQkN6DjcVmwoUFjUEzPaZb0Rz7xHjfmZj7WCTlsFynXId9FQ==
X-Received: by 2002:a05:651c:231:b0:2ad:9a87:ed46 with SMTP id z17-20020a05651c023100b002ad9a87ed46mr2285708ljn.0.1684724948261;
        Sun, 21 May 2023 20:09:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4649:0:b0:4f2:5c9b:31ac with SMTP id s9-20020ac24649000000b004f25c9b31acls643355lfo.1.-pod-prod-00-eu;
 Sun, 21 May 2023 20:09:06 -0700 (PDT)
X-Received: by 2002:a05:6512:a8b:b0:4f3:a55c:ebdc with SMTP id m11-20020a0565120a8b00b004f3a55cebdcmr3530387lfu.17.1684724946501;
        Sun, 21 May 2023 20:09:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684724946; cv=none;
        d=google.com; s=arc-20160816;
        b=thG8N70drHGP7qtOAQUEiuiLJVEZm2RNpHy/tT/9DVRrH5yWOhBBS3uTe3Y8xgWdlC
         lXjIC+5oSf0di+nEGyCabdAGKRAEKwaiqu+y5MwbtygDn6UYFl55jdWqUliG4728m/d3
         Kh1XhXnmkRoPimKBVAhWfT3XohX36S8y1E21azFof3SMg6cVh/R8eVZ1wYI4Wyla3w4Q
         XkPEWZvILoX5GwAUF5CoYE6zJCyJ3lBLY/3hvfg+drZA14QiJ3u1ub9j62TizbIF5n6g
         SbnBE20oZK3ed0unG0b6Lcfqyo4/sTp83eeeWnVmeK3oalkNey7q14mLHrbNSdO5bKQ6
         jw2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=K9MuGJsi5JjLfoRa/mOczbDbsd2ONxYBrKvWRFN07F8=;
        b=vIwQpNSUQfLgIc58YuLIvYTWQoobSuVMihaYPbSX+7YPin3E4XUe/TB7gPwdTjQwSD
         xPhTBvUihc9JVTgXSXCsiRTKkPt1CETfkTf/J3h/QOmSTsMI0Yt7Xq4Z67h9RqH3d7tK
         Fa1Sg63QvCj3iCVOf0GdlR8F4oiFE3hUYqU2XcneV2Xpe/XRo+abUM8dvSxrYj3/O1bh
         hgWlpcdOiH9UcxXk8yHzlotynmzzOQdckIZOvWxKfk8pBjDMfebPCDUpNFgQUVrDLHzz
         v3uKAJLtL2sCBRpX42TcTsvAcwPW3BZuYMuEFYH0irQgt23y9pDR8dvM66Xk2m/VROKI
         k54w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=amVE8uj2;
       spf=pass (google.com: domain of ying.huang@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id v20-20020ac258f4000000b004f3b045aa3asi383703lfo.3.2023.05.21.20.09.04
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 May 2023 20:09:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10717"; a="337402806"
X-IronPort-AV: E=Sophos;i="6.00,183,1681196400"; 
   d="scan'208";a="337402806"
Received: from orsmga007.jf.intel.com ([10.7.209.58])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 May 2023 20:08:57 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10717"; a="697491000"
X-IronPort-AV: E=Sophos;i="6.00,183,1681196400"; 
   d="scan'208";a="697491000"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by orsmga007-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 May 2023 20:08:54 -0700
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
Date: Mon, 22 May 2023 11:07:51 +0800
In-Reply-To: <0471c62b-7047-050a-14f5-f47dfaffaba7@I-love.SAKURA.ne.jp>
	(Tetsuo Handa's message of "Mon, 22 May 2023 11:47:25 +0900")
Message-ID: <87a5xx2hdk.fsf@yhuang6-desk2.ccr.corp.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=amVE8uj2;       spf=pass
 (google.com: domain of ying.huang@intel.com designates 134.134.136.126 as
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

> On 2023/05/22 11:13, Huang, Ying wrote:
>>> Any atomic allocation used by KASAN needs to drop __GFP_KSWAPD_RECLAIM bit.
>>> Where do we want to drop this bit (in the caller side, or in the callee side)?
>> 
>> Yes.  I think we should fix the KASAN.  Maybe define a new GFP_XXX
>> (instead of GFP_ATOMIC) for debug code?  The debug code may be called at
>> almost arbitrary places, and wakeup_kswap() isn't safe to be called in
>> some situations.
>
> What do you think about removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT?
> Recent reports indicate that atomic allocations (GFP_ATOMIC and GFP_NOWAIT) are not safe
> enough to think "atomic". They just don't do direct reclaim, but they do take spinlocks.
> Removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT simplifies locking dependency and
> reduces latency of atomic allocations (which is important when called from "atomic" context).
> I consider that memory allocations which do not do direct reclaim should be geared towards
> less locking dependency.

Except debug code, where do you find locking issues for waking up kswapd?

> In general, GFP_ATOMIC or GFP_NOWAIT users will not allocate many pages.
> It is likely that somebody else tries to allocate memory using __GFP_DIRECT_RECLAIM
> right after GFP_ATOMIC or GFP_NOWAIT allocations. We unlikely need to wake kswapd
> upon GFP_ATOMIC or GFP_NOWAIT allocations.
>
> If some GFP_ATOMIC or GFP_NOWAIT users need to allocate many pages, they can add
> __GFP_KSWAPD_RECLAIM explicitly; though allocating many pages using GFP_ATOMIC or
> GFP_NOWAIT is not recommended from the beginning...

From performance perspective, it's better to wake up kswapd as early as
possible.  Because it can reduce the possibility of the direct
reclaiming, which may case very long latency.

Best Regards,
Huang, Ying

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87a5xx2hdk.fsf%40yhuang6-desk2.ccr.corp.intel.com.
