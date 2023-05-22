Return-Path: <kasan-dev+bncBCN73WFGVYJRBE5AVORQMGQEYVQB6II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D86E70B315
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 04:14:46 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-52c3f0b1703sf5243476a12.1
        for <lists+kasan-dev@lfdr.de>; Sun, 21 May 2023 19:14:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684721684; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlfkxk2akCKa4cAO/e3sZbmqpvWMDvPGjjH+doIKNA9qmeXxwahxCBdnOQFEzT7yL/
         UR0mrTkPi0dv7Dj/VkzyHxkjchmVN+g7wZE96UnspQTB/YJ2XXY+cglDJ7g7c/RLVLLK
         W2gjJNzE5jax3FTnIsBmkwR1D4LBcPXHpf86A4creZZr0Hj4ikjEs38qCrZfVADNnMNv
         Hg6bno2yoU0l7b7voWI7r6UkJHS4yX44NIg1UmR1doy/Rvb5hXp7e6It/5P+ffHbAwIS
         k/mRSdoD6u//nNtqMGpfZ2ievdv9AmGWwk3HCH/Ehimc0CCq4Mc6opEYterNkUDq5s5A
         k11A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=dea9HI99wuQoaZ5qOGiZanTg7eQsYkuFp3VVILfc73c=;
        b=dtOhInRYR3sdlC1aIrIcNF0mke+XpoE8VWDLj+6q+p0bw10IyEzFH1JRDI2aB7kstd
         mkX6fxO1swVJCPYW3NtOVJ3LD63bIPb1d9a/niYf+H+RhWq15BT9kCooslqt3ThnPBC7
         FY3BTBtVPyB+hwtig4uDZx5U35bRRSq9hruKFycukMU2qIie/ItvNcg56wMqP0s291Fg
         CsxoDPULANMTco0VEkbpHZwRRlW4PSocgI0ooKmQBKMOyO8iMpXc9x4PkzpBJkU39arQ
         m6Zph3IsizUq9BEH0WXLOGlyhChmyRxPYaLmSOgJi4ZaIOTVXnxUTyvTdcnRTvx+bPd3
         cI+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ca9OopQ3;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684721684; x=1687313684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dea9HI99wuQoaZ5qOGiZanTg7eQsYkuFp3VVILfc73c=;
        b=jexdvwLe1fFedXD1iC4brZ8IdU6laR7MCb+UqMegcqWPj4u0jWTdwiHTZ6qlIFvTRO
         GFVzRz8zhWsBOiXnCFwRxeHOeNYT+wIK++inqdZITjPF7wT7GPJwambNZuwXadgAkiB+
         8CLQuGeezyPZsOBWxB16yJhwFK93qlPr2Xdl6ZJMhUml+TBHqoAgkCduOWOEXkSOnWGR
         GT36xwmHut1hazNZq/We+44AFU5jAihVrfwo5cDEj10u73VfXlgqFpE/R31/CfrSpn7D
         m3cQhEsCMNEraLT+ytr79cEF+aCBvuVeWLAY0vSOidSxIthC4kJpXgEAE4nqtBtPPgNp
         prWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684721684; x=1687313684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dea9HI99wuQoaZ5qOGiZanTg7eQsYkuFp3VVILfc73c=;
        b=dUEfK9dhnyDacta4ZRft/KUl3zBT6tTMVNuPTbT0SuQHxM3mJVJbHvBfDii8YKaS7v
         bVQ2YuN3mYoa/rptNLhZOTaPOZP39fjRANJ+7pBQUpNYHteF8V6uQxsGJMS0KJDsEBi6
         6ehSx8j/xGOmo6f1s6rBBE7JuNhme8lPDQtgE71hRdPxKVC8/bfKM2xIq9HWI+bmZoU5
         M0PGWj3Yt0d/e9LAGd3t7C/uRiq8G/1QzUpU20i8Qp8OBdC684MpN9pq0WSogQoxx/aH
         VjQGm2FtiR7xihxE/HB0ah7VbLIePn4XYm3LeKO5xRjpvgw1Oxsb0iQeXQsgsdCcHYuy
         GjXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxKLfZaJfP1GBm48Y4Ccon5QksQbz8lgORrzu37ciChA/O7ZQYc
	KBxZyWoND1pokC5UVlJYh2w=
X-Google-Smtp-Source: ACHHUZ6BC/m/CwGbe3awj61ErnGMaITqw8+NY7mHQ9yDGJXv2yXCKZrqI4NTL7ONcd0gWNJcsYVFoA==
X-Received: by 2002:a17:902:d14c:b0:1a9:baa8:359f with SMTP id t12-20020a170902d14c00b001a9baa8359fmr2051618plt.6.1684721684098;
        Sun, 21 May 2023 19:14:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8304:b0:1ac:896f:f650 with SMTP id
 bd4-20020a170902830400b001ac896ff650ls2748259plb.1.-pod-prod-09-us; Sun, 21
 May 2023 19:14:43 -0700 (PDT)
X-Received: by 2002:a05:6a20:1590:b0:102:8f0a:5acf with SMTP id h16-20020a056a20159000b001028f0a5acfmr10161713pzj.62.1684721683225;
        Sun, 21 May 2023 19:14:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684721683; cv=none;
        d=google.com; s=arc-20160816;
        b=xJGCHIpwb/XG/Jz+hm2E/4EuHuFauZeidPWS6A9fmUlWSYUdA0lMYcSSZae4ZIIdfd
         9btvBOk6ho21RF8ALKSNP8IaM85ajYTdwwABwZxJ7MAPxPZ4lyizajPkKF3kq8/wPtiN
         3zyv2g8LBb9ptd9rD6kMw3U4fKM6cd2VaAI8ysDPZgFpcKqPsPWNTbMUEr5+n2Mi3aWN
         9FQosHB0WE/FR6ePC9DdS9upy/fq8s3235Le3zkQwX/V84NjlMfYqjE5TP1/NfuTUZpn
         8zkcoXihmyuYz+IyKptEKHr0gbKn4jViTk63B34ytLdSeepT7J5qEB9qZuaX84fmSFJp
         cjUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=We3jTxvIVde71cTLw2VX8M1hrldlnhZiWJe07joqnEc=;
        b=p9M1QSmwYGh5ShZeH7tyWmpdwpfUbNrgV+TA8El5JsdLNHFDDrVyvMnDfsfBU/bCfF
         H2FWsSxfsSnUBirmiZJ6wZEKJz/agxtJVM6Yoqy3ouDuzg0j/vKYPworYdAsutsKa3iU
         lmHEywZC1AMmWCXTvWb6hxudfZ2lZVdP+78fLZCSj70OiI4HtX0Hbkt/jp7aJOCfi4J5
         wbHgpRK3k0L5lO2eM2kqJBwJjO/flaAY76HnRpY+kB8AsgdH/sHqrSSx0G2gs3YVZLU1
         1m6r7AFkvIuqMMsgur3g+ToXnYbk2Fqk7CbB94Zeu5xmBnExMyZSUtV6SCRZCZ2AW4Nh
         6BTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ca9OopQ3;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id a4-20020a63e404000000b005289dd0b142si301553pgi.3.2023.05.21.19.14.42
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 May 2023 19:14:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10717"; a="351654945"
X-IronPort-AV: E=Sophos;i="6.00,183,1681196400"; 
   d="scan'208";a="351654945"
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 May 2023 19:14:42 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10717"; a="1033427960"
X-IronPort-AV: E=Sophos;i="6.00,183,1681196400"; 
   d="scan'208";a="1033427960"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by fmsmga005-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 May 2023 19:14:39 -0700
From: "Huang, Ying" <ying.huang@intel.com>
To: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
  <syzkaller-bugs@googlegroups.com>,  Mel Gorman
 <mgorman@techsingularity.net>,  Vlastimil Babka <vbabka@suse.cz>,  Andrew
 Morton <akpm@linux-foundation.org>,  Alexander Potapenko
 <glider@google.com>,  Andrey Konovalov <andreyknvl@gmail.com>,  Dmitry
 Vyukov <dvyukov@google.com>,  Andrey Ryabinin <ryabinin.a.a@gmail.com>,
  kasan-dev <kasan-dev@googlegroups.com>,  linux-mm <linux-mm@kvack.org>,
 Johannes Weiner <hannes@cmpxchg.org>
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
References: <000000000000cef3a005fc1bcc80@google.com>
	<ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
	<ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
	<48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
	<9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
Date: Mon, 22 May 2023 10:13:36 +0800
In-Reply-To: <9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
	(Tetsuo Handa's message of "Sun, 21 May 2023 07:44:20 +0900")
Message-ID: <87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ca9OopQ3;       spf=pass
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

> On 2023/05/20 22:14, Tetsuo Handa wrote:
>> On 2023/05/20 20:33, Tetsuo Handa wrote:
>>> @@ -405,7 +405,10 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>>>  		 * contexts and I/O.
>>>  		 */
>>>  		alloc_flags &= ~GFP_ZONEMASK;
>>> -		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
>>> +		if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
>>> +			alloc_flags &= __GFP_HIGH;
>>> +		else
>>> +			alloc_flags &= GFP_KERNEL;
>>>  		alloc_flags |= __GFP_NOWARN;
>> 
>> Well, comparing with a report which reached __stack_depot_save() via fill_pool()
>> ( https://syzkaller.appspot.com/bug?extid=358bb3e221c762a1adbb ), I feel that
>> above lines might be bogus.
>> 
>> Maybe we want to enable __GFP_HIGH even if alloc_flags == GFP_NOWAIT because
>> fill_pool() uses __GFPHIGH | __GFP_NOWARN regardless of the caller's context.
>> Then, these lines could be simplified like below.
>> 
>> 	if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
>> 		alloc_flags = __GFP_HIGH | __GFP_NOWARN;
>> 	else
>> 		alloc_flags = (alloc_flags & GFP_KERNEL) | __GFP_NOWARN;
>> 
>> How is the importance of memory allocation in __stack_depot_save() ?
>> If allocation failure is welcome, maybe we should not trigger OOM killer
>> by clearing __GFP_NORETRY when alloc_flags contained __GFP_FS ...
>> 
>>>  		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
>>>  		if (page)
>> 
>
> Well, since stackdepot itself simply use GFP flags supplied by kasan,
> this should be considered as a kasan's problem?
>
> __kasan_record_aux_stack() {
> 	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, can_alloc); // May deadlock due to including __GFP_KSWAPD_RECLAIM bit.
> }
>
> Any atomic allocation used by KASAN needs to drop __GFP_KSWAPD_RECLAIM bit.
> Where do we want to drop this bit (in the caller side, or in the callee side)?

Yes.  I think we should fix the KASAN.  Maybe define a new GFP_XXX
(instead of GFP_ATOMIC) for debug code?  The debug code may be called at
almost arbitrary places, and wakeup_kswap() isn't safe to be called in
some situations.

BTW: I still think that it's better to show the circular lock order in
the patch description.  I know the information is in syzkaller report.
It will make reader's life easier if the patch description is
self-contained.

Best Regards,
Huang, Ying

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87edn92jvz.fsf%40yhuang6-desk2.ccr.corp.intel.com.
