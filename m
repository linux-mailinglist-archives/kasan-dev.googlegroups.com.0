Return-Path: <kasan-dev+bncBCAP7WGUVIKBBRWCSGSAMGQESZQP43I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4178272AB38
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Jun 2023 13:40:56 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-19f1d9056fbsf1561401fac.0
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Jun 2023 04:40:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686397254; cv=pass;
        d=google.com; s=arc-20160816;
        b=iAu8CZBEigyOPhOyp1VbQTHfmEe/EjBb3oN/UXTuc0eBzgzR8fjJe9C4Lw/o3fm1i2
         BJKUXIhIPMRYNELFK8hUew7ob9owrdnboSK94U8xa19lCOk5K4iagegyg9xQjyU/FYJO
         kgfqZ+NtnZw2zVpcVajKAm8odYPwbgsGP6sJLTH7uK1NSIScJvmSh3W9tpMSRP2db9zq
         AaAgl/X4XanvfLuFpO4V5bZmiwUQ/bcnMgewOsq+89lRvn5Bjp17by3sVaATEDrBjQrp
         PWGteUmqco9pYqyANskMOBqLL4/f5lSVtC4MNNMEvHXXmwVvPftHdqhOKziTYtWHthS2
         H/Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=b+9w15oor1/84mourfpw3RHY06du32bR/JQ7/cadxOc=;
        b=QVVBff96QunSxrH8ND2Ebhq3lP6w8Yv4sIfEUD8dYdfOZo0YkVWTwnEqX1KJPMqGgg
         /IUu7djJD9yz2tG5ireaNDqbp8PT2T7TvsdGxyzudR69uvV1kUAJMJ8Pvq5NeeJd8H4r
         wCCpmcx+sMMNEXe2xJM1BgiH5pF/KJDH/C9n//vcAPDk9Lv1j9C8QMVa310mHskMZeRh
         3cvJzk/vaP0lhtdCSqMDwi2yGWqsK5ZCs0Yqs51dlmNnp/oOtJIszbq18Liz00EipZ5h
         nKJlHxyGmIDjjomoMga75SwPN5SoHxDZ/2L0+mKeY0NkSs3zvWhp5LPj87XLoM9iaEqc
         Mm+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686397254; x=1688989254;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b+9w15oor1/84mourfpw3RHY06du32bR/JQ7/cadxOc=;
        b=dnidYlfLyIRyBD8vR9vPFHdiG/v3rX17E0Q/M26fhi4wgHFP2qYnq6cQcwek/2DWrx
         0EOYxWMjUeXaza812IVucYxBLePysM+JvZRBQQ1lZ4CyZykIat8AvvXGLAknpx0Bonak
         2aXfP1jwOd0hYBod8zA8jctFpBOpyqcMVG1Aca4wSNVxkHS9mkMDcfP2p+p4gaJ9K5ST
         rV6g72pFBliT72vG7drPb4qXYaadVSlx7+5izNAVyOgO+JrA3tdo7RY5FweREuUiKEK4
         alioo1x5AfeFcFfhmJ+ypUMPeEiHxLyX/V64OjaFWYOjcqEnjPliX/hdQ9ufYh0Rvo4d
         kaWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686397254; x=1688989254;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b+9w15oor1/84mourfpw3RHY06du32bR/JQ7/cadxOc=;
        b=E8ZdUTron22BAwr4NnhHGR+tROy9S6sYpHScHgSFW0VaN353bS6h2yGqaZ5Pv780jV
         ch9hx32iWsadjtjuYel4LjbOhoBHkqDHi1e74i7WtPiwyo/X402NBtkLH5V9SrO7I6s/
         76ZgbMGOartGIbwDz/sLAmlG/2NGtc/iuhcPlX7aRxQWwStT4TaLO22dC/ZNwKj6nErm
         8akeQFXNNu2aJCq62MItFTBQQfQN00K88aLLqSHBMhMsCtGJHUpeIa9AsMW42a004b2d
         rIc9QqqNmO/2wQ9jPxdHF7v6IUWxgt1MxhAXMXGAUHPE1a9gmvQNH0qqcy0l9mJJkIA7
         t1XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwdS9966dTF+p0hVk4XvkE/prEVh40ji+gD5Mely/SJxj4Xjn7X
	iG7ahlT0GrgL+O6O4xHKjN8=
X-Google-Smtp-Source: ACHHUZ49KxEq2MvVc8MONBMztEtE4CI1vWLLauZWBCHJhWE6KlsInPhTCtBOTfQBD81JcX+w71lZig==
X-Received: by 2002:a05:6870:8447:b0:19a:ce25:6d06 with SMTP id n7-20020a056870844700b0019ace256d06mr2731985oak.56.1686397254659;
        Sat, 10 Jun 2023 04:40:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c69f:b0:187:a128:fe88 with SMTP id
 cv31-20020a056870c69f00b00187a128fe88ls383229oab.1.-pod-prod-07-us; Sat, 10
 Jun 2023 04:40:53 -0700 (PDT)
X-Received: by 2002:a05:6870:d303:b0:192:597c:1c17 with SMTP id f3-20020a056870d30300b00192597c1c17mr2452429oag.7.1686397253763;
        Sat, 10 Jun 2023 04:40:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686397253; cv=none;
        d=google.com; s=arc-20160816;
        b=hIwTsDe1rZMbg5ISzFFIUVhZ2Lti1H7M4ipZeY7007GolBFMYSrKRUUALKFKnsgxDL
         NabeIdwCYGGDZXYGA4mBW7du8hFImfkjwqXQapS+uS4QK9A1RnRzXdFYxTAp4dL7NqxH
         NjyFBK3DySxpprGY2YjVlBeDoU5budoY4vo7OeQsUjV9C083dF+PzKg2KzFkxGZNiH70
         yk/NuKzghI/RoDtqgrRccH/g9qp5q2x80nEORe82dJEM3ku6nvUCEuFzM5yaPd2XsWTK
         e6vzagz22CXa0fJZACwlk2m+yF7XV+y8/2/QpcTa1j7QES2PS+RWRXXGlPEWFVeAUBcv
         VLkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=AlPWNVhKGCybEMbewqZO2WyJQUErrIT/InT6OilCzRw=;
        b=N9gezMKsXHvaA7+ZqNlah0qxrMfSiZSfum9dpTA/lQf4erg6iOKeu59Yxhy0fWiOJQ
         D5r2v1Maw5WzAiOp4hsj+v9JrYw2uwOpwxix67z7NlZbaiPKg7TI1YWo3pbE9tMLqcQy
         MfDYjCPvb1srZicqz1yP2MYTlOBPEbCyhMmfeD/QXkK5hjWeZDjYKFTfsitNdQRGQR9p
         r2DTn4gsgHydcaCphSRlGNMnXeNyzvPqHdRaEv++PB2jJV4pVTRbAPMi7Vhus2a/SRZq
         M2icSqnNUgevv2UHtWI3BhsMIruftISUWnxulaTTGr9aKniXFei1+hS1fDbbHDnWjcq/
         Et/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id vj1-20020a0568710e0100b0019a6e9c429asi651011oab.3.2023.06.10.04.40.52
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 10 Jun 2023 04:40:53 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav311.sakura.ne.jp (fsav311.sakura.ne.jp [153.120.85.142])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 35ABeZYI019328;
	Sat, 10 Jun 2023 20:40:35 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav311.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav311.sakura.ne.jp);
 Sat, 10 Jun 2023 20:40:35 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav311.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 35ABeYD5019323
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 10 Jun 2023 20:40:34 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
Date: Sat, 10 Jun 2023 20:40:33 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.2
Subject: [PATCH v3] lib/stackdepot: fix gfp flags manipulation in
 __stack_depot_save()
Content-Language: en-US
To: Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        "Huang, Ying" <ying.huang@intel.com>
Cc: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        Vlastimil Babka <vbabka@suse.cz>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin
 <ryabinin.a.a@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
        linux-mm <linux-mm@kvack.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
 <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
 <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
 <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
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

syzbot is reporting lockdep warning in __stack_depot_save(), for
__kasan_record_aux_stack() is passing GFP_NOWAIT which will result in
calling wakeup_kcompactd() from wakeup_kswapd() from wake_all_kswapds()
 from __alloc_pages_slowpath().

Strictly speaking, __kasan_record_aux_stack() is responsible for removing
__GFP_KSWAPD_RECLAIM flag in order not to wake kswapd which in turn wakes
kcompactd. But since KASAN and KMSAN functions might be called with
arbitrary locks held, we should consider removing __GFP_KSWAPD_RECLAIM
flag from KASAN and KMSAN. And this patch goes one step further; let's
remove __GFP_KSWAPD_RECLAIM flag in the __stack_depot_save() side, based
on the following reasons.

Reason 1:

  Currently, __stack_depot_save() has "alloc_flags &= ~GFP_ZONEMASK;" line
  which is pointless because "alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);"
  line will also zero out zone modifiers. But why is __stack_depot_save()
  trying to mask gfp flags supplied by the caller?

  I guess that __stack_depot_save() tried to be as robust as possible. But
  __stack_depot_save() is a debugging function where all callers have to
  be able to survive allocation failures. Scattering low-level gfp flags
  like 0 or __GFP_HIGH should be avoided in order to replace GFP_NOWAIT or
  GFP_ATOMIC.

Reason 2:

  __stack_depot_save() from stack_depot_save() is also called by
  ref_tracker_alloc() from __netns_tracker_alloc() from
  netns_tracker_alloc() from get_net_track(), and some of get_net_track()
  users are passing GFP_ATOMIC because waking kswapd/kcompactd is safe.
  But even if we mask __GFP_KSWAPD_RECLAIM flag at __stack_depot_save(),
  it is very likely that allocations with __GFP_KSWAPD_RECLAIM flag happen
  somewhere else by the moment __stack_depot_save() is called for the next
  time.

  Therefore, not waking kswapd/kcompactd when doing allocation for
  __stack_depot_save() will be acceptable from the memory reclaim latency
  perspective.

While we are at it, let's make __stack_depot_save() accept __GFP_NORETRY
and __GFP_RETRY_MAYFAIL flags, based on the following reason.

Reason 3:

  Since DEPOT_POOL_ORDER is defined as 2, we must mask __GFP_NOFAIL flag
  in order not to complain rmqueue(). But masking __GFP_NORETRY flag and
  __GFP_RETRY_MAYFAIL flag might be overkill.

  The OOM killer might be needlessly invoked due to order-2 allocation if
  GFP_KERNEL is supplied by the caller, despite the caller might have
  passed GFP_KERNEL for doing order-0 allocation.

  Allocation for order-2 might stall if GFP_NOFS or GFP_NOIO is supplied
  by the caller, despite the caller might have passed GFP_NOFS or GFP_NOIO
  for doing order-0 allocation.

  Generally speaking, I feel that doing order-2 allocation from
  __stack_depot_save() with gfp flags supplied by the caller is an
  unexpected behavior for the callers. We might want to use only order-0
  allocation, and/or stop using gfp flags supplied by the caller...

Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>
Closes: https://syzkaller.appspot.com/bug?extid=ece2915262061d6e0ac1
Suggested-by: Alexander Potapenko <glider@google.com>
Cc: Huang, Ying <ying.huang@intel.com>
Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
---
Changes in v3:
  Huang, Ying thinks that masking __GFP_KSWAPD_RECLAIM flag in the callers
  side is preferable
  ( https://lkml.kernel.org/r/87fs7nyhs3.fsf@yhuang6-desk2.ccr.corp.intel.com ).
  But Alexander Potapenko thinks that masking __GFP_KSWAPD_RECLAIM flag
  in the callee side would be the better
  ( https://lkml.kernel.org/r/CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com ).
  I took Alexander's suggestion, and added reasoning for masking
  __GFP_KSWAPD_RECLAIM flag in the callee side.

Changes in v2:
  Mask __GFP_KSWAPD_RECLAIM flag in the callers, suggested by Huang, Ying
  ( https://lkml.kernel.org/r/87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com ).

 lib/stackdepot.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..33ebefaa7074 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -405,7 +405,10 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * contexts and I/O.
 		 */
 		alloc_flags &= ~GFP_ZONEMASK;
-		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
+		if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
+			alloc_flags &= __GFP_HIGH;
+		else
+			alloc_flags &= ~__GFP_NOFAIL;
 		alloc_flags |= __GFP_NOWARN;
 		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
 		if (page)
-- 
2.18.4


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/19d6c965-a9cf-16a5-6537-a02823d67c0a%40I-love.SAKURA.ne.jp.
