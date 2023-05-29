Return-Path: <kasan-dev+bncBCN73WFGVYJRBEHWZ6RQMGQENRV5S4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 42BE171418C
	for <lists+kasan-dev@lfdr.de>; Mon, 29 May 2023 03:08:34 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2af1fd4d30bsf16065271fa.0
        for <lists+kasan-dev@lfdr.de>; Sun, 28 May 2023 18:08:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685322513; cv=pass;
        d=google.com; s=arc-20160816;
        b=k9WWOkb3J5ytOKoO/jcawsTzZhh7N1uiD++3ZH+B6RSAe/gcwFT5k6+v993PalAuFn
         yhb7zGjeRNp91Dr8hk5i32p1WsyAlowxNdiS5gX8nJ6ZYmIltnHi9WFAG8k9KnQ8iIS4
         4RCLMpXQ9qnw3ARYxn2M2D9o27WEHaRH0dUVgWw6wl8gooq27gm8rMEyomC4hbzhMyiY
         rvjJjdpQBt9lUvIu5k594ir1j0DMVfABJRPEo3wHkNbzbuRA7ZKYCXZ0M4r9wOt8aEzM
         9q+pwOkTQza/Mc5zLnY5+7T07cXwidyXLk6u+PLDQPUhgi4QpRK4ccGj6rV7muQ2wLvo
         ywUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=E7UsDkRLuF0aOCgiI4fc813/IjY+xOW1AIIgyh06E5Q=;
        b=KG5yqHXBmFfaDtLFhMAQdXqPeexnptquX9wsh05w3aBVQILin9O/1PYqSessUiw2i2
         dLaPXLwQRpwjHZDxpXzqNWINRakhsaJWHzxSBzjmvcNdRW5VF4i80bvf5nm4PMg26eEz
         DMLqUeXfws2OrkN5vOCXVYfBJnX+4Cu3471/ZIN5RvgtUoJBEL0qgr3r1wL5/7rpZPq5
         VBHU63z09kDYlDXulEiuZNE5PZJvCkuGlIUPX+IYRlNr/dJUFy+W+loOWKEAJNV77w0H
         EuHgYNoT+bUUSg2oqwq4Th2F6ablhBJOUlPBY27ZfOMOWL4+gUaPjTZcgmFwAfvb6Ixg
         jWnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YCqXjc8b;
       spf=pass (google.com: domain of ying.huang@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685322513; x=1687914513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E7UsDkRLuF0aOCgiI4fc813/IjY+xOW1AIIgyh06E5Q=;
        b=PVi9OaBqAF/XMn7aaoH0igX1KtwBRtqZ929YuZcxIiR/nMPNVVAPs/Y+RsdvSjJlVg
         bSyD0ZTWe9GFSatupfGeJeLBpHoO/ajIGXXGRoXYV9E3cTx42GX0Jt+Lsx5cOtyIa/ZF
         Nz3721WwBRR3C86WsuY6maY2V5yJcvv45y3d86Li2bWqstfzswFrHQh5sypcn+eJ8EVk
         02jE9+xfGBSTl7Zk1SyYLHAxjYjSw/8UlLvhlrZRAdLbpKIi00Chb2Z28zNBJC6RkSNf
         Djso0WgLkhVEoYOkon/sBlz3rgTbNVvNRF+6KL8guyzTzY50t/r1qQZaWfsz1+lGHTZA
         HwQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685322513; x=1687914513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E7UsDkRLuF0aOCgiI4fc813/IjY+xOW1AIIgyh06E5Q=;
        b=e4kak7BHAUE+fd6j5yK4gsTYpYSOv84XclS4TbKJnIgx4ZQWTkU66oAPX1U3sqpZbo
         ri82osBOeDUmmpqzQLQvWGa7+nMHWXTjI6yY5SWXShdjcMgSNTZcyVDKpRpI6vIlFxS3
         s0qwzFRIsza6bXLmDUKrqoK5loMXBm/dHZXeog659HMDlT9ytwJm+utHR6w53djau9ah
         xaMdct3OQ/WIIUBMgjDPJZDcUuII4sU/NsKSv0YMyp7gEQjaBDBfYMRQ1r2eyAIq5+84
         Ggh0iZhXYSu/7J1D9i9JqwZJVmMpjWHsH8LUCbmyj63gsayc2UJRzJriUWAKYzDet2Ng
         XYCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzcA1vPMKCvBB/JgnJAG88QtWUBgtfyX/uU+qDYZUDsxD1FAvtB
	nLaYGLFwyq07sGWd+OCckew=
X-Google-Smtp-Source: ACHHUZ6YMk4Bc8PJp5X/bq9IuYZewx98++RdYHVn0zvt5rCewobvNjMphPRvYXoJGO3KjgQoH6zMnQ==
X-Received: by 2002:a05:651c:1987:b0:2a7:75b2:ae4 with SMTP id bx7-20020a05651c198700b002a775b20ae4mr1895944ljb.2.1685322512759;
        Sun, 28 May 2023 18:08:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a05:b0:2af:3051:12ed with SMTP id
 k5-20020a05651c0a0500b002af305112edls132359ljq.1.-pod-prod-01-eu; Sun, 28 May
 2023 18:08:31 -0700 (PDT)
X-Received: by 2002:a2e:b162:0:b0:2af:1dd5:b068 with SMTP id a2-20020a2eb162000000b002af1dd5b068mr3901129ljm.48.1685322511085;
        Sun, 28 May 2023 18:08:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685322511; cv=none;
        d=google.com; s=arc-20160816;
        b=nAYlaK0C8mRkqb8B6bzX+1lzWpCvPcvyyx0c+L/akDVoCdT5Kr8UgQ7CSr5NUB/0Rk
         E5Ce6M1rTjMLu9eFV0IEIyzTQh4up093r9//qJeuAip37+xSTFBk9HQqID5vfkjp9Q2e
         eHq0mqPkZ/95cXVtHXFwLMndky2JbkN78liEUu/Wc2IegA7qGwDhmWqo5jmZw+fTHQQ5
         ZoZlwH0LwlSGPHogjC0nuLmfZByiZwzvahlAvBprFEQlN1UnWgK1NTMiNxBwtfF5RtLF
         ZJC9ABoPHXTPX1ol0ellA8rRLfgboUJyzs29tIkNXgBvcOStY+lAcyH0GOuP3wYV3g+4
         pWKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=6IE6kmaNP+13cdk3lZRKBoXCBljbT9SD9hfWoGRN4PE=;
        b=W97ZeRRGMYUAnhDGRIpIVq4F5IkMasesOFB1uCcX2d3muN9i25rVhz7tqft3c2ADx9
         jV6WNvxe3i94JhFlMzOjCjQKJhNBeFbF5lg627sguYyKMGFGzdUuy94XV7CcPlbYIA8L
         rhrKc5W+xhoHYip++LO3E4jATAtP5Q0EzJvKbNVw2g6O/rp5FCIwVsHsdFM82086gFfg
         c3ZO77YpeQ3I5g+AcyV4Lx67ZbNQteioXusmn18wkcoK9fJ3yI6rzAQKxN+9GJPBqqZA
         pp4esoXGDxf/+QEyAA3/6lwkL7GFRGGHBy5Lcnmez0zudFd97+ateULP7Xuk5xyIlq1G
         iIOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YCqXjc8b;
       spf=pass (google.com: domain of ying.huang@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id d2-20020a05651c088200b002ac75541fd4si852857ljq.0.2023.05.28.18.08.30
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 28 May 2023 18:08:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6600,9927,10724"; a="356963801"
X-IronPort-AV: E=Sophos;i="6.00,200,1681196400"; 
   d="scan'208";a="356963801"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 May 2023 18:08:28 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10724"; a="952532962"
X-IronPort-AV: E=Sophos;i="6.00,200,1681196400"; 
   d="scan'208";a="952532962"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by fmsmga006-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 May 2023 18:08:22 -0700
From: "Huang, Ying" <ying.huang@intel.com>
To: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
  <syzkaller-bugs@googlegroups.com>,  Mel Gorman
 <mgorman@techsingularity.net>,  Vlastimil Babka <vbabka@suse.cz>,  Andrew
 Morton <akpm@linux-foundation.org>,  Alexander Potapenko
 <glider@google.com>,  Andrey Konovalov <andreyknvl@gmail.com>,  Dmitry
 Vyukov <dvyukov@google.com>,  Andrey Ryabinin <ryabinin.a.a@gmail.com>,
  "Vincenzo Frascino" <vincenzo.frascino@arm.com>,  Marco Elver
 <elver@google.com>,  kasan-dev <kasan-dev@googlegroups.com>,  linux-mm
 <linux-mm@kvack.org>
Subject: Re: [PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from
 kasan/kmsan
References: <000000000000cef3a005fc1bcc80@google.com>
	<ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
	<ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
	<656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
Date: Mon, 29 May 2023 09:07:14 +0800
In-Reply-To: <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
	(Tetsuo Handa's message of "Sun, 28 May 2023 00:25:31 +0900")
Message-ID: <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=YCqXjc8b;       spf=pass
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

> syzbot is reporting lockdep warning in __stack_depot_save(), for
> the caller of __stack_depot_save() (i.e. __kasan_record_aux_stack() in
> this report) is responsible for masking __GFP_KSWAPD_RECLAIM flag in
> order not to wake kswapd which in turn wakes kcompactd.
>
> Since kasan/kmsan functions might be called with arbitrary locks held,
> mask __GFP_KSWAPD_RECLAIM flag from all GFP_NOWAIT/GFP_ATOMIC allocations
> in kasan/kmsan.
>
> Note that kmsan_save_stack_with_flags() is changed to mask both
> __GFP_DIRECT_RECLAIM flag and __GFP_KSWAPD_RECLAIM flag, for
> wakeup_kswapd() from wake_all_kswapds() from __alloc_pages_slowpath()
> calls wakeup_kcompactd() if __GFP_KSWAPD_RECLAIM flag is set and
> __GFP_DIRECT_RECLAIM flag is not set.
>
> Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>
> Closes: https://syzkaller.appspot.com/bug?extid=ece2915262061d6e0ac1
> Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>

This looks good to me.  Thanks!

Reviewed-by: "Huang, Ying" <ying.huang@intel.com>

> ---
>  mm/kasan/generic.c         | 4 ++--
>  mm/kasan/tags.c            | 2 +-
>  mm/kmsan/core.c            | 6 +++---
>  mm/kmsan/instrumentation.c | 2 +-
>  4 files changed, 7 insertions(+), 7 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index e5eef670735e..2c94f4943240 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -488,7 +488,7 @@ static void __kasan_record_aux_stack(void *addr, bool can_alloc)
>  		return;
>  
>  	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, can_alloc);
> +	alloc_meta->aux_stack[0] = kasan_save_stack(0, can_alloc);
>  }
>  
>  void kasan_record_aux_stack(void *addr)
> @@ -518,7 +518,7 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  	if (!free_meta)
>  		return;
>  
> -	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> +	kasan_set_track(&free_meta->free_track, 0);
>  	/* The object was freed and has free track set. */
>  	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
>  }
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 67a222586846..7dcfe341d48e 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -140,5 +140,5 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  
>  void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  {
> -	save_stack_info(cache, object, GFP_NOWAIT, true);
> +	save_stack_info(cache, object, 0, true);
>  }
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index 7d1e4aa30bae..3adb4c1d3b19 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -74,7 +74,7 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
>  	nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
>  
>  	/* Don't sleep. */
> -	flags &= ~__GFP_DIRECT_RECLAIM;
> +	flags &= ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
>  
>  	handle = __stack_depot_save(entries, nr_entries, flags, true);
>  	return stack_depot_set_extra_bits(handle, extra);
> @@ -245,7 +245,7 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
>  	extra_bits = kmsan_extra_bits(depth, uaf);
>  
>  	entries[0] = KMSAN_CHAIN_MAGIC_ORIGIN;
> -	entries[1] = kmsan_save_stack_with_flags(GFP_ATOMIC, 0);
> +	entries[1] = kmsan_save_stack_with_flags(__GFP_HIGH, 0);
>  	entries[2] = id;
>  	/*
>  	 * @entries is a local var in non-instrumented code, so KMSAN does not
> @@ -253,7 +253,7 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
>  	 * positives when __stack_depot_save() passes it to instrumented code.
>  	 */
>  	kmsan_internal_unpoison_memory(entries, sizeof(entries), false);
> -	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC,
> +	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH,
>  				    true);
>  	return stack_depot_set_extra_bits(handle, extra_bits);
>  }
> diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
> index cf12e9616b24..cc3907a9c33a 100644
> --- a/mm/kmsan/instrumentation.c
> +++ b/mm/kmsan/instrumentation.c
> @@ -282,7 +282,7 @@ void __msan_poison_alloca(void *address, uintptr_t size, char *descr)
>  
>  	/* stack_depot_save() may allocate memory. */
>  	kmsan_enter_runtime();
> -	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC);
> +	handle = stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH);
>  	kmsan_leave_runtime();
>  
>  	kmsan_internal_set_shadow_origin(address, size, -1, handle,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87353gx7wd.fsf%40yhuang6-desk2.ccr.corp.intel.com.
