Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBCHFUCMQMGQE4BAWSXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F4715BC510
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 11:12:41 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id o7-20020adfba07000000b00228663f217fsf5652038wrg.20
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 02:12:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663578761; cv=pass;
        d=google.com; s=arc-20160816;
        b=LQfPNTWuOE/5w0dVysa3AJpM+pgNnK4QttAwOmBMhiiciGJQ+9ibQsp/7TRdhT85M5
         nVldwFm5m0NYsNVnvup7EysTeBveLWsnTWkeVvZTD3v3y0N2LQZB5RpmqjZTGWIFA697
         G63EN9xh5Y1/PHRNy8aKgPWy3eb64Zgbpq5PS91AqnMAfzxGKazIhY8/8cOfhHJ/G/4b
         z4dXjDBEwj4XF7cfSFMDhztKZbf/6BKhpsKp1dtUs6+fx4yf1c3a90JFFQd2kqjkoERA
         tcMsq8F9S+4OKwIAu2gqhMrg3oqRC9tvhHe9k1r/kOzOc43jXzqzHjkrIPGG0AuabZs7
         +IOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=D2eF3MvA/WY7dA2i7VTnK2D6MRTmrA7qKg0J9cBxzwI=;
        b=LvsG4SNDcBoL0HD7radBNyHevqf6q6QVYpnnKuq+hkm7nFM2/erjGXkPIljIMLP2IF
         maSTR5rMv68Sxe29z/TnrF+MAnpsr39uKwF1IdZ8Q5P/3OduoRd4cVV3ic5fVulymYQY
         sigtlKvsMcRJDEtc2Ho49up2Kj8alhlTdouTviI5NPEmanOxRZGoJV/g0olQWedUteeF
         QPLEd9wfKx2h/778nTRWAVUFkcyvA89coMDjIrSoRm3JMVv8un0RzkFQzEl2P8szUa5D
         qchwTdQHOU8S+T7ZowB85OkCXS1xHWkPUKNPzxhYC0DGCUbbWVXAuai6sVE6xq/4JPmr
         J79w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pbyvXzk6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rWSaOkuP;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=D2eF3MvA/WY7dA2i7VTnK2D6MRTmrA7qKg0J9cBxzwI=;
        b=KbMiHSOtUqZFZeSDeAfbxDFVu+e4CbAtSuTGAoHMdMf98oS3un4fGlIxheCuwke1S5
         W/Mzw3o8Bm5QVI7Xx1+ssWAG1i9VBNkz+tkFA30v5gfi3W5LrUF25+lc5rx5mFAbbvOM
         SjbAz34N2vE1cJ3vmw1f+itzlBXYTyoORgBTvs6O4GEuuzYumcsLYsX2lAAYtl+rwV7X
         Xn40UWtHpWUHT4hQYnaT0U2C0DhfzrmcPeT1A/QTTwmpu4QaWOXnD52hK3mcZOcQOOdQ
         5Gnk4/TWhqoyUxAWhwLlRt+paYoZZJ2yk7smp77dyg3reo5apes5ydtwwghMpFqtM+e4
         I5IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=D2eF3MvA/WY7dA2i7VTnK2D6MRTmrA7qKg0J9cBxzwI=;
        b=3xK5u86Fc8lSpAj5BlcMHYB52flzr3fdocXdTnt8y428I3ltw5OUvR7b0PGB4IEmAG
         EmYmpRhAqCJ1PlpBjCZD/VzpS9wVYVnpuhUEOjgkihpldxcxmEbUn59Z5wnc55UfuaWB
         SCreysf3okIUXgO7VuQ0wa84xOC6OniUgT1YyUiVyY1nNYkDeDv0NwaMknqH8lG3TehY
         rq8+MCnYzNSlMSYFE6LNUPSlLsUR4/8uvBSB8YrANF5zLKP3PrVohDfBZsNXOwp/sWIs
         JVt93jvh/i8cIljY4BhHJwtRyBZ9CdRQfcx61JqHe+vnwJ1vAhV9dD7E2SWthnHb+X6N
         sQtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3oe5bdLWHYygXhunpLkgoSWSr1QbXqgOp0dLsGY7GL3YUho66Q
	6FHwx7pCCnVLrbEXdLI9uBQ=
X-Google-Smtp-Source: AMsMyM6giRTv7K+96O6nH/zNDZc8dfLm0vuOrch3lytzWJqz9z1m39EnPFHRjEw7BgqIXF74wb6OMw==
X-Received: by 2002:adf:d4d2:0:b0:22a:d0c1:185a with SMTP id w18-20020adfd4d2000000b0022ad0c1185amr10369342wrk.16.1663578760768;
        Mon, 19 Sep 2022 02:12:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2610784wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 02:12:39 -0700 (PDT)
X-Received: by 2002:a5d:5611:0:b0:228:e1d2:81d with SMTP id l17-20020a5d5611000000b00228e1d2081dmr10084866wrv.210.1663578759558;
        Mon, 19 Sep 2022 02:12:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663578759; cv=none;
        d=google.com; s=arc-20160816;
        b=cHxaZWvVG1xmb8WdKWqv7BjKZQQXrOJRLWFvHMhetWZlLvxfmOZmA1FJelofCCylum
         YoRZBof5RPsK1eSSl9IoWndB07Mh7HBpLTkPti6kSpgEqoXT63zPVWITkpanvFL3Cm3y
         MAezKBIRCbk8wqm/Jcg6b4flI4CShOJGl5q7KwkNFuuM7UXgeiXpgsJuTJStRPsHCowy
         94Cu54Io2sOY597q7sH5XhXWs10jPorjBBd8K2yuW+7SphCsSZ+8did4wI00MF1VqbLz
         c6wX+a2INdWakI4Gxmv1MumEe3RGaaxTOJsK0DaybGCcNOhAVC/4X0HUybKwySbdH3P8
         KkVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=PpwhdWQ/DibiLYGXocoBIeu2gKOgVn+LTBrujpjkNLI=;
        b=ZNP7zH3nbO4Aw7LfUfRLl3isPehkIZkqJN1PEuMA7/695WoC654mXsAHUypp4OCMtS
         BitbSlTL7pBXjqurKpYDtSb0dS6j1diVyLHYtrYzzaGeZa5tQIpyPx6W5RFg1qa5yq6v
         z65HiO7efGXmc0Po/gFlcC2qYnC2GWH6DRTM8sXpmtzTGTrvaPK0Yy4VOJ2rXah+pCa1
         Fef1gcRenJFeVe0OOXEEHAXNjwm30jSxIootijTfzrKzePOj/6wMBRGHwtGSKPymbZ4m
         8u0sZrLbuNZoxFmnGxeQ33DZIP6z+YQkxZFxld0z83rcFO0/ap2cYTdTN4wtQIn9f/zF
         LCIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pbyvXzk6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rWSaOkuP;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id az7-20020a05600c600700b003a54f1563c9si219583wmb.0.2022.09.19.02.12.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 02:12:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2DDCC1F8DB;
	Mon, 19 Sep 2022 09:12:39 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 067A113A96;
	Mon, 19 Sep 2022 09:12:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id FYYPAYcyKGO/TgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 19 Sep 2022 09:12:39 +0000
Message-ID: <e38cc728-f5e5-86d1-d6a1-c3e99cc02239@suse.cz>
Date: Mon, 19 Sep 2022 11:12:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.1
Subject: Re: [PATCH] mm/slab_common: fix possiable double free of kmem_cache
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>, Waiman Long <longman@redhat.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20220919031241.1358001-1-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20220919031241.1358001-1-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=pbyvXzk6;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rWSaOkuP;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/19/22 05:12, Feng Tang wrote:
> When doing slub_debug test, kfence's 'test_memcache_typesafe_by_rcu'
> kunit test case cause a use-after-free error:
> 
>   BUG: KASAN: use-after-free in kobject_del+0x14/0x30
>   Read of size 8 at addr ffff888007679090 by task kunit_try_catch/261
> 
>   CPU: 1 PID: 261 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc5-next-20220916 #17
>   Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
>   Call Trace:
>    <TASK>
>    dump_stack_lvl+0x34/0x48
>    print_address_description.constprop.0+0x87/0x2a5
>    print_report+0x103/0x1ed
>    kasan_report+0xb7/0x140
>    kobject_del+0x14/0x30
>    kmem_cache_destroy+0x130/0x170
>    test_exit+0x1a/0x30
>    kunit_try_run_case+0xad/0xc0
>    kunit_generic_run_threadfn_adapter+0x26/0x50
>    kthread+0x17b/0x1b0
>    </TASK>
> 
> The cause is inside kmem_cache_destroy():
> 
> kmem_cache_destroy
>     acquire lock/mutex
>     shutdown_cache
>         schedule_work(kmem_cache_release) (if RCU flag set)
>     release lock/mutex
>     kmem_cache_release (if RCU flag set)

				      ^ not set

I've fixed that up.

> 
> in some certain timing, the scheduled work could be run before
> the next RCU flag checking which will get a wrong state.
> 
> Fix it by caching the RCU flag inside protected area, just like 'refcnt'
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>

Thanks!

> ---
> 
> note:
> 
> The error only happens on linux-next tree, and not in Linus' tree,
> which already has Waiman's commit:
> 0495e337b703 ("mm/slab_common: Deleting kobject in kmem_cache_destroy()
> without holding slab_mutex/cpu_hotplug_lock")

Actually that commit is already in Linus' rc5 too, so I will send your fix
this week too. Added a Fixes: 0495e337b703 (...) too.

>  mm/slab_common.c | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 07b948288f84..ccc02573588f 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -475,6 +475,7 @@ void slab_kmem_cache_release(struct kmem_cache *s)
>  void kmem_cache_destroy(struct kmem_cache *s)
>  {
>  	int refcnt;
> +	bool rcu_set;
>  
>  	if (unlikely(!s) || !kasan_check_byte(s))
>  		return;
> @@ -482,6 +483,8 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  	cpus_read_lock();
>  	mutex_lock(&slab_mutex);
>  
> +	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
> +
>  	refcnt = --s->refcount;
>  	if (refcnt)
>  		goto out_unlock;
> @@ -492,7 +495,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  out_unlock:
>  	mutex_unlock(&slab_mutex);
>  	cpus_read_unlock();
> -	if (!refcnt && !(s->flags & SLAB_TYPESAFE_BY_RCU))
> +	if (!refcnt && !rcu_set)
>  		kmem_cache_release(s);
>  }
>  EXPORT_SYMBOL(kmem_cache_destroy);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e38cc728-f5e5-86d1-d6a1-c3e99cc02239%40suse.cz.
