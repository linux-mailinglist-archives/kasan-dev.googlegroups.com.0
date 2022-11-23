Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBBGZ66NQMGQERDWTAOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7CFF6357EE
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 10:48:53 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id q2-20020ac24a62000000b004b4ec7b83f3sf330937lfp.19
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 01:48:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669196933; cv=pass;
        d=google.com; s=arc-20160816;
        b=ivj+/aTlvR4GaXafo/N01lTCJK12HOs+rfaSjzo016//kKJ8DSE+XgmEy5bY5gzu0Q
         CNgaWShArm0elhXhAXhF6V+Bn0SxUN1+/7vHL0zLddgkopHoCcKsUDJfHZVE+xURTbCZ
         O3INBajYlLu92zoC9vhsThulO2yE3rXUi+wsX5mFR3IaMXpA2T8E9nSUjH04kfmjX7fx
         5G5yFxp/TaSgA9zCKHTU71gnVzaok98upXivGo97+vAzw3kr1QEv+9Q2YvpIYgZ+MQy5
         2grazIE8D4PxvGRVhd+6KOx+1pWB/eT2B7YCRGzSTB9MdAYtuoJY8i5DZSqpMOf8hsnu
         +X/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=BOzPVMLLqhj84nMWtaataHWNB48A8dmOKpHVjjNbEQY=;
        b=JxEyOGigvJc2BF9jywtxwI51mkUvi8KLbs4uKQoBs6R7gCtFTCzMHLB4Bvk0YRAuTq
         wRo6q6q8geLOtzH4xsvtWZ/HWhwo6oWLoFBRiq6imMVxlMONl3pa6saxZ6T5FWNYHkKM
         h8ygLIpZb1SI6CiF7gxyBWxe5rDv8hFboew2kKDKuKqWGw7FEuzlu+2TZCcuJwnAMhEB
         BD6IQgNvBVJhOrHtiLaPkXrDmDbKm/g9wjSd+lV2dulG1iZmK6p3hyr+eP7YFycXS2Nf
         UqL/Go6m/B/ySKHeVOZq256+zKmwm1529f7n+B3T85J4DyIi8IjxkOfvIn9ZtueG8A+N
         NI0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YhJf3I9D;
       dkim=neutral (no key) header.i=@suse.cz header.b=whDE5Rto;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BOzPVMLLqhj84nMWtaataHWNB48A8dmOKpHVjjNbEQY=;
        b=PvovBxKW3gE9YSkECUJdmH+ErCLeRAmSdTupCIW89C+xq9AtNnJzJzRXC3sQi8vs9s
         ENPkLdtHzpBushWJSbbWLakjCrF055FTOjSZfQjo9Y1htGTa8LSER4zPa9eHGeaUUAPz
         HGwZHTx4bnyAaSc285sp+Byy/FRNPfumetzjUQCXCWObs2X+eVBmy/abBCMVrqKcfgpZ
         hoXU9gGbqXAFbDqRdSf0stM/9N8T6TnmWb1SzepH76QmtSNvC4lF0ob7MB4SKP43XqHh
         N4332/gLVXkfL5QLPANAtXd1gUC+/3al2VM1NHuLDaLOcA+ZQbt9M5uUwh9t01dIMEjW
         kRXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BOzPVMLLqhj84nMWtaataHWNB48A8dmOKpHVjjNbEQY=;
        b=A4vnEt0JwYxnl5ggZzLyIA79zUtLoY/17ApY3YRIqP/UlO2mn+tI7VT1ova2afRNJm
         pzCwqlVabo3DRdgXJtxV50v2x8qRpqC5Av769MvOf9u3JD7llBcpGCESep1fMmZuOd/m
         /ER5Qt42Vj0TUZwcdRVQgq+NXDPQrkepHjL/MvQTpkRs56kBhGusirsRRB3uuIDDss3s
         UCeAY2k07JxuA5XkL47C4ZfnAGVlE6qaVGwVqVu5lfVpD68fVihyczDuEgj1O4SAncev
         PTVBDw7RoWpSBKLTfNny1PD6vP/46//wLSF2oLZMFqWhDOxziGJQTE6T4+8aha+SOa0I
         ShLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pl5MNXQG8H0YRKVV/E2UqkXEbQoZX/VgvkREvJi+I/wDPRbqRBe
	/IMtn7gFGUh2+A3e34yfp8E=
X-Google-Smtp-Source: AA0mqf75N5ynKw4BLM7F+LCOkjpyF8445pKU5he+G6AsPanfmGgd609HgzZ+dwct1BQTBGm+GvTouQ==
X-Received: by 2002:ac2:5e37:0:b0:4a2:4d72:6cc2 with SMTP id o23-20020ac25e37000000b004a24d726cc2mr10399795lfg.511.1669196933022;
        Wed, 23 Nov 2022 01:48:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:12c6:b0:26f:8b88:ccbf with SMTP id
 6-20020a05651c12c600b0026f8b88ccbfls2873369lje.1.-pod-prod-gmail; Wed, 23 Nov
 2022 01:48:51 -0800 (PST)
X-Received: by 2002:a05:651c:883:b0:277:34b:1bfe with SMTP id d3-20020a05651c088300b00277034b1bfemr8973722ljq.8.1669196931501;
        Wed, 23 Nov 2022 01:48:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669196931; cv=none;
        d=google.com; s=arc-20160816;
        b=JTUGU86UCSJpBjcTSSRW2sn5VwROVdGwKJKybXYInj8tZezGaHW+B6uyXh4i8AW8do
         38zVtM1CB95idk4HMhoIWPpI5NMOhWrvf0oW1+ot44pPPvSKY7OJW9JjFTAsKnrDoFB6
         3w61n7QsQnOEGqvEO2H2wo5x65XctvMgtOCbV32IlDy4HBQ8fVpQJUVRkNlJtAt+kLh3
         XrJNLt9YTJ2QaJhBfiCvIjwugviAH88/93kJZWBMYk7tYBMSSMbujuefexohn69zNsTk
         L6B4wT1LS7rIrupYB0GqcSyrpkBUEgwrdJSbX2Qef1Kg6s67i2wihtOA/EOHXhKal//q
         FENQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=HXnIT/Zuv/T9a6KrJB+Xh6C3fIWPtdkO8jUxlxm68QQ=;
        b=ataYwaz6edmJRxh7JDvxloDn/YoHCPlb1uDR63wiJ0VhrrVMn3SB+YCHpsgCF868Wg
         L6FpGjPiL3gL7UL0Gwm48dlQ96cKeEZLKm0iptNfrhyD8GqRVBVMsHgfIKn3DAQ5Jsdz
         +/7C8ZOBHHC6G7CLz01o+NQOXGJa1HxYBwE4dE1omK5O68aOPHO1e2TrbcniJoBX7DCE
         TviWCJcBgwhYUdwDZ+ATBeqEZAfaPB4fV8tLWvGxvQBDQOHutxml4rofJwdAjhDsRFGz
         clnAYhjl/aReQIFzrtL/ypqk7QIUfykR2XZAwd2ND2xy05bxrgXe0t3fjSbxT1j9W0pU
         +Uzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YhJf3I9D;
       dkim=neutral (no key) header.i=@suse.cz header.b=whDE5Rto;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id k8-20020a2ea268000000b0027737e93a12si697615ljm.0.2022.11.23.01.48.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Nov 2022 01:48:51 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C7DDD21D31;
	Wed, 23 Nov 2022 09:48:50 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 867AA13AE7;
	Wed, 23 Nov 2022 09:48:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id yN/6H4LsfWOVGQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 23 Nov 2022 09:48:50 +0000
Message-ID: <88abafb9-a961-a217-a95c-744258498722@suse.cz>
Date: Wed, 23 Nov 2022 10:48:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: [PATCH v7 0/3] mm/slub: extend redzone check for kmalloc objects
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Kees Cook <keescook@chromium.org>,
 "Hansen, Dave" <dave.hansen@intel.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <f9da0749-c109-1251-8489-de3cfb50ab24@suse.cz> <Y24H998aujvYXjkV@feng-clx>
 <Y3sc1G6WEKte4Awd@feng-clx>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Y3sc1G6WEKte4Awd@feng-clx>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YhJf3I9D;       dkim=neutral
 (no key) header.i=@suse.cz header.b=whDE5Rto;       spf=softfail (google.com:
 domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/21/22 07:38, Feng Tang wrote:
> On Fri, Nov 11, 2022 at 04:29:43PM +0800, Tang, Feng wrote:
>> On Fri, Nov 11, 2022 at 04:16:32PM +0800, Vlastimil Babka wrote:
>> > > 	for (shift = 3; shift <= 12; shift++) {
>> > > 		size = 1 << shift;
>> > > 		buf = kmalloc(size + 4, GFP_KERNEL);
>> > > 		/* We have 96, 196 kmalloc size, which is not power of 2 */
>> > > 		if (size == 64 || size == 128)
>> > > 			oob_size = 16;
>> > > 		else
>> > > 			oob_size = size - 4;
>> > > 		memset(buf + size + 4, 0xee, oob_size);
>> > > 		kfree(buf);
>> > > 	}
>> > 
>> > Sounds like a new slub_kunit test would be useful? :) doesn't need to be
>> > that exhaustive wrt all sizes, we could just pick one and check that a write
>> > beyond requested kmalloc size is detected?
>> 
>> Just git-grepped out slub_kunit.c :), will try to add a case to it.
>> I'll also check if the case will also be caught by other sanitizer
>> tools like kasan/kfence etc.
> 
> Just checked, kasan has already has API to disable kasan check
> temporarily, and I did see sometime kfence can chime in (4 out of 178
> runs) so we need skip kfenced address.
> 
> Here is the draft patch, thanks!
> 
> From 45bf8d0072e532f43063dbda44c6bb3adcc388b6 Mon Sep 17 00:00:00 2001
> From: Feng Tang <feng.tang@intel.com>
> Date: Mon, 21 Nov 2022 13:17:11 +0800
> Subject: [PATCH] mm/slub, kunit: Add a case for kmalloc redzone functionality
> 
> kmalloc redzone check for slub has been merged, and it's better to add
> a kunit case for it, which is inspired by a real-world case as described
> in commit 120ee599b5bf ("staging: octeon-usb: prevent memory corruption"):
> 
> "
>   octeon-hcd will crash the kernel when SLOB is used. This usually happens
>   after the 18-byte control transfer when a device descriptor is read.
>   The DMA engine is always transfering full 32-bit words and if the
>   transfer is shorter, some random garbage appears after the buffer.
>   The problem is not visible with SLUB since it rounds up the allocations
>   to word boundary, and the extra bytes will go undetected.
> "
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  lib/slub_kunit.c | 42 ++++++++++++++++++++++++++++++++++++++++++
>  mm/slab.h        | 15 +++++++++++++++
>  mm/slub.c        |  4 ++--
>  3 files changed, 59 insertions(+), 2 deletions(-)
> 
> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
> index 7a0564d7cb7a..0653eed19bff 100644
> --- a/lib/slub_kunit.c
> +++ b/lib/slub_kunit.c
> @@ -120,6 +120,47 @@ static void test_clobber_redzone_free(struct kunit *test)
>  	kmem_cache_destroy(s);
>  }
>  
> +
> +/*
> + * This case is simulating a real world case, that a device driver
> + * requests 18 bytes buffer, but the device HW has obligation to
> + * operate on 32 bits granularity, so it may actually read or write
> + * 20 bytes to the buffer, and possibly pollute 2 extra bytes after
> + * the requested space.
> + */
> +static void test_kmalloc_redzone_access(struct kunit *test)
> +{
> +	u8 *p;
> +
> +	if (!is_slub_debug_flags_enabled(SLAB_STORE_USER | SLAB_RED_ZONE))
> +		kunit_skip(test, "Test required SLAB_STORE_USER & SLAB_RED_ZONE flags on");

Hrmm, this is not great. I didn't realize that we're testing kmalloc()
specific code, so we can't simply create test-specific caches as in the
other kunit tests.
What if we did create a fake kmalloc cache with the necessary flags and used
it with kmalloc_trace() instead of kmalloc()? We would be bypassing the
kmalloc() inline layer so theoretically orig_size handling bugs could be
introduced there that the test wouldn't catch, but I think that's rather
unlikely. Importantly we would still be stressing the orig_size saving and
the adjusted redzone check using this info.

> +	p = kmalloc(18, GFP_KERNEL);
> +
> +#ifdef CONFIG_KFENCE
> +	{
> +		int max_retry = 10;
> +
> +		while (is_kfence_address(p) && max_retry--) {
> +			kfree(p);
> +			p = kmalloc(18, GFP_KERNEL);
> +		}
> +
> +		if (!max_retry)
> +			kunit_skip(test, "Fail to get non-kfenced memory");
> +	}
> +#endif

With the test-specific cache we could also pass SLAB_SKIP_KFENCE there to
handle this. BTW, don't all slub kunit test need to do that in fact?

Thanks,
Vlastimil

> +
> +	kasan_disable_current();
> +
> +	p[18] = 0xab;
> +	p[19] = 0xab;
> +	kfree(p);
> +
> +	KUNIT_EXPECT_EQ(test, 3, slab_errors);
> +	kasan_enable_current();
> +}
> +
>  static int test_init(struct kunit *test)
>  {
>  	slab_errors = 0;
> @@ -139,6 +180,7 @@ static struct kunit_case test_cases[] = {
>  #endif
>  
>  	KUNIT_CASE(test_clobber_redzone_free),
> +	KUNIT_CASE(test_kmalloc_redzone_access),
>  	{}
>  };
>  
> diff --git a/mm/slab.h b/mm/slab.h
> index e3b3231af742..72f7a85e01ab 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -413,6 +413,17 @@ static inline bool __slub_debug_enabled(void)
>  {
>  	return static_branch_unlikely(&slub_debug_enabled);
>  }
> +
> +extern slab_flags_t slub_debug;
> +
> +/*
> + * This should only be used in post-boot time, after 'slub_debug'
> + * gets initialized.
> + */
> +static inline bool is_slub_debug_flags_enabled(slab_flags_t flags)
> +{
> +	return (slub_debug & flags) == flags;
> +}
>  #else
>  static inline void print_tracking(struct kmem_cache *s, void *object)
>  {
> @@ -421,6 +432,10 @@ static inline bool __slub_debug_enabled(void)
>  {
>  	return false;
>  }
> +static inline bool is_slub_debug_flags_enabled(slab_flags_t flags)
> +{
> +	return false;
> +}
>  #endif
>  
>  /*
> diff --git a/mm/slub.c b/mm/slub.c
> index a24b71041b26..6ef72b8f6291 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -638,9 +638,9 @@ static inline void *restore_red_left(struct kmem_cache *s, void *p)
>   * Debug settings:
>   */
>  #if defined(CONFIG_SLUB_DEBUG_ON)
> -static slab_flags_t slub_debug = DEBUG_DEFAULT_FLAGS;
> +slab_flags_t slub_debug = DEBUG_DEFAULT_FLAGS;
>  #else
> -static slab_flags_t slub_debug;
> +slab_flags_t slub_debug;
>  #endif
>  
>  static char *slub_debug_string;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/88abafb9-a961-a217-a95c-744258498722%40suse.cz.
