Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN6T335AKGQEP7IYNLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ABA92613EB
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:56:40 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id w27sf6863252ejb.12
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:56:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599580600; cv=pass;
        d=google.com; s=arc-20160816;
        b=0DXj32jdpmL848/DwYLw4znXVEF0nQlFJpK8jAseYugw7xCjWDOU8IxNXkX2Xjkw4g
         sQchjZlqiKHruz7+rY6zNKAj5Sosuv6OBuQitbp5aSIcQqV7HEFg06ih6XmUcxf6rfaU
         vLikL2jhpCVAaVZtWPDMaySeUpvkYuqVZf2TMSARZjkqKTZo6f2gNA7jJgESyvwqNGHp
         229kmV1VahnU9wEJXweKbYUvtOFhW0n3lAqyC5xTOpemYyx11IhWNdWyzUIjGztnHUqc
         FAtCqZIHDH1IJZ49W5WDAM4C6GKnH1Qg5KU3qeIau2dVnlmBjRLvYD6cpcX/L0CqPkzi
         OCIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=5aWF5HAmz7vZojdrbsOgy02DoWvhPth9SM91zteG7d0=;
        b=KFiARlTiIfS+PQIQIDiG057Q5mIfaMwxfOH3bqTUQI61trC9VhesupBJqRJkoGtF5E
         nuKWO2x9EXqVc4xH9BW/4RI1NYCFWG6qEhl3OSrhgiDVlYYCX0RQS62/2DM22vueeXoK
         rpiWOt6zQegTFvXEdRBbv3BLs6ngq0hH6dz7YxDmQcULBTJkWr8RSUwX3TQFWAXT7kVq
         uSxR5zKLQkLTV2HY8LV3n1lZJjodAPOxsgqO1NVybX38KKcIwDbEy89Q1VJf8AZ6yxlk
         J8NFIkQqSohqoiLUTC1+ZCIIBVNNO/Z5BrpZwQnDerr1yWYCb/a00DwJvHVDi3z4TO82
         upJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wETpD6sa;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=5aWF5HAmz7vZojdrbsOgy02DoWvhPth9SM91zteG7d0=;
        b=iUkuMq+2akCLzQ4rPB32deEgcWYPM1n8Tuq+0wn2crVMpDjhyPaHZvjZJhwS+T/AiZ
         cWlB/1OljfSZpTjErQMroszWzCoh7pOz0ewakB4Du9MVambcN0ADePk/zAdRin29U6UD
         pur1GwDoDciBob3P723xoZQUXgRyyRiBNODohjeJo6z57AF3Cgg53/c/GARwmNI73jlp
         2+vcWEXNV4STB/tFBvSworkFUv8onbNFS8I9Y1L3/6B3v7Xd52sI3sHysb3OO3tHt3x+
         7aTiKdPPOr9M7n4XHBKdisYOvBYCw2r9mq4GYYwm2Bek6Y/Ac60Xts02OGoetT81kfcc
         kMGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5aWF5HAmz7vZojdrbsOgy02DoWvhPth9SM91zteG7d0=;
        b=UyJmugLlcvXjfYcV4NWrgWk4tfYkbsaibsuEZXfwYxEJ2P3Nd65U0LSgCIN5myd7KJ
         uW4iC4eE+A48sWh4dM0xYqBUo7iTV6hO1TCZDBcJqyN1YDSyD+HboMc/t9tEozoaHBTA
         wfddC8gIwcHJ98zvo41Okhm5tXnp+Mqpsp9ojuhugop3HObvJd+Ox/4FGj6iudflgrEu
         JCSjPwLToK8yBLfplu6iiHOzV6WARgLBfSs43sYMwM3scW88vRu1qgf8ZpI1cU8UiirF
         eDhZ1InyN8oVUpyDAHajFqxY+0+lMlbvrd3GcU58k7e+0WhgGohNsO50n9pz+At2eopn
         nC4g==
X-Gm-Message-State: AOAM532m5n2ZPph9mvLXCaveXOSRNzmdsIOt5mCgxvO1hWhPxjzq/E7y
	lJ3NQm7mDPibWrrg6idQtXY=
X-Google-Smtp-Source: ABdhPJwQ23DqtzA+RZLRZja27ndG8Oid9s96OVTodMznyLZw98xZ9vC9qhsN3b8iKTlPPcHkf3/bSw==
X-Received: by 2002:a17:906:4a53:: with SMTP id a19mr9295568ejv.56.1599580599870;
        Tue, 08 Sep 2020 08:56:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c545:: with SMTP id s5ls3988753edr.3.gmail; Tue, 08 Sep
 2020 08:56:38 -0700 (PDT)
X-Received: by 2002:a05:6402:1151:: with SMTP id g17mr28259555edw.227.1599580598774;
        Tue, 08 Sep 2020 08:56:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599580598; cv=none;
        d=google.com; s=arc-20160816;
        b=DNeQ9rRR8KtL+JxjeUBqtTCrRUVt6EhoylJDLgAw+Xphw3yOCb0utjkkw2h9q4huIB
         9+pPu32TfeY/b4bcgffjIr++fh1s8KdAMUCTTpzp1qS2/N/e7zqMVZ8VxIP0yUNjI8DW
         2QNq+Pc7Dp8p+DQC6cSk4zYhfD+caVR3j325qyVnaf1M03ScQZ/Ki7C5VJZeOZ85jyUJ
         vZUyPGYQx1Q1F7NGeLBnOeo5AVWqpdEcUhLP6ncuztJykME7MW99mcYm7hQJePe85QhC
         KwDH5FHcj0IojTPT0CXcLlQieaRpse6VPpPYLVj3+x7m2cs9TZYsvEe65TqAtkBej2Em
         +rTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jYC9v1Z1TC/eRVDb6B6iUcOvbi2c078flAMPYhklKtQ=;
        b=qBCMRUTlCpQN2eLV4XWYptQjaPFM8UT9w8h/gKr5IXwW2//EBcq5z7LuSKvwKRrnpq
         UAoTt+M6WEOBxTzNqwjC28TdMlgOmYVC3NG12kWXzrwujV18wpRBxysufnfLRbVeAYf1
         3+l7WtVIZlKqlNxICyl0l5CKlCDjk7qf0HNig2X/A7vnBHGp4koDURFK4vqoJ7mYZ9vk
         J5/ZGD1nbE5ygWqKaGhpoziDQC3mCuw1BZgL2khb3TEZK9B2eCWn587gYN0YbiHgNOBc
         urGe0MUuVX8NgKjaFTRppvMec9yKOk8Lu9g3Z9SNUVTtHhNqRxceze8su0COBkCfSwbY
         Ng7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wETpD6sa;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id dk15si838244edb.2.2020.09.08.08.56.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:56:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id s12so1294555wrw.11
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 08:56:38 -0700 (PDT)
X-Received: by 2002:a5d:4a4b:: with SMTP id v11mr335425wrs.36.1599580598237;
        Tue, 08 Sep 2020 08:56:38 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id h184sm34756040wmh.41.2020.09.08.08.56.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Sep 2020 08:56:37 -0700 (PDT)
Date: Tue, 8 Sep 2020 17:56:31 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Dave Hansen <dave.hansen@intel.com>, glider@google.com,
	akpm@linux-foundation.org, catalin.marinas@arm.com, cl@linux.com,
	rientjes@google.com, iamjoonsoo.kim@lge.com, mark.rutland@arm.com,
	penberg@kernel.org, hpa@zytor.com, paulmck@kernel.org,
	andreyknvl@google.com, aryabinin@virtuozzo.com, luto@kernel.org,
	bp@alien8.de, dave.hansen@linux.intel.com, dvyukov@google.com,
	edumazet@google.com, gregkh@linuxfoundation.org, mingo@redhat.com,
	jannh@google.com, corbet@lwn.net, keescook@chromium.org,
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de,
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
Message-ID: <20200908155631.GC61807@elver.google.com>
References: <20200907134055.2878499-1-elver@google.com>
 <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com>
 <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wETpD6sa;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Sep 08, 2020 at 05:36PM +0200, Vlastimil Babka wrote:
> On 9/8/20 5:31 PM, Marco Elver wrote:
> >> 
> >> How much memory overhead does this end up having?  I know it depends on
> >> the object size and so forth.  But, could you give some real-world
> >> examples of memory consumption?  Also, what's the worst case?  Say I
> >> have a ton of worst-case-sized (32b) slab objects.  Will I notice?
> > 
> > KFENCE objects are limited (default 255). If we exhaust KFENCE's memory
> > pool, no more KFENCE allocations will occur.
> > Documentation/dev-tools/kfence.rst gives a formula to calculate the
> > KFENCE pool size:
> > 
> > 	The total memory dedicated to the KFENCE memory pool can be computed as::
> > 
> > 	    ( #objects + 1 ) * 2 * PAGE_SIZE
> > 
> > 	Using the default config, and assuming a page size of 4 KiB, results in
> > 	dedicating 2 MiB to the KFENCE memory pool.
> > 
> > Does that clarify this point? Or anything else that could help clarify
> > this?
> 
> Hmm did you observe that with this limit, a long-running system would eventually
> converge to KFENCE memory pool being filled with long-aged objects, so there
> would be no space to sample new ones?

Sure, that's a possibility. But remember that we're not trying to
deterministically detect bugs on 1 system (if you wanted that, you
should use KASAN), but a fleet of machines! The non-determinism of which
allocations will end up in KFENCE, will ensure we won't end up with a
fleet of machines of identical allocations. That's exactly what we're
after. Even if we eventually exhaust the pool, you'll still detect bugs
if there are any.

If you are overly worried, either the sample interval or number of
available objects needs to be tweaked to be larger. The default of 255
is quite conservative, and even using something larger on a modern
system is hardly noticeable. Choosing a sample interval & number of
objects should also factor in how many machines you plan to deploy this
on. Monitoring /sys/kernel/debug/kfence/stats can help you here.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908155631.GC61807%40elver.google.com.
