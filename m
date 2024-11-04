Return-Path: <kasan-dev+bncBDBK55H2UQKRBWPIUK4QMGQEC3KYNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ACEB9BB3C9
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 12:47:39 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2fb53ef3524sf23729451fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 03:47:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730720859; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zh3trPWSQOeXsbUTPVB55YXA5Kfc3hzMKjW9PYLFb3NAcZwZLZqzPHPAWd+TmBiXuQ
         N5wj9nDZalTrgNKswDmLg5Vbdp+Rz8yE21LCbNQSf/YOJ+THX36SvzZusMga9jbS6o4y
         L68jh0/e58jq4TKmDJEyc5uPqO2jzztAFULBmJZYL7T937onjx9HrlHNna8RU6jOwS7u
         /JJ65hTbzLKouST8+1ZtATx+3WeuMXhDyGC7BtRx1xG33FLMm53Ppo0Xsun+2HqElmTU
         v76qMwE03ynqctamvnEJSTfucDVwL+YUa+BGLyvd+mqRDdNk2Ok6icOcQlEIN5VWekr6
         rRmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3KCwB1h6u1V7qTq9Jb1bEx2xmY6T0Gyrl6BJCExVNHQ=;
        fh=on9NZIEiG9/rkM2RhzrMTeBdyBZnHxgzmtVCETMYeKU=;
        b=kVPJd2Kt5LX0pp2XhLsT6DSNFIoKu0CZr6AC7xwd4hXQ8aDezkxy43FY42LJvOodZJ
         oCKod7q8qAHzVnD5X7de+5IHmB9ApnJRIVzRcttStpLH/MzFVZw/kbFQcKcPfdHrU+Mh
         yh5t4N5bhTeUblxMfoRWGGq6qN3JAYz8y7o1omkHDfWJ8XZFHOyO3FMGmJpQuPgThEMk
         HAHqEeGSJczKnkrNB9Lixma4yMPIg9NFrmuPfmtt/482XoiyKripJb15YWpnWtDKbXVc
         h8PeDRMDZH0wDMdoh/B3qQB7vuIuB1XzQ2+p0bQkjY+kHHiccBIM5NkCyBInfq9JvIp9
         XLKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eX6aRPOy;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730720859; x=1731325659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3KCwB1h6u1V7qTq9Jb1bEx2xmY6T0Gyrl6BJCExVNHQ=;
        b=LZ+tc8UWILqja1MuBZw0Xr41kC73pBfXT7iuYaO01wAVaQndPmCDUBXa09+KqXIb5K
         om3kxZIAGfE1Nj+g9zZL45Fh5qYfk8unLOoOS9mxMVOHjyovfEDubl4kYQl6FLyZ50wf
         HDCT18VKFnM76jQl79lJ283e9GAIAGGal0ZScbGtm+HOGShoP1+blqqXfeSg8mmPkttz
         jj/NcQG53pACFRLegj2A3W+BbLISgHzBT+0wgyGnSMVa80/d1obAujoTTyZS7TkGzZZ0
         6tlxsDm+J0R0QJuATK/ON68zOEFWIfmA/TsdP4hhZ51HFkG3eQpImSwsAqasUDe1NPjK
         gzIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730720859; x=1731325659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3KCwB1h6u1V7qTq9Jb1bEx2xmY6T0Gyrl6BJCExVNHQ=;
        b=jgsbuleJUimRO+czlLbGNCOdBkgoJsbQkbEX/G118mhEq56s/vt1HaImRP23KjX+WS
         mS0LXd3aqew+Fy+K31YEtgpq04txC8uNpwnyCpWcT/VHJy+fjM2slT8yIdQ8QTjcIE8h
         buRcS7HVYTD6mY3WECPrfFITBKzfQZBk1GsvfUanehRqAyV0ser+Zpt0jAfOTOYKzPT1
         gzyzHV1krIZ9nPkApIRs8UP88vgqjWiOMhAK3adIXNANeny1nziuRbUNAxnxOE9DID42
         lXPlyMHuvTcwt8gx5aLeYGnthj74zfhaGLTDUUm3FQT2ITQSySsAZOVZ6/evqPJExWBA
         3fBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWz3fYnyagUrkz4IN/8nnIqUcy26bQb3Wo7VwtrgBrVTNTzcQ3riX5RL0b5jFpCAMT7bqiOBw==@lfdr.de
X-Gm-Message-State: AOJu0YzcDBJVRSSc+bPebrQ7q4nlOBcm2y3ohqrYGr0hOFiQpfpf43yH
	3CZgBwUF4AolzIEWcUIaY/OmIU+PRxu/yrK8fanpKBX5cqOwz+e/
X-Google-Smtp-Source: AGHT+IHgAUVhOI4a2oWl2CYqixFCwFpySyv76IN1+7ZHhtYxcMJV5Xi+xfhaOTv2QuewxgsBuJw1dg==
X-Received: by 2002:a05:651c:1990:b0:2fb:3a78:190a with SMTP id 38308e7fff4ca-2fcbe04f08emr157171051fa.29.1730720857805;
        Mon, 04 Nov 2024 03:47:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a42:0:b0:2fb:3982:4e2f with SMTP id 38308e7fff4ca-2fdeb437aa6ls11452741fa.0.-pod-prod-07-eu;
 Mon, 04 Nov 2024 03:47:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVdtY/OIAQets+/0K2SeQxLhZAoStmLbcWgnDKU92Xudr6owZVBwUZUmfP6loWEzh47E/XQQaZr+pM=@googlegroups.com
X-Received: by 2002:a05:6512:10cb:b0:52e:f2a6:8e1a with SMTP id 2adb3069b0e04-53b348d8f8dmr14443721e87.29.1730720855397;
        Mon, 04 Nov 2024 03:47:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730720855; cv=none;
        d=google.com; s=arc-20240605;
        b=FNxN76WyMXKrnQ7PLP9tht/AGKfbgbhIuuUDHy6yttJdGnegzFFHGd8GCbOjhMZQ3k
         sYh+7hAwQjJEEyKAmqTE1qYg2Egd5TmknqRf46jFs0FSGp7oUkVxSABUpYewNGxL7t0o
         kSWMoktyFB1rH/63JD0XOXpx/fSKMkXoZ7QQlsr+3R4DzQqIsaziLL96tYzmeLYaCp7m
         ax6r5qTScfjM6PRDsUoBbNCP14tGUkFZDvREueY0lT9lJ0AT663k4YaDfSOGFI3//HE2
         gfHpWaN5O6GbdSAB1zQCRuWdIsw61BCx0/RsXK5nviAgbe2nDdq04x/WynCB5SQopUPQ
         B7hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xA1XZPA7ROpkAWO42tjuiUPyY5dJ4CkrP0Yv74uKLYE=;
        fh=O7qDJmcIBozqV8VgXnQmfywzNtjkeq7H8K/SafUqtZw=;
        b=Nxo13TKVBfXu1wLXEasiTcwlevtrsUpSPYVNWTUfuL1J2KduIofHWKeJB3LyYp7rUj
         1Z70/zcUW1f9cz7v/Y8VKYqj6dFADddEUSX2c0CALEBdysACVS6WPPkYrOssx7oriOrR
         Q66IEZgOrY2LwANQ0AWkItfv3sE3rgxE4T1WcIJLendTxbjQP+BzQzXStjTP2XoUIGTN
         lTYCQtNJlNHgzroqC/7nPfxLdsDrJWhIMYbhxcfA3vMPJaQe7Bo8FuBwSF6SIUxagpql
         vFr1M5bfq6RSGexl7vec5wMMNn4AeyzRE7KUjjoKeBdI/3rSIFxLSZtSEpS42MC5UNDt
         tBSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eX6aRPOy;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4328bc063e0si3956825e9.0.2024.11.04.03.47.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Nov 2024 03:47:35 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t7vYM-0000000BJRc-2PoW;
	Mon, 04 Nov 2024 11:47:26 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3837C300324; Mon,  4 Nov 2024 12:47:26 +0100 (CET)
Date: Mon, 4 Nov 2024 12:47:26 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
	Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Waiman Long <longman@redhat.com>, dvyukov@google.com,
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org,
	josh@joshtriplett.org, boqun.feng@gmail.com, urezki@gmail.com,
	rostedt@goodmis.org, mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com, qiang.zhang1211@gmail.com, mingo@redhat.com,
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	vschneid@redhat.com, tj@kernel.org, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, rcu@vger.kernel.org
Subject: Re: [syzbot] [mm?] WARNING: locking bug in __rmqueue_pcplist
Message-ID: <20241104114726.GD24862@noisy.programming.kicks-ass.net>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241104114506.GC24862@noisy.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=eX6aRPOy;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Nov 04, 2024 at 12:45:06PM +0100, Peter Zijlstra wrote:
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 6310a180278b..ac9f6682bb2f 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -521,12 +521,12 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
>  			sizeof(struct kasan_free_meta) : 0);
>  }
>  
> -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
> +void kasan_record_aux_stack(void *addr)
>  {
>  	struct slab *slab = kasan_addr_to_slab(addr);
>  	struct kmem_cache *cache;
>  	struct kasan_alloc_meta *alloc_meta;
> -	void *object;
> +	void *object

Clearly I'm still struggling to type ... *sigh*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104114726.GD24862%40noisy.programming.kicks-ass.net.
