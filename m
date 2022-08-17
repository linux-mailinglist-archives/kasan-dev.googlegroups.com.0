Return-Path: <kasan-dev+bncBDBK55H2UQKRBBWH6OLQMGQEVW7AFAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E15CE596EB1
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 14:48:06 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id c6-20020adfa706000000b00222c3caa23esf2405179wrd.15
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 05:48:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660740486; cv=pass;
        d=google.com; s=arc-20160816;
        b=neXbfyqx+/zrmw/FI5Hi9vmFH+/Y1kcP3AveQbNr8G40LA8+6sJe85K/n5ESbDdKXh
         CpR2BUj1zatONDzGToAFxy0+jQBhY231NBSqr+jvnOUYg2r/UDUJ5tJeOuC7Frhu21l9
         ASl7AAXcZ0W7L/FFZK6OFeY7ZSeIQ2YNcC/5Ul5Nftjwofd2lLoLSTpJy8LY4BXcOYzH
         bRWJqOXL9cM0yu6KR2oqexzjg96klkm8QiIJOPD+yNAMCZ0sOl02KydtX2I7pzGemIex
         G2eLrcPzaW/qY/As3WPS1h3ZvL+vy/+a1n86dIC1lEhqMM5x1zv9YlT+dbxqTO8BX2rz
         qOmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s1PYTr1HujkNe37cwvJQKNqXHYiDZikW5Rwq52i6w9M=;
        b=P26PZgwNtp2KNz+oDZFRA0yJmMQlUSUDP4If8hUS9hvNQFWrNnYKPCeFdJEZM1/Ssv
         eeGPQJp2iWRrw6Zhba00pkuCr3YpROWt4soGkKkQipMZpljLI7FDsaMelIpNIJwvNzu6
         w7TmSPa6to1rXbUtNqhxp7VuQe/XlxrZvv7v13lCvEMn2sm9oA0dAqarkx+3nRyH08Ei
         81F8jD/Wdha0Wu5JpcV64CdMoUVvqE6PLV6KR8hFw1jZoHO3W0Txw5nStWlLAkKdnuBK
         3mlm+4JNHdO4d19M/UCc5nW7gBZv621ha+zF4kAFC9Uraq1Es/9967GbgKuN6hilC6mO
         do9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=OWOFpkz+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=s1PYTr1HujkNe37cwvJQKNqXHYiDZikW5Rwq52i6w9M=;
        b=TiZvoVt5Hs5Ozjnw40/KHI6xFId+zxdfnqcEuOvZif/sEPEAmhEf4oDGROqZUhzhAL
         LC2cyhQCTkKc8rxhtmwjF7x4BqA/Cz4ng1ySVWBgjLk335vW+4rAAvwfA8mRqO7DJEcA
         LKoawuxnjkmn4ohH+CQqotZezxGYfFa/fQGYP/OB7sgCWSM21NFYhdG0jpm01A5F0IvQ
         yqhZKdbzxXk4MqM79Cnkx0GZt6b9yuwGSSFZ1njAloH2saBLXYM1NVIpHM1AovUJ49x3
         2rR1AE5US3qz5vaZLjY7VlibPGOPUKW8AhLIrS0Ej8IIN4azhX/AV2Qdk8TgQ6VALRUa
         /9sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=s1PYTr1HujkNe37cwvJQKNqXHYiDZikW5Rwq52i6w9M=;
        b=rUrs9YawEr79SFgVdT1DfspUPpt29T4sGp1zmaJ+1TsB6EonYtNZbJtkJVA+T8Z3xy
         7LZS2rsa2piXLhbaknkAvJu71fxqjK7vhGUWgDbJTxF+qvd7p0iT1Y8lYeT6Q2CmzBK0
         rNqLg1QbaMcA9bnfuB9nfzve0pMyQ00qUzkW3Y5zf0pKrY2+Vj0MPFy4V310bUD8viL3
         c+rztysNvBdung7PL5tGfaz5LMKEppkYspqa6aJ9fT4WmGriTkZgbpx7PSaDuTyPSXus
         lUYf7pI6YCqF8MQE20O8/Y5Uaf4cu5RvzhpoRAk7ozPhM+TKfszQITVm5Wfs9xvc46HW
         ETUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2mPF3+cb5mWNQpezkpm5YyafmyNUH5p7Q4C3K2iFF9jdc4hAet
	ce/l0D76eOgJilpLnEouiZA=
X-Google-Smtp-Source: AA6agR630560cX+voGfcugbdO/ibs8GzxbQFjQbmTHgDdy31ST8cBWNcisHuU3aHg3wjImWhbvqCsw==
X-Received: by 2002:adf:f708:0:b0:221:6cb7:8d52 with SMTP id r8-20020adff708000000b002216cb78d52mr13962934wrp.186.1660740486341;
        Wed, 17 Aug 2022 05:48:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c1:b0:220:80cc:8add with SMTP id
 b1-20020a05600003c100b0022080cc8addls2828061wrg.2.-pod-prod-gmail; Wed, 17
 Aug 2022 05:48:05 -0700 (PDT)
X-Received: by 2002:adf:fe04:0:b0:225:1c8e:9027 with SMTP id n4-20020adffe04000000b002251c8e9027mr3713141wrr.155.1660740485007;
        Wed, 17 Aug 2022 05:48:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660740485; cv=none;
        d=google.com; s=arc-20160816;
        b=XfpQn3zvQsSjDhff/VAMQzwiCe6CsY7TiW2JHZj1bmxWVLsH8whxIl5/ntrXvbaft2
         yIJdqSE1g5E4XgtXBvxvhj7JwQVLjVU+qdgywtnybEkZNyO1jjDbi3/OZIwRDOCCq9Dq
         a/Cs4oS/Gbk3+zDN3OdyBs+zUBCevPvK6R8F8lim7WeU8SnfyeXpcxXDvtx25IE2Ct0R
         dSdFtY0JGnHv66R168KkA4FcsWpo7DRl2Fuzw3ZdtbjmaeSGWiqJO5kRN0/3za5CRk3U
         Lp7YUKGNW8F6yGS0zisrSNPDFQPuKVQm+8skyL/+8X4KR75IIP3JYlNQFWnZL8yltRi3
         sM3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1qmsUsB+4SBL13h98w97pLya6IvHEpIdUKliGvuz3Dw=;
        b=jM/rzqoBYUveluzI1Bpr9MebHv8daBfZJdu6gM0XE7dOgjIAwJP0NKVWR1CbDNtqH7
         dINoBkoGqyQGOrvbxOsiRPviQNmQ/ZB0epUgyC4RQb0plIUygastH2jZZormer66uvJ5
         r/QbhHxzz/ReiX7p5NBs+pVbF3loF32pDz7D241oHbzHKJCHdz83WB1phTzxP5A/5oRN
         GqX6QL2/9YWdD+/gNwn3EyO1DgsOiGYzVmKzY+yYPEWgyZudLeLxOvAqDqGUrlY4LEK3
         SG/aliBZHvYiEs13P0w0cpe1h8T/7Fwyw+1yGKrlqBiOdsLM+X+XD651V0G93+7wSD3v
         LH8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=OWOFpkz+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ay9-20020a5d6f09000000b002236ac50ec6si730897wrb.6.2022.08.17.05.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Aug 2022 05:48:04 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=worktop.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oOISg-003HpW-Mc; Wed, 17 Aug 2022 12:47:56 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id C3BE1980256; Wed, 17 Aug 2022 14:47:52 +0200 (CEST)
Date: Wed, 17 Aug 2022 14:47:52 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linuxppc-dev@lists.ozlabs.org, linux-perf-users@vger.kernel.org,
	x86@kernel.org, linux-sh@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 10/14] locking/percpu-rwsem: Add
 percpu_is_write_locked() and percpu_is_read_locked()
Message-ID: <YvzjeEHYX9d5dhAt@worktop.programming.kicks-ass.net>
References: <20220704150514.48816-1-elver@google.com>
 <20220704150514.48816-11-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220704150514.48816-11-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=OWOFpkz+;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jul 04, 2022 at 05:05:10PM +0200, Marco Elver wrote:

> +bool percpu_is_read_locked(struct percpu_rw_semaphore *sem)
> +{
> +	return per_cpu_sum(*sem->read_count) != 0;
> +}
> +EXPORT_SYMBOL_GPL(percpu_is_read_locked);

I don't think this is correct; read_count can have spurious increments.

If we look at __percpu_down_read_trylock(), it does roughly something
like this:

	this_cpu_inc(*sem->read_count);
	smp_mb();
	if (!sem->block)
		return true;
	this_cpu_dec(*sem->read_count);
	return false;

So percpu_is_read_locked() needs to ensure the read_count is non-zero
*and* that block is not set.

That said; I really dislike the whole _is_locked family with a passion.
Let me try and figure out what you need this for.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YvzjeEHYX9d5dhAt%40worktop.programming.kicks-ass.net.
