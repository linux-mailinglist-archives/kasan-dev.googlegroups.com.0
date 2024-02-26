Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZVQ6GXAMGQEYKZHFNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 11280866E37
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 10:22:48 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-565862d2fdfsf98998a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 01:22:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708939367; cv=pass;
        d=google.com; s=arc-20160816;
        b=ELiWeraXfsrBpLxjMfej7ZeXKjTfr/FvXR9sa4qvwkN6gAbX5cKqg5dAZNq9VhA2N3
         RW5NSmOB9RXYHmczsSSPtS61ZENl/0O/R4tbFnKwV3ZikxMdEGNSWEnCylq+V1kvWTuC
         uUT0zeZARo0DU+NWzu9bwCmsJun7dH4/VZrF1KkSZTXE+GQURYYrORwlgoS3R2pIaVxF
         b25H3RXAVB5P4h610KT7vGSqkA/KfUuatyFlw3K9nL9yRtbBmYKjkdEDp/2Ek+GfDmnB
         Xjq1mVVo4v672uFeTZgyIhJnUlKl9GtbbHN1JAnjSpwMmWGCt36yKkfWTlVFeTExE0az
         yzlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4qkmY0yMb2ppyHhZFoX0yB1msbWPZ9nziHFUHHzEhSs=;
        fh=HlDQVenr0JE2m+M+lLULYNtXhsoQJKm+pzdDy9Gr1ZM=;
        b=If2/PXDIYBRv0v/qnD6hmEG49ijCPeIS1TOJtSpwpSkPR4BgMQJOG9hvCjyMsxXoiG
         EE2zGuzge+LsenHQq0DWvUr+c3yCgphqDXXonwsclaj7CzGGeHnoIMOgRKuob6+x50KV
         8iMRiGGp4YZ5Lxsv8xWMYoSaia9bqOSCUnQ/Yk6pjLB35eixkERpV8HUXQSsGA8X63ga
         GxZGyj7Rm5AB5XMxsSghNfIwjtFnO+mPTaGnAS9+9WgggGVHchPI42m9LfU0DhG/6RFt
         BMOTopNru0urdLttIjTb8ioK42dQROhYhCSb/Yxpx8UVDOGC2TdTmeEc7/vlRJHxTWaq
         79uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MKaP2hzG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708939367; x=1709544167; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=4qkmY0yMb2ppyHhZFoX0yB1msbWPZ9nziHFUHHzEhSs=;
        b=TxoiTxsbNXUXfEcDGGFOKk7C0iX1M8gU2irHrzVdgdCKCpCpG3R62sHeIl4x4vJH+e
         PMStTUEGuxLBTlZJaOgLTRCgVewvwsAHaDKnsY8mPj/oeFg7Wwako68M/el8yEEtaAfs
         Ed7xpv76KhYsVx9I3HzUL5gnktUIKRheaWK6V+FA2Scsem90zQUHKWStmaHItvw8LpOp
         EtI+7RghDsflh30GinHspfh3tIm1qQe7suRdM8IqVcQTNw/dyONKE4Ag3APCfeqQxgN4
         i6kLQpruCfvewKQ49durN9FBFf6Zfa37yeb1ffSPh5PMzS/XxrEMXGlCyatfZsvBiQlW
         WJ3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708939367; x=1709544167;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4qkmY0yMb2ppyHhZFoX0yB1msbWPZ9nziHFUHHzEhSs=;
        b=lghMMAZy8CtJRVHboFZdNA2Nt+0eWcJSNN+bQjggVeQ6nwPjSrZdI2gE+wcdnTHjqN
         F/eG0mq89t4Ld1O11uVLc3jrPXDWNnUkCiG+oO1LGRymUBFtx5Bey+B/TWQnqCTAqSfI
         EGf9AOtNDppi1sB/V01hQK88+i0zRIkiXVle0NicGMP43rKmPc2H5+26AYxpuTmCj7rU
         S33aJvsE2jK7ym2Y7cll9ZS3WtfOkj6qQfuYbXOBkf1Lm31ra1Y96Mw4XwnXoe3wvuC5
         Ld4rXXqfi71/JHnnEqypxzbvnPi0GGWgUuzmP1gHXRBGf7uAh30iyGGwQJD/0PNH+plM
         7DaA==
X-Forwarded-Encrypted: i=2; AJvYcCUyWOwnbu2FWh7Oc/o8oChRSQWKD5QhmDfZhsi3J1WrgMZzlHoap1m50cwj0Iowk9x5zQkK2EiJ98xcSQta80Tq0kHnD9eyBA==
X-Gm-Message-State: AOJu0YxVhJlEwzQ+vovP2M7UX/+zhV0ndf2dcf/AhmfyIULFBSRMKe2g
	w8Oyz3eJJPxAZYIBDoWorI+1zBH636bcuK+VcWd1zb7nOyYdI6p8
X-Google-Smtp-Source: AGHT+IFSBt+E4BmOWOioPGM0Qe0yqraumzPDnAyZUzfe//xnsvn7LRUgndwING5pmsZRqExFLBJy+g==
X-Received: by 2002:a50:c05a:0:b0:561:a93:49af with SMTP id u26-20020a50c05a000000b005610a9349afmr239177edd.7.1708939366911;
        Mon, 26 Feb 2024 01:22:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3896:b0:564:84d0:f1cb with SMTP id
 fd22-20020a056402389600b0056484d0f1cbls110498edb.0.-pod-prod-06-eu; Mon, 26
 Feb 2024 01:22:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXptGsCqqsmTlNigZjk/ddnqFb2kpww8uj9z+IrYNTMDcoGTe1KJVZrvgFQnH9fC/n55ftmgpXO6HggaUEsZkKkPzJt46VYOCKl9Q==
X-Received: by 2002:a17:906:16cd:b0:a3e:a951:4087 with SMTP id t13-20020a17090616cd00b00a3ea9514087mr4300043ejd.76.1708939364720;
        Mon, 26 Feb 2024 01:22:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708939364; cv=none;
        d=google.com; s=arc-20160816;
        b=iZpX6krv1euuKqDCsaCFAUx3BKvPnSeZQ6CaR2ONcMiqjAhPpQVJoDItaYSkO4Np30
         fzFGev/CZbdpDmvWWzTfkzhm43/F2saGO4u+k/zZlpHE3Ds6YSMCTEyd8ub3GSiyb80t
         JBCLSBpzVGQGN7/YeSOzJX3u9NwHXYpr65XfhQCpfanKctqvZwIox6ByerdBDxvMx9GK
         DP6xFZaCAB/1YZibeMerviasVTmt6YN6AzlbN0hLxri6y7Dkfy42rMNyg0ZZ/ZmQSbzc
         oVrinlAQzsM4RE4JQPq1QqYIvn48DKNomWpyQpcfFprykK6uZjql8PtF23g5aAmwz6to
         12Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8QfBmNQlREY1mFL6Qy4q05yfZGbpdHZnd4065oOqFl0=;
        fh=lNuuQex4Nfvu1o67ocjPJw7weNIwz306GVvChRLLWNY=;
        b=MyITVIiCdIiTkIeUsk/WP+WxSyqrGPayQsVvXts9iH/X4sRzfxj/bezBTC7xvTa0W6
         r8lFyeK8FfrV/zexwvRBRZB6R3hw1TDNNfy6wccyXNYmz1U7UDC5XxUf24JOig9Kp7y1
         +hyHLijcaqeqEiUWdp3yd7lgbnlL+kQPRtSgtBXjir6CpD88hgnOHEKRVBw0uSwQJHjq
         ZzWkd6ZSuCHQgk+3+SB1xp33XveQJyKRuaUoQhQVBC2uWFsMDH6RA1KtnWqgrZlXuGCm
         ilyjtTsfMjMjXRjiPO/LxYVD4xSzcOo6H2+0DAdDI3670vRc9Cz/QHDkzTm+0gy7e9fR
         q1GA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MKaP2hzG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id y19-20020a170906559300b00a3e643fea3fsi386023ejp.0.2024.02.26.01.22.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 01:22:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-41296dce264so18530645e9.3
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 01:22:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWt7mmJx0xx5qMP5Sq9JJWJVNtuz9oda5NfHzKCLQroU9SGHEzcumqp062QB7F7VB2b59IQ5US419NZux5lcOVXcLrhvnNgozWaJA==
X-Received: by 2002:a05:600c:4f95:b0:412:954c:801d with SMTP id n21-20020a05600c4f9500b00412954c801dmr5459772wmq.12.1708939364176;
        Mon, 26 Feb 2024 01:22:44 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:2bc0:f3a5:93e2:b2c2])
        by smtp.gmail.com with ESMTPSA id az8-20020adfe188000000b0033d7dd27d97sm7607221wrb.45.2024.02.26.01.22.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 01:22:43 -0800 (PST)
Date: Mon, 26 Feb 2024 10:22:37 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Andi Kleen <ak@linux.intel.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH 2/2] stackdepot: make fast paths lock-less again
Message-ID: <ZdxYXQdZDuuhcqiv@elver.google.com>
References: <20240118110216.2539519-1-elver@google.com>
 <20240118110216.2539519-2-elver@google.com>
 <a1f0ebe6-5199-4c6c-97cb-938327856efe@I-love.SAKURA.ne.jp>
 <CANpmjNMY8_Qbh+QS3jR8JBG6QM6mc2rhNUhBtt2ssHNBLT1ttg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMY8_Qbh+QS3jR8JBG6QM6mc2rhNUhBtt2ssHNBLT1ttg@mail.gmail.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MKaP2hzG;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as
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

On Sat, Feb 24, 2024 at 07:03PM +0100, Marco Elver wrote:
[...]
> 
> stackdepot users who do not use STACK_DEPOT_FLAG_GET must never call
> stack_depot_put() on such entries.
> 
> Violation of this contract will lead to UAF errors.
> 
> From the report I see this is a KMSAN error. There is a high chance
> this is a false positive. Have you tried it with this patch:
> https://lore.kernel.org/all/20240124173134.1165747-1-glider@google.com/T/#u
	^ [2]

I see what's going on now. The series [1] (+ the kmsan fix above [2])
that's in -next that brings back variable-sized records fixes it.

[1] https://lore.kernel.org/all/20240129100708.39460-1-elver@google.com/

The reason [2] alone on top of mainline doesn't fix it is because
stackdepot in mainline still pre-populates the freelist, and then does
depot_pop_free(), which in turn calls list_del() to remove from the
freelist. However, the stackdepot "pool" is never unpoisoned by KMSAN
before depot_pop_free() (remember that KMSAN uses stackdepot itself, so
we have to be careful when to unpoison stackdepot memory), and we see
the KMSAN false positive report.

Only after the entry has already been removed from the freelist is
kmsan_unpoison_memory(stack, ...) called to unpoison the entry (which is
too late).

Therefore, the bug you've observed is a KMSAN false positive. This diff
confirms the issue:

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5caa1f566553..3c18aad3f833 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -423,6 +423,7 @@ static struct stack_record *depot_pop_free(void)
 	if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
 		return NULL;
 
+	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
 	list_del(&stack->free_list);
 	counters[DEPOT_COUNTER_FREELIST_SIZE]--;
 
@@ -467,7 +468,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
 	 */
-	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
+	//kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
 
 	counters[DEPOT_COUNTER_ALLOCS]++;
 	counters[DEPOT_COUNTER_INUSE]++;

But that's not a good fix. Besides reducing KMSAN memory usage back to
v6.7 levels, the series [1] completely removes pre-populating the
freelist and entries are only ever inserted into the freelist when they
are actually "evicted", i.e. after kmsan_unpoison_memory() has been
called in depot_alloc_stack, and any subsequent list_del() actually
operates on unpoisoned memory.

If we want this fixed in mainline, I propose that [1] + [2] are sent for
6.8-rc inclusion.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZdxYXQdZDuuhcqiv%40elver.google.com.
