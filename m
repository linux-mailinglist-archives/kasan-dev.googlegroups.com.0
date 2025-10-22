Return-Path: <kasan-dev+bncBCT4XGV33UIBBSE44XDQMGQEVXVEYYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B293BFE533
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 23:36:11 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-27ee41e062csf736625ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 14:36:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761168969; cv=pass;
        d=google.com; s=arc-20240605;
        b=kNNMo3nH+mwrrFF/zfOltmDlSTThgNW2fLjyz858OHCYiG8SMJsAEQbeAPUiF+QrzW
         KzVca2G1ZYQQrOsSC1BPdYRk4q++QZGP2fWiQJh6EteP9fx2l/8qum1MOuOspFg/3/7q
         gcHyas4CxiYQpsjlvbUlpa9Q5ZGliu466mK5oaKBk01+C18KVypB67Boz45tzjyTDvgi
         Wec7yywDIZt8LpxAVoUeyn4crHm518vZ0/mNb348FKLLhWJXOMWK3pweavStxrZPY5LZ
         Kpu/rDP3094bKA/SOZjYZMMTSeSZfz44qyMFBduAe11denrBpQC54+Q3mBKVJlNYhQo+
         Y9SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=r4qmy6WR9alXrYOQNWIgLdWaVLyNfkBAjzrc1lvyK0Q=;
        fh=JkHtdiD3CJdEcRFT8ut2tJO9a0drRKlfD84HCamQ1KE=;
        b=dTd1VsrRtjgapYd2kfOchdsbKiJsztyq2I+Zf6YydTrRPzq2XsVhz3mRwmGPWm6iGY
         n9cgb+cG25obh1+xqaZ/ff2MZqVnTYmWTrwreFI83mnb39/H548PppyccPoaqCWhWnjI
         P7YYsXDFtUK4PM57FCl7JUrOpl3B4bSIzrIX+MnnW3C1URcK5WAf5+euMO/RuBN/ZrtY
         MtTjUjcPpKAmQC8Jro5juaOtcB24VcrqKXLzLmmXFH6ZTBOlYkpIshQwlARGnEwZQzPw
         0qnOvuBBAJw3XeONSymOVYzkVF/BBblVqdMbhUSCq6i97lWXT9sRPBoyieAUp8+2OTSM
         TJBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="YD/zEhKO";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761168969; x=1761773769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r4qmy6WR9alXrYOQNWIgLdWaVLyNfkBAjzrc1lvyK0Q=;
        b=hJZdNsubi0hXkBQ3ClrEYXLabVc+wDO32apDtmD/xg+vt08HQHnCWUNWBw99wg/tVg
         YFfibn9bt0ZGfBuftXMtjd08GzXHQXV5om/GOSCdzN2npqD6VmlD9o5FOloIwZ+U86ax
         HPZtcXMYpv00vhI1CdSLxIfEKP0hL2vZxTrOd/4R/jziSrXK3/0Y4hX/oIwFC4+SIqpA
         qe4DTxwt+tRd+p1Va+s2d9guRBnbdMq8AaCxFW2HZu6AolrLc2L7kGEKds1mPpCRdW48
         qud906U+1n7n1vNhELrEkGjvqb/wkNVIFqJReqXWG4xmrSG66T1dDyWl5bl903hmsErs
         aEdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761168969; x=1761773769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r4qmy6WR9alXrYOQNWIgLdWaVLyNfkBAjzrc1lvyK0Q=;
        b=Lr229qI798/JTS3r9VrhcodHFWv/85F5klFW3CV3stVtHv5knyP752YsSuNJGMoxyc
         p1A4UJKU4B9ymfoyQxPjnABERD7YpGQ0Lts7Sf6YMbmXNRVRGQigtBr6077o1nEpd051
         HY5I+YwWOSm7/AbINb4YMMFvx8tte9i8iiEIwmFfK8gHF8RLu4tGXhjXh+gxRWb1pa1n
         rk3TMqNGdeJvAaoKEtNQHzBj+3CpUA5XXuweQi9kLW0pENvtqJwT098Xx69iVby7jOGu
         Qa/+YvX9i7Gjqpo0rLH5opszn+zg0S3P3J5HMV+NMmE4BFRyKzITK2ODeP5j/8HyUsCy
         IzfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiJgSPIg5xYgq0DKeRZvirgVw8MoMR7sjQHOW0JMjIXvBMcxkjaiaI5eJNy5ms7cHbrN3B5w==@lfdr.de
X-Gm-Message-State: AOJu0YwpIQ/o1kZqUE+ZQdgJiB0X5IaRp1WF7nhS0P7g7n3LiDwuGg0g
	fKdDtUz3AVJ8aQ6ADI8KCbr3lHKWRONZNJFscRw+biLHZNXKMBcCQS/Y
X-Google-Smtp-Source: AGHT+IGH/zAQ1BL3r0p1DkI7mn6E6Q8FUUudTv7erpXvFyq94Ah44v+ZEW4pPSCrF56Rm/G24uxQpg==
X-Received: by 2002:a17:902:f706:b0:269:6e73:b90a with SMTP id d9443c01a7336-290c9ca6b11mr262987505ad.15.1761168969215;
        Wed, 22 Oct 2025 14:36:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4lUSigRO0yYET2JZYBvWdBD5LIsQp2ShGEF9xAazB/0w=="
Received: by 2002:a17:902:e394:b0:28e:cc52:e2f3 with SMTP id
 d9443c01a7336-2946dc9ae03ls325565ad.2.-pod-prod-09-us; Wed, 22 Oct 2025
 14:36:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwzIkTwQWNj5wJFKqIyOvaa8W74qlEZw49m7cwYYoSgH5r9iAtQG0ofwyyam+MjFWCdlgitgFmNjA=@googlegroups.com
X-Received: by 2002:a17:903:b90:b0:290:bd15:24a8 with SMTP id d9443c01a7336-290c9c89fa6mr273058255ad.11.1761168966385;
        Wed, 22 Oct 2025 14:36:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761168966; cv=none;
        d=google.com; s=arc-20240605;
        b=UwfqAAoNTYl+wN0r3yTXP49Tt+55ny0skdiUjbJeIxwob9s5iqpvLAwjyZRpVjW2n/
         cGSQsR/ANft9u1KJpLjTVvuX55YX7OHQF4wgC4gzYolQhwWVe57Q/bKGS9ye/a19gDWM
         ZeJZnhF+abQH8r1A3Y/8FqVGSh1ThFR9IsVyBaPeJPtOn5BSNG9m375ep7tYpYQcq+ZC
         5icAN1NG02ss7U9Jsazkohl/ODxyOYyhoLF6MHbbHDo4QYnGCEytuQ8XeNP3A9h2f3gB
         7T7Jv1p+3SWU+Zj+NuRRJHuF/bzGQwLE1cdxcfuaN2fpHs+NkgjGS91XA9SzJT+90d8o
         AiYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QS/wDVWg/99dm/YWlTuIw+3X1HjWCfQCG/YUCbH1ck0=;
        fh=fysEXhAOJHtXZ4oxaNZMd2DL5AODcyJSqclD03bI3jU=;
        b=e6nRfRQ5VahbVX/EuRZHSnhN5so0aTUd7+jnSq9tP/JuGFrXHZWaaHkLXI7V9D2N3N
         PsXspwGAvRD/qbpaWb2H2huBrNGJezP80qKtf3sFVaYg+jS93Oym7HckfpcqWy7rPODE
         +WtZPb1go/Ak0s2vwEgUw0nnJBcMKUA8p/F1oCAND0UiywBuL6pv1HINmP9lyhK+hnck
         uYyOX7Y2SPB7avUfs7YK3mDdCoifik5beXkuIJvkYeMKQM4aAXf2SXUXiy5qpsPbeh6J
         OffFe5ArIpiBA0PRNlglOVGx8L4HgZBpGTbh3wyvl2reZHYKWi6UAM4LWDGxCGo4tCX4
         MV7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="YD/zEhKO";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2946df1b719si71375ad.8.2025.10.22.14.36.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Oct 2025 14:36:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 010D2402AB;
	Wed, 22 Oct 2025 21:36:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 81401C4CEE7;
	Wed, 22 Oct 2025 21:36:05 +0000 (UTC)
Date: Wed, 22 Oct 2025 14:36:04 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Eric Biggers <ebiggers@kernel.org>
Cc: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Ilya Leoshkevich <iii@linux.ibm.com>, Alexei
 Starovoitov <ast@kernel.org>
Subject: Re: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots
 are allocated yet
Message-Id: <20251022143604.1ac1fcb18bfaf730097081ab@linux-foundation.org>
In-Reply-To: <20251022030213.GA35717@sol>
References: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
	<20251008203111.e6ce309e9f937652856d9aa5@linux-foundation.org>
	<335827e0-0a4c-43c3-a79b-6448307573fd@linux.ibm.com>
	<20251022030213.GA35717@sol>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="YD/zEhKO";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 21 Oct 2025 20:02:13 -0700 Eric Biggers <ebiggers@kernel.org> wrote:

> On Fri, Oct 10, 2025 at 10:07:04AM +0200, Aleksei Nikiforov wrote:
> > On 10/9/25 05:31, Andrew Morton wrote:
> > > On Tue, 30 Sep 2025 13:56:01 +0200 Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com> wrote:
> > > 
> > > > If no stack depot is allocated yet,
> > > > due to masking out __GFP_RECLAIM flags
> > > > kmsan called from kmalloc cannot allocate stack depot.
> > > > kmsan fails to record origin and report issues.
> > > > 
> > > > Reusing flags from kmalloc without modifying them should be safe for kmsan.
> > > > For example, such chain of calls is possible:
> > > > test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
> > > > slab_alloc_node -> slab_post_alloc_hook ->
> > > > kmsan_slab_alloc -> kmsan_internal_poison_memory.
> > > > 
> > > > Only when it is called in a context without flags present
> > > > should __GFP_RECLAIM flags be masked.
> > > > 
> > > > With this change all kmsan tests start working reliably.
> > > 
> > > I'm not seeing reports of "hey, kmsan is broken", so I assume this
> > > failure only occurs under special circumstances?
> > 
> > Hi,
> > 
> > kmsan might report less issues than it detects due to not allocating stack
> > depots and not reporting issues without stack depots. Lack of reports may go
> > unnoticed, that's why you don't get reports of kmsan being broken.
> 
> Yes, KMSAN seems to be at least partially broken currently.  Besides the
> fact that the kmsan KUnit test is currently failing (which I reported at
> https://lore.kernel.org/r/20250911175145.GA1376@sol), I've confirmed
> that the poly1305 KUnit test causes a KMSAN warning with Aleksei's patch
> applied but does not cause a warning without it.  The warning did get
> reached via syzbot somehow
> (https://lore.kernel.org/r/751b3d80293a6f599bb07770afcef24f623c7da0.1761026343.git.xiaopei01@kylinos.cn/),
> so KMSAN must still work in some cases.  But it didn't work for me.

OK, thanks, I pasted the above para into the changelog to help people
understand the impact of this.

> (That particular warning in the architecture-optimized Poly1305 code is
> actually a false positive due to memory being initialized by assembly
> code.  But that's besides the point.  The point is that I should have
> seen the warning earlier, but I didn't.  And Aleksei's patch seems to
> fix KMSAN to work reliably.  It also fixes the kmsan KUnit test.)
> 
> I don't really know this code, but I can at least give:
> 
> Tested-by: Eric Biggers <ebiggers@kernel.org>
> 
> If you want to add a Fixes commit I think it is either 97769a53f117e2 or
> 8c57b687e8331.  Earlier I had confirmed that reverting those commits
> fixed the kmsan test too
> (https://lore.kernel.org/r/20250911192953.GG1376@sol).

Both commits affect the same kernel version so either should be good
for a Fixes target.

I'll add a cc:stable to this and shall stage it for 6.18-rcX.

The current state is below - if people want to suggest alterations,
please go for it.



From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Subject: mm/kmsan: fix kmsan kmalloc hook when no stack depots are allocated yet
Date: Tue, 30 Sep 2025 13:56:01 +0200

If no stack depot is allocated yet, due to masking out __GFP_RECLAIM
flags kmsan called from kmalloc cannot allocate stack depot.  kmsan
fails to record origin and report issues.  This may result in KMSAN
failing to report issues.

Reusing flags from kmalloc without modifying them should be safe for kmsan.
For example, such chain of calls is possible:
test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
slab_alloc_node -> slab_post_alloc_hook ->
kmsan_slab_alloc -> kmsan_internal_poison_memory.

Only when it is called in a context without flags present should
__GFP_RECLAIM flags be masked.

With this change all kmsan tests start working reliably.

Eric reported:

: Yes, KMSAN seems to be at least partially broken currently.  Besides the
:_fact that the kmsan KUnit test is currently failing (which I reported at
:_https://lore.kernel.org/r/20250911175145.GA1376@sol), I've confirmed that
:_the poly1305 KUnit test causes a KMSAN warning with Aleksei's patch
:_applied but does not cause a warning without it.  The warning did get
:_reached via syzbot somehow
:_(https://lore.kernel.org/r/751b3d80293a6f599bb07770afcef24f623c7da0.1761026343.git.xiaopei01@kylinos.cn/),
:_so KMSAN must still work in some cases.  But it didn't work for me.

Link: https://lkml.kernel.org/r/20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com
Link: https://lkml.kernel.org/r/20251022030213.GA35717@sol
Fixes: 97769a53f117 ("mm, bpf: Introduce try_alloc_pages() for opportunistic page allocation")
Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Eric Biggers <ebiggers@kernel.org>
Cc: Dmitriy Vyukov <dvyukov@google.com>
Cc: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Marco Elver <elver@google.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/kmsan/core.c   |    3 ---
 mm/kmsan/hooks.c  |    6 ++++--
 mm/kmsan/shadow.c |    2 +-
 3 files changed, 5 insertions(+), 6 deletions(-)

--- a/mm/kmsan/core.c~mm-kmsan-fix-kmsan-kmalloc-hook-when-no-stack-depots-are-allocated-yet
+++ a/mm/kmsan/core.c
@@ -72,9 +72,6 @@ depot_stack_handle_t kmsan_save_stack_wi
 
 	nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
 
-	/* Don't sleep. */
-	flags &= ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
-
 	handle = stack_depot_save(entries, nr_entries, flags);
 	return stack_depot_set_extra_bits(handle, extra);
 }
--- a/mm/kmsan/hooks.c~mm-kmsan-fix-kmsan-kmalloc-hook-when-no-stack-depots-are-allocated-yet
+++ a/mm/kmsan/hooks.c
@@ -84,7 +84,8 @@ void kmsan_slab_free(struct kmem_cache *
 	if (s->ctor)
 		return;
 	kmsan_enter_runtime();
-	kmsan_internal_poison_memory(object, s->object_size, GFP_KERNEL,
+	kmsan_internal_poison_memory(object, s->object_size,
+				     GFP_KERNEL & ~(__GFP_RECLAIM),
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
 }
@@ -114,7 +115,8 @@ void kmsan_kfree_large(const void *ptr)
 	kmsan_enter_runtime();
 	page = virt_to_head_page((void *)ptr);
 	KMSAN_WARN_ON(ptr != page_address(page));
-	kmsan_internal_poison_memory((void *)ptr, page_size(page), GFP_KERNEL,
+	kmsan_internal_poison_memory((void *)ptr, page_size(page),
+				     GFP_KERNEL & ~(__GFP_RECLAIM),
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
 }
--- a/mm/kmsan/shadow.c~mm-kmsan-fix-kmsan-kmalloc-hook-when-no-stack-depots-are-allocated-yet
+++ a/mm/kmsan/shadow.c
@@ -208,7 +208,7 @@ void kmsan_free_page(struct page *page,
 		return;
 	kmsan_enter_runtime();
 	kmsan_internal_poison_memory(page_address(page), page_size(page),
-				     GFP_KERNEL,
+				     GFP_KERNEL & ~(__GFP_RECLAIM),
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
 }
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251022143604.1ac1fcb18bfaf730097081ab%40linux-foundation.org.
