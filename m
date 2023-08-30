Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVEVXSTQMGQE7OWWFWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 70EE078D491
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 11:24:38 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2bce272ebdfsf58164441fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 02:24:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693387478; cv=pass;
        d=google.com; s=arc-20160816;
        b=cuFLl9vhHBUL3jKAlgWa0EQRHUTSWekBFz34b52gVCiTZtq3qkJn/TJg7lPO9N/XLf
         FLHbtBVEhUDBeNQipq619VlS59S56e03XtzV+cJfQyyuG2WDj3WZpC69m/kOQOqBTIrn
         wyxCTo/b4j7FQElqz3dRyryo8Vszm6EQ47A07pSOaGg4eR95Boaf9FDGGLGlrC6gVuJG
         p+Xoi3l/fdE36iTi+uoW40Eotec17KyKZKKtHHGVhtt2CALVNV8CG8sZvB/E7tDdYGnE
         igmAs7C8V/+2R8q6eTYkbfgqy69ZNH6GGad4Xi/tuyZLT78irqPPyp7wKW9k6x2TcUKU
         B/tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=PcjJSIAp97ycfhl6KkaSqn/3oQpf4w7SvHYymE3I+aI=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=0fZ5aQnzRMm7eqFE2MdSwobBzcvemISWD2GNX2IWy6bhbsPs1hGCzyfXvWg3eQCtp9
         H3CSBdkBZIHzhcze6Q2QtA6wPZN2NTyt5u2nBhAf8T55UdUTqlxs9LVlCbSulQOsjQX4
         Nlu3DjgppIkK07yq3mufNmhF9kcTPXO9WhKnWtx2RgoP4SJmVyYhAIy2BAVfftF2Dgr8
         GKV1lMTya6BVUzIjjnntb1G3eivWkKiIWq555kExCgxwJZU3IjaN6fWWu8PlgtONOFwc
         J69WkwpPByrGvWlrcd2AUzCsoae/LCnV+mzbIoUDOeSBPtgoHPjVFoIvxa5N0dgX7Y+H
         UPSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=uYglWNls;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693387478; x=1693992278; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=PcjJSIAp97ycfhl6KkaSqn/3oQpf4w7SvHYymE3I+aI=;
        b=blntZX2w1sNpuwlsVkcDLVj54kZs+KOcQKayzmpHC589x7cF1nHgDr8VBzIoISWi1P
         POv74cen8cNfcJ3FxaaINCk8XhGIs6FHrcDg6Va6DAa9Ns+JufYk9nZduFJMQgui2Coc
         cC9Ngs4J9c81I3kRaCBJIvCJVeLMXQAHfs0HAkhm00/fQYG0I6CprUcH7wIL1eyT4QDi
         vmafob+LHTUR+iJXh1QBUd5PuYXRI9aRVIoSyf9zLDENT7VM/SjrdcREtPLh/CmkHXuM
         CdYuB7xL/z4duxSUV6psLrhu9mUJekufR49tZEGzI0yMMeRUSG77f7duWcZvDYr1XgPG
         swQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693387478; x=1693992278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PcjJSIAp97ycfhl6KkaSqn/3oQpf4w7SvHYymE3I+aI=;
        b=BnTd3p5pdolZYwzzqT7U4LhvIk3QKU3wUCYReB4ml8tDM5VDZPgNjDK6Y8meuSsaJr
         /Sl1iNaV/naOHNrBGDFgMv9yTsV4SKSU1db0aLxWwQDM8LkvpJzWv2p/N0eL+2LhHm+J
         JttiLwglwaK6HiVnHNgxiR4X/T8WEIs5PB9WDPnNgQyKnfyTf5dpQZrwqFpR48MtEDR0
         k8HFJNFluA6anDgHzZ/Mj5PnOaUN0qegNLdc2txeurpEOWGDccCrM40CCnpPSHPzC0g6
         d45GBsuOlM2QJV292GHLILOGSH5PhMWLP8qWoNoUfqGPOq2pb7eewqCBQqVi+CHwlSRt
         qpCQ==
X-Gm-Message-State: AOJu0Yz87wte+BchrKf+TYxaKgvkZh1E9tOSCB2KiKKYtztOcTylkyl5
	YbM14QCGPwT+viXl7P49VR8=
X-Google-Smtp-Source: AGHT+IFt9oJnyQuijn5/hhj544HqApDrhCbrRc4TEtII7RKBcg2o9cPg+fZZgWaLrgZwt+to1BMlVQ==
X-Received: by 2002:a2e:9045:0:b0:2bc:de11:453b with SMTP id n5-20020a2e9045000000b002bcde11453bmr1252278ljg.1.1693387476952;
        Wed, 30 Aug 2023 02:24:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b7d4:0:b0:2b9:57fb:fcf1 with SMTP id p20-20020a2eb7d4000000b002b957fbfcf1ls1242447ljo.1.-pod-prod-05-eu;
 Wed, 30 Aug 2023 02:24:35 -0700 (PDT)
X-Received: by 2002:a2e:330e:0:b0:2bc:d7d6:258f with SMTP id d14-20020a2e330e000000b002bcd7d6258fmr1415686ljc.35.1693387474895;
        Wed, 30 Aug 2023 02:24:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693387474; cv=none;
        d=google.com; s=arc-20160816;
        b=DEuwAGfIRFvPC/pUBc3f8KkBZnkWYX2C5C6efl0Dze72YXYzo9L+wln0i6N+7t6zoA
         2E2yXi1LOOfS3WQoALvOBphDVuBxznShA6Ygt8aHlnvGGl8hWdw5VSerOEIu/H7x1iYJ
         PQzllE8cqKCB5+iFCKOGFFKSOgBPelkWnPKRNymTV6OaiO7z7mOk9bcjs0lBYRY7yQpH
         rbtZjZxkqS8L3iyDj6v18NPk8U1qG859LZkuupPBvQvCsPLpM3MYO9Fu9PROrVX7868u
         aU9ycPdz5A5U0iIvef1QmJuJs6Bg5cNeVX6dWwWhGrn8QUkCeMPmseBFuZO6T/a4sRjx
         JgPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UI7fXVlKfpB5b5W3nvIcPqt6ERVpjXtyoJBz3Uqak/4=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=F0PFen8E5naDz2YQA42cBpEWkUHecjFGw3v6q92TEQdIhnVU8gGlyiHwE5cH9SF4P4
         VCXP71H1b7oVV2RXMuYiEA5HF5fowcWl1/323Kmb+57A8Z4OqCKodyAg2yZjf1vMKb5d
         Pmz4JEEcBk1qSc6/CYZF/EK+BPh+VRMEB0bs11YNg6qPS/0/ezCV4fGJCsr06Df67fLs
         Fx0kYBJ1ctW3gzjtERCsuXi41+nePxYXKV6bMi5c8NQnAujI4w3Ohar3FJqAadVZdJS3
         4uazI2ZwAJP1a3tOZ1CsuDeHCGJY9e6cmngHCLF2HCjrIXqBmsG5ICKDuTM/4xwaeQ2l
         C2lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=uYglWNls;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id k32-20020a05651c062000b002b6f8d5f93csi786374lje.2.2023.08.30.02.24.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 02:24:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-2bb9a063f26so81763291fa.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 02:24:34 -0700 (PDT)
X-Received: by 2002:a05:651c:10cf:b0:2bb:b56b:f67e with SMTP id l15-20020a05651c10cf00b002bbb56bf67emr1392650ljn.19.1693387474397;
        Wed, 30 Aug 2023 02:24:34 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3380:af04:1905:46a])
        by smtp.gmail.com with ESMTPSA id x1-20020a05600c21c100b003fe3674bb39sm1652429wmj.2.2023.08.30.02.24.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 02:24:33 -0700 (PDT)
Date: Wed, 30 Aug 2023 11:24:28 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 13/15] stackdepot: add backwards links to hash table
 buckets
Message-ID: <ZO8KzKWszioRKrks@elver.google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
 <e9ed24afd386d12e01c1169c17531f9ce54c0044.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e9ed24afd386d12e01c1169c17531f9ce54c0044.1693328501.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=uYglWNls;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22a as
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

On Tue, Aug 29, 2023 at 07:11PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Maintain links in the stack records to previous entries within the
> hash table buckets.
> 
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/stackdepot.c | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index a84c0debbb9e..641db97d8c7c 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -58,6 +58,7 @@ union handle_parts {
>  
>  struct stack_record {
>  	struct stack_record *next;	/* Link in hash table or freelist */
> +	struct stack_record *prev;	/* Link in hash table */

At this point this could be a normal list_head? Then you don't have to
roll your own doubly-linked list manipulation (and benefit from things
like CONFIG_LIST_DEBUG).

>  	u32 hash;			/* Hash in hash table */
>  	u32 size;			/* Number of stored frames */
>  	union handle_parts handle;
> @@ -493,6 +494,9 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  
>  		if (new) {
>  			new->next = *bucket;
> +			new->prev = NULL;
> +			if (*bucket)
> +				(*bucket)->prev = new;
>  			*bucket = new;
>  			found = new;
>  		}
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZO8KzKWszioRKrks%40elver.google.com.
