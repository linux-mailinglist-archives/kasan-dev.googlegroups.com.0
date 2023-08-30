Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBZPHXOTQMGQEGZGSPPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CB0178D3B6
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 09:46:47 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-40ff56e1c97sf196741cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 00:46:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693381605; cv=pass;
        d=google.com; s=arc-20160816;
        b=hjAzQa4mEmLoLxp2FqmM6hlfU6XZLGtLuxcXCyjmMXXOcyS0NFbmqIbQnz/p8W0wTL
         SCdckctgmsLvkNlbPTnm1l6QtHDYYtDMc3d6ahLXHRPptvAJyi6QPl+e4ceuU0K81kv7
         /aWG/aqcr1MuB3xDSWMVgIYWpdb3iPnZf2zUmf/3jeKhecy3tspAQsaQ1ExLdGMhjgb2
         T1ezha8kRkwH3maRtzDJcnLH5fo9QW8fEGoi1Rj2vZF7YkPslGRJUUJ2oQg0hgyzDRkz
         w91T/yHrS8F2qr0PPTDOjrI9szt8+IwYAkhjf/yGN1ftGrrOGlvHMSzgT27/HbGrIiBt
         0eHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=VGx9zFbNX0+ZxXypSjxNLKSiP7RzZc2qIyWg8kB5EJI=;
        fh=hmTGvR8BoVXMJ8Viw/SSMi/sPWuQ4lRaxdihYWJuTs4=;
        b=Sa9Cs6gkwos480Wg/+vhs0bBG6N7EWn9j6Loli9k+JCY1S9iuOtgbp4Hv1imqRVIC5
         goTAm3vm311wAU1F6A06YMRInyKp2OWtwRzig+UJcOhQBswTCsiTaGDf4lcxslJOTgdy
         2cpOBOqaBvRj6BSpsUqSkj0G5ga/0iAul8MMaA9XN3Yhu3nzidTtPCzSteyW0dP/0C9S
         xdg9xiGwQWc3mDDpYVnI92RGPbU4HAm9KQiLZ0Co3Q7CZfxW2PYGHFAHwIFfz6fnMZbd
         j9Hg/rR/uWx66Us6OOFTHRbM4AtUiTUD0SuhEdll43lNLkuyV7TzeHTIN54Xsznuq90r
         DxoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RGKsMd13;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693381605; x=1693986405; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VGx9zFbNX0+ZxXypSjxNLKSiP7RzZc2qIyWg8kB5EJI=;
        b=ICvlLmVV1NKcu/dfE0d1W6eLwlJqp1moigSo+00xRDl9lnlIbXheZ3+hEZoW7AhU1Y
         D+vtfzsfiFrTl+/diICPgNFzdUu6iz7GUw6YmRejVpJ3v/dKsGYLjShn0gBH8YVy3hg1
         aVD3EiUrztbCqkJwsYooDp5Ldx6r20b7tLpexo62fWZjNBcsujIDt7gZ6o5JZ0XHMMv7
         bU2Mu4NvKvud34ZF8oO0sw6MCJWK7OLwwT3Ey8Hi8qhN5XPq3a2OAlNuE2la08dhn46s
         5lVPRFNP1S5AUMZEouU6n814hhq0BPrbHtB7jRwiqz2iq9K/Nh4f89HpLytU5RwgIKk4
         AKtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693381605; x=1693986405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VGx9zFbNX0+ZxXypSjxNLKSiP7RzZc2qIyWg8kB5EJI=;
        b=XaZAGaLe/IYg+2a2IZl2SVb5RMxKneQoZSIRuI+iy1yymtm9DVgVKhPVGb7hnXq1Uz
         TA14E66u2sTTzpO3CllydWo6GKqnGsZ2c6uWnLnVzFRM/N+E3QSxB32naxxdrnFP/p72
         Ow1DIhhCu8rh6NBzX1m6c7HFzv94lBwbT5AEE6ZTo20/eD56jt0jbghA6+078994FZlP
         XXZu7OwoupWM/4UiwwMXyUDjtMQdOmqQ921UrHNoO8eXMz2NDUgCWhy409MjxLmJJXnK
         hYazOaHq5OO1w21eJ+i20sFuS1z0Z8yF8gIh4qCXsZ91YRzFlaDM2+culpLFKLi5LM7v
         4ZPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywm+il0/QEA0vnHngEc/4A5Z2JZAytXwqA2UEoSAjUDbf2tQ1iD
	Pb/IqNwTmPxbKTxyI/0ul6Q=
X-Google-Smtp-Source: AGHT+IEwlx6rABr7Q4k6aFr96MvQ7ACa0B0waw1hzuK9uhwU5JR1+lALDzoToiEA3ugP8Zq+BrR2uA==
X-Received: by 2002:ac8:7d56:0:b0:403:eeb9:a76 with SMTP id h22-20020ac87d56000000b00403eeb90a76mr441615qtb.17.1693381605522;
        Wed, 30 Aug 2023 00:46:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e7c9:0:b0:d7a:e0a5:9256 with SMTP id e192-20020a25e7c9000000b00d7ae0a59256ls4257624ybh.2.-pod-prod-03-us;
 Wed, 30 Aug 2023 00:46:44 -0700 (PDT)
X-Received: by 2002:a25:cf42:0:b0:cfe:8cbf:5d28 with SMTP id f63-20020a25cf42000000b00cfe8cbf5d28mr1527069ybg.31.1693381604417;
        Wed, 30 Aug 2023 00:46:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693381604; cv=none;
        d=google.com; s=arc-20160816;
        b=ifFOh6+8Tp7Sfm2MLXhQ3WYOT8H4GENF+9+6rewk3KNAqsZ8BM+0UGRt5BIyc1VpeO
         fPbWDA2sN0Tj7R8QeX9lJxE3pxYmyA9KFtawkfpfalfYB85/tI4JuKEwoq6y8Erbv3gN
         tdxt9FXn4eYGCS89JI1/i5S8/PmAX9o8evmbqDWdKt30/g5KOVnVtmNUA8qJP/7fukZL
         3TpZ6ERWhRZwI4S2jvQ59z6ffq5Zjbn4Voh8ttMvZXR4DmvF4iX0tYodTqFXR5M2G3bO
         WnhxXGGdt+NpYi3cQZBRx0jxtczZ2LvJTfXWxmWlWtolWYp2HklO4CAqOLKu1JxDLOAW
         3IzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=EanoFzDaTgMOXfxRNHB3pneacsX9gjh73UwzM6zHsNY=;
        fh=hmTGvR8BoVXMJ8Viw/SSMi/sPWuQ4lRaxdihYWJuTs4=;
        b=KGzDxym/ys9RsthLnQgzWjR4gRffRSGnSD0UqK/Me56eDdoI8wOgBWFsTSren7AJQQ
         3aU0Ce7BJ0jTu/a9Px2oSN9zwdKd8scREN1T+//DYYn7jbqmkGFE/k8BuZ1DZ0K2xMRb
         gW+PhCpHaMevRoGXyjgQvnRlsWDdVw2AlBNszrxrNTJzr7nGy8o7H/yCCN4qmEc2BfFw
         p2r5BdlWDgGSQ3yR6G/ty4EZfUYIos4ss+5rKE5RNSZzviDeCa40Eb/rnhyW9hNGuKAQ
         tHdrd1Q3s8VEWNK5V0UHbsgOIntlXUhb66dWgIMErCUm17JWzA+yzZ3E5WVU653hpsss
         zsJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RGKsMd13;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id o16-20020a25d710000000b00d3bd00b18e7si1115718ybg.4.2023.08.30.00.46.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 00:46:44 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6A2CC211F0;
	Wed, 30 Aug 2023 07:46:39 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2EF0A1353E;
	Wed, 30 Aug 2023 07:46:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id cD+pCt/z7mTlYQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 30 Aug 2023 07:46:39 +0000
Message-ID: <3948766e-5ebd-5e13-3c0d-f5e30c3ed724@suse.cz>
Date: Wed, 30 Aug 2023 09:46:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.14.0
Subject: Re: [PATCH 00/15] stackdepot: allow evicting stack traces
Content-Language: en-US
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Evgenii Stepanov <eugenis@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RGKsMd13;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/29/23 19:11, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Currently, the stack depot grows indefinitely until it reaches its
> capacity. Once that happens, the stack depot stops saving new stack
> traces.
> 
> This creates a problem for using the stack depot for in-field testing
> and in production.
> 
> For such uses, an ideal stack trace storage should:
> 
> 1. Allow saving fresh stack traces on systems with a large uptime while
>    limiting the amount of memory used to store the traces;
> 2. Have a low performance impact.

I wonder if there's also another thing to consider for the future:

3. With the number of stackdepot users increasing, each having their
distinct set of stacks from others, would it make sense to create separate
"storage instance" for each user instead of putting everything in a single
shared one?

In any case, evicting support is a good development, thanks!

> Implementing #1 in the stack depot is impossible with the current
> keep-forever approach. This series targets to address that. Issue #2 is
> left to be addressed in a future series.
> 
> This series changes the stack depot implementation to allow evicting
> unneeded stack traces from the stack depot. The users of the stack depot
> can do that via a new stack_depot_evict API.
> 
> Internal changes to the stack depot code include:
> 
> 1. Storing stack traces in 32-frame-sized slots (vs precisely-sized slots
>    in the current implementation);
> 2. Keeping available slots in a freelist (vs keeping an offset to the next
>    free slot);
> 3. Using a read/write lock for synchronization (vs a lock-free approach
>    combined with a spinlock).
> 
> This series also integrates the eviction functionality in the tag-based
> KASAN modes. (I will investigate integrating it into the Generic mode as
> well in the following iterations of this series.)
> 
> Despite wasting some space on rounding up the size of each stack record
> to 32 frames, with this change, the tag-based KASAN modes end up
> consuming ~5% less memory in stack depot during boot (with the default
> stack ring size of 32k entries). The reason for this is the eviction of
> irrelevant stack traces from the stack depot, which frees up space for
> other stack traces.
> 
> For other tools that heavily rely on the stack depot, like Generic KASAN
> and KMSAN, this change leads to the stack depot capacity being reached
> sooner than before. However, as these tools are mainly used in fuzzing
> scenarios where the kernel is frequently rebooted, this outcome should
> be acceptable.
> 
> There is no measurable boot time performace impact of these changes for
> KASAN on x86-64. I haven't done any tests for arm64 modes (the stack
> depot without performance optimizations is not suitable for intended use
> of those anyway), but I expect a similar result. Obtaining and copying
> stack trace frames when saving them into stack depot is what takes the
> most time.
> 
> This series does not yet provide a way to configure the maximum size of
> the stack depot externally (e.g. via a command-line parameter). This will
> either be added in the following iterations of this series (if the used
> approach gets approval) or will be added together with the performance
> improvement changes.
> 
> Andrey Konovalov (15):
>   stackdepot: check disabled flag when fetching
>   stackdepot: simplify __stack_depot_save
>   stackdepot: drop valid bit from handles
>   stackdepot: add depot_fetch_stack helper
>   stackdepot: use fixed-sized slots for stack records
>   stackdepot: fix and clean-up atomic annotations
>   stackdepot: rework helpers for depot_alloc_stack
>   stackdepot: rename next_pool_required to new_pool_required
>   stackdepot: store next pool pointer in new_pool
>   stackdepot: store free stack records in a freelist
>   stackdepot: use read/write lock
>   stackdepot: add refcount for records
>   stackdepot: add backwards links to hash table buckets
>   stackdepot: allow users to evict stack traces
>   kasan: use stack_depot_evict for tag-based modes
> 
>  include/linux/stackdepot.h |  11 ++
>  lib/stackdepot.c           | 361 ++++++++++++++++++++++++-------------
>  mm/kasan/tags.c            |   7 +-
>  3 files changed, 249 insertions(+), 130 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3948766e-5ebd-5e13-3c0d-f5e30c3ed724%40suse.cz.
