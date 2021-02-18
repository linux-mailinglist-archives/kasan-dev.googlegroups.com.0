Return-Path: <kasan-dev+bncBDDL3KWR4EBRBCMLXGAQMGQEQ6RKSMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id E923031E888
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 11:46:34 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id d8sf2207928ybs.11
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 02:46:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613645194; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gzwkisl6P51De7lauCkTZTPF/V8Wn/t1C5xDAkn25yC8ytvXahzTKtJyk7cNywM70z
         v16HnfwVeU7gsfoTUrUWVHu9rUONf5rZj7AOnt70qpSEz6gE6dJJCCkBv0PEU/DJJYZ2
         g3fcCfHr+NGQCcETKORKDBjWY9AEzoeKgE9QSr8XyZeT2P9yG2biV96v89wJmQy4Uoz5
         ZEyGi6RagKigfy5GoucLEKhB4Z2s3nLGjNNJtfLIrsnvzQerXqx7liwfSS3gOKE2Sqqn
         vzhzXoLwgMgKOy9f/9DGBGI0TfyN5wKnZZKbWYBKuXMHp5brJ6enW059ToejtTRRYVv6
         xB6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=VqJKEu+g8dgBkqWnUG+/O5ff1bVafZ7I1DP7QmKp/pw=;
        b=dZS1RY6qM0IGLl83K5i5bY4mH52YHJ2p5/ktJ4aDBqjaJ690UdRow7CCJkoDzYqp8y
         wGTs/U8rvv1URVm6F57rXQHCopy6GW2y22y/SDpTplyAKfPNOKeRPgqUJ/grKCrWa4Hl
         eUzgRqSbrhugxNV81A6iHkfY4d7WRTKL/OlYH6wpGP6UreJkzTB52lR7c9sMU/VoTZkl
         LtAZFZo5OwWJFxxrNZ+p0tMEUgRrzYI8kc42KXrro0hPskvNxps5nxyt11X1zBUSZ398
         HbYA8/ictdtnQZemG2qPa97S7cbiPcZUYQp84ebVHYITZ1KcDjOsgyRuCR1U/bRCUQLW
         Sxdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VqJKEu+g8dgBkqWnUG+/O5ff1bVafZ7I1DP7QmKp/pw=;
        b=APKs3IAb4I5bmnU3VZo4odNxSJKiFwVE/3ldgVupqmM9HIDsG0naz37eI43TgO9cOd
         ANRTgx9QC09KNxZENIn8Tc1vpI6//T1tlBFXppmmj3BwhwQ+8C6zxGXZf6rHgNN2iMAQ
         BmU4RHxjwy+fJEWNQe2Zfoq74w7YymC/iH6igZgHBq5di7HngPDW+gvV3AdAKdeu33W2
         FrellkhbHTU7oNKQvA3ASWgYL8EB9Ahk/Lg13OeJaNBI9h+8NsEHdnvnLpeVoot6JghA
         0gKGVM/vtdA+8fXDpk5zZLN5gjFNsYcYCtYmCgnH6VbmZ+GXEPP+Y7o2cyAYX9gxQmwN
         Fvdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VqJKEu+g8dgBkqWnUG+/O5ff1bVafZ7I1DP7QmKp/pw=;
        b=ITNyOtGRYDcHXzU30k35r1Y6oQpMQFexsk3tBKIgLVC29u6zuUPh+en4uSJuJ1eLXR
         JHwtPGpRb0Rh2NV72lPwDdtI0MzxpcDMPpgrVhWyLJA56EA+2pOIgikMAR8nzAFmxvry
         AxfDTfi5C0t7fP9VTr4N/xH8RlYD1RgpS6KiLjxvjb4qrrlidi8/BEBYRITI2zgvL0cB
         YKA6lQLp/DJUA/o/T0UgY8WW5GN16YFroKquCFM9WjYUVaSjRUnx7S9EmnPwc2UvQtUA
         ni/fu+XTYCnWCn3+cg6RQek2fZPzTu9ZpcLij9mgNGcwBvlK4hcSOlzj/CL6Z6EwfUJX
         SenQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vmtq3lLJqRJpvuX1BFwH+WiDkYwyxbibODj8qU9oqB5T3+S6H
	EKgTIqH8JwT5XjykufG+/9Y=
X-Google-Smtp-Source: ABdhPJz2uXBgvJOVUnNpOaztzJTOLkdagWsJe+ERPNZRESL044/05IZIvmfyNdGVqVH4/b5U0HCRBQ==
X-Received: by 2002:a25:4fc3:: with SMTP id d186mr5083944ybb.343.1613645193828;
        Thu, 18 Feb 2021 02:46:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3b57:: with SMTP id i84ls2749187yba.2.gmail; Thu, 18 Feb
 2021 02:46:33 -0800 (PST)
X-Received: by 2002:a25:1457:: with SMTP id 84mr5941091ybu.74.1613645193374;
        Thu, 18 Feb 2021 02:46:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613645193; cv=none;
        d=google.com; s=arc-20160816;
        b=To3cuKNeUr/jNKKF5FxfPQEqhfR/3j4O7YgI3SV1dyk5v1Z02OVFzXUKs6y7eiqGPV
         5lEn8wJMIhy5fusJLuOTLYAIFHJ9BnYwcyiMKERqT4/h3QAUVwYppAA2UN/GSL0h7XRI
         i9yyLxF+sUAMzZ3aWCHOOVGbfLv0RUhOAbiOmc3FNjfNMnvqCpTYxKpliFWY+qEhs+Qa
         AKOZwO+/KZ0K+8an6l2+3oIy4YHXx5AbK6k7zd1Sq1vs5tmumKjgPiQwHILPl6w9Rmrd
         +M9KSxMKbgSNCtv8bDFKOvfwYQn5b8LbN4RdHx0qDCwxHrQSGkBLPWMjQtRgnLhPh47o
         41hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=nMuJpiIUKPuppxPO0TqQZA+suJ4G0Tl3fdwxHhhlFA0=;
        b=EEKKHSveEgae5DMfes8AZ44kxfiBfK1bQ9IQiJ4D3ppFVh6jAfxHqvtWqdA7WmByQQ
         In3JWOby4UZzMR57iLK7MCCh0J8ATPI6FwE1ns0KvfHOhMCbi+cDP0X5jjR+AFztPbv9
         BwdltCcKthimqItK9+9+LKiPPvlDmDAbN8jBgDQFuLaOiDhg9dwJRFEjqf/ZT8DmBw/s
         1w8ZjXwXoTaR8ldl7VFN1vRr/icBTf8ya403d48cYDnoVyZ0ktsyEtdt7QPb4rEnuWSB
         wYfekpMkptOo4JDdu6OPCQsOxrr8bF/6S2l8YlSE2ktTLwyKJIukI+Rz8W6Y6PV2KdcB
         aNmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e143si270600ybb.5.2021.02.18.02.46.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Feb 2021 02:46:33 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 827E864DF0;
	Thu, 18 Feb 2021 10:46:29 +0000 (UTC)
Date: Thu, 18 Feb 2021 10:46:26 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH RESEND] mm, kasan: don't poison boot memory
Message-ID: <20210218104626.GA12761@arm.com>
References: <8d79640cdab4608c454310881b6c771e856dbd2e.1613595522.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8d79640cdab4608c454310881b6c771e856dbd2e.1613595522.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Feb 17, 2021 at 09:59:24PM +0100, Andrey Konovalov wrote:
> During boot, all non-reserved memblock memory is exposed to the buddy
> allocator. Poisoning all that memory with KASAN lengthens boot time,
> especially on systems with large amount of RAM. This patch makes
> page_alloc to not call kasan_free_pages() on all new memory.
> 
> __free_pages_core() is used when exposing fresh memory during system
> boot and when onlining memory during hotplug. This patch adds a new
> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() through
> free_pages_prepare() from __free_pages_core().
> 
> This has little impact on KASAN memory tracking.
> 
> Assuming that there are no references to newly exposed pages before they
> are ever allocated, there won't be any intended (but buggy) accesses to
> that memory that KASAN would normally detect.
> 
> However, with this patch, KASAN stops detecting wild and large
> out-of-bounds accesses that happen to land on a fresh memory page that
> was never allocated. This is taken as an acceptable trade-off.
> 
> All memory allocated normally when the boot is over keeps getting
> poisoned as usual.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

The approach looks fine to me. If you don't like the trade-off, I think
you could still leave the kasan poisoning in if CONFIG_DEBUG_KERNEL.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Just curious, have you noticed any issue booting a KASAN_SW_TAGS-enabled
kernel on a system with sufficiently large RAM? Is the boot slow-down
significant?

For MTE, we could look at optimising the poisoning code for page size to
use STGM or DC GZVA but I don't think we can make it unnoticeable for
large systems (especially with DC GZVA, that's like zeroing the whole
RAM at boot).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210218104626.GA12761%40arm.com.
