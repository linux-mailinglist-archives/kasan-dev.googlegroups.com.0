Return-Path: <kasan-dev+bncBCC4R3XF44KBBLHP2TDAMGQE5NC2AHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FD9DB9F480
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 14:38:06 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4bf85835856sf25431161cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 05:38:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758803884; cv=pass;
        d=google.com; s=arc-20240605;
        b=IteIc7nTuhjsJkeRP8EmQSJMutuFqSU8u7T1A+LvtUPlJnTz8tGm6F8mNUW4UDpnlY
         FWYwsQSZpd/qzWxcEJwIZ7ns0TYYYRdnNWUVdVAPWTctsPSONgiUCR6wisak73sN5Zeg
         JXsYGERkJPlhexwCw8vN27A/qxF2a+6HRUT3lJnq+6e9wAcgXYvPtrt9WKo9bGUjyg1Z
         LYqEst8SjKvUqQxAk2FxkvqxKS3PtLSy3UONleYPSK5Jh51isWnG6XMu4w/OOYiEq+24
         YzS2yESC/nkr20IX1nnkjNiixeGG5qYqKZZy7cM7FR4o321lBOsGZ+a0v+bPgGQIPjKR
         wnjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XF6kuWwozZXrEWzlUTJkSjV/p/BfN1itGJBAVJOUYSw=;
        fh=9/3iADo2es38me6IVE47jCrgOECubFxvmnsmERPgQgY=;
        b=WE9mow1JrIkJAtvZBf01FQUbOdmea0bAjgRtUj9+UNiYWtzZMDrs9KdKV6FkIZNv5k
         ZjwC1Tjz0erI/YRB9Kf8J/AscjL6qU3eOpadhiUIbfVfQYHXnp0oSdyCQmGhWhq2NSvo
         ATZSRzgxftiHZoefW8DZ+9uqGLcBvQKePcLYjX8s1NoXZtCUUXrltT8gI75Nh/cLqn4R
         DLe4A+QM0xmOuSaznvbGCgrJKDxS5d16YpMdMz+kcuuOrwPvjh34YeMopMgELHLoXOob
         QLDhUKYereUPFLZ6QGsLNAdJUkVD1R8jaW0hgewUc/8A5YzJnCGqNZ9+1IEHTX1TcSy0
         vxPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G1UgG+40;
       spf=pass (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758803884; x=1759408684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XF6kuWwozZXrEWzlUTJkSjV/p/BfN1itGJBAVJOUYSw=;
        b=YcVv3oJCfHZCVQepewgnxCkEvD8xYtB656t7NeH6Yem4M7vEl7ZFbCyw0A0rgr5kIm
         qfqPr9YaqtFFy1TEWwLBDHAfzf1hENkMSpvKB68Uy5ApfJWbb2IcYRa3gbUWhhhFHnDa
         4DsPb3Kruljp6Qyf8lh0/gEoZPVaIsbQxlTXVZzPuwiOwoUnBulo+Tj9vlYzE4GFACG/
         5nOZEX6MRDVCmfcQRYQwsUWZz3douzSv8BqFR+61uoKKXS6BuMwOzdGmIbOzilqzA4jU
         ErtjkuFizv7Bc1VWLpnR950Cw6dIX/XTpIMmyxPzf4OvvaZllzq+ZucY4KOSkFeq8BfF
         LHxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758803884; x=1759408684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XF6kuWwozZXrEWzlUTJkSjV/p/BfN1itGJBAVJOUYSw=;
        b=ThozCOnj0IkP9fqClp0r8RvacUKxh3MDqroHxMLUJRlvhcvFxVcKLpQ8WjoBsmkC25
         6RVxqaJb0KfqL6BPjZqMYzdH0W51pgh0Q1ZWmExGcNJ9etFWyTdU46yLWx0rUSTGdxJ4
         LW3p/w7RH4GEYRAHTQ09jQc/pE5fOBTtouJy164ZY7+4K6WQHs1cf6RVWrGQMh5ypkQE
         hLIz3yjK+p5it/1KJQX9ISWn1F/XQ8oGpMmGMpEnwsDm2ltN0E+ADInjaXMZwFfD83//
         SBoTUNlqbr7/U7o0FGmT19JjbkE1tTF83KOUgnQILyc7GNn0swbQEKprFjF2J4TGb3/D
         Z9tg==
X-Forwarded-Encrypted: i=2; AJvYcCUb57po5R4SPtr6sPNs9V9VGGzpyD6egskleiXpdYSIwtjBqxKtCJx0fxjBzUkTzoEp0RHw7w==@lfdr.de
X-Gm-Message-State: AOJu0YxYeUIQjwXXDqU+JHgoc7hpxw9AIc4zlP5Zyd50IH5lLtZtPrn0
	SJBdrBdtKgKmBG9DBG69YpLrqTADtVQ+xgs5iv5aimBSfeMORvoBDr/u
X-Google-Smtp-Source: AGHT+IEzmiayZsiRym2Eew/bN7mvA60rC8i8uO1qnMSlyEK+6UGBi1F7T1VXIHoMhl1QWM2EPKDNPw==
X-Received: by 2002:a05:622a:4817:b0:4cc:6d84:819d with SMTP id d75a77b69052e-4dac4ea6c9amr18931041cf.0.1758803884489;
        Thu, 25 Sep 2025 05:38:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6AIdCvev2B5T6/bw8ZSZjSjj0igjj+l/TIsDZqfn1tTQ=="
Received: by 2002:a05:622a:4b0b:b0:4d2:e61b:22e4 with SMTP id
 d75a77b69052e-4d7a3d8a8dbls24833981cf.1.-pod-prod-00-us-canary; Thu, 25 Sep
 2025 05:38:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8uBx+POqfYfJwHEzpar/6HhImWAbRyGQ1RHQacQNx5zWrJrVO56uiq346z8B/HCRCJbn8nEjwbEA=@googlegroups.com
X-Received: by 2002:a05:620a:711c:b0:858:8937:d7c5 with SMTP id af79cd13be357-85bc3049cc7mr300553485a.16.1758803883046;
        Thu, 25 Sep 2025 05:38:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758803883; cv=none;
        d=google.com; s=arc-20240605;
        b=bY1FQU9s3rRkVFJ3wAYiHx/oCoYw6A+BmG+uXw8L2wvEU74E/Gn5FIFDZqPC1iqq9p
         jRBlCqTBmAX0yMUoWr2kZGGWgXX8mu1d/ce5tyXc5QZ+B5v68uESGHcnmVRQToXmp1ph
         xYxZh9Zw73ObPf8oa41DXGOZ5a7WVCy91VJz7wE1t5XSRK93BXwuouyzdvPil/ckqKvp
         uuqldKMsRYcxOIdPe+5MXAEV0Tk5D9OZAieMrBGNqWWu4ab1u0uDL1n5MUfJi1/I1SQ/
         8mqGnIPV813fYvdmRqtz9R8u3gbz9OC0KE9qTfbs7//p1rTQ5VVNvxbKAkid+QC2kOK8
         tROw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mTflhHg+Amnrc4gmGWdRMi+hJzntvupMEeV0yseBNG8=;
        fh=KneJ800ia+KLVyCDLGnY3DWfDHHNesPwbKLMgoepDao=;
        b=QZCx8bx0fX/x8XzsbKNosuk1FLaT/xN6s5wQ5lBl2XNwQlFIO2IvLpIdDTP6//oqre
         Y2o4YVVIdKA6gtRbIIgcvtjO7OQOkvcnQTqSR+540PtEp0UsCWUo3xforTLXbX5sgMQW
         BkRSDkvsoPGzUn0lOsyKzXZmbOho/yAsRvPYvgH9okAOy5e6b0dW7O6bdoSJujXpfzlm
         jVjWkqLbm4Z6QFUMUIsPNBRzLwQpA2ogktY35h3ddqgFj8+iFQ58ByctPSDGIE5+RSfb
         wv4pVFaGYO9ZlXNL+3owrD51bKO6TfuxOo2iVaq7yte0PXT3yMXxde5YSRd64h+MPJMI
         qEGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G1UgG+40;
       spf=pass (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-85c1b58b4e5si5230185a.0.2025.09.25.05.38.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Sep 2025 05:38:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 60FFC60555;
	Thu, 25 Sep 2025 12:38:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F0488C4CEF7;
	Thu, 25 Sep 2025 12:38:01 +0000 (UTC)
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: SeongJae Park <sj@kernel.org>,
	akpm@linux-foundation.org,
	david@redhat.com,
	vbabka@suse.cz,
	rppt@kernel.org,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	elver@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with KMSAN
Date: Thu, 25 Sep 2025 05:37:59 -0700
Message-Id: <20250925123759.59479-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250924100301.1558645-1-glider@google.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=G1UgG+40;       spf=pass
 (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: SeongJae Park <sj@kernel.org>
Reply-To: SeongJae Park <sj@kernel.org>
Content-Type: text/plain; charset="UTF-8"
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

Hello,

On Wed, 24 Sep 2025 12:03:01 +0200 Alexander Potapenko <glider@google.com> wrote:

> When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
> for metadata instead of returning them to the early allocator. The callers,
> however, would unconditionally increment `totalram_pages`, assuming the
> pages were always freed. This resulted in an incorrect calculation of the
> total available RAM, causing the kernel to believe it had more memory than
> it actually did.
> 
> This patch refactors `memblock_free_pages()` to return the number of pages
> it successfully frees. If KMSAN stashes the pages, the function now
> returns 0; otherwise, it returns the number of pages in the block.
> 
> The callers in `memblock.c` have been updated to use this return value,
> ensuring that `totalram_pages` is incremented only by the number of pages
> actually returned to the allocator. This corrects the total RAM accounting
> when KMSAN is active.
> 
> Cc: Aleksandr Nogikh <nogikh@google.com>
> Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>
[...]
> --- a/mm/mm_init.c
> +++ b/mm/mm_init.c
> @@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *tablename,
>  	return table;
>  }
>  
> -void __init memblock_free_pages(struct page *page, unsigned long pfn,
> -							unsigned int order)
> +unsigned long __init memblock_free_pages(struct page *page, unsigned long pfn,
> +					 unsigned int order)
>  {
>  	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
>  		int nid = early_pfn_to_nid(pfn);
>  
>  		if (!early_page_initialised(pfn, nid))
> -			return;
> +			return 0;
>  	}

I found this patch on mm-new tree is making my test machine (QEMU) reports much
less MemTotal even though KMSAN is disabled.  And modifying the above part to
be considered as free success (returning '1UL << order') fixed my issue.
Because the commit message says the purpose of this change is only for
KMSAN-stashed memory, maybe the above behavior change is not really intended?

I'm not familiar with this code so I'm unsure if the workaround is the right
fix.  But since I have no time to look this in deep for now, reporting first.

>  
>  	if (!kmsan_memblock_free_pages(page, order)) {
>  		/* KMSAN will take care of these pages. */
> -		return;
> +		return 0;
>  	}

I understand this part is the intended change, of course.


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250925123759.59479-1-sj%40kernel.org.
