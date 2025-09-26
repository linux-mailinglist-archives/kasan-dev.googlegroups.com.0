Return-Path: <kasan-dev+bncBD4YBRE7WQBBBDF327DAMGQEN3KKFWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC7AFBA20D2
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 02:25:49 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3f4fbdf144dsf841117f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 17:25:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758846349; cv=pass;
        d=google.com; s=arc-20240605;
        b=K43DWr8RvRtvZI5OiH9WQrHMVQJFKITDi+jrT5KCEZVW2s5t66KmTEBFgzabiYXcab
         Mspc4NlvLIzCp3znQnSfK+JBMTCY+NKK8/SJUU0rji1o7T6CTfqc6ZAckEwIZk3B4dy0
         Rg90QXmqwpPdIqyBoOql1LGONMnCCLdI1EBiQGAQu3Vi0mynRFLFyZZvrxMMZ39enPX5
         Sm4bUFT7WRHLOAcafm3swMpVzJYeq1ivG69oKfdTR41bli6ptJv9ThV/oTEz9xVQ7KUo
         A5n0sCrLeni4lDle3sdz/kWhhHwO3Wzj3SPww3PPfXENzZnGftL/7QnfU+EbBbpaqKzL
         /HzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=UTc4uJqwGAT9/2eayF1Dnoo3sS68UCEpSCRKS/Fpxjs=;
        fh=f+fTyxRf8mIznKHit/Z4Do3QSo6ovYZrhWSWab3BGXI=;
        b=EnJuoEUcRTOAFX9V1gYvgsIj/uyxr58UcFBCOKFl1rGviCkseiT3ceojvcDhu9wpTY
         sTvEIyDxZJxmxQoVd7gviSYjgeWdIxMbHYP+o3TIwt7f8Cl8nE78RD0fBjKWw/mPTGfJ
         mUPB9yAScSrRcG6ErBg5j+1IYKwUyZyRRs2y7kqjsTH//S4UTwi15u3FPXjIAKvVT1Eq
         9TlcIC3H1Ph9NrdMhklcsaL+0dcdtHfCci9otb71aEogEYR8i3a5xuAv6knYBCenyIGQ
         g6SMbGK4afro5G5oeTM63ZlU+R+Y1lVyhO/Nc0EVvPNAGCdVrzduYdvF0YZd/NPQINca
         NYmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YoiKRnsL;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758846349; x=1759451149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UTc4uJqwGAT9/2eayF1Dnoo3sS68UCEpSCRKS/Fpxjs=;
        b=fnMSTgSFBEMZPL+cM2rzswfch7JXvn2/PVqDZ4Z3m2HPjKnio4vmwoiiAFfX1MzKov
         XlhyAUInMcouotBUI44kA3rc+M78NeeBRBZXp5ojdSGxB4FwSiq/RmTLEjX4OGnFb4NT
         nM9YwKKZGC2cfLoWeE1NZi48RJh4SeaCbKmSHLPH9FYTjGwyGy0AVNrkHDdT3tn3OlDy
         mHalS+nuS/NXo6P2DISNFbBKDrSsKHAewd7w9Zlt/IsNK+LUVZD7EYn1j2PW4rMIoTeZ
         kz28kFPnn5E9A+tMjceyuGIYJC2UqgHPgfQ6yWT8Fsb2DzbdJ3ua0N1S+9ekSiXFxrCH
         zrfw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758846349; x=1759451149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UTc4uJqwGAT9/2eayF1Dnoo3sS68UCEpSCRKS/Fpxjs=;
        b=Kr2ZA0WZW2mQxouML1MnEuOoEe3WWPyTNoLbIg4LXNH6LFRUCJg/HvaqQ/X0uEyclF
         PDQa2lDDikyuyF6yD0S1wQccGZggnxjBoprGagyUtHlu2MWoulu2U7U3jyKI8IF19tno
         BtV1udrR7qG+a7I/Xcm+PZHMpltAC8Brhw9b5uG+eOXmf8N8Tn1/2lZsfQu/CLAN0jsp
         ea5xi4SwOrATHRx3wBdf+9cfr9b/g0JNQIIBMdXI0zh6ywTc0n6KsX5b3ZWarF7DEgKG
         rzgZ4V53gxiqw+7vgmyWLNinyQYqJ5gmjqBTaEhdugv0dHAaLmRRDSSDC/+Bys8z9W7V
         3pNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758846349; x=1759451149;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UTc4uJqwGAT9/2eayF1Dnoo3sS68UCEpSCRKS/Fpxjs=;
        b=qJYOsoCWlpCsI2T93Suwyi0FJQ2LGQiAw86ToqMxYdawNTUqhBkYoxlxTEF4DfN/L6
         Px35hNCRGKSije0CHpEOdr4AUpE3sO4PN1IZSt/IydZgOJTeDzvH7qJZClqgyxHlpvM9
         dw/ucGHfd3gBd+lCxDL+PuBJqtSMrJl4bsetp1vizOrLqZJafxacvYa7btFgOQXL4H8C
         poQVtGhfmjeeC2aK+7Cw9WExXM0AiR0WS+6/PlsOzJWXh78enXRynx1OiYZhBPVgTdNp
         wc0Y0lVQ/PxPhrRrsjkN01BXbpvynrqV/vu3b/77iit9I27hVQWIexuyNlnnYKKsJgaj
         u86Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVEb1gcLLTTu0CWbctFJPP0HkzsqePsYlxO5LttZihm93HxIrjV4/kzOphOWNdV36R/vHEAEQ==@lfdr.de
X-Gm-Message-State: AOJu0YxTLlVxwis7LOuKZ3vRSwQ9mfsUsMzW8hjHEQrmu9/sdk2PqnKn
	PtPYbHFMsJJ70an4Qjl+rbHqnom23UG6SQn8EHzeyNUDCR/zMpzCD26F
X-Google-Smtp-Source: AGHT+IGLgHrQzpN9a9WJmcrg5G15V9kj86bny5mq5CS11yhaaA65MNsfxU1HxObo0jDRHT/qhXkL4Q==
X-Received: by 2002:a5d:5d0b:0:b0:3ec:db87:fff7 with SMTP id ffacd0b85a97d-40e4a9ee4aemr4562186f8f.26.1758846348681;
        Thu, 25 Sep 2025 17:25:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5DM/VJ6n5xX66836czXP5j57iNKnBfMWJp1tjNpjCcWQ=="
Received: by 2002:a05:600c:154c:b0:45b:6a62:c847 with SMTP id
 5b1f17b1804b1-46e32dcfd37ls8934195e9.0.-pod-prod-08-eu; Thu, 25 Sep 2025
 17:25:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWi7unMIZnSzV245Vxk289JucVXwqLyfj6uW8t3lcp03HYDfII/xNj2+/VkmPe/ALXbzxilGwtjPA0=@googlegroups.com
X-Received: by 2002:a05:600c:4511:b0:46e:1d07:5cac with SMTP id 5b1f17b1804b1-46e3292451amr53007215e9.0.1758846345299;
        Thu, 25 Sep 2025 17:25:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758846345; cv=none;
        d=google.com; s=arc-20240605;
        b=MsYRFJFYnR+WGxWsnYL2naZpIPS0ht4S6fprTiTVc1ZPH4TFF/kmPaPi5HoiQvg+9a
         jT+KsNaBoHZ6rhTLKg72+y3/iQLS5/gHoKO0CfOoE+V+maEjQyS2zXSkr1YAS/AuvozH
         oGXxZlcpZOoVIdg7bNpjOUtKG4XuSKXZPKM03k1KY4FfBPp1PAUSKMsVw46xlNg+OOyp
         R4e6DgoUgwzSc8P/Nt+/KRZdlHPCmM2yjbopzUQLuZupFSRglIALKwiva/hgn0kIwkTf
         G6U1bS/6IOgPGkY7TquZ5wyJKtEBw7X9MY28Q2W1MMJgY+5nk62iuuucmDTANSjmULF8
         quXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=NMC81w+JaNK7q2bunYAj8hHN6HLRojIWD4Z/O2pUXCA=;
        fh=5kdSue04YB9ETMILLRQJ7NkCGVo5ApqlSR2iVjDYoYg=;
        b=JPahpMqaPXR3JyxzcoPAxUiH5qH6gfcvnmMYB6nlVV1nTnZ0yhpXYMHHLS1jywT7Qn
         urA8qRpHBj0Jrd4Iyl/A0c+8KR6A34pWRd0UpXfH8m+Mtgi4py0Ihe8SD7FYSf9Zvd96
         IgSZ0iTO+wTHkSG0c/RIp65VWuR/RzM5dijIEi/cMMqH+qO/zmnOky0GLk8vY5bVQoqH
         k8uiJZdI51TmrBiE7S5L69UOMFnm29GaxLFr7xX0LWC8kQ6ECqR7vOzT4pwUfUyxCsLe
         mNt8cbT3HyXCgRVKeiEe7NCXcX3duRReknDS/HAndn+Ady3D8qsB9HSYbH3+avVV4yIe
         tgpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YoiKRnsL;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e32b4f4dbsi806265e9.0.2025.09.25.17.25.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Sep 2025 17:25:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id a640c23a62f3a-b3727611c1bso151673866b.1
        for <kasan-dev@googlegroups.com>; Thu, 25 Sep 2025 17:25:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXYJDAuFFw5tMeYJbc45Xqmwh5OsVnQr1u2414sPn0Kyxbr8jEvmFguUUH/7QVEifzyqrLncoO2eWc=@googlegroups.com
X-Gm-Gg: ASbGncvF4gPUrycx3NiB30hR+4TtFU6ZXDQHl40uq/kgBHh4UX7d8KKrSLoQj5F+jQG
	hSVhZ9lDREGTbt1JwZCu71GeQWqJqEc5RKFtnJRq+RHLKDyLuwaDRqNOHk+nfUTIKrHMKMnOCD5
	+mRrXFic2pe+FmVBJi0lT33m9ZnaxixWgUvFuUXwi/Eng3r+6lq/MMI2GwtIBH86DZ1mgdfXTLf
	yaqmLvqqXXBPruGiVdHKqUPekStFo8QsT3n2FbsQU7sL7cbAZDO1umcgrzge2bdNu8qRmpMwrBL
	BvU/1YNGLRjxN+TezRDa6BgYmThb8uc4jkA5DYbKPQ+mQkneWBSoUrscBQH2RDs7nq0RtLVKoGW
	Dmzjhl9OuLX4GSUKPoddaVHhqTzEL+FSLFFxY
X-Received: by 2002:a17:907:7e88:b0:b0f:a22a:4c3c with SMTP id a640c23a62f3a-b34bb41ad93mr619135966b.48.1758846344556;
        Thu, 25 Sep 2025 17:25:44 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-b353e5d2ddfsm260259566b.14.2025.09.25.17.25.43
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 25 Sep 2025 17:25:44 -0700 (PDT)
Date: Fri, 26 Sep 2025 00:25:43 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: Mike Rapoport <rppt@kernel.org>
Cc: SeongJae Park <sj@kernel.org>, Alexander Potapenko <glider@google.com>,
	akpm@linux-foundation.org, david@redhat.com, vbabka@suse.cz,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com,
	dvyukov@google.com, kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with
 KMSAN
Message-ID: <20250926002543.fwkf5qldhkapcmqr@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250924100301.1558645-1-glider@google.com>
 <20250925123759.59479-1-sj@kernel.org>
 <aNVWzaxq82UI3wWO@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aNVWzaxq82UI3wWO@kernel.org>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YoiKRnsL;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Sep 25, 2025 at 05:50:53PM +0300, Mike Rapoport wrote:
>On Thu, Sep 25, 2025 at 05:37:59AM -0700, SeongJae Park wrote:
>> Hello,
>> 
>> On Wed, 24 Sep 2025 12:03:01 +0200 Alexander Potapenko <glider@google.com> wrote:
>> 
>> > When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
>> > for metadata instead of returning them to the early allocator. The callers,
>> > however, would unconditionally increment `totalram_pages`, assuming the
>> > pages were always freed. This resulted in an incorrect calculation of the
>> > total available RAM, causing the kernel to believe it had more memory than
>> > it actually did.
>> > 
>> > This patch refactors `memblock_free_pages()` to return the number of pages
>> > it successfully frees. If KMSAN stashes the pages, the function now
>> > returns 0; otherwise, it returns the number of pages in the block.
>> > 
>> > The callers in `memblock.c` have been updated to use this return value,
>> > ensuring that `totalram_pages` is incremented only by the number of pages
>> > actually returned to the allocator. This corrects the total RAM accounting
>> > when KMSAN is active.
>> > 
>> > Cc: Aleksandr Nogikh <nogikh@google.com>
>> > Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
>> > Signed-off-by: Alexander Potapenko <glider@google.com>
>> > Reviewed-by: David Hildenbrand <david@redhat.com>
>> [...]
>> > --- a/mm/mm_init.c
>> > +++ b/mm/mm_init.c
>> > @@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *tablename,
>> >  	return table;
>> >  }
>> >  
>> > -void __init memblock_free_pages(struct page *page, unsigned long pfn,
>> > -							unsigned int order)
>> > +unsigned long __init memblock_free_pages(struct page *page, unsigned long pfn,
>> > +					 unsigned int order)
>> >  {
>> >  	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
>> >  		int nid = early_pfn_to_nid(pfn);
>> >  
>> >  		if (!early_page_initialised(pfn, nid))
>> > -			return;
>> > +			return 0;
>> >  	}
>> 
>> I found this patch on mm-new tree is making my test machine (QEMU) reports much
>> less MemTotal even though KMSAN is disabled.  And modifying the above part to
>> be considered as free success (returning '1UL << order') fixed my issue.
>> Because the commit message says the purpose of this change is only for
>> KMSAN-stashed memory, maybe the above behavior change is not really intended?
>> 
>> I'm not familiar with this code so I'm unsure if the workaround is the right
>> fix.  But since I have no time to look this in deep for now, reporting first
>
>With DEFERRED_STRUCT_PAGE_INIT we count totalram_pages in
>memblock_free_all() but actually free them in deferred_init_memmap() and
>deferred_grow_zone().
>
>So returning '1UL << order' is a correct workaround, but the proper fix
>should update totalram_pages in the deferred path IMHO.
>

Maybe I did something similar at [1].

But this hit a problem for shmem, since shmem_fill_super() use
totalram_pages(). And before DEFERRED_STRUCT_PAGE_INIT finish, the size is too
small, so it can't boot up.

Per my understanding, shmem_fill_super() could be invoked after
memblock_discard(), so it is not proper to refactor to get ram size from
memblock.

Could we adjust shmem_default_max_blocks/shmem_default_max_inodes use memblock
at boot stage and use totalram_pages() after system is fully up? Or any other
suggestions?

[1]: http://lkml.kernel.org/r/20240726003612.5578-1-richard.weiyang@gmail.com

>-- 
>Sincerely yours,
>Mike.

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250926002543.fwkf5qldhkapcmqr%40master.
