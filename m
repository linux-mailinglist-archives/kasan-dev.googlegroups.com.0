Return-Path: <kasan-dev+bncBDZMFEH3WYFBBVVN2XDAMGQEMVMKU2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB3BBA0123
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 16:51:04 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-78efb3e2738sf20731446d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 07:51:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758811863; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q7I2HmI08sXAqWrEFHczly1X2QAUmZwdb/a//zoApwKUKavoD7fMohix6hvqRWu8xp
         bbybJ4xpQu5fz4WMJaoMkgZrSb0mv5QSsx2jzkELHSiejw7LnDKkYTgUoub6wsJE3LVo
         pCfMNRXtmpQvjZKH2VXWWd2tc7jtK4OtJEaIBWTH0Noot7KgVvE+4VP8vjDO3wcmEsmE
         yr21MolulPNW/2Fg38DgbaqSRA11A0SnGIbU9diHHDTrjlBfbms26IfSxkw8NmFtMT3m
         uuAFD9b5icZ7oMUGJCyk5+0SKs/mRXy59uO8XEHGcFGL2SD59XQ/UT23Mpd3w7GUwE7q
         vXLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CQvic1q4w8jPRPIGTD6caTf43I92y5q/Pc38UDlHLH4=;
        fh=7sM+77jIEjpea5IX2g213qnxC49Z+080zCqNT130jQY=;
        b=fDbRdUAcrUIDWWYV0dGCi9DBHT1HSilz/XSiRFGR73EirAv8EcUZ8aZnfHqihrL7Yq
         NJgQMXuqYhcDXKJ8l5xxZqT+34uB14sWuCZo0zSwdeUCMrXuM5cWbyf+XSFJeJmzzlcn
         H4Z0li+xz1fMXXcTHe5oielfrY77MfJoHVRQFQUbTfalNL7Iam4KFkpdgPiHVkO2iXIL
         O5NPPF1n+ou3JRG2mcYRqakYpbF/AjeMggF2ah1BWzraTZP7/t2/7R/ZI4uLlh9/j2Ir
         ctSVEPl0vzNNqeZQ7kbc/OafQ6nNam6Nbbf/QY7Lt3E3xvk7a5dF6JjYT4haV+Rs/2Mn
         /XTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VIupcSCT;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758811863; x=1759416663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=CQvic1q4w8jPRPIGTD6caTf43I92y5q/Pc38UDlHLH4=;
        b=tqY/q3EXcQ5lzk+f4a990myPDFMONsICDIZL7W7TZnBWEtsINLrVd1Lt0juAahH2ue
         GV6r2DmKrNV92rD5EjIXEIYXNqU+BKm3BUMJNG+8Ho+7fJ78Y2L8qHR8WJoCmcTNdNLI
         3oDin80+Sdv7iJAN+HmmkRQlInuJOGicuOMxJj3ONjtnByAxXUc9OMdjvgf3K/HPoSlA
         LUAyQ721Hq69jHj1VQZ1mmZVXsEVVEQ7ilEhnncXL3SSYYTbCpw1fqZLDU14bGCDqrHl
         yLuxb/+fG5umuAUiennjqENn+DIDtqCKnlk2bGAbLJg2xrsVVl5wYtavqPgbPcB8AGd8
         GitA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758811863; x=1759416663;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CQvic1q4w8jPRPIGTD6caTf43I92y5q/Pc38UDlHLH4=;
        b=lJjnerIHZz9CtMw5HZn3Xc1swOlpbD9kdYpP49/L+HG8jO8E/bqmspj6fFoFjCpudV
         zRiSWfqiHlGq7b4NGQfoUkh6SFBfQxA5H1SJfJAnR6b6yIqc/WRj1nER+xM4zi0akiat
         +MZisQ7xwK2sANkt2UoUwYDVlplZwxK45AWTSbrPezAHxIayBFzGQFcBDTCJ8b6XgooL
         mWP0cSnxMlP8ZArcFN3Fx8VUtCHpA4PSH1frUXtsEeP46W5ZqsvHDyG2DbqQmcAL2j3q
         3sJ3p2EJbL+mUSre4nZNkbcIUFR4lEyGPUM8/49gIMThSlOE5mMwNo04BpLT8AZM+2r4
         SKTQ==
X-Forwarded-Encrypted: i=2; AJvYcCXpoYQ1c9nlTkoRPDVEGAK3/A04iQ0qbCummt/dIHil9qbOWoP+bRyujfB4LcWeINKp3MMrBQ==@lfdr.de
X-Gm-Message-State: AOJu0YwhbkCnWxsngMsSAoC4NGZLM6MvG/kSVYV5wu6ewnBS8P5c5ZR8
	CvzSMq8ob0kLhfPC3HknKL4JPN89WpLyTWARobvKb+KmtUQ67560id+j
X-Google-Smtp-Source: AGHT+IHExWUAYmrZa58KpQz/a3iXdL2nYus/4XLa0BbBKVzgfLsDfgSUs4ruzk1+gWMV/Rmj4pxKcw==
X-Received: by 2002:a05:6214:d8c:b0:721:812a:e6f0 with SMTP id 6a1803df08f44-7fc3f52e78fmr55292156d6.38.1758811862732;
        Thu, 25 Sep 2025 07:51:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6IIinj3XN8L39cnAlnA188Yr9OZj0rXi7tbDQ5kVTVpw=="
Received: by 2002:ad4:5589:0:b0:78e:136c:b6d8 with SMTP id 6a1803df08f44-7fd7f9730d2ls17416506d6.2.-pod-prod-07-us;
 Thu, 25 Sep 2025 07:51:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQ6YdeLwsIENU22PstZcSHqRVPJ/b1d/y5ByKzoVk8DVYsylKeqXRXVbyAqwMgQL3s5oRzo1SloAs=@googlegroups.com
X-Received: by 2002:a05:6102:2924:b0:52f:12b3:4505 with SMTP id ada2fe7eead31-5acd624798dmr1704119137.23.1758811861876;
        Thu, 25 Sep 2025 07:51:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758811861; cv=none;
        d=google.com; s=arc-20240605;
        b=VoU7GuWzjsoT/S6ChksHyhQFm8KyfnMp1tAiEqdH9fxifbFUL5VkQnz+DLk3yj9lRj
         bl/01eDw+2aS9vxTNq0CN5iqgc/sHlwQUZyy/vWa3lXc4Bn5qipgrjY+r97sTDQhakhX
         vpu3+GDtoayUlwDO+gAdRiOYOTQxQfGQQ7RqTXl9IKHSjEkZ4E3rGlSRsc3UDsIUyoVz
         Qb6d/d6bwS1/mC54mhg+LWcdbtPilMPA4DUEjpG94mLCVIDzDYAwzZt4aZBxk8v1Jwal
         Ce2hmpn+Z1hX4tNUj8eZdVYaqHxy3W3pZzvkM+WA6a7HP4L++X90ILw1H9pCTXCQaO1z
         9avg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+Nm7KkRF3KWMNrOa4fDQBFrmMYTVBsI2qgUFaE+AmVo=;
        fh=F5QVoid1eVTO/wRfnPUM/B3x2plSYoZEji1pL3T59Fg=;
        b=lvmwgXh5IGZUd/IFmpp00iXq1DwR9ttUYAbWrtilNuzf6ZTJTIm4vl5AUgwMtj/Q+U
         kLqfgYOte0/3W/qCLPFrdLjC/XXHyZkvDkILA/zeRuuC3mxE6eunzdRE+UVXWz5eM4zj
         zvM91m2xp3Hhwt+HjlZQ+YRbl2/0FxcUIt4mn3HD7kjgfE/kFPA41JauI4V7WyCV+to+
         H83Ud+WSj4mZ5elHnRe9SM+Q1G7Q48T3931xYppm73qeOP9btzCXRXd0NiDPAM0ciT2E
         P76rQDPdTnORy4lS7CdmgrTvs1iQZYi7/3KTtAMBGIxJySwKNMt8kPiaG+70iy2O8TMr
         8B2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VIupcSCT;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ae31ee650fsi83515137.1.2025.09.25.07.51.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Sep 2025 07:51:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 33CED605E9;
	Thu, 25 Sep 2025 14:51:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 53405C4CEF0;
	Thu, 25 Sep 2025 14:50:57 +0000 (UTC)
Date: Thu, 25 Sep 2025 17:50:53 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: SeongJae Park <sj@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, akpm@linux-foundation.org,
	david@redhat.com, vbabka@suse.cz, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, elver@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with
 KMSAN
Message-ID: <aNVWzaxq82UI3wWO@kernel.org>
References: <20250924100301.1558645-1-glider@google.com>
 <20250925123759.59479-1-sj@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250925123759.59479-1-sj@kernel.org>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VIupcSCT;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Thu, Sep 25, 2025 at 05:37:59AM -0700, SeongJae Park wrote:
> Hello,
> 
> On Wed, 24 Sep 2025 12:03:01 +0200 Alexander Potapenko <glider@google.com> wrote:
> 
> > When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
> > for metadata instead of returning them to the early allocator. The callers,
> > however, would unconditionally increment `totalram_pages`, assuming the
> > pages were always freed. This resulted in an incorrect calculation of the
> > total available RAM, causing the kernel to believe it had more memory than
> > it actually did.
> > 
> > This patch refactors `memblock_free_pages()` to return the number of pages
> > it successfully frees. If KMSAN stashes the pages, the function now
> > returns 0; otherwise, it returns the number of pages in the block.
> > 
> > The callers in `memblock.c` have been updated to use this return value,
> > ensuring that `totalram_pages` is incremented only by the number of pages
> > actually returned to the allocator. This corrects the total RAM accounting
> > when KMSAN is active.
> > 
> > Cc: Aleksandr Nogikh <nogikh@google.com>
> > Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Reviewed-by: David Hildenbrand <david@redhat.com>
> [...]
> > --- a/mm/mm_init.c
> > +++ b/mm/mm_init.c
> > @@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *tablename,
> >  	return table;
> >  }
> >  
> > -void __init memblock_free_pages(struct page *page, unsigned long pfn,
> > -							unsigned int order)
> > +unsigned long __init memblock_free_pages(struct page *page, unsigned long pfn,
> > +					 unsigned int order)
> >  {
> >  	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
> >  		int nid = early_pfn_to_nid(pfn);
> >  
> >  		if (!early_page_initialised(pfn, nid))
> > -			return;
> > +			return 0;
> >  	}
> 
> I found this patch on mm-new tree is making my test machine (QEMU) reports much
> less MemTotal even though KMSAN is disabled.  And modifying the above part to
> be considered as free success (returning '1UL << order') fixed my issue.
> Because the commit message says the purpose of this change is only for
> KMSAN-stashed memory, maybe the above behavior change is not really intended?
> 
> I'm not familiar with this code so I'm unsure if the workaround is the right
> fix.  But since I have no time to look this in deep for now, reporting first

With DEFERRED_STRUCT_PAGE_INIT we count totalram_pages in
memblock_free_all() but actually free them in deferred_init_memmap() and
deferred_grow_zone().

So returning '1UL << order' is a correct workaround, but the proper fix
should update totalram_pages in the deferred path IMHO.

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNVWzaxq82UI3wWO%40kernel.org.
