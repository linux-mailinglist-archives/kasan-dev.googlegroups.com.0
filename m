Return-Path: <kasan-dev+bncBDEZDPVRZMARBFMT4HDQMGQEYZSBN7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 21D1ABF9C72
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 05:03:52 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-7810289cd5esf1909989b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Oct 2025 20:03:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761102230; cv=pass;
        d=google.com; s=arc-20240605;
        b=EfYBbsvphTGEZWVv/vIVLw3gLqH0swZZtq4n9lj+jRFtLg9YqVQQQtDDadDTTTM11p
         pY8f1Fd/Q2ocvNbpKjzUCd2wUYrJbvdSeD/0hdH3jyl2apVWZVSZl9pKbmcq3MPFIVjN
         lsFqwi5ah0GT91UnKLRLf2A8fZ6cQ142jeh9gGnfyu3VnWhhTReUR6358f6kUgVk/tJX
         G5gGXFLheAPmiaeCq+oDKuB333EPR1lYp7UZGYyJlPhvNrg63JkPtPBUNB+fNzNOyF3P
         fcjmKuFq6gQWuzeQkQIBcPqu9HedxqiFNVjIv7ZvQStPo0e2k2rmd0LOqA6kUEfiH8Bj
         wwdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UPSNn1yOaofCVhRBDEgd/Z1Krg6Ny0gc7hBGYKW39vY=;
        fh=5KAFc9CWdRcMI2JLTjyx+KCq9RyTnf/SiNxUz1JZMuY=;
        b=PxCVdFsgtSIyDqthiLHKBtCQP+F2bUIEaCHrggbe234EUC+Pa6gODUKYgv9BJPzRm6
         Kb85Pnxq7XVeo00ja+pq6LXliq4tnN+W3Bw8Z0EZj+GYZb8/aGvE+h7FwNb9qTpvaflQ
         +B/tTnevSEwL720re3M6O8ddyr2KU9Ma+S9c1JeTRqj2Edhm3WcpE0AzzoJjFBottIP7
         A4jt4+nsHW+dn4s+yLdZLbsCvx/M9EWJolSe1/rq2RzVlEIF6+ZYa+eDS77d89FQAhRd
         z3+mOBHw0iyJKWuzeNhxGgZvV3oMDTRZxuG7htJ2PmFkUixvvB1F2nb1eFWRUIfCtRS/
         lR6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j2Q0iTku;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761102230; x=1761707030; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=UPSNn1yOaofCVhRBDEgd/Z1Krg6Ny0gc7hBGYKW39vY=;
        b=joVQQLUGRKI3D6feJM+Cpm9YLbjbPLLzoVsAtOqy/mS3M8teOyqag5EVxeh//nDx4J
         8pHEVaDv7CH0DiGy8QtP6Vbs6x5+6UF5Ic5JzkeWMcWBsWlQjLAlgo6LMSgDbEAcpUl/
         6HIdljGOwZCnx/QflwOczSlqM9pAZcxC8CwfaEuhPscj91k1WjisTx7Zd7nGqXMZxlPN
         vHacfRMjFovdoQNzcX7qlobLnH7sRvSzaTqgqAg17fsR7XXUf7bMcXfoqjX/EvBLxQzS
         rsilUm3B/EdAGKtQWBXpLHjCkoh1o9up9MCRBHhXhlw0SkZYaZ2OZ/t7Vp3NFfW6DND6
         1cTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761102230; x=1761707030;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UPSNn1yOaofCVhRBDEgd/Z1Krg6Ny0gc7hBGYKW39vY=;
        b=SPo2S+Usx/npKlqtu4Ny1RfI6NOxOQC3Qxl/uBrQl8Li5Ey4GBrTT7KHP+viurTpnq
         d6JjVA4YEcOq22IQgGF6qG3Onylq6rQQ8cYc91OwYQq4LqrkkxF4LIy8A4RZkMaZjitk
         cQvbEnG68K33KbpcCdRlRCkV1arISoRn9D1V1HIQEfuAAzigwen3KBFiVOLnJWmvSfyA
         Mcm/HptJ0hFKxWfhNcP6QCbmlDxvXsvbsc3edxqabDDWD6+548+L/0XqpB2qwYHkryAv
         wYri11bIY6fSa2SdZT6xJVerMNRyrL9+vWHryF3wb+Vzy+Gvn3wU3TpAFRxAxK3nZGPt
         H5ww==
X-Forwarded-Encrypted: i=2; AJvYcCUA0wU15fuy0OsBgWtd0sQsxhDuWPwP1LTYConM5weXtahqP4NTLOMbiRzrBFNb63CavfKOuA==@lfdr.de
X-Gm-Message-State: AOJu0YxHEnmXY7/Cr2g92RFHE8KI+6A9sXWlT8Ej8vFC9S0PeBEcLA4J
	MlNvCljo8+sDQrEaMvI0CykLzVcci9yKEuvpEMRV2DhJQGE9yQQv3UME
X-Google-Smtp-Source: AGHT+IHCtmgAQKIVOBUeH9CcQ+vmdXZh9hhK2AeEiMDBG9bJDlQdB4DH0xhRlYuSvbyKPBl9BRRDvA==
X-Received: by 2002:a05:6a21:3396:b0:334:a2b8:183c with SMTP id adf61e73a8af0-334a863824cmr24296287637.44.1761102229775;
        Tue, 21 Oct 2025 20:03:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6PdETF/nzkCeybpcuNlN1awyv+MPBqA+NnuQQ9yLlQEg=="
Received: by 2002:a62:e712:0:b0:792:f1c0:cbea with SMTP id d2e1a72fcca58-7a26a54ddd1ls49249b3a.2.-pod-prod-06-us;
 Tue, 21 Oct 2025 20:03:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZQ2i71a+XlzG5HSNHl+3JrR6DpugFiUgfTWTnn5+HSETGS1MgEr+JUgWbV9PrTb4LHnd27o121Wo=@googlegroups.com
X-Received: by 2002:a05:6a00:2308:b0:792:52ab:d9fe with SMTP id d2e1a72fcca58-7a220440d9fmr23560897b3a.0.1761102228371;
        Tue, 21 Oct 2025 20:03:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761102228; cv=none;
        d=google.com; s=arc-20240605;
        b=FsOyEOIb7y5fpCMlGuMplL3s4cSQ69UxHvSdE9GduvWBKha2mY7Ay14J0UVu4irgmr
         CHfeDr61hqNIi3ek0JQYN6TPGoDYToFIrXsHWkpMBd3xNIeZ4POz6B4jF+kbUjCT/rlT
         Qa7Y9+BL1Pz8Qe7XLk9v1LnemewdIscGkkrw9wuyDFLNLHfysglDHlHrkvDfWQ+RkVxu
         bcDLq2VAa+Lz5YUVLOGOc4y3TRzxB5xnhRSzZ4AynWDzHooSs9yrSH0dCopmTJ1xeMlO
         ySO66/+rR0lZOoT1EXa1Nc7CwkQcTDWEveJxdGsgH/VQTyGnuIqi+dd3/i5NVlVwhTvP
         Wsog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZE2B58x1fd9+uScJ88B3iTwTcHnPI9yX7gy9i8nW1Y8=;
        fh=iewbNjrzwCVC5c1JVn4NSXLbVY7pZ3EungLuzzCJInU=;
        b=iVkaiF8tLRt7c+akNymZEa3PjIULO10tQwoVgLxpG7NUdEEj9IidQIVEZuJU1pUKk3
         X5jomgOUgmagMktNcvPQY0B/iwJMvwPr6VYIAml/y4cBEfQ/eIdUbO86tq4P1DDjmGbk
         +JDG/WakTzeQhhcDhb6NFBSUOANJ67lcGyI3G22Fg1zLnzorftCKre/b7XlkY804o2cf
         X6q2lPWcfWPTvuJRi1PKoAcZoiN3h9CXEClx1DmkCG/P8BDjIgp2y0a71CImko7pHXJw
         I7YBPFOU9mRuaLNTiuw5CdgSfVmQtpRq60q7IP9p5GpxkmnqG5gSiAgOGBvz7xQ57wkR
         BvKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j2Q0iTku;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7a2300f2611si228876b3a.5.2025.10.21.20.03.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Oct 2025 20:03:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5718560325;
	Wed, 22 Oct 2025 03:03:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6658C4CEF1;
	Wed, 22 Oct 2025 03:03:46 +0000 (UTC)
Date: Tue, 21 Oct 2025 20:02:13 -0700
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Ilya Leoshkevich <iii@linux.ibm.com>,
	Alexei Starovoitov <ast@kernel.org>
Subject: Re: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots
 are allocated yet
Message-ID: <20251022030213.GA35717@sol>
References: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
 <20251008203111.e6ce309e9f937652856d9aa5@linux-foundation.org>
 <335827e0-0a4c-43c3-a79b-6448307573fd@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <335827e0-0a4c-43c3-a79b-6448307573fd@linux.ibm.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=j2Q0iTku;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

On Fri, Oct 10, 2025 at 10:07:04AM +0200, Aleksei Nikiforov wrote:
> On 10/9/25 05:31, Andrew Morton wrote:
> > On Tue, 30 Sep 2025 13:56:01 +0200 Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com> wrote:
> > 
> > > If no stack depot is allocated yet,
> > > due to masking out __GFP_RECLAIM flags
> > > kmsan called from kmalloc cannot allocate stack depot.
> > > kmsan fails to record origin and report issues.
> > > 
> > > Reusing flags from kmalloc without modifying them should be safe for kmsan.
> > > For example, such chain of calls is possible:
> > > test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
> > > slab_alloc_node -> slab_post_alloc_hook ->
> > > kmsan_slab_alloc -> kmsan_internal_poison_memory.
> > > 
> > > Only when it is called in a context without flags present
> > > should __GFP_RECLAIM flags be masked.
> > > 
> > > With this change all kmsan tests start working reliably.
> > 
> > I'm not seeing reports of "hey, kmsan is broken", so I assume this
> > failure only occurs under special circumstances?
> 
> Hi,
> 
> kmsan might report less issues than it detects due to not allocating stack
> depots and not reporting issues without stack depots. Lack of reports may go
> unnoticed, that's why you don't get reports of kmsan being broken.

Yes, KMSAN seems to be at least partially broken currently.  Besides the
fact that the kmsan KUnit test is currently failing (which I reported at
https://lore.kernel.org/r/20250911175145.GA1376@sol), I've confirmed
that the poly1305 KUnit test causes a KMSAN warning with Aleksei's patch
applied but does not cause a warning without it.  The warning did get
reached via syzbot somehow
(https://lore.kernel.org/r/751b3d80293a6f599bb07770afcef24f623c7da0.1761026343.git.xiaopei01@kylinos.cn/),
so KMSAN must still work in some cases.  But it didn't work for me.

(That particular warning in the architecture-optimized Poly1305 code is
actually a false positive due to memory being initialized by assembly
code.  But that's besides the point.  The point is that I should have
seen the warning earlier, but I didn't.  And Aleksei's patch seems to
fix KMSAN to work reliably.  It also fixes the kmsan KUnit test.)

I don't really know this code, but I can at least give:

Tested-by: Eric Biggers <ebiggers@kernel.org>

If you want to add a Fixes commit I think it is either 97769a53f117e2 or
8c57b687e8331.  Earlier I had confirmed that reverting those commits
fixed the kmsan test too
(https://lore.kernel.org/r/20250911192953.GG1376@sol).

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251022030213.GA35717%40sol.
