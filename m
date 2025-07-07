Return-Path: <kasan-dev+bncBAABBQVLVXBQMGQEJTA643I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 92DC2AFAAB1
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:12 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-237e6963f70sf50863555ad.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864771; cv=pass;
        d=google.com; s=arc-20240605;
        b=MHNrV+GSGV8xSLoC1ejvqi4iiG7LJSAlwFgaskvwZtN5gOMZ6HlN3bzyMQm9j3MvFQ
         JUspO29ysP4Xqm1OfF5+dytE+u/lqEYdL1BULuSsV5VjO3iTrYskOLYDNByUYXJjRx/d
         vjdaIuYgzaGMQyCrBGPmsKTavVJlCvvbthItksCSqmRPCRUvAuOwIg7nNiN7TLTCfAb5
         +KD2084TSeWYVg4HtaFMVkZbxXjygHHE+2O+1ZUpz5tRzxHPc3sWl5aLbfrCnWbV1pFp
         e4cbdnyoL70oJLCDEzsI8bHJ1tP+ne3oSzM9SZyrYN08Dz5gRTpQYwx8jSuJgBZFT19c
         SeEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ZSmxAxvRSASZJmwCttQZ+ged8T8lEfPHzioW76nuR78=;
        fh=u8dByvPItY+ADnzCDeC/Q2g4+V85hCnIbNM4JqP4OX8=;
        b=Ko5wFtpJvR0lhBv5+vdmJWthXgA5+u6UdnP5Y5GxLOEG9EetL+BwAibk0wTGDH/JPN
         7a4hnOilk8tY5dx08WK2Ogg4RU9tJFf1+8JLGi7d7Hc/1W9Aab1xSyh46n6Or2mwIB24
         qmMUF3QPPVOG33hh5DFKZqprMg4S2sY1L+/L2gKw+Yqz9VDm/E994YNuzj9FjVZEJfwi
         hYKksvy4m/xzmD9PiIsDGd6G2zwQisnzOb0bMJ/cRaEew70EcG3OB/U6FZPlrSZrDvso
         c0RGMihyC3sNDL5t3TYZWpvsjs+yo9vRcMf9CndXYHd9OiBQ8y+uy1/Afy8HrEDEdO+n
         KGWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j3aDEKSR;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864771; x=1752469571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZSmxAxvRSASZJmwCttQZ+ged8T8lEfPHzioW76nuR78=;
        b=ilkyt4HSPsOLUrlpXT3SJCF7SCUT1XhVLJ4Pp3HufSq7sbfKvV7ZyMFbe17c5gV2+e
         6bN901YHaNM83oqiFRWfxGi8hzh+WFmdqiF7j3j424+7lC13z6sb2uz/BD2clTFnZsfk
         1oOSyBLSladPx3oORCU2ITqWRRKPuToeP2DQYrGFCl3+KJh+DlYNQn6rymoQnuaGzZFp
         CtVlPB+j61aDoo/Lj256HjX5+PN7VxMxT8v6GBRYTUAS8Vu3jkYmRV+jIkW2extBIpKr
         pbfZPagkggMpil9RjoLS0mU45ep4OpN3UTrXWXKLE16BwNi5En0iELdNQevrdJKqbk35
         nwvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864771; x=1752469571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZSmxAxvRSASZJmwCttQZ+ged8T8lEfPHzioW76nuR78=;
        b=QMz5UBE8V/wxP4wx4v+Qti4baMJ5PArS6g5Ngjc9fjVz9QEf4xAzV4Eq43dOhslfbB
         gEgSWklKR7gI4ypa/FiaGWkuirTCDHCOf/GUyu3MvNLyvb5d3mseu2fQaiOc1HYRDs2A
         muzr3LHTisL9LQ96wKQniLfw4WqZ3y5F/3uiyVZsWYb5Fpuc+Zyxbdg64FX5M/7Mb9sy
         liE9ECslaSGrZuv1sPRr3WVZp8R3UpoO33Q68hqYZ6J18O7h4260Cb3EltF8M6eKhtqe
         u6RgCsScsfdHi6AcEdstUo9pvFa0Mxd6VSSJoKr7tapwRNuqbtuwKtYUpUp51FWojCiN
         wGlQ==
X-Forwarded-Encrypted: i=2; AJvYcCXby/KK21RpPAJgXLdOVe1H+Io6wuu4Qs3j2gKyAEpwl/O22BS+wPa1Vhrfho26C9g2PUvTiw==@lfdr.de
X-Gm-Message-State: AOJu0YwIcRxf4/qx8KSNyDMrfNp4uHI2/X+Daq+Tue52zSzqROLy0EJw
	K8pTCoS+vNKOqSZXifKRiuKjeam1sMNU39yD/iEODrWRnS7eZjxbastI
X-Google-Smtp-Source: AGHT+IFMl/Oivm7qBRvSWHRJU3iwrpn970G6j6cHgUhkMII/7fA5sesx3BzHioDM2hADDH0pLEll+A==
X-Received: by 2002:a17:902:cf0a:b0:233:ab04:27a with SMTP id d9443c01a7336-23c90ffa419mr106319275ad.53.1751864770634;
        Sun, 06 Jul 2025 22:06:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfrBo/pYFPsSiAHj0TyS5jGmOlnO00ALOLkV/zQRTHKcQ==
Received: by 2002:a17:902:e052:b0:237:f1a3:b13b with SMTP id
 d9443c01a7336-23c89decddals17348855ad.2.-pod-prod-03-us; Sun, 06 Jul 2025
 22:06:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYx2ZZu7FtjEj5Xz5rIgFKhrxxy1gijiqPQF6NNI/BXlzZHgV9yxzhl3qwTVVHfPMUGZPRV7ezbKY=@googlegroups.com
X-Received: by 2002:a17:902:db07:b0:235:88b:2d06 with SMTP id d9443c01a7336-23c90f37382mr90174225ad.6.1751864769482;
        Sun, 06 Jul 2025 22:06:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864769; cv=none;
        d=google.com; s=arc-20240605;
        b=G07mErs+l7JZ9b0TLaB7yBB1Fjw2zoQw58kZN914ts3giuSKm8hYmIgPIn2Kqh85Vk
         Y0wk8BH18qEV5a2iuwcDVP7hGpzbYWeg/UTGYHjpXgmDVTGsgzKtDjOlF4BMRnmEZDpc
         /kL/tAj8CZmHEde6mFmeMor+fLmSsRXfFD1DwUNev4A/VBnF6ZPe8uy8/2NVAhbxLoOc
         mbVrqp4vZ2yr5UvYpZ/NQzf0qNCkxr3fSurg/MvoJqrLcEBzTQDtL9v41segBBCa6ZjO
         qHBLne/EpUue2BAMLD4n+YOcuIfTDrWA5LEZr1WHEcLz9oNZjE3z7ZfInZrzwBg4G2Q1
         lS+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5VXyIw+NgcVC1CyowYH3S4P0b+rnQX8+FYUxV4CEt24=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=E1k7VEtIkOSkfSRmr0G2tRQRSxgVBiEz3eeUUtwPDTxDLPjm6RMbiot8ba4TkBrU3o
         tvOgq7OVi9fPGfxONTepf62TURqQ6IVp3qQLC3ft4uPBZJWjexQ6IqOM7YM8HmMdCT5T
         +8Wd5IopB3Lz49oYwkxF7YZ/gSuRiqp+NqXgQwVgTVF33WOm4qjCAds7u+V6TVhia8KG
         KYHUA/wZoklqXMfmcMi3xKK5j/6lI6ivovgdJ3tRbI2bNHTt/nGZNIGBJeoKJFT9gVRk
         xYlLDy/AYYobcb4cWl7DETI3E4lc2nKlN+bh3n+b3bYvJadm7pHet3o+Gv9cnSpEp+MP
         Hm7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j3aDEKSR;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23c8430fb57si2872195ad.5.2025.07.06.22.06.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id BB0C25C5789;
	Mon,  7 Jul 2025 05:06:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A9048C4CEE3;
	Mon,  7 Jul 2025 05:06:07 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:06 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v3 0/7] Add and use seprintf() instead of less ergonomic APIs
Message-ID: <cover.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=j3aDEKSR;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

Hi,

In this v3:

-  I've added Fixes: tags for all commits that introduced issues being
   fixed in this patch set.  I've also added the people who signed or
   reviewed those patches to CC.

-  I've fixed a typo in a comment.

-  I've also added a STPRINTF() macro and used it to remove explicit
   uses of sizeof().

Now, only 5 calls to snprintf(3) remain under mm/:

	$ grep -rnI nprint mm/
	mm/hugetlb_cgroup.c:674:		snprintf(buf, size, "%luGB", hsize / SZ_1G);
	mm/hugetlb_cgroup.c:676:		snprintf(buf, size, "%luMB", hsize / SZ_1M);
	mm/hugetlb_cgroup.c:678:		snprintf(buf, size, "%luKB", hsize / SZ_1K);
	mm/kfence/report.c:75:		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
	mm/kmsan/report.c:42:		len = scnprintf(buf, sizeof(buf), "%ps",

The first three are fine.  The remaining two, I'd like someone to check
if they should be replaced by one of these wrappers.  I had doubts about
it, and would need someone understanding that code to check them.
Mainly, do we really want to ignore truncation?

The questions from v1 still are in the air.

I've written an analysis of snprintf(3), why it's dangerous, and how
these APIs address that, and will present it as a proposal for
standardization of these APIs in ISO C2y.  I'll send that as a reply to
this message in a moment, as I believe it will be interesting for
linux-hardening@.


Have a lovely night!
Alex

Alejandro Colomar (7):
  vsprintf: Add [v]seprintf(), [v]stprintf()
  stacktrace, stackdepot: Add seprintf()-like variants of functions
  mm: Use seprintf() instead of less ergonomic APIs
  array_size.h: Add ENDOF()
  mm: Fix benign off-by-one bugs
  sprintf: Add [V]STPRINTF()
  mm: Use [V]STPRINTF() to avoid specifying the array size

 include/linux/array_size.h |   6 ++
 include/linux/sprintf.h    |   8 +++
 include/linux/stackdepot.h |  13 +++++
 include/linux/stacktrace.h |   3 +
 kernel/stacktrace.c        |  28 ++++++++++
 lib/stackdepot.c           |  12 ++++
 lib/vsprintf.c             | 109 +++++++++++++++++++++++++++++++++++++
 mm/backing-dev.c           |   2 +-
 mm/cma.c                   |   4 +-
 mm/cma_debug.c             |   2 +-
 mm/hugetlb.c               |   3 +-
 mm/hugetlb_cgroup.c        |   2 +-
 mm/hugetlb_cma.c           |   2 +-
 mm/kasan/report.c          |   3 +-
 mm/kfence/kfence_test.c    |  28 +++++-----
 mm/kmsan/kmsan_test.c      |   6 +-
 mm/memblock.c              |   4 +-
 mm/mempolicy.c             |  18 +++---
 mm/page_owner.c            |  32 ++++++-----
 mm/percpu.c                |   2 +-
 mm/shrinker_debug.c        |   2 +-
 mm/slub.c                  |   5 +-
 mm/zswap.c                 |   2 +-
 23 files changed, 238 insertions(+), 58 deletions(-)

Range-diff against v2:
1:  64334f0b94d6 = 1:  64334f0b94d6 vsprintf: Add [v]seprintf(), [v]stprintf()
2:  9c140de9842d = 2:  9c140de9842d stacktrace, stackdepot: Add seprintf()-like variants of functions
3:  e3271b5f2ad9 ! 3:  033bf00f1fcf mm: Use seprintf() instead of less ergonomic APIs
    @@ Commit message
                 Again, the 'p += snprintf()' anti-pattern.  This is UB, and by
                 using seprintf() we've fixed the bug.
     
    +    Fixes: f99e12b21b84 (2021-07-30; "kfence: add function to mask address bits")
    +    [alx: that commit introduced dead code]
    +    Fixes: af649773fb25 (2024-07-17; "mm/numa_balancing: teach mpol_to_str about the balancing mode")
    +    [alx: that commit added p+=snprintf() calls, which are UB]
    +    Fixes: 2291990ab36b (2008-04-28; "mempolicy: clean-up mpol-to-str() mempolicy formatting")
    +    [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
    +    Fixes: 948927ee9e4f (2013-11-13; "mm, mempolicy: make mpol_to_str robust and always succeed")
    +    [alx: that commit changes old code into p+=snprintf(), which is still UB]
    +    [alx: that commit also produced dead code by leaving the last 'p+=...']
    +    Fixes: d65360f22406 (2022-09-26; "mm/slub: clean up create_unique_id()")
    +    [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
         Cc: Kees Cook <kees@kernel.org>
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
    +    Cc: Sven Schnelle <svens@linux.ibm.com>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Heiko Carstens <hca@linux.ibm.com>
    +    Cc: Tvrtko Ursulin <tvrtko.ursulin@igalia.com>
    +    Cc: "Huang, Ying" <ying.huang@intel.com>
    +    Cc: Andrew Morton <akpm@linux-foundation.org>
    +    Cc: Lee Schermerhorn <lee.schermerhorn@hp.com>
    +    Cc: Linus Torvalds <torvalds@linux-foundation.org>
    +    Cc: David Rientjes <rientjes@google.com>
    +    Cc: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
    +    Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
    +    Cc: Chao Yu <chao.yu@oppo.com>
    +    Cc: Vlastimil Babka <vbabka@suse.cz>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## mm/kfence/kfence_test.c ##
4:  5331d286ceca ! 4:  d8bd0e1d308b array_size.h: Add ENDOF()
    @@ include/linux/array_size.h
      #define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
      
     +/**
    -+ * ENDOF - get a pointer to one past the last element in array @arr
    -+ * @arr: array
    ++ * ENDOF - get a pointer to one past the last element in array @a
    ++ * @a: array
     + */
     +#define ENDOF(a)  (a + ARRAY_SIZE(a))
     +
5:  08cfdd2bf779 ! 5:  740755c1a888 mm: Fix benign off-by-one bugs
    @@ Commit message
         'end' --that is, at most the terminating null byte will be written at
         'end-1'--.
     
    +    Fixes: bc8fbc5f305a (2021-02-26; "kfence: add test suite")
    +    Fixes: 8ed691b02ade (2022-10-03; "kmsan: add tests for KMSAN")
         Cc: Kees Cook <kees@kernel.org>
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
    +    Cc: Alexander Potapenko <glider@google.com>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Dmitry Vyukov <dvyukov@google.com>
    +    Cc: Alexander Potapenko <glider@google.com>
    +    Cc: Jann Horn <jannh@google.com>
    +    Cc: Andrew Morton <akpm@linux-foundation.org>
    +    Cc: Linus Torvalds <torvalds@linux-foundation.org>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## mm/kfence/kfence_test.c ##
-:  ------------ > 6:  44d05559398c sprintf: Add [V]STPRINTF()
-:  ------------ > 7:  d0e95db3c80a mm: Use [V]STPRINTF() to avoid specifying the array size
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1751862634.git.alx%40kernel.org.
