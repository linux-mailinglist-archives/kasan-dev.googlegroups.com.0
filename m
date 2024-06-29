Return-Path: <kasan-dev+bncBCT4XGV33UIBBVHD7WZQMGQERQVDZ3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D98491CA8C
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:47 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5c41551a445sf1144771eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628245; cv=pass;
        d=google.com; s=arc-20160816;
        b=AtwEJen+mbYzLyqIPMPmmoCGlGv8C/AWfSvXmVj/QxGgznarqk+EezCnkt5lW3ZOHL
         u63nP3EqYaT0cOhHTH1CygDePw03L/0PI9qRCzvihmKTWOHOexbM0sopHCNCl+NMGLIi
         K6KIaTMM01MbeB2KhEmAxEaKXcpQ9IA4Iy1/IgtYIAWGMROUX1a0EMiOerFOntKxFPjs
         qlO3ZzR8pZG3ynI2EHD7bBhBbZLGTrws4Aizly1GWs7V+PkHdtj8aTDwDCMMKgbmfUdH
         51Sbs9CbdaoChQF+XdUQ4Ljjl/nR1BzaHzLghsIYPSuvb9J/KGQoc71qibZQUNN0kF3c
         zLGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=FxjvbstjU3UeVGtsCiOUyYUoNV65K6q9PNWClR0TmLI=;
        fh=DXLVJrrUZmzwCHcu5dW+bnwvpQygAZkE+pu9WMS1FkU=;
        b=Ft1kWide2134n0SDEkRSkAdIVg3XezIO/eAwjTx3wtL8MqSFLwG2Y1ICCq7Y8WcI+7
         egMzhMznG78qrpJTwCUVLJ063R7qrBC1PTxVgr2gfu1CXaQzXJ7jD6oQKwOzfwcg9C0Z
         NZ18gsoWfM7lmBOeuegy53m6rT+bCzQfXEEPnv3oxLs8Yh+l9oupjGlseGLO5DCpPmux
         8OAA/UGO8DZBKm2sOaWPiN9oDW++WUAQ+eVul+6Sv50Pf/q5O+twtjiJWsA5dHioahEy
         Ybhq3W+z7ZRdDrafEZg8y/eKc+9H3ohyJqnerb1nP1HOzacp+fqQaGa+GYCPmmr2uTNx
         9f4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UyTPuz1i;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628245; x=1720233045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FxjvbstjU3UeVGtsCiOUyYUoNV65K6q9PNWClR0TmLI=;
        b=M3LjkvbkPWfXZE15hBh0qy37KpGe3iTX6KFVZZSJ/cI2IwAzdymCY4J5LxzYBFkALZ
         4uGokpagxDZwyTuJa2hJEEs3zy3wHVOCliqdKzKt37I+KErE/6F2Na2yOZhen8TPJ6nK
         FGJZOo6xpW5pTSWmTPYyw+lyPhV4O1yA/e+DaLXpUP3xhaqBRy1zTPwwpJ4yka1YwVgL
         zXPH9nM70yMB0IH3KqfQKCoXhhkQ6NJgvTq6CCmuLu5QgF+nP8ITeq3i1l0Po3owjoye
         xu85KRb5tPI7O/4SpWWVTtUpKnKoWj3/M4gMDRXkBQ36izO6aDHs7BUpEdRWyQS99qoO
         FyXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628245; x=1720233045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FxjvbstjU3UeVGtsCiOUyYUoNV65K6q9PNWClR0TmLI=;
        b=Kh+yJZ2hOn9efUtF2px7xcc1onxRnf1JS6/gg6Ql8EjmUgz9YUs4iJ+Kg4+CDLgReM
         oo0TWD2kssKKOBCMgBO4dgB6XzJtAaZAZGxX1WWXL+rMTYZOG+P6xnLXhWNZBWqdPMyV
         rQITGUbJ4Oj4sys3UNEr4jZsHWien1TzAFbi1mlI/3X0Qgt9yY7QiXdrUtv5b/0fC1jh
         Vh4gZjPSrYG9X5cIz2fbuu3WNZFMxHEQLQ90llxxrazUmnDb2eE0bm8YWTK2C0FyG/T8
         I8WcoppgKjcvU2Dpvo/GYqeVQjZ81P0pBfq442IDxGHp2OQD6kEGgDcJlVKOiL6ShI4l
         Js5A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwx0ptSB6zvweQz2ko1qkDxJ1RSVfJTs94dRL3DnOBCpma21WUVVLqfVFRTkBXhmORkh94B1JqUuyeVZN6o5hYvpS1qHCS1g==
X-Gm-Message-State: AOJu0YxRk6oB6tj9rktahKX56dLrhPbjdI6cBsufUe81Jl85tvc3ngDJ
	A+PQJmRZcoMHo6oOqWhk3QK3rMlDlossXKOdjhPxoXDVgwmLon8U
X-Google-Smtp-Source: AGHT+IFL3RDU9EoQcIbZSkm2iwx5UpgFilqtVsUxo6MHHq1f8YtI4jo0PZtO7zxKvL5Mz4seuDJFcQ==
X-Received: by 2002:a05:6358:9392:b0:19f:5a42:d2bd with SMTP id e5c5f4694b2df-1a6ace9a783mr5799755d.22.1719628245205;
        Fri, 28 Jun 2024 19:30:45 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8d09:b0:2c4:c051:4b77 with SMTP id
 98e67ed59e1d1-2c924b3da10ls633060a91.2.-pod-prod-09-us; Fri, 28 Jun 2024
 19:30:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUSydF2L4lEM0RnFjEM0c5yXxH0Gp8fZ12YmsOQmCKrlYhbND/auFbx1+FLfS41a45rq77sjUFHwJXg06Fq1ynmqJiz939Ew72XxA==
X-Received: by 2002:a17:90a:d3d3:b0:2c8:647:217 with SMTP id 98e67ed59e1d1-2c861224451mr14334722a91.1.1719628243822;
        Fri, 28 Jun 2024 19:30:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628243; cv=none;
        d=google.com; s=arc-20160816;
        b=zz4Pm0uxQCjwBPe6yftROMHF52rLD2dUH5w0ternhbbpYxxEMRHm3TV928xoKv2B0r
         VpmmEqxKyKOwY/7yIzXu3kv41iASFYE225AzVlWFqPLP42WxWBU/Wtb1vtIZEC8QMTb5
         hNGk3ij5FS3aivc43dVeHggXuywES8BuXppGJy4aKj63Ah8DgL2mmCVo9dCsqeQMgzTK
         WdIh6edmPOHPXdot33YH7VAtWn9iBkYAkRymmzvjnNJu02lajXzusQgCVJrUhwdAf+Aj
         Ytjt3LHYOKrAlA3EE8RI+vtNrruw0NoBH9PXs+DA/92Hlg7Zilf+sGb1T2hT/+maTy0O
         trBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=C2JzCleF6KMhP92n1w3Xb8CEpyBH7XlgjorujMRNVYQ=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=uidRfBnWSa8R/g8E3OfagQl2y04TMYZ3TZaGSxZ2MGB7fnmQhc9S7ewj8Gzb97QTWC
         /4UjjJ0tr3uiR0zCjpSOW22pNxoOzOjIbbQNmB1ZKEzQPqekLD0w3SMZXJJ4KNcIEpGT
         8f+oU7ZyHNClwjlZHq2gQ22kRXSWKhmB9Ru2TClB/QLIQFJGSyfYl+lWs6WseNP3G7Cs
         EyCt3nKAwslQ5JcA0YCH4b4gU6G05VRDFE1E/X2JY21WreZNUUYyzydkClkgLlGJVuPC
         1BpgTyj5AQ2SlgdaNfUwAZYPlgpVppBBlBKI8kHq6zt8TczZrl4+fRVdElNsK4SmbUku
         Iavw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UyTPuz1i;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c91c80277dsi130873a91.0.2024.06.28.19.30.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4C225622B9;
	Sat, 29 Jun 2024 02:30:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E75AAC116B1;
	Sat, 29 Jun 2024 02:30:42 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:42 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch removed from -mm tree
Message-Id: <20240629023042.E75AAC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=UyTPuz1i;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: kmsan: remove a useless assignment from kmsan_vmap_pages_range_noflush()
has been removed from the -mm tree.  Its filename was
     kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Fri, 21 Jun 2024 13:34:51 +0200

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL.  The right hand side of the assignment has no
side-effects.

Link: https://lkml.kernel.org/r/20240621113706.315500-8-iii@linux.ibm.com
Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/kmsan/shadow.c |    1 -
 1 file changed, 1 deletion(-)

--- a/mm/kmsan/shadow.c~kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush
+++ a/mm/kmsan/shadow.c
@@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsig
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
 	}
-	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
 	prot = PAGE_KERNEL;
 
 	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023042.E75AAC116B1%40smtp.kernel.org.
