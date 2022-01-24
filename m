Return-Path: <kasan-dev+bncBAABBX6UXOHQMGQEPF5GASY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BAB04987B5
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:05:20 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id q12-20020ac25a0c000000b004389613e0f7sf1682902lfn.9
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:05:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047519; cv=pass;
        d=google.com; s=arc-20160816;
        b=DXUP2SoRlzkU3zb4RCh2evn3F+gPt+mkYxh2WKb6R+AZFN54P1fmjFBb/4jaLgss7D
         uQHokZOrj0gA3R228nbSGtmFkzAQEFMpE2zdx0OOT46+fWCKLrWd8BK4Ry0zyVFRGf1o
         3In4dmXpNJL3Bf2tuNk8LCIvuHq6CuVpzXyf1YWouhAxqMGk3BmHGx+kVK70teWfmM3W
         RbuVmPHEjQPCH96itda9qgskDGtx+L+IsEd8hLlhXpUNUvCKK+xi0470raltFWWALr81
         rp7bNrQPOqF6j0KbvMDoSo1QBzxAHMYaxXHO/VsLfIL91HtzzvR6twWUTpEpKt0i0LC7
         nM5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZEZ0RmfcD0+1P9SAkb/vRlLfajLFj3p6X+CYYhG+yM0=;
        b=HiP0ZwZJTKtAgm152WR3M+5WslDW2VgfRwL4ALs8OgyfoUpblkLHmZVFQlzqSRadux
         V4851l15uSWVtvKbjUMoAeHd2iUYHgixQoVB/+cmSfaUfhrIX3yOM2m1g9IR8o+vJ80Q
         UF5ZscLDk05uAMugw944dqeQikCXpqa3P9rF8QO5joXy0DNpbbD6em9/KqNcXKVjC+NW
         /m4gaJZ04nYhryyenK9Xlut8Ck6gOHEZVDl5vvrpuIEBBfvy4jGsXp2JyxN+jTw0rkEX
         tORZNFNSE8YGPEQvIot928FRbMJdRpbHZ4HL0MExqry4kG4zQqxTDM5CajkyBgZ3uuQK
         tQfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UlCrGKBA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZEZ0RmfcD0+1P9SAkb/vRlLfajLFj3p6X+CYYhG+yM0=;
        b=LlkUme1NSSa840sr2+3PcIrXhWMRiJwJz027cyjZkGnDo3Z/EGkkm1C5qbxPuiFI9i
         idHRYG5zSJ3dJ1a/aRtUzaZHRrpQPBrnZBZfqynBm7FJq63pMDysVThWm79vkZYRsGS8
         meJ/TXaeFl2UFJhXOb1tWiTHHC9nFhoUorJYsaDadQQ/+eiefFyJ5CWymOUH6KErFhkx
         cVGVY/ojU6Hgbh+9kMRkBqN1Lak5bJLGmKDZ0iwcJpN8Rp2gKVJO4HAIimK/17/IAfNY
         4/9J0GKFCWwRXyAMpn6+fcrcx0F2NQ7DV8iu7tcU1YgGuANlFYsR1821V1cZ2/yJvqYX
         z2DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZEZ0RmfcD0+1P9SAkb/vRlLfajLFj3p6X+CYYhG+yM0=;
        b=nI9B1AhBOghnpCm3t9bHDMfRLiu0Qb7+6EkEo1aMASbfYn96PNf1b8HjgQ5f2DMioo
         74IGkebSw17vcZDsLusbPm4t4Cz5HsAwX9MKvPgN4hpOTC1S9YEU9J1cL9NZeugr5RjH
         Zrt6YAwtyhCJPTwanMFJOyDNPoofteJXaX67lOCEmQjh/NRCMr+hxfmvAxv4/tgFph3C
         4739idPVElRh9IroR1jgXiU7OzLwoVN0kOadCHZ/4wVEKHInz4ptC6mp6TMwWni/ujl3
         64+S95EfSr33mnPvWOh2CHvz+0cOXTfjijXYMTOJo+en6BDm5BeLAUR4It6sT8ZoQLs8
         f3Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nlkFZJGA7N2hHZOHja35mPX9OCs8AM0PfwFtPdxj4SvV0lNIV
	XFCP3pQOfs7j0cAHdK7zCfU=
X-Google-Smtp-Source: ABdhPJxQOaeuG2MTjNy8GQJrf+u3HPnjjKl46zX65W+uEM2kT5zQsut89wm2qc+Nx26TxPPdYpOk4w==
X-Received: by 2002:a2e:3c06:: with SMTP id j6mr12296681lja.484.1643047519729;
        Mon, 24 Jan 2022 10:05:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c3:: with SMTP id k3ls571094lfu.0.gmail; Mon, 24
 Jan 2022 10:05:19 -0800 (PST)
X-Received: by 2002:a05:6512:4001:: with SMTP id br1mr5496511lfb.450.1643047518933;
        Mon, 24 Jan 2022 10:05:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047518; cv=none;
        d=google.com; s=arc-20160816;
        b=MVNjD0cIbqvm32jXWLgzb/Beczx4rS0HZO3pcobD1AfY11z0rSFRQZe/xHHLcQLDQ2
         /iFyt3eeMsjrgabV3dBqel08Dk+2uYVxumxIneqbiIFWMWZohE3TjAmUxncwDaPqu5Rs
         p4YG51QNQSGOPlYzGpq8HNhUW7QIEkYf59nHljAIl5l8EJqzSd7T20PGv07ay67VcUXT
         zcxkrOlTrUFDCpjArtoVObnyX5K7p7aKEo1WWBInZUG7YA1+bQhNY+jx1KYTGNyeIYqA
         sPP1wRsFpTYWCJGsevi4i//BgQeB85+b7VySMMfog/HJ5uBPCoIWqsSeV4AQXfu8s+GB
         5sTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4jFZKwC+1fGM+Zh4UMZz7D7AiRXqN4olJqxCqj+PmMQ=;
        b=TdRI7yBtpVAltXH1RXVeLjWmmDoC4WYOQ++4dJiok7cv3H6uFZn5e09pF/9CC9qHyZ
         l9mwcK1ZR7IkzwXyjuzAbzbj9Q7TWgWco9AS3xz3vH72Tv/EF/0NMHDWv36cC/BTvk0A
         6gTGT7gNp157hzJ4bp+CQ0JRgiaJkdETpTFgx60Nn6henaZQg8LhsGAw5rUYP3jaNBDY
         eZ/X6krCUoZ8BxGC0k2q+tiF/VybJBdlMVe9f2uL1PS9ED2diJ+XE1hEtGq8ixw/6AGN
         WPWScsPXDKZ87z5oY3pArxSyfwVErjemOeJQ76/CTC/z1m+YxXvzJz7tTMqd/w7x+bbx
         yQCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UlCrGKBA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id g17si380043lfu.4.2022.01.24.10.05.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:05:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 20/39] kasan: add wrappers for vmalloc hooks
Date: Mon, 24 Jan 2022 19:04:54 +0100
Message-Id: <3b8728eac438c55389fb0f9a8a2145d71dd77487.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UlCrGKBA;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add wrappers around functions that [un]poison memory for vmalloc
allocations. These functions will be used by HW_TAGS KASAN and
therefore need to be disabled when kasan=off command line argument
is provided.

This patch does no functional changes for software KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kasan.h | 17 +++++++++++++++--
 mm/kasan/shadow.c     |  5 ++---
 2 files changed, 17 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 46a63374c86f..da320069e7cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -424,8 +424,21 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_unpoison_vmalloc(const void *start,
+						   unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmalloc(start, size);
+}
+
+void __kasan_poison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_poison_vmalloc(const void *start,
+						 unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_poison_vmalloc(start, size);
+}
 
 #else /* CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index bf7ab62fbfb9..39d0b32ebf70 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
@@ -488,7 +487,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
  */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
+void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3b8728eac438c55389fb0f9a8a2145d71dd77487.1643047180.git.andreyknvl%40google.com.
