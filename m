Return-Path: <kasan-dev+bncBDCPL7WX3MKBBA43ULAAMGQEUL2GPPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 45CD8A97F8F
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 08:49:41 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e6b94812e6asf8140438276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 23:49:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745390980; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mmh/XgBUUchmD37o5NK0bycee9QSAKSqhzqKvKiHUhCUC6qe5ZzQM5X1aO+prI0hsc
         U9stQsbuk2gVi3/kBabIVTn6rvDG8OqcqTUn2Xe9dARRTf9HNNFRjsR1Q+1H110pwGk+
         VyPAt2Vi1cFaPRk0jgxqZQacQAmjRHkSFXjMt0XkMV7vudqM5vbutCgkkglsvCwmuEgL
         iMFfUQ5G52GrLMsfww6rKvyMeRk5dY/us4wD3/hBhoChmXnjFeOyamEkIww7C1A9LNC0
         GMtRdYgzSn1LSWb+uXzSh86h7HcrqovRnqzWN5VMZG9m2gKWp+spJCcnHDoU+D4EY1sJ
         cizw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=XQVWXU9W+R0MjgHxWRZUGlCHnE9kEq1eDmtQgN+IVeo=;
        fh=+8DSJNAZG30ge+OSQ6DaZvEvakELBNSRUlevO+AbYjQ=;
        b=bUoOCMtLaIlNZSHmU4rsjjxcWH0r3EGQNsXqSxY/TUoXogb3D+2theceo3ZE5cl8yw
         pVGclJXj/iRJoIiR84QnizeznIxByB2oEZa43kXHdpsif9j7Hf+ubyCSaiV51bIBTrci
         N09d4ZJjKEBekrJwrQ5iTeCGrS7OFd6n0rK07MI1GmAdBkBxJBasi34sxtlSlK28tbEw
         Q+c/hzgaqMmJrZxPNUuw7VinE6Z5HP9jimCnl+FfnwS1d4raCTQLieKYLMwLsRtikDwR
         2vXJy067ZwkqaCiudjcMGSySq7eBtNoxQivk6Z0NKamRfDOu/BVBkeLwXcxh7BPohznK
         LkSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=anv9Vn7+;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745390980; x=1745995780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=XQVWXU9W+R0MjgHxWRZUGlCHnE9kEq1eDmtQgN+IVeo=;
        b=vVz5a2GeEtSWz85h/PsVNsd8+pkxMBzpLnnYdrDVfliF1urP2Pxav+fR1CzKwGZp5C
         Ff8uX5oJuyvvMyo9HToDxRLX3WdJWFFrPBPyL6XZThyVRX6a62dFwRGX/aNLKFSK4qHP
         67U9fc+ZtXSRionoGM5QWPlpe+Qq/pqfWGFap4QLXI+ObYl5+PWGCFk8KvBBqAT5HJWT
         miwX2Mrrtq+5p7NuX2x1yBWzDqKe+Og5ZKpdtizfGvkWGPHkG6wvveIUUOihSTSRV7n5
         KuuEXjHUEYMhj+CUnuuJRfAgjzgAP71PHbulhQYv0sBVgjAJwQqudd9e51ZNgFB/on6q
         +hGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745390980; x=1745995780;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XQVWXU9W+R0MjgHxWRZUGlCHnE9kEq1eDmtQgN+IVeo=;
        b=rJQs6070w1z5Y1JtHEflDTIA89TsWaayCWcsLNVe9cNWuwp99AsApIVhL8fbHH/13l
         sbsxgwTQHYNJ+qjYOwYNByR8VOnAsrXqb7m4E/QoqJkp/t8FM511mpIIFr+AEkr2b0Ch
         tWD5I0YScQLzJ4aaxY2dXAZBP7H+/DHQvbVvkMjA17Jl4kKNkSv5G5tifbNGLFvW79G/
         SJ9Ut0liqgFw6tuWIUVfJ63lO5APa6sa5NeuIm3YoFvun6GhKsDM3bzfdaop1QHXoSon
         xb3oKdHIecKGeGdCejpPD2d6hTWeCzBJTylz6Rfwxfclcme1tbwB3B/0Y8ew3HAnGxt0
         mt9g==
X-Forwarded-Encrypted: i=2; AJvYcCUbWKse0MvqM2xglqR8hZZvnvknnC1u7D+stxyFTOhb97SlgvSXPeW7Xtn8mC1bO4DeYlQU7g==@lfdr.de
X-Gm-Message-State: AOJu0Yz4ANa+3eLyXs5nUDJ1u4ZSjCChs4kzsS0eUr3nBfRaLFKveFM5
	vVQvhIjBz7EHnPkmqTvU1qByOUfeoup/TUkF1yjHYEVSc8JQK0gI
X-Google-Smtp-Source: AGHT+IGfvgHvl5OXpRPWhYJxHqdZtZiXmtP8qkVNoOpe0oFws9yjCUE6zhHixEX1MKOOcNfpgYa9oA==
X-Received: by 2002:a05:6902:4103:b0:e72:a02e:aebc with SMTP id 3f1490d57ef6-e72a02f0b83mr19775268276.13.1745390979856;
        Tue, 22 Apr 2025 23:49:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKWiLZqWTc67ssc9aw+mrEt2ALIxhDExRnTiI9KCeOIyg==
Received: by 2002:a25:aaab:0:b0:e72:eb79:6bb3 with SMTP id 3f1490d57ef6-e72eb796c61ls762965276.0.-pod-prod-07-us;
 Tue, 22 Apr 2025 23:49:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbPH8n7B06Xlkn/nCwwrMjsdtCg4UDBcfcO+q8pRpLRdf1q+Nxr+k63MzH3+bYn3S3A4hVQ8FSld0=@googlegroups.com
X-Received: by 2002:a05:6902:cc3:b0:e6d:ee69:dd3e with SMTP id 3f1490d57ef6-e7297ecc821mr25052266276.47.1745390978753;
        Tue, 22 Apr 2025 23:49:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745390978; cv=none;
        d=google.com; s=arc-20240605;
        b=JUvwGyOSjjdCbUfe6ohn+6Hu8WbSr5Ma7Il6Cto6CwzdEPvqrdEgeMq+N1wAYAJ006
         d0wu/pC0a276p0zi2z0Fiq7o17kwz21CY6AObdZb+SiC4z9u85PT4dnaOg0G+ukKuL0x
         pEw1slqMCheRo00cLfwKmtbqKbdAuKKLBKQXpwv6gaq0dcEBvpCSPNK0ZWgxp3AuCCWg
         bdO7HMhtx8nZKXHsOx6dfeaWkHghwcDxL+LT1XQ7a5XEewQRhy6DMIXtIEngA7TOR4nC
         /GUEqnq78fHA4EMJdEgyXpYXc5tSxvuIzYZoCy/4zY84duubgQnqpGCuvmHrf+F5Xp6k
         5KOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tN29ir1S6sxDCqMPz/MY/sHGybhwMYFo1u8e0s1TAiQ=;
        fh=VIIBVPUZ2UabN0jeXKJCz5oM11D0mB53/u8EpNj+RFA=;
        b=MrqfGMSoK+Ss3zKKiD6ab/Opx0EoBJNZacVHT4DvDf7G+Ayqd0bn7VOZwRku3C4T6H
         9W4ZvLpr7hiCqCBfNmIHiQAe7BP+uEHFqySIsMgpPYq/yJ/pj+sLfoJhW/E8Rs+ko/fc
         9w21rSEKIw5guZ0qnMfVI3iIx2TtIw3C+cNM1BgjZUjgz8EhvaMlUsqVE0thp6oLpPe+
         1jQfbcMZ4WShHoU+U8tZ917PTSoJu+79rHYHrJ7px7IIOQv4lkzk+wc3/nL1bFoPxW8X
         iFUyl6NBnHqRUojIhhakclT6u4UHt360O6y9KRPhW2HR/TNS3xdASlGR+KEBWZXo/W8X
         o9eA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=anv9Vn7+;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e7295987654si644278276.4.2025.04.22.23.49.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Apr 2025 23:49:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 4AB8AA4C187;
	Wed, 23 Apr 2025 06:44:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EBFA8C4CEE2;
	Wed, 23 Apr 2025 06:49:37 +0000 (UTC)
Date: Tue, 22 Apr 2025 23:49:34 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Erhard Furtner <erhard_f@mailbox.org>,
	Danilo Krummrich <dakr@kernel.org>, Michal Hocko <mhocko@suse.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com, linux-hardening@vger.kernel.org
Subject: Re: BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x195/0x220
 at running fortify_kunit (v6.15-rc1, x86_64)
Message-ID: <202504222221.6EA181A7A@keescook>
References: <20250408192503.6149a816@outsider.home>
 <20250421120408.04d7abdf@outsider.home>
 <202504220910.BAD42F0DC@keescook>
 <20250423004422.3c4ef599@yea>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250423004422.3c4ef599@yea>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=anv9Vn7+;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Wed, Apr 23, 2025 at 12:44:22AM +0200, Erhard Furtner wrote:
> On Tue, 22 Apr 2025 09:50:24 -0700 Kees Cook <kees@kernel.org> wrote:
> > On Mon, Apr 21, 2025 at 12:04:08PM +0200, Erhard Furtner wrote:
> > > fortify_test_alloc_size_kvmalloc_const test failure still in v6.15-rc3, also with a 'GCC14 -O2'-built kernel:
> > > [...]
> > > BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x2a2/0x370
> > > [...]
> > >     not ok 7 fortify_test_alloc_size_kvmalloc_const
> > > [...]  
> > > > I gave v6.15-rc1 a test ride on my Ryzen 5950 system with some debugging options turned on, getting a KASAN vmalloc-out-of-bounds hit at running fortify_kunit test:  
> > 
> > I'm not able to reproduce this yet. What does your .config look like?
> > [...]
> > What other debugging do you have enabled?
> 
> Hi!
> 
> Sorry, I forgot to attach my v6.15-rc3 kernel .config. It's basically the same as the -rc1 one from my first report (https://lore.kernel.org/all/20250408192503.6149a816@outsider.home/), but with GCC 14 and -O2 instead of Clang 19 and -Os.

Thanks! I was able to reproduce this by not using UML and forcing on
CONFIG_FORTIFY_SOURCE=y:
(Bug #1: CONFIG_FORTIFY_SOURCE should be enabled by KUnit for x86_64)

$ ./tools/testing/kunit/kunit.py run --arch=x86_64 \
	--kconfig_add CONFIG_KASAN=y \
	--kconfig_add CONFIG_KASAN_VMALLOC=y \
	--kconfig_add CONFIG_FORTIFY_SOURCE=y \
	fortify
...
[22:52:53] BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x1a4/0x200
[22:52:53] Read of size 6291456 at addr ffffc90000200000 by task kunit_try_catch/41


As it turns out, I had to go back to v6.11 before this passed again.
Doing a git bisect lands me on commit 590b9d576cae ("mm: kvmalloc: align
kvrealloc() with krealloc()"), which certainly sounds like something
that might break the fortify_test_alloc_size_kvmalloc_const test. :)

$ ./scripts/faddr2line .kunit/vmlinux vrealloc_noprof+0x1a4/0x200
vrealloc_noprof+0x1a4/0x200:
vrealloc_noprof at mm/vmalloc.c:4106

4104:        if (p) {
4105:                memcpy(n, p, old_size);
4106:                vfree(p);
4107:        }

This seems to think it's the vfree(), but I think this is off by a line
and it's probably the memcpy()...
(Bug #2: KASAN is reporting the wrong crash location)

Looking at the commit, though, I think it is just exposing the use of
vrealloc(), which was introduced in commit 3ddc2fefe6f3 ("mm: vmalloc:
implement vrealloc()").

The KUnit test is attempting to allocate these # of pages:

        TEST_alloc(check_const, 1, 1); \
        TEST_alloc(check_const, 128, 128); \
        TEST_alloc(check_const, 1023, 1023); \
        TEST_alloc(check_const, 1025, 1025); \
        TEST_alloc(check_const, 4096, 4096); \
        TEST_alloc(check_const, 4097, 4097); \

The realloc test doubles it for the realloc:

        checker(((expected_pages) * PAGE_SIZE) * 2, \
                kvrealloc(orig, ((alloc_pages) * PAGE_SIZE) * 2, gfp), \
                kvfree(p)); \

So I'm not sure where the 6291456 bytes from KASAN is coming from --
that's not one of the potential sizes.

I bet this is KASAN precision vs get_vm_area_size(). i.e. KASAN marks
the exact number of bytes requested ("size"):

        area->addr = kasan_unpoison_vmalloc(area->addr, size, kasan_flags);

but the allocation in __get_vm_area_node() is going to round up:

        size = ALIGN(size, 1ul << shift);

Instrumenting the test for some more details, and I can confirm:

[23:27:36]     # fortify_test_alloc_size_kvmalloc_const: Allocated kmem for 0 bytes
[23:27:36]     # fortify_test_alloc_size_kvmalloc_const: Allocated kmem for 4096 bytes
[23:27:36]     # fortify_test_alloc_size_kvmalloc_const: Allocated kmem for 524288 bytes
[23:27:36]     # fortify_test_alloc_size_kvmalloc_const: Allocated kmem for 4190208 bytes
[23:27:36]     # fortify_test_alloc_size_kvmalloc_const: Allocated vma for 4198400 bytes, got 6291456 byte area (2093056 unused)
[23:27:36]
==================================================================
[23:27:36] BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x1a4/0x200
[23:27:36] Read of size 6291456 at addr ffffc90000200000 by task kunit_try_catch/41

Ta-da.
(Bug #3: vrealloc attempts to memcpy the entire area, even though only
the originally requested size has been unpoisoned by KASAN)

I'm not sure what to do here, as KASAN is technically correct. Can we
store the _requested_ allocation size somewhere in struct vm_struct ?
This likely totally insufficient hack solves the crash, for example:

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 31e9ffd936e3..f77ab424b4f5 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -53,6 +53,7 @@ struct vm_struct {
 	struct vm_struct	*next;
 	void			*addr;
 	unsigned long		size;
+	unsigned long		requested_size;
 	unsigned long		flags;
 	struct page		**pages;
 #ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 3ed720a787ec..e4ee0967e106 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3859,6 +3859,7 @@ void *__vmalloc_node_range_noprof(unsigned long size, unsigned long align,
 		kasan_flags |= KASAN_VMALLOC_INIT;
 	/* KASAN_VMALLOC_PROT_NORMAL already set if required. */
 	area->addr = kasan_unpoison_vmalloc(area->addr, size, kasan_flags);
+	area->requested_size = size;
 
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
@@ -4081,6 +4082,7 @@ void *vrealloc_noprof(const void *p, size_t size, gfp_t flags)
 		}
 
 		old_size = get_vm_area_size(vm);
+		old_size = vm->requested_size;
 	}
 
 	/*

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504222221.6EA181A7A%40keescook.
