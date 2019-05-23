Return-Path: <kasan-dev+bncBDQ27FVWWUFRBYO3TDTQKGQEUBFWHNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 84C2627567
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:38 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id x10sf933824vsj.19
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588897; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ae+8wQ7jyERz1hQYIWYcYtVXaAmSp+n0LMZjqq1s68LpIIGtsVgoPYi+QrBNGS1w2s
         DN8g1/WTKxmiFISG1i8/23oUFy4HrA1jXRUhaz4B/x+SgrSU0P0V7LWMAWRJiqMhUG/k
         fMbrmszwcXuIJ5dueEQ2OZcmlkxa/DiqwpCz59mBtpwtPOS6Bx6n4wi/UdXqsBdnrJwW
         jNVjSOb8pNdQyMQUOa1b8Hdq4oQw5q+/5NFyMDV47vd44zBKGlmmA7clOwSuCZwwvKds
         q8I9A5dkHHLN4eVDvUxlh8IKkQNHGZnI5jjlfm1oO2y5yyiyvFj0mqjGOILZCxfmWQHA
         H/kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6erF16tjvRIWCrkcPcYVRdulTGMHds2aLh3TaHFYQHI=;
        b=N/eh82nKRpR4tMIrqwBXsey2O+GwnS4NElNTYntQFBGopP3f1FYMnzbfUS3pgPRhE5
         RWypUX1VlvO8vJtNH5n7LHrJH+FBBrF9h7mLAM6pAtsnh9KXgysiLY4esEXUQ/nd7Wh6
         bvDDaBpq9gWGb4iYBid23mopBp1rC7Roz3M4JBNlvhXc5eqvtYMKUBfzYYNS0wywGH+L
         MOhs3wWN6oleaEWEqss0a77EyFGcmVDWCOj8/6wf2l9SU9AJSMmC5gDjamldflYAeVtx
         yRLMGMQN+C95yENjulpQFad++5nrEdV0T0EAh8n40gIEmPmXf85Sy1+y/cKYkNSkNKW9
         zWzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=dzYgAfVp;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6erF16tjvRIWCrkcPcYVRdulTGMHds2aLh3TaHFYQHI=;
        b=mpnVGOi+uNKY5/Xm2GgUUA+OG6VyR4G1oycWOhUeX2xbwPf0yJm7ERh5h0kN5MpyWm
         d0IeP2KhrYrI6ebLXbMfkPxcnNdk793ZfxvlX3Fuxi2MNQAGorF8xsWaXvRj6J9nr/tk
         zL2wtqJlxeXfdmoqYb0nvIHriQSR+y7vwN/TYe8jI7SjZQnKeiYgmrPKephnTnPdP6j7
         KJitNLnjG5vXWFSvTKAhLMXXaS3QVJijoJ6niLC3pM+T5LpMJCsdN9YbyXzhnt1ULTgd
         vMUDkXFnusQ2EvZw+5Br6bwCf5IMmDF03JZ1QwuwF1BnTNK40dzmef2VJJoLoMgd3Rf/
         f5GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6erF16tjvRIWCrkcPcYVRdulTGMHds2aLh3TaHFYQHI=;
        b=nfKez6274w3VKYX8kq8lM1GxEibF1s/2QtT8mnpD+5ZBcY9ykKSbRIO7va67l4pcsh
         H9BFuP5nOQiMooAn3kAJks1afghrrjMD8XsLWePYClVBsFJ8AlWcunAdRCV2i41cfj3I
         ddrgsBGdwuz+deIBcRXyVZSmlFwkmqIM1Sf0WeNCGpIS7a64kBelft/CQJ8Kuyxjt2G6
         FoTUNm32Evg47wEdClpglUDccVLws0PmV8NHHF2SBxXhRdLsggYraQEl9KRouyh5N8xH
         kDDuQWxaEUkSEG6bVqnLuZ/Ja3aZJ6f3bTBfElrw9vW5hh9wKvpVzFAT29Jixyl1dNOb
         DSXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV8FA+NUNU+rCQLz4Qh8kqoHGihXEypnSZ5koqD/kiEqTl8YjSi
	rw0QVwggpYqP5OB3DyZqgpw=
X-Google-Smtp-Source: APXvYqxtBfZEkC9opYkvRa2Gp++4RVDZz5soQe1/72LrvAmzqE+eB2Gev+VOLxifS9NfXYvhoHXKwQ==
X-Received: by 2002:a9f:22ac:: with SMTP id 41mr27517938uan.42.1558588897471;
        Wed, 22 May 2019 22:21:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:18a3:: with SMTP id t35ls283035uag.13.gmail; Wed, 22 May
 2019 22:21:37 -0700 (PDT)
X-Received: by 2002:ab0:e08:: with SMTP id g8mr17064128uak.32.1558588897198;
        Wed, 22 May 2019 22:21:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588897; cv=none;
        d=google.com; s=arc-20160816;
        b=jHK7PBsvrbf0EKL7vK7zkPvgcOOYW2nRHHufvOWRT1RIRLakwqo/V0/DijkWX3nHqV
         Is3qGK2lefFtVNMp5Pg91dX9EWTHVH3QTyPEo76ExXMrW97Wl+etAojWj8GkS4tjO1Oe
         gFKvIvzOcQ0fIX20MHugBAwzwUywHxhR3ixdaB0WpWWPJQQynwKnw9lFlKcbzcfcIgb7
         mFQYA0MxtLpfpBBU6K2wXFj69kiMfBJOYfRSrzL0R35eiZVFHsAI+cHn3wmAlXpBmsgw
         G7PLIzBCySaMxDMJnjRnOO9sUbQ2XlTCo28c5dwCmC3a0kZ9IuuZHIuD8jauaJGYHeft
         +RJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fjOaqB0oVkfbrEJKn0VoWTH231yfH85u91Z/PupfDqE=;
        b=roXeQ2gEFWDCJjo9WPUtmiNBjgC03WJcRWaL0uOsV97w22DBoIjzmx0cn3+JzHBHzp
         ksEh2aI/B+2lIBg1lDBN6kWPIgkxZpg7oAqB6uSTBejLVrggmukxY/DP3s+LXSBC9Sm8
         bhMfb3WSrRGV+eRau/vWkUq88t77nEF3lUyX/9Ff5uu1cFPB3E8larrpZgGF0m42599j
         PgO/axyvjssZbfsq/bEUl37g1v2qYQb4KQnbgWWk4samlduUn5Z1ZDkbCOko5OBhtIQv
         cigs7uv3xw2RCI8NZR2+8mIiTC4UK75lLVQtWqY5/4g/sekqigqDTFj55Zw/3nXIwB+h
         dOVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=dzYgAfVp;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id r5si1458696vsi.2.2019.05.22.22.21.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id z28so2583609pfk.0
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:37 -0700 (PDT)
X-Received: by 2002:a63:f44f:: with SMTP id p15mr94759765pgk.65.1558588896307;
        Wed, 22 May 2019 22:21:36 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id k3sm11861396pgo.81.2019.05.22.22.21.34
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:35 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [RFC PATCH 2/7] kasan: allow architectures to manage the memory-to-shadow mapping
Date: Thu, 23 May 2019 15:21:15 +1000
Message-Id: <20190523052120.18459-3-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
References: <20190523052120.18459-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=dzYgAfVp;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Currently, shadow addresses are always addr >> shift + offset.
However, for powerpc, the virtual address space is fragmented in
ways that make this simple scheme impractical.

Allow architectures to override:
 - kasan_shadow_to_mem
 - kasan_mem_to_shadow
 - addr_has_shadow

Rename addr_has_shadow to kasan_addr_has_shadow as if it is
overridden it will be available in more places, increasing the
risk of collisions.

If architectures do not #define their own versions, the generic
code will continue to run as usual.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
---
 include/linux/kasan.h     | 2 ++
 mm/kasan/generic.c        | 2 +-
 mm/kasan/generic_report.c | 2 +-
 mm/kasan/kasan.h          | 6 +++++-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/tags.c           | 2 +-
 6 files changed, 13 insertions(+), 7 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b40ea104dd36..f6261840f94c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -23,11 +23,13 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
 
+#ifndef kasan_mem_to_shadow
 static inline void *kasan_mem_to_shadow(const void *addr)
 {
 	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
 		+ KASAN_SHADOW_OFFSET;
 }
+#endif
 
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 9e5c989dab8c..a5b28e3ceacb 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -173,7 +173,7 @@ static __always_inline void check_memory_region_inline(unsigned long addr,
 	if (unlikely(size == 0))
 		return;
 
-	if (unlikely(!addr_has_shadow((void *)addr))) {
+	if (unlikely(!kasan_addr_has_shadow((void *)addr))) {
 		kasan_report(addr, size, write, ret_ip);
 		return;
 	}
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index 36c645939bc9..6caafd61fc3a 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -107,7 +107,7 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
-	if (addr_has_shadow(info->access_addr))
+	if (kasan_addr_has_shadow(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3ce956efa0cb..8fcbe4027929 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -110,16 +110,20 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 					const void *object);
 
+#ifndef kasan_shadow_to_mem
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
 	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
+#endif
 
-static inline bool addr_has_shadow(const void *addr)
+#ifndef kasan_addr_has_shadow
+static inline bool kasan_addr_has_shadow(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
+#endif
 
 void kasan_poison_shadow(const void *address, size_t size, u8 value);
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 03a443579386..a713b64c232b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -298,7 +298,7 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (kasan_addr_has_shadow(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -309,11 +309,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_shadow(untagged_addr))
+	if (kasan_addr_has_shadow(untagged_addr))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_shadow(untagged_addr)) {
+	if (kasan_addr_has_shadow(untagged_addr)) {
 		print_address_description(untagged_addr);
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 87ebee0a6aea..661c23dd5340 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -109,7 +109,7 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
 		return;
 
 	untagged_addr = reset_tag((const void *)addr);
-	if (unlikely(!addr_has_shadow(untagged_addr))) {
+	if (unlikely(!kasan_addr_has_shadow(untagged_addr))) {
 		kasan_report(addr, size, write, ret_ip);
 		return;
 	}
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-3-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
