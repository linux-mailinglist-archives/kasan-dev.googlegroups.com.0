Return-Path: <kasan-dev+bncBAABBTUJXCHAMGQENHU7LDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D6DD3481F8A
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:18 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id r20-20020a2eb894000000b0021a4e932846sf8500920ljp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891598; cv=pass;
        d=google.com; s=arc-20160816;
        b=frjTVwTZvp6K/k/4+7/bn20QIlRAcNzFQ2zWng8cqgSzPJh/JHsrSPlAu1IMT4Tf3A
         ScS+yxz8IrvSY+P3qwMcKUyG4LL18i5OeaMPxMSw3JHOT5zBkzKvgrCcGT3ffjimi5Bi
         zUxdKHnUWZZkxOMDvZrGeEXUZhX/3DqsjPGZtoqDva0620xWXLynhniDK22UTVvHyfij
         hFySU5AedpF/eSZWQPM8BdyAgsEEpuiFB4rbX80mX5yJsgLVtqmnYprbZ+n5ZXx6pe5n
         ZP7uqgesCDiFiEa1VoJYcbkiLg7bRIWcTHKqxK9+0tLVBqehSrBm+pppA5s9YZt18kRk
         Tikg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=E+95DhNDao4nw6+BDYIfIGdRMXQAMvlm7K5tX+dp+/w=;
        b=pcNtZA6K0EFPeZ7ykNRSyZ6L87Zj8qGN+da/iAvXVagogZmkmi5F9fLS2yEZoqFW4p
         vaQLRky2ExcRaccaRCPSTMRvqlk3KNgh2XPRI/wwaFDzXgaHgT5NE0JgfHhwSGlW5r8M
         JOBTWp1gWcWlLER0AIaAk70Zj3aRZqFJgg2neWbk7Ubbpn0igivLGrnc3t/O4HoXytAr
         FMJvbYYI5sB+lKcfgMsTIoVlvjmRuZlw+VusE1hyI6m5aIXQ3hoGifSV4aoCWib6b7ua
         sVHZ408NiVe1ghs/UKBo6KuIjqoC56RcxpTCo1azvPwxnTGhFpW1iT006ZwP/RDIwE+7
         gSKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VuYGh7eM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E+95DhNDao4nw6+BDYIfIGdRMXQAMvlm7K5tX+dp+/w=;
        b=Xt1wNY3JxsQBilXnuyAyZK9aL/thQ4ipW5fS98PIhBMNjpCqfQO8SDUh/35oiUZEkt
         AhKSnB8OJKYJY5jq3W9sOB7BlCqhpriQwu0p2cJr7oqt4p7avlnL2W+lPSkz+C3JRwdF
         8xjAeOAVF86AoMN5WQeDfK6AhZIuOO68clHvxhZoxLR46qFheKc3jCaeEL8T34W81dnY
         i0ClrbrViPiVGpk87+EYvX0qzAspSQiulLE4UF0Kmvn5uvI7nnVfB/cyON19yPbmEYon
         ho3hOvk+wt+jMevY4Bb2I/hZ195DsEb8QLauxZ3wFxN+b+vs0liK0jTecKI9pq9efe6m
         GQhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E+95DhNDao4nw6+BDYIfIGdRMXQAMvlm7K5tX+dp+/w=;
        b=eE4edKOc5rNuH2lAs4U8NtFGoqSRSC4u55AAiAVlOHDwz1iixxoUpbraMQkR5GZwtL
         FrHKt8GcwWuFHHZ1f3B6vkV8twBaGwGS8FmeMXY/zlrBUJsVRHTRJiIBjtOMKVf/0CSG
         AEnPhUUDFhYlke/YMKBl9cO27GFG4cnSIhJYdoJpSv2+DoYOv7/3qWVConIHnaPsNW2w
         vAQ/Z/ELKe2ifSHigZFCbOyZvpQ7k7TdOi3rSMxDtBTRHplbnMTbc4U7pb4xCLrKIH8r
         6kLlHxnD0KCuQiqKHMwW3U2wG9MdZX8ZjBr5EYWWLx5XgI62ibIjQDLQu/KZOetfB7nX
         CRLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322vwWlOL6YgyFlaTK77v0fapkaKBCrQjtwJv4tn6c6pIwYwwVx
	Oll55y32cTYrKREuaH6ZXoI=
X-Google-Smtp-Source: ABdhPJxlQZiQwbwPvVDAYEll3zctOP/Hal5ssQiTgLRDVyjg2gqTaJkmtDgyE8HitEkGnzqwpwDevw==
X-Received: by 2002:a19:5019:: with SMTP id e25mr29829362lfb.254.1640891598468;
        Thu, 30 Dec 2021 11:13:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211c:: with SMTP id a28ls1840843ljq.0.gmail; Thu,
 30 Dec 2021 11:13:17 -0800 (PST)
X-Received: by 2002:a05:651c:886:: with SMTP id d6mr6841690ljq.336.1640891597667;
        Thu, 30 Dec 2021 11:13:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891597; cv=none;
        d=google.com; s=arc-20160816;
        b=nhdrrXESP3CaUBj1vy2nyBqWR+BmHzE8uCsoH1wm9GKpyb6ZOvQ5PrJ1zeksYU6be/
         /rSU/38+VbIVAoj26GhfJBlJPgL7+9hasHhslCC0QKTl9fqVR4yOYI3rec3gfgv0kAvX
         SKi+UPTQdcLIIgk0TjnfDLAkVbgOz+CG2RDP3dY/ScwCLhWrko3cn3tBJtb/+2jQgxEI
         LWGzZA2m9Eor+HEzBf7zDt8uIsNjTa0VET76QSfUVETtmAyOMHeYJgAxXQ/LobPBoaRK
         kMsReI8M1VpyNALSAuYcxlNu4FupMXpb4mNkKnccsyEhbuAMoqGX8TWb/foSbO6TEY7f
         kz8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hDNFc5UvCUKs8p8aVVL2SzowdanE4VeRdtYVMovopAs=;
        b=Lxnu2bJxYNt2EHen4vq5zsid+v4IgpD5WGF0bAkvpFS5mXJJH5gQZHlc/rApY/ieG7
         oK2/3XjK5T5UbzpjnuNLy/rnfxVI8U18fYO3kSitkQa10xlSxGU85Wqg26RPQd5PBvr+
         zWYglY5C3jAQOEKaRaCZZ+p7H6Rj6P1BpSXN8ZPLIy6vfZcI7p3cxivWhMHcPDGlEl/9
         Ab0IBlEmcOa4k7rGqMvwiSK/m9S/k0Q8bscbJPwfnUgiiHZTCFtCXoYYpMn7S90gOw4d
         adD/yYtJZ1PN5eYfH58fKWrOgoKUM45KkpikVPkfDoDYcP5fRwTldBgKkEJym3d5lGQw
         tAdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VuYGh7eM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id b7si1306339lfv.5.2021.12.30.11.13.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v5 12/39] kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
Date: Thu, 30 Dec 2021 20:12:14 +0100
Message-Id: <7597c0ebcb1c2b46241c44a3307e21a7418f5df6.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VuYGh7eM;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Pull the SetPageSkipKASanPoison() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patches.

Also turn the kasan_has_integrated_init() check into the proper
kasan_hw_tags_enabled() one. These checks evaluate to the same value,
but logically skipping kasan poisoning has nothing to do with
integrated init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Use proper kasan_hw_tags_enabled() check instead of
  IS_ENABLED(CONFIG_KASAN_HW_TAGS).
---
 mm/page_alloc.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2fe02d216c5e..d96a43db90c8 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2435,9 +2435,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
-			SetPageSkipKASanPoison(page);
-
 		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
 	} else {
@@ -2446,6 +2443,9 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
+	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
+	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
+		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7597c0ebcb1c2b46241c44a3307e21a7418f5df6.1640891329.git.andreyknvl%40google.com.
