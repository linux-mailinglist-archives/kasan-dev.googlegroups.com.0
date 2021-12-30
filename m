Return-Path: <kasan-dev+bncBAABBS4JXCHAMGQEQ5CPVTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 98B7D481F87
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:15 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id v18-20020a056402349200b003f8d3b7ee8dsf14175080edc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891595; cv=pass;
        d=google.com; s=arc-20160816;
        b=mkoPjE06ODg9mNgV5UgE3I7/lWV6+kaJ08GzfAvfGUYYsM7+cIfEIvWhjlczdmxbH0
         eEBSIJwVMqTTUoC0KctjNF+GInqzQZb/J5fdg/aAPKQI1l2ZGDKi+ZhFXmRRPVwUl7Zs
         mRkIbhHsM5FpqMY7akQsHgkVCarQqWVKmsjvBwOQ+igv5rbj4iVRBs+JeYFR5ysi4ZzY
         cNzI5jB5VwgUBVrI9AO/dyD5wL0Mq9Ent/CXe1gU3wRDC8Sww0qv1X4j/Ylpy7WVQgwP
         ZHs+jfJCBZI6JnQPmBaZvtc4fLHu7B3YMxGsdYWKGOon7R0bmmCJJgZeWXmJPNAoTlQS
         HvSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LyJA5MCschnXewIgDp71R5TW0z7cAAlJxqvy4f9cEWI=;
        b=wXEH9gmKvyAdxWICHa2U07H1S/06JIGBur6qB7wQms3683JWkPpcNGQL7I3jKxbEA6
         GR9N5CjrVGvS3a3ltFeAQ+/JEucxiE2XaW/dZiYmowe2sASzpbTUyMPMU+l2e8q8y0mE
         pv6Ls1rb5dTrB4C4FA2lL1iwElbFsSAsaEHmCe0ueYwONSGEaGoVAt0E4/iWch4EfWsc
         pe0+IXmhpUSfhaGiDqzG0oHBnMtnkmAU3KDb+es5Dl5zBZLlYcyUfF8VB+YGus14fQoi
         F6SHz9/Oqd76+8FbWm+oRlnq4cU+vJGF98OHFiWFguGnCBUdsIOQIKwVwGJ7EQkKr+WS
         f1LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dBAICovb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LyJA5MCschnXewIgDp71R5TW0z7cAAlJxqvy4f9cEWI=;
        b=th6QbKBNyP6qitmB8l4iWwg6W1+7nasmqSYleYSdg90TbqQNnPXBTCxrGAMrUrr2o6
         jVnsgb8zSOyVPscMYyQiF4h/BdnD0v06yoqwtATTJ/DtmZL1uVzHvTp5M91QWx46/vaf
         0Y8BWasC58bp77Aqc1J5CqhV/q06zrikIDx48VbyKcRXADFXNjUh882JXOvIEAouCNO0
         bwQmRCOXCw4OVK3MvEhAMVyhT9FwTQlT9XXD2POJ61rBmHysFfJEpMX9XjPSwznxGCHZ
         gWVnnwLCCzUpK6eMoZEh4pbkUyWzMKwbwfvM99cL5Kk5/7sjYQMAYHxAK3nCPZR9feLX
         D0og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LyJA5MCschnXewIgDp71R5TW0z7cAAlJxqvy4f9cEWI=;
        b=a/hzq1am3AvOpyJ10ZQOEdpt1W0tMACQQ2RTR6aKu/KhGcx0Ugk7h0FKqtcDDkJYLF
         mNk36FVBX+8uAf/bS3rmDk4JihIwBIFtiFLnStzJCscRno3Hrpu2tHVWTRVoJH+WP0OM
         OK0FgYemzA3PeZkIjmNVRtjrm6E9fh5Ze+UNsSqzY5CwrSaPpjJbV6nmFNOhOkDRlG/o
         N1rYsEuLSFCTifxLxJroOX9TDQoANYXyPVYMi7Xk7ZkK7CkUR7Ur3TKBTyn3amZyJ8U+
         OyHoP5x5szyqI5f+3whz8VhAh8fpmcTQaHleDaHyIOX7fVOOD1t4o9DVTO3Hwd3sqY+j
         Ekpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53204hRNVnjpPnyHZvjuB7mX69HlrSaoIaH7cW+vVlI/KpINWXBE
	LPJjEtaLEZfuLoV0j2eLDiA=
X-Google-Smtp-Source: ABdhPJzvzM+F24SDobHAMwWgOr5FBqq7Fae1m/SCAEcDq0q9USyNA6/Am8jSH0UCQ9XW+vLu6dvV/A==
X-Received: by 2002:a17:907:94c9:: with SMTP id dn9mr27839704ejc.298.1640891595341;
        Thu, 30 Dec 2021 11:13:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:270e:: with SMTP id y14ls195798edd.1.gmail; Thu, 30
 Dec 2021 11:13:14 -0800 (PST)
X-Received: by 2002:aa7:d6d5:: with SMTP id x21mr31904677edr.201.1640891594651;
        Thu, 30 Dec 2021 11:13:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891594; cv=none;
        d=google.com; s=arc-20160816;
        b=AQcytyOy7dchmpdXSfeBIzrAg31khrCge5OE5MTDdtVOG67D8qcU6yFoVTToD8msnc
         Z0qBITv7grxu31Ct94mjV7twcTpinzWm58i2vvwrXDOR8+7tqxdiIDMMrZO11k2Z85F+
         VJjdec3UsJXV04cmAbbxesnrMKpmeWDiPJJRjMnsfqoB+Z2aUrg0qN/U3VaOsX8viSwv
         mtEl09pXxVSjIpi4rdGEuWuy7Yk2ZJyf0L0qqNa+9kquBKAIiPNCTsuOBVnJzMUSc1fj
         up6rqZ3d5x+3FwsgjyQUls2EXsgDxN7u6n5rWP2xWVG792X5pnOvEQTZerzJhmIT/L5W
         inGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iHLM7WJYyEaQmQn/NV+5NAsD0aRu16wvdOFSFs8DPDg=;
        b=cb6yrBjULyFsPXHXA13XfXCs4VeuaXI4ZrWFsMNHBuJ/tXfoai5GR4FR50mFF55PpH
         aD1nr9yCBDbnWgkBxk4p0SeMP65ILjTSOjU1TiDYECzK5y0XI81GeomcDqGrcCvQO16E
         4zJt/5q8fttJXQn1BIEQRoRurem28Vev73+/LrNWnPBw+xZK5dNUpNM5Bd/D7qMGcrs7
         fi+NDcoDQMtK6V5Wf4vueW94RqU8Xjj7iGB+s7cAFCA6wDNvRapWZOnFbq1As7V/hUkX
         ZT9d5FKJQNK2yP9jSk1mc9a1xAGgmfKndXvHLd/5FGdEgg1vipbaLn43RCE7Km1kBSBt
         wwdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dBAICovb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id y11si760115eda.5.2021.12.30.11.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v5 09/39] kasan, page_alloc: refactor init checks in post_alloc_hook
Date: Thu, 30 Dec 2021 20:12:11 +0100
Message-Id: <4653f0aa00b575a4dba7df4d44b7a7c92a3f43f2.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dBAICovb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Separate code for zeroing memory from the code clearing tags in
post_alloc_hook().

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 18 ++++++++++--------
 1 file changed, 10 insertions(+), 8 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2dcfcaada9c6..c39e6acdd7c4 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2420,19 +2420,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		kasan_alloc_pages(page, order, gfp_flags);
 	} else {
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+		bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
 
 		kasan_unpoison_pages(page, order, init);
 
-		if (init) {
-			if (gfp_flags & __GFP_ZEROTAGS) {
-				int i;
+		if (init_tags) {
+			int i;
 
-				for (i = 0; i < 1 << order; i++)
-					tag_clear_highpage(page + i);
-			} else {
-				kernel_init_free_pages(page, 1 << order);
-			}
+			for (i = 0; i < 1 << order; i++)
+				tag_clear_highpage(page + i);
+
+			init = false;
 		}
+
+		if (init)
+			kernel_init_free_pages(page, 1 << order);
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4653f0aa00b575a4dba7df4d44b7a7c92a3f43f2.1640891329.git.andreyknvl%40google.com.
