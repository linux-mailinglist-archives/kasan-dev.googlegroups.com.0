Return-Path: <kasan-dev+bncBAABBCOOXCTQMGQEN5DKZGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 025AA78CA5A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:12:43 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2bbc1d8011dsf55476531fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329162; cv=pass;
        d=google.com; s=arc-20160816;
        b=ly5BVM/K7KUOIr0KBM0lJ8346BFzWRY8IAirZ3dhQEWZnD2v1Kit1z+aU7fzcK7Uiw
         qBBcTUaYuZb4+6+EhBGy0b/iyjzFTl+ypoddSp39L5N/Fehkat/VTIu/8N2bkokCqfxg
         OMK7QJAbFTClUxT6k78r+3tOfRf7Cvz0kFtvje7Uum2I+AYc7k9FqHqfMtlIVxaIXXGP
         gKwGgz8+59zLP1l38VeeBHL7bZBFX5KDtB0sdM8skjPt3ZTAWQrz1AQpgbtc9EyzcTkG
         OV+3iHwqcYt+aFIuGQZSXDytEgOMMWm63p1Ysa0gx0W3bHYIeid91SvV7RsokZJk6NfT
         Ui7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=078wc/umk/ajXmmYVRGGHeEaD8sJj1ELsf/AkFKn2YM=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=C0Yb6c3/CN2/Ff0VBmIv3VaB1eEjKL7P2EGQG2bGyK4iv0wXMg/Sd2RNW9CZA4G7qH
         H2HvXO0HdE5i6edc4uX55phY3gaB0vpX04vDrgb+QDlSdcy3XRV7v1n0VtfmBIUXORmM
         vuX7IRJTOKBg3e4eXugmqXtgUa89x7tXbu5QOnTZIWNohKJoIdfN+NDzdt42Y+pLSUYm
         JuIKVdbqxGyVYgSF8HjIcWQf2XH6t5ssPyAkJpwRgqGuOIzQC2hY2vchefG20GvUW5gT
         o3KXpItFlPykXWSSp0H097T0mZEC0i46ErUVYBIVxlmDBndj1WkX2wlaolHc6TZhFLT9
         HJmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xUAvBItl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329162; x=1693933962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=078wc/umk/ajXmmYVRGGHeEaD8sJj1ELsf/AkFKn2YM=;
        b=BJZMyHGx6Vo7LgRCYM53jcAeFmyT/Dd9we63C0oBOizoo04gZC4Xj/oswuJj+SUjtJ
         7PIEhvn1GN/JVg85Sr6hkLwk//OeUkUeQelle0bvtHCCtgPHWnRGNH8vyu1NjAgvvQsv
         9gY3jv0zeNwfxIsaXfp+2EUo2f3JvgQJcM74cPXiyfA+T+DpOMpB9gwoAawLs7BbQNTb
         +H3jlvjurqbPZfb7dtmBoFGo8YdQ1V46VsiXi7dA3rJP54L+Dcu5YTNEJXbJJmGCZEGc
         uEb0bYyccAHgkht8ENGoYxjp5eKYwFKk4rwHEUcgm85F4cyPshY8+O1eW9Mib+jQf7x/
         em1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329162; x=1693933962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=078wc/umk/ajXmmYVRGGHeEaD8sJj1ELsf/AkFKn2YM=;
        b=aOnwudgXLm5F87itmwOQnksVGxWRHQZml++nN+Pv3aM/oaaxhhagUTV5rL/In5xoxs
         Cy5L3hxJ+v+nsNI6mIhDLW1OGD2E4QAJeYEbxYnMa/CIF6/PLwY/Afgn+jHQ3x8DaHZa
         RXm6/xzftTltSZVzEqzCC4GYK6hwjWazl57wrddnYeRflgYutV34bmznwGXRUyx1d2CD
         PDasTgzwHs+bPtDuXNkvkqONyQUVMCMeG5ICRH0qNVeOpG9AybhsOTAFvbZAtr94sy6o
         M3fg3bYm14V6pgccJkk0ARzyjRDENO1tnu6Gf7eGvkD/i+c02xVJ8v8cmDNlQ8dfAsBo
         2S8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzeWQz5P3b8yuZupuL9vIR2gz+bS/7Er8HyS40s71AqaqXc5+94
	HkPVPGE164PEoRpO7OMaAXg=
X-Google-Smtp-Source: AGHT+IFnBatnY9UaQtfTuclrnvjg9TsT6EY29QLgnHASY0vm5CSsPXpy/EnF3JvK3awEHm3E16Ze0Q==
X-Received: by 2002:a2e:3a1a:0:b0:2bc:e808:e735 with SMTP id h26-20020a2e3a1a000000b002bce808e735mr11347538lja.21.1693329161924;
        Tue, 29 Aug 2023 10:12:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1c9:b0:2bb:94e3:fea9 with SMTP id
 d9-20020a05651c01c900b002bb94e3fea9ls93309ljn.2.-pod-prod-02-eu; Tue, 29 Aug
 2023 10:12:40 -0700 (PDT)
X-Received: by 2002:a2e:9409:0:b0:2bc:cc1a:139c with SMTP id i9-20020a2e9409000000b002bccc1a139cmr14722067ljh.11.1693329160334;
        Tue, 29 Aug 2023 10:12:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329160; cv=none;
        d=google.com; s=arc-20160816;
        b=HKvw1irSqCvuzvcwrFrQVc5obp0469Jc2UhQOAJWmsfntHNQ7fhYkIb+fWcTnrAG/M
         pWqWefKZlOeRjeGyMTsnWl3s36HMXDOSWdSWTO9iqXH/qG6P7rr/J16NYXgE0WFZ/y1l
         FLmR3WNGFcFcxir52N7wZvLV0qxVMuC8RWSl/n/t34ZkOZh20txxYimkd8D1/7v/Tb2x
         tBDtSJcmYCqV98XoR/nIsNG12gtj6Zaq69ij5KtjJGcqYvkkXiak/OXkHHlBgeJUIytt
         1PLb+J9Lo0VJbxHVTd5UxPy4cMkFpjQGBfKjWXVb+TFqpek4uo0uj17MQCtdkd7lTIht
         KR5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+57664S6bw4mOO/qPj8h7l/H8qh2Ip2xAdoPp4fmyag=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=u2ocISjQquGALUvDIgdAbbBWkpS6djz6SYhk2ksLm5GMs20ztJY8y89uIJ3rXOj7zT
         3A7f431MReH5ys/aIIScgrPXSfw/6SqfPPfJvS5PPvdTiYTlaAanJItX3vGm5h/uk/PH
         ahepE7jtaEeOYFNTI6IxsToXhmoM4YypcG0dku1oDfYg/pTChFBOihVLEZwtzumFF+19
         uj8p7jfqPPwqIlPxSzG9V74NhgDhx//LPnrpKJVcIF044yCNrI3NEjJ9y6lh4alWZw6k
         v/0eitEQgIdWxHieRM/rF0BjglrsCVarvypOT1Mfy8KcXbphuZXtVpPJj8AGcK2oWOIW
         VwHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xUAvBItl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-242.mta1.migadu.com (out-242.mta1.migadu.com. [95.215.58.242])
        by gmr-mx.google.com with ESMTPS id i25-20020a2ea379000000b002bcc064ac3asi645829ljn.7.2023.08.29.10.12.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:12:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as permitted sender) client-ip=95.215.58.242;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 06/15] stackdepot: fix and clean-up atomic annotations
Date: Tue, 29 Aug 2023 19:11:16 +0200
Message-Id: <8ad8f778b43dab49e4e6214b8d90bed31b75436f.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xUAvBItl;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as
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

Simplify comments accompanying the use of atomic accesses in the
stack depot code.

Also turn smp_load_acquire from next_pool_required in depot_init_pool
into READ_ONCE, as both depot_init_pool and the all smp_store_release's
to this variable are executed under the stack depot lock.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This patch is not strictly required, as the atomic accesses are fully
removed in one of the latter patches. However, I decided to keep the
patch just in case we end up needing these atomics in the following
iterations of this series.
---
 lib/stackdepot.c | 27 +++++++++++++--------------
 1 file changed, 13 insertions(+), 14 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 93191ee70fc3..9ae71e1ef1a7 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -226,10 +226,10 @@ static void depot_init_pool(void **prealloc)
 	/*
 	 * If the next pool is already initialized or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * smp_load_acquire() here pairs with smp_store_release() below and
-	 * in depot_alloc_stack().
+	 * READ_ONCE is only used to mark the variable as atomic,
+	 * there are no concurrent writes.
 	 */
-	if (!smp_load_acquire(&next_pool_required))
+	if (!READ_ONCE(next_pool_required))
 		return;
 
 	/* Check if the current pool is not yet allocated. */
@@ -250,8 +250,8 @@ static void depot_init_pool(void **prealloc)
 		 * At this point, either the next pool is initialized or the
 		 * maximum number of pools is reached. In either case, take
 		 * note that initializing another pool is not required.
-		 * This smp_store_release pairs with smp_load_acquire() above
-		 * and in stack_depot_save().
+		 * smp_store_release pairs with smp_load_acquire in
+		 * stack_depot_save.
 		 */
 		smp_store_release(&next_pool_required, 0);
 	}
@@ -275,15 +275,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		/*
 		 * Move on to the next pool.
 		 * WRITE_ONCE pairs with potential concurrent read in
-		 * stack_depot_fetch().
+		 * stack_depot_fetch.
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
 		pool_offset = 0;
 		/*
 		 * If the maximum number of pools is not reached, take note
 		 * that the next pool needs to initialized.
-		 * smp_store_release() here pairs with smp_load_acquire() in
-		 * stack_depot_save() and depot_init_pool().
+		 * smp_store_release pairs with smp_load_acquire in
+		 * stack_depot_save.
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_required, 1);
@@ -414,8 +414,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 	/*
 	 * Fast path: look the stack trace up without locking.
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |bucket| below.
+	 * smp_load_acquire pairs with smp_store_release to |bucket| below.
 	 */
 	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
 	if (found)
@@ -425,8 +424,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * Check if another stack pool needs to be initialized. If so, allocate
 	 * the memory now - we won't be able to do that under the lock.
 	 *
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |next_pool_inited| in depot_alloc_stack() and depot_init_pool().
+	 * smp_load_acquire pairs with smp_store_release
+	 * in depot_alloc_stack and depot_init_pool.
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -452,8 +451,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		if (new) {
 			new->next = *bucket;
 			/*
-			 * This smp_store_release() pairs with
-			 * smp_load_acquire() from |bucket| above.
+			 * smp_store_release pairs with smp_load_acquire
+			 * from |bucket| above.
 			 */
 			smp_store_release(bucket, new);
 			found = new;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8ad8f778b43dab49e4e6214b8d90bed31b75436f.1693328501.git.andreyknvl%40google.com.
