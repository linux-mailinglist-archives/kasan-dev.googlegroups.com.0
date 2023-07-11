Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBPN2WWSQMGQEQBQPO6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D83CF74F09D
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 15:46:38 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2b698377ed7sf56845951fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 06:46:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689083198; cv=pass;
        d=google.com; s=arc-20160816;
        b=nqGjMnPU4JH1deUSA4Z67xEF3JxD7+Fn+QgXw3JV6PfkulJ8nPgIaPeGx8t/fLnx/Y
         tABYn//mHz5KVqzcJVC9Q82r7vMf5FbTxGkmvQWfD93ZPXwEHIhfolUn2Z+ELANu5lUq
         1r4Ft5yMlxm2fERRe+LQvXJ/JlWs3P7vUrkiILqpxatFnOimqI5PYdj34isJtOOD86ij
         LHuJWvv55MqeGKIzr4GCPSFnOY7vMSwLT6oVRRXvLs3llGjFiVw/QvFR7DWRNtnku/RU
         Xh2P82RG/GJlDLqWhyc/xznHDJsOQINqKQMIKWOhGMz4RqQo6bD30FVcqS5FgiDluiuR
         N19A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Alo5mfTOdvhMcTQm1rbTR1vW2iECgl1iSv4eYaKuOow=;
        fh=5wkMzutboah3mIJLA2vngQ+rKosaYb0XpIOjNELWSA0=;
        b=pCEFuleaoRSY5srC/SVfx8LtEjf/I7lm8Q0sflbdVrhCjQyOCg8PKjebWGku5of4gt
         X85MvkpInpYBxZFdkjs82XeL4KLrdFoJEcTgnOyAdCsLqnoGyPifl0CDeI+CduT7KNmd
         DLUsKT8J1i2Jwj4u9Za4WThl2qY5DIUwsyP4EIb/mpQ2RRzdXmR7HbUnLs/kQ/wtBteX
         IF0l9whv27Oyt7CqS9e5E7+mvFzVjgnANQ/jkiMqt9+pFyVM7VIhPoZBQiz9RYbYzZqc
         y13dn8gDXcEleGAexk4u2M3RuUjYIATbFiaztl7zwyM4mFdk3T2dws8botlLMyPbNw9S
         W5Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DVO93ktx;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689083198; x=1691675198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Alo5mfTOdvhMcTQm1rbTR1vW2iECgl1iSv4eYaKuOow=;
        b=Ea0aqrM5fNv0FrkK/X+gKSsTYmjuuqeLEeoajE7BE/D9v17yd03erMVpA1U1wmqnCi
         AdFzCT7q8qWr7DC0RowX0b+mAkYA9twFYE/As7G7N2bas02bfmyVaLpUAswgf9DomJ4b
         1w/A15qGp2ydtr1lZxMdTrBrGCWQbgjihsSYz4zHiC6C5zBXAG2wofBzhApSq1dYtMza
         26snKyxfeUkELlq/D1u6E0iSikWjLeBUfetYpWkjXbfhc9vXr2I5iMOJaqSXIlOc6AG4
         Sz/Zxaq0GIs6KQeFO8hjX6kGrAD8mOrmKOtxnb4vBRhiU6bP7ye48Ofi6tCmjqBbTLxa
         8dZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689083198; x=1691675198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Alo5mfTOdvhMcTQm1rbTR1vW2iECgl1iSv4eYaKuOow=;
        b=eTfpMht4og86xxCgYGBy6soHENmEZvLKnpDTxkSbDpmhNpMX3Yqvd6rGCFRqaJJ109
         hZbNu6pJib2Bq6GpQiXHEtuhPM4POMTPkBtnIsA+b46GWhznVuauDtzfL8gm19ECPy8W
         VHtaix6QUGo6AXs69C/KD9VUYrjrf99tiS4py86XpcAYPo/rQuYssKQJT4YlpNBY3cGP
         F4URZx3/CjwLo8EyFIfwSz5sVbWhixVotRC0+s6+hgT6QUx1MV1wXW4y6FZ7NieFwfmA
         +Ept1TDyBxcZo40l6m2+locAsWb805zYfNq9s8ykaQYIH7OvDbTCyAsJapqQrB68gSEZ
         nLrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZy7bZiwaDlnPhSMPpUWMYVa7rwlHR1kSBx+wBy5OGir4q2mLBU
	b+Kg5y1FzJcDLMVEgLFKBDQ=
X-Google-Smtp-Source: APBJJlHWFmgQUOmLe5fS/3g35jv/tI5lraD35A7cU4ScxLPHq/GE76GueiCJM+Ruz5OHO5e2zj/SiQ==
X-Received: by 2002:a2e:a0d7:0:b0:2b6:fe3c:c3af with SMTP id f23-20020a2ea0d7000000b002b6fe3cc3afmr2243196ljm.27.1689083197429;
        Tue, 11 Jul 2023 06:46:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc0a:0:b0:2b6:d6ab:415d with SMTP id b10-20020a2ebc0a000000b002b6d6ab415dls2068623ljf.0.-pod-prod-08-eu;
 Tue, 11 Jul 2023 06:46:35 -0700 (PDT)
X-Received: by 2002:a05:651c:104b:b0:2b6:fe75:b8f3 with SMTP id x11-20020a05651c104b00b002b6fe75b8f3mr13327626ljm.29.1689083195687;
        Tue, 11 Jul 2023 06:46:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689083195; cv=none;
        d=google.com; s=arc-20160816;
        b=jgVuhgemtNaoeAqIKvKNnu3B8ar0Cc/fwU6clUkiBPhi3O2u+WTltQntVXW4On7VSD
         cPP8DhAKpk+peDije/7Go0LevfOS4+oIuEMTPtZaRVu2W+ZTsHJ0JBQFSXpJR6d9bPsP
         xPkxEbGw95PxzZdNvk39ajrma9V/PjhGQVrIcoLUYiPHYJ5Pt6FPPaA+6v4O2LaYSQoG
         fq5mhG4JhtCNZccA7tAlYb8ceLGkwBM/l295+M4Ua2l5AYZAWqur0JI3tZd5hD1UIujN
         2jw31yOg4vAGsl+lTyHvzpFrl9oUbr3SvBq14znrPXYjDGGkuffuG+kOa9f0gRvN1fad
         tU0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=RXHIYdVmdQJX5tnkNjy37yeBssRnaU5MoOmNGkfF484=;
        fh=5wkMzutboah3mIJLA2vngQ+rKosaYb0XpIOjNELWSA0=;
        b=nZ5KkhV2K4THBCGi5XCMYdjcvw4IDMMSIRv1P4kRZs9Y7aIxaObk8aikit1s3t2wJI
         KBqx8HgZXMisk8y78jHDndh1sQaJ9dMFjjywQuVrvptWAY0DqWMC2imKAzfOiOPW2sSj
         wvT+6njDc+TRI2f1xe8IAfGjZAz+Ixe2DCtl6jMnk2q5wsmCTqnRg1D9aU2hXzN8Twcd
         3SzMj/1k5Eo3T7HeMCrZ29GkEM6ODYfRJjrwCl743xs82aES/ljIWqdRybaca9JX+hXj
         tMbRJyt6uIsw98nhL8uDYAbNrrB4R+Sa/+nPAl3fADP7A0u0+6jquKQFPnJ4ltsZDl1r
         RLAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DVO93ktx;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id bz18-20020a05651c0c9200b002b6c1fe07c1si152772ljb.8.2023.07.11.06.46.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jul 2023 06:46:35 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0FF911FDA0;
	Tue, 11 Jul 2023 13:46:35 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id C1D2D1390F;
	Tue, 11 Jul 2023 13:46:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id NXqMLjpdrWTSYwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 11 Jul 2023 13:46:34 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	patches@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	Matteo Rizzo <matteorizzo@google.com>,
	Jann Horn <jannh@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <keescook@chromium.org>,
	linux-hardening@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 1/2] mm/slub: remove redundant kasan_reset_tag() from freelist_ptr calculations
Date: Tue, 11 Jul 2023 15:46:24 +0200
Message-ID: <20230711134623.12695-3-vbabka@suse.cz>
X-Mailer: git-send-email 2.41.0
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DVO93ktx;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Commit d36a63a943e3 ("kasan, slub: fix more conflicts with
CONFIG_SLAB_FREELIST_HARDENED") has introduced kasan_reset_tags() to
freelist_ptr() encoding/decoding when CONFIG_SLAB_FREELIST_HARDENED is
enabled to resolve issues when passing tagged or untagged pointers
inconsistently would lead to incorrect calculations.

Later, commit aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing
metadata") made sure all pointers have tags reset regardless of
CONFIG_SLAB_FREELIST_HARDENED, because there was no other way to access
the freepointer metadata safely with hw tag-based KASAN.

Therefore the kasan_reset_tag() usage in freelist_ptr_encode()/decode()
is now redundant, as all callers use kasan_reset_tag() unconditionally
when constructing ptr_addr. Remove the redundant calls and simplify the
code and remove obsolete comments.

Also in freelist_ptr_encode() introduce an 'encoded' variable to make
the lines shorter and make it similar to the _decode() one.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
These 2 patches build on top of:
https://lore.kernel.org/all/20230704135834.3884421-1-matteorizzo@google.com/

 mm/slub.c | 22 ++++++----------------
 1 file changed, 6 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index f8cc47eff742..07edad305512 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -374,22 +374,14 @@ typedef struct { unsigned long v; } freeptr_t;
 static inline freeptr_t freelist_ptr_encode(const struct kmem_cache *s,
 					    void *ptr, unsigned long ptr_addr)
 {
+	unsigned long encoded;
+
 #ifdef CONFIG_SLAB_FREELIST_HARDENED
-	/*
-	 * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
-	 * Normally, this doesn't cause any issues, as both set_freepointer()
-	 * and get_freepointer() are called with a pointer with the same tag.
-	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
-	 * example, when __free_slub() iterates over objects in a cache, it
-	 * passes untagged pointers to check_object(). check_object() in turns
-	 * calls get_freepointer() with an untagged pointer, which causes the
-	 * freepointer to be restored incorrectly.
-	 */
-	return (freeptr_t){.v = (unsigned long)ptr ^ s->random ^
-			swab((unsigned long)kasan_reset_tag((void *)ptr_addr))};
+	encoded = (unsigned long)ptr ^ s->random ^ swab(ptr_addr);
 #else
-	return (freeptr_t){.v = (unsigned long)ptr};
+	encoded = (unsigned long)ptr;
 #endif
+	return (freeptr_t){.v = encoded};
 }
 
 static inline void *freelist_ptr_decode(const struct kmem_cache *s,
@@ -398,9 +390,7 @@ static inline void *freelist_ptr_decode(const struct kmem_cache *s,
 	void *decoded;
 
 #ifdef CONFIG_SLAB_FREELIST_HARDENED
-	/* See the comment in freelist_ptr_encode */
-	decoded = (void *)(ptr.v ^ s->random ^
-		swab((unsigned long)kasan_reset_tag((void *)ptr_addr)));
+	decoded = (void *)(ptr.v ^ s->random ^ swab(ptr_addr));
 #else
 	decoded = (void *)ptr.v;
 #endif
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230711134623.12695-3-vbabka%40suse.cz.
