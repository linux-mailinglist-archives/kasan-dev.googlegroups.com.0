Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ5BYSEAMGQENE2NHOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F9663E44C6
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:56 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id w29-20020a4a355d0000b0290284805c0a9fsf6030264oog.21
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508355; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGTFr1WrgLqgzY/Smq9Au8LBgqJxsEqfU25h+oP8bmne7YaiNqkG6/lJholwOvsfQm
         uUPFJcEQLHtrjWM23BJ8G5uSTaHxzZ0G6OW05o9dEktI8opPSfM5Rs7kJD+dvoQUi8oE
         nGC90eNa4XxfYuM3Wd32dBn7aIJBIaVMo5OOLXyEgtj936ft3slNnSufxX9ZGNMz+2co
         HdBdbtbytBzLhH2LX7/PAskdSm9LihqmIr/7b1sG5VCPBnC2l+X2FqGJT4p722lCFyed
         CBT2u7eBvJCV3BrgjGxCjTY8PuLlCCB0rhGJLMkMzXg5HXCL21GB7KRauVI5voNMZ5Fe
         pupQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=P6ZgpejoOvve01tqV4CL4qAkMEAGyEVdm6PExMsvK0o=;
        b=oqDb2q67rLgt8cUmYaMyWpJzpb0/Uvjnaaski/i1IxEceocZMYX+ER1Nx9QkDSIRtJ
         f8LPv0aTrjjbhrCjbgSC1IlHYBTrHnGs75u+GFCvAXBoMURX3xbIMxlHlSZH//SoN8xL
         p+f3HQ0+moLMr//LU3WsDCXZDhYjiqTkyOV1pU956gxtGAj23jdrBrrF80L9mRDODWI7
         DUDfUQRmiPed5s7OQL3em5rdKYVqw7jVCfQVr2neQkAMs2/LqN6bJzNg64Wfx1m4+DxL
         hXpdyiyiO982zAhlLM1qYF32Y0rJGy/gtWkrPczPDQYLw/Oq0Rr6hfw2P2R3rr8ABe2D
         yAlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aBPh3KoQ;
       spf=pass (google.com: domain of 3wxaryqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3wxARYQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P6ZgpejoOvve01tqV4CL4qAkMEAGyEVdm6PExMsvK0o=;
        b=auE5FZHr5JUU2mWKHrAMsYqlUGoIMZ0CXa0GC5IRy9OrtP/gtXLPM7NoV+YEZFb4pb
         zyVenfkwW/c7gZWMHazqetijsrBeQSZt5rxQBlpgkwV3CBisPaVfsG7OshswBl/YSmSq
         52SB19RKZHWG1zLATGGJGaeKDtfgDQssefDSGcJNDqnEj6LRRgP0xjUZuGN3qceROtC1
         y6ri42ruRAvrK3BHvaE86SXQqPSKQhbg47rwF3H76rXQBMnScEwZoDF5Sqr8nU71y30J
         fixp3Ek3lOt+sJ9zA34oPD6yc8zAMC5BgSaxb24x8hHl46VMijrkHus8lmz1x32kaMHX
         dtNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P6ZgpejoOvve01tqV4CL4qAkMEAGyEVdm6PExMsvK0o=;
        b=JJxH+mlyQCRNGaeYZftzyjJXN0m8ynYkHJ4zVcKJMwY+ZShOmZV1h6vqVtuOsnqZve
         pkgK9m9uVa/INhdqO0HxfO5N0yS8XQ7SYbjaUXG8Pan35619vvYWxkC7ZldSZcNAXCPB
         E3QWKpr2S4gBiDd+mb0nzLrT240uzdJBw6mmpcv7hMHUphf1DPszUXfpfVCqs/DgdqTn
         DQ6ko0EJyjGzp74LKND5/dD1iIoRqHplEFSCXUIqBR44J9HWGgC9aaPodwG07HM8KWDp
         iiZxTQ1Mu2lD/y7PpnPFDBCJ3AiXnKXfJ7KelsaZfSLoqBCA1gtLRVTLJpu5QKIwpAnY
         XnPQ==
X-Gm-Message-State: AOAM533MluYnmuoEmQ+/0HYxxa/f9ga/Nb6cAI2WLwB1ihUNlyGf9iKm
	1pS2Mc8hDoKvgn4G8UaDkTM=
X-Google-Smtp-Source: ABdhPJyTyTUjeLTO4h5e2woPuUIWGfxzwrv5ZfKppCtwobQD4sL3BTF+CtemaEHE/Dmsf/Ux5Ll2nA==
X-Received: by 2002:a4a:e5c8:: with SMTP id r8mr14704642oov.65.1628508355601;
        Mon, 09 Aug 2021 04:25:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2804:: with SMTP id 4ls3441099oix.11.gmail; Mon, 09 Aug
 2021 04:25:55 -0700 (PDT)
X-Received: by 2002:a05:6808:f94:: with SMTP id o20mr13030880oiw.112.1628508355275;
        Mon, 09 Aug 2021 04:25:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508355; cv=none;
        d=google.com; s=arc-20160816;
        b=xO47qOzE8cwjO0l9OgWH3AHCIIQRUI8f5SyUq7JBwlsWVLBEf/x6Dm9Fh1EaDXh0Lc
         45yZ9fNwSVuIEa+0ZS/vxoosR//AKNLjpF4GQS0RFYSYzS8/BGFTaN7jW+lImnYrfzIp
         XvowVisTKoUa503Q0i4NgeeBaIxt9DoT3ou85QIYcs9QixXUR8eT1pAX6OosVAZMd9fJ
         ECidZpjrE7l5tyKCWlGEnm1kbZ/KEpqnDnaYaRps7dM9nQqoiqHkLfdmzU2UNR4t4PkF
         PGiGnMTGXJPcbbLegzXpVXTRlusoE9VwcUSQPK/GfitvOZUSML5NIAitFkxI1zm2MpkI
         Pb6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3M2/xbQIahIs7ogtIo1dLeYQP/7ls8f8pJkByGd/S5I=;
        b=SxCx3kDKCQ3yCGeBzVg0Gf0wteLl5AHa7aqpPW8N/6coim862Hz2ncM1JDCd3TydLh
         HihpMcM4CNBX7S0a4jBtf4V2QfWCIjARKZcvx3GQ1YTeGZX736Q5S182zw23DXruCpNR
         rv6mDwNMrUwJZCZt4lsQx82Kr0hlAI7N8I+govvRKoQ3mmGNRUKZtkpURBe7Pxh0bIno
         nA1nkn5xqgTqATb06rzZoOyFUVpU4FEQtOALw+wlHr7rPmKQ9c10iczou8qTX4NiIWNl
         2Ekr9QZGWFnsoq4WeD+0dFHfjnq6iNNgf9uq67twZxgEaBTK1UDrqNyUwhLJTPrCkDtO
         zE3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aBPh3KoQ;
       spf=pass (google.com: domain of 3wxaryqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3wxARYQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id 72si229764otu.2.2021.08.09.04.25.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wxaryqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id b8-20020a0562141148b02902f1474ce8b7so12048128qvt.20
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:55 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a05:6214:d0c:: with SMTP id
 12mr5970119qvh.10.1628508355005; Mon, 09 Aug 2021 04:25:55 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:16 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-9-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 8/8] kcsan: Move ctx to start of argument list
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aBPh3KoQ;       spf=pass
 (google.com: domain of 3wxaryqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3wxARYQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

It is clearer if ctx is at the start of the function argument list;
it'll be more consistent when adding functions with varying arguments
but all requiring ctx.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 8b20af541776..4b84c8e7884b 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -222,7 +222,7 @@ static noinline void kcsan_check_scoped_accesses(void)
 
 /* Rules for generic atomic accesses. Called from fast-path. */
 static __always_inline bool
-is_atomic(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx)
+is_atomic(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size, int type)
 {
 	if (type & KCSAN_ACCESS_ATOMIC)
 		return true;
@@ -259,7 +259,7 @@ is_atomic(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx
 }
 
 static __always_inline bool
-should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx)
+should_watch(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -268,7 +268,7 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
 	 * should not count towards skipped instructions, and (2) to actually
 	 * decrement kcsan_atomic_next for consecutive instruction stream.
 	 */
-	if (is_atomic(ptr, size, type, ctx))
+	if (is_atomic(ctx, ptr, size, type))
 		return false;
 
 	if (this_cpu_dec_return(kcsan_skip) >= 0)
@@ -637,7 +637,7 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
 	else {
 		struct kcsan_ctx *ctx = get_ctx(); /* Call only once in fast-path. */
 
-		if (unlikely(should_watch(ptr, size, type, ctx)))
+		if (unlikely(should_watch(ctx, ptr, size, type)))
 			kcsan_setup_watchpoint(ptr, size, type, ip);
 		else if (unlikely(ctx->scoped_accesses.prev))
 			kcsan_check_scoped_accesses();
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-9-elver%40google.com.
