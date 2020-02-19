Return-Path: <kasan-dev+bncBCV5TUXXRUIBBYG4WXZAKGQEF3YAFQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AB28164BC5
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 18:20:34 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id w4sf548866pjt.5
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 09:20:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582132832; cv=pass;
        d=google.com; s=arc-20160816;
        b=BUtAWSpl3wVq1eD/iev/8ZQRxwCMPazL4fu9nwZRJXhZuNZF2XVN7WXB+nrDE1r4NI
         vbBprUu/57WcxLiPT4CMKgVogKAtzFf8G7a0yBc5RIVL4L/c6tcifMhTxqTAoGLDnzIJ
         9bRJvSzuYQrVT2Ll60UIEViqilyIOsRbvYye48dTjKc8blMqm4bXwHat/BiNF961RA2n
         uAT2zbe4XyUwId7ngeQe6xa3skgwrIOCcQWqQvMg62N1jx/katf5zOnnLZ+VUh6JHRh9
         pz0yIr4DML0PzPd1RGSTnyh3Dbj1Zs00jP3YPnCD5FlqlVu5gUFtl7YD3tOgk14n0kVv
         MDQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=etdeIP0rQaf93u9zoOSQAP+jdxg3rNyqN+xq4E4soCE=;
        b=cVjs0RwCJc8eoT/IZDLRqlc/2haDyKmI0GyumDACVNk7xFe38JGkbm2igoZES2GUKC
         I0PbMaCvy54cSNktRZbpaJjfwO8o7cI6mwIjAcEm92ePcz2vvOV4ou80G0t3MoFNGBKZ
         rQYoTmdMrn0TD4jdhlD6mSB9DcVEGesVUgkDIFLBzkxSGTYHzqo7dzeGKFpw3Tug0OZK
         KmATzoITdk+lM3ezuEW0hdE9T7cyHa9dzuDdAEGys/7I1lCQdS82kVTpWit3iygU4DdZ
         SheFnqhT4xFwjVyHiNn/kPD/oRR0uK6Rd6KeYBrsJiSXeVNQ8cdTwSvBJmKdNorNdNdU
         Q8vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=KFt4lYhl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=etdeIP0rQaf93u9zoOSQAP+jdxg3rNyqN+xq4E4soCE=;
        b=QmI12Cakp/oC3s7IztwjLYu0/PrHWxZspfyASU+1v6GjINqKjYw1RRYwSuUzZj1zAO
         pzaMZlZf7otG8m+XdTNBz1S8W/GWMTeA0GqDQg2dwk3Ooec+hSOy0/YcaUq+HJ2pELhi
         OtRQGj15NM3AqgCYjwqm7m2X8Z1tH0s/U31aOvrPCsQ9crWLkKBjdd7WGX1KxeIf4Ch9
         Gr9gRij34q0rZOrGoECT01XAgUPSB+8Sc8bvMEVPiLh1tSxsuvgEIUjfZBwQ2P483lqj
         93AHduruopszFqvhwRamHWodj8AxLYo8rSmQNlWF6WWuOzk5VrLuNwCRHtC3wtZSGVkh
         1DUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=etdeIP0rQaf93u9zoOSQAP+jdxg3rNyqN+xq4E4soCE=;
        b=a0iA1A/KtJIK+JVzo+815D0aPR3PCaBNK50W/GCJO2/VT7iEZVLnoiYenv0LUuAEly
         uEB0i9F6E0Z3KsVB40TG/oNneX/svNM2v1nVGtZjGrvn9D2BqM6hzLykZAZ99O20pudk
         H7JapOb4He9GJi3Lk5uyJS1lwiJoz5gggAKsK7RxV3nRgQpi+rTlU/uHFOhEm+Uu7bjf
         ONIdmnQ14JaVEOBG4oGiWpCjVpuvtl3EP5Zkq5Z1fV3B0aNKQYulFHGN4mNa4Y++t2UR
         NL6rgFu352+0XnPbCDCwxVFy7vr3czg9Z6MZA9Ou8Y6xjh4Sc5cOkVwuWZcKRZplCkr9
         x67A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX+9MG/NS2UYpMzM36GLCh0z63f/2Tlj7xk4cXFTXXAWZV1JPtC
	r8R7pZZggyB++me00OLuFTE=
X-Google-Smtp-Source: APXvYqy5HSJUiM/j+NGm3LRjCaebj/biZqlYPaVm/uy2WKVfTpEDjVKIBM/fgEsnMriNUtVkMi2ohw==
X-Received: by 2002:a17:902:41:: with SMTP id 59mr27880688pla.39.1582132832373;
        Wed, 19 Feb 2020 09:20:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad06:: with SMTP id r6ls3122115pjq.3.canary-gmail;
 Wed, 19 Feb 2020 09:20:31 -0800 (PST)
X-Received: by 2002:a17:90a:154b:: with SMTP id y11mr10025622pja.78.1582132831656;
        Wed, 19 Feb 2020 09:20:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582132831; cv=none;
        d=google.com; s=arc-20160816;
        b=XY8hhRzcIU1M3+Afb6wojgd3O1/Y6cuhiEXSJqtKMhbjoejwxu55Q2X3wCdG7yawLY
         Q6VrYrKQjpOTcroDFtxTw4EerlPu8BH/jNvDxmcIP2oRWWQqPjcWYZ6UL/Dh/aGlpjEb
         /yPlZLb4I9Gg0mNbGIpmWmATP7dkfql/tQVIQRzntfRkfogYl7nv8+AvL4QL4eyEiKjF
         jnBVit46JIOZ7fMjDV6GBtR2+Uai5/idQ5QSL2tLRBHwwtnpve57Bx43av+hcdCZip2D
         zxL1szqHckijQScHcvsV3izT8dAGB8n33/AF5WDYbwpRXyl3zCmbIMux6a8hckBIA9aX
         GGjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QTd8tp07eNhPjbukKA+LEnzzWa9t43kN5uiLpBUNZb0=;
        b=rJs9af7tyzt2vroIO6jL9xSjjeFWmKRAQQHNMxSdu0FllQkr0vzGeA1c8z30NsF5iL
         EQ/GsnJJVanzaPiE8EYiFkEW98O5llYfgauABv28JU+t7TDk6KCUZJ9NG6j2SfzHYvqZ
         lKblA/EHa7LPgEL+kGSebWLXIQ6pHEcGgMEUCkx08e6HnQ6Zr85xb+xDQA/KtAVFZ03w
         rWOYfgs088Mdk0XhOSi750j52dY+Po7+CVUPA0RtYSTqndJDkhR3QIC4HwzjA4f769YB
         p+kHiyOYKhov4Q97fLWJRpmwGP9Uj88FTNTyJNFvXTLwahaObO2CY1NcPZkD1XSjPq+s
         cb/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=KFt4lYhl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id x78si31098pgx.5.2020.02.19.09.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Feb 2020 09:20:31 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1j4T1E-0006Lh-1T; Wed, 19 Feb 2020 17:20:16 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D4845300606;
	Wed, 19 Feb 2020 18:18:21 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 17DA920AFA9B7; Wed, 19 Feb 2020 18:20:14 +0100 (CET)
Date: Wed, 19 Feb 2020 18:20:14 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ingo Molnar <mingo@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, tony.luck@intel.com,
	Frederic Weisbecker <frederic@kernel.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 22/22] x86/int3: Ensure that poke_int3_handler() is
 not sanitized
Message-ID: <20200219172014.GI14946@hirez.programming.kicks-ass.net>
References: <20200219144724.800607165@infradead.org>
 <20200219150745.651901321@infradead.org>
 <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
 <20200219163025.GH18400@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200219163025.GH18400@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=KFt4lYhl;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Feb 19, 2020 at 05:30:25PM +0100, Peter Zijlstra wrote:

> By inlining everything in poke_int3_handler() (except bsearch :/) we can
> mark the whole function off limits to everything and call it a day. That
> simplicity has been the guiding principle so far.
> 
> Alternatively we can provide an __always_inline variant of bsearch().

This reduces the __no_sanitize usage to just the exception entry
(do_int3) and the critical function: poke_int3_handler().

Is this more acceptible?

--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -979,7 +979,7 @@ static __always_inline void *text_poke_a
 	return _stext + tp->rel_addr;
 }
 
-static int notrace __no_sanitize patch_cmp(const void *key, const void *elt)
+static __always_inline int patch_cmp(const void *key, const void *elt)
 {
 	struct text_poke_loc *tp = (struct text_poke_loc *) elt;
 
@@ -989,7 +989,6 @@ static int notrace __no_sanitize patch_c
 		return 1;
 	return 0;
 }
-NOKPROBE_SYMBOL(patch_cmp);
 
 int notrace __no_sanitize poke_int3_handler(struct pt_regs *regs)
 {
@@ -1024,9 +1023,9 @@ int notrace __no_sanitize poke_int3_hand
 	 * Skip the binary search if there is a single member in the vector.
 	 */
 	if (unlikely(desc->nr_entries > 1)) {
-		tp = bsearch(ip, desc->vec, desc->nr_entries,
-			     sizeof(struct text_poke_loc),
-			     patch_cmp);
+		tp = __bsearch(ip, desc->vec, desc->nr_entries,
+			       sizeof(struct text_poke_loc),
+			       patch_cmp);
 		if (!tp)
 			goto out_put;
 	} else {
--- a/include/linux/bsearch.h
+++ b/include/linux/bsearch.h
@@ -4,7 +4,29 @@
 
 #include <linux/types.h>
 
-void *bsearch(const void *key, const void *base, size_t num, size_t size,
-	      cmp_func_t cmp);
+static __always_inline
+void *__bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp)
+{
+	const char *pivot;
+	int result;
+
+	while (num > 0) {
+		pivot = base + (num >> 1) * size;
+		result = cmp(key, pivot);
+
+		if (result == 0)
+			return (void *)pivot;
+
+		if (result > 0) {
+			base = pivot + size;
+			num--;
+		}
+		num >>= 1;
+	}
+
+	return NULL;
+}
+
+extern void *bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp);
 
 #endif /* _LINUX_BSEARCH_H */
--- a/lib/bsearch.c
+++ b/lib/bsearch.c
@@ -28,27 +28,9 @@
  * the key and elements in the array are of the same type, you can use
  * the same comparison function for both sort() and bsearch().
  */
-void __no_sanitize *bsearch(const void *key, const void *base, size_t num, size_t size,
-	      cmp_func_t cmp)
+void *bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp)
 {
-	const char *pivot;
-	int result;
-
-	while (num > 0) {
-		pivot = base + (num >> 1) * size;
-		result = cmp(key, pivot);
-
-		if (result == 0)
-			return (void *)pivot;
-
-		if (result > 0) {
-			base = pivot + size;
-			num--;
-		}
-		num >>= 1;
-	}
-
-	return NULL;
+	__bsearch(key, base, num, size, cmp);
 }
 EXPORT_SYMBOL(bsearch);
 NOKPROBE_SYMBOL(bsearch);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200219172014.GI14946%40hirez.programming.kicks-ass.net.
