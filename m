Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3ODUOMAMGQEMVKKUNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E06A65A2A5D
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:29 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id j9-20020ac24549000000b00492b0d1dea9sf292344lfm.16
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526509; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pr6pVu+ymD49FyYKpyfknZ5G0Rb6Z5SflX/Gnfp1WjnNtI7J2VKFK1ahAJ92TTkm4l
         UBTl2B7VOboQaJF//BIsqOWFQFkVqphREveOMqiar4ncwe1k9pAqREftcBMSWdIzzddO
         8pBMlSEWtb8c0w1ChYNwmZBO3+oddW9NKz1lgBrc0i1TrPbv12XYmM8KA7AHnvjQ4+aH
         kFY75e4hmxD9Utt/4oYfNBYHOmCoXBcNHowbOgVZrUB9dPc7Re4TqheL2mG1S0R1fWWe
         ZcJvYm61/yZN3gyuIiODjDHAYlnPXHAmgq9mr8OUqAbcxY0J5OdSmG2TLm/z/sFwDQ9h
         F86A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YruzIjFw50sfj1sn5RQt53yQv29jXqgereLNOank4VM=;
        b=hg7wQUlRwgrBWr8wEbu9CGoQH4GOBh3VMdG0qhO5G3khpPgwydde2XYsODzx8VRske
         u9N/boZiCEBqaLHjF/GRjw/hgDhZJ/inEgzSKIO4aV96O9hNGq5fdWIlawQJr7H4Sz8c
         loAjKRtbdK9qIWnpEPEwVTLiHDt1Ay3scBXuAMuApoblcgZGAC2frY6a99bvBVKE+/Je
         z0A7AnL9y0pVLUxulqT7tJfuxihQiSCFQBNAq8Bkp1Mq6ZQ2D6RKSqrZU7KhS/kGcGJI
         Cw8eOl7wwXPzTHoJ+gBY6nYJIRRWIrmgY94cpZBFsURJP1VkIdWDweUCIfv8DQ1CtEHt
         9+DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gfe3GoUc;
       spf=pass (google.com: domain of 36-eiywykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=36-EIYwYKCfAYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=YruzIjFw50sfj1sn5RQt53yQv29jXqgereLNOank4VM=;
        b=oag/9A+JPCS+zLoY/S4sERghHIb33LUAqBMZrcWcoQgRjMN2Fn46NGvkI0FBjxagjz
         /q4GG2reBgNZK7/mJ+XNkBBXsWS1XqxGe99vF2D5dxvoX5Gphx6AJVdD79oucxupAnEF
         lf0YZu2LWgorn9G5stM6mGeM6g7iK7zY2cuUTHzy/xs8Ei59t1Oe6Uxvia3qb4GMi6ks
         RzSz2hhtEXnYmzmp9Mk3Dydh19RZsC+SrWppHR+LNFAgj6huUns8tlmm2VhTMG87tO3o
         9ZaITdPiC3ABA6UQItn7SuBBcpwdF8TE+3uLt9+uFFPWjCJUzW93fY7hCOQZ6gBEti+m
         gGtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=YruzIjFw50sfj1sn5RQt53yQv29jXqgereLNOank4VM=;
        b=l1zGbhL+jmQ2vWWAWqx7RcNoMuNAgi33N3Cz7Xt2AFtJ+RS89+70aeFKpqdvFun3O/
         RGFzukP+7PeRDo8bx5b99xSmUKHNOGLiKr1DgZrHyQenlmkzLAPE4cHRn7ZhxYuhP4kD
         Uwyc6b52dWV33MD6lVUGhkf9wGHnXo3hKRA3oQC4VKAknkC5VQsNKp6tfDNYFvCWvPnl
         FW2LzwtbtrtM1zeRbfeTXIH8f246dkDu4PLjLQJ/Wdtqsr8UPjHtuOUGv6v/9ROjWYyB
         TSohfSz9/jyO9eyMAzb3mWfOuYC6fEAZplI0HpdC1QnRbbzjGv55cX5yJdu1eJZal4zA
         IMKQ==
X-Gm-Message-State: ACgBeo1jeSn3n03X6X6bTAGR+EfhsMdUqPNJsRDAk///cpWcCzSKMhqX
	CS1Zj/G960SZj0h0Nes8PDY=
X-Google-Smtp-Source: AA6agR51aaPYSORCQ+0jpGYKbBRSAw592MUf7t4fQHqMEXU0+Azq3WuN5xkEng4dsQ2+lxX5UfAz9A==
X-Received: by 2002:a2e:9b95:0:b0:261:df1e:118b with SMTP id z21-20020a2e9b95000000b00261df1e118bmr2492945lji.470.1661526509372;
        Fri, 26 Aug 2022 08:08:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f53:0:b0:48a:f49f:61c4 with SMTP id 19-20020ac25f53000000b0048af49f61c4ls1121893lfz.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:08:27 -0700 (PDT)
X-Received: by 2002:a05:6512:2306:b0:48b:2905:21a8 with SMTP id o6-20020a056512230600b0048b290521a8mr2954789lfu.167.1661526507760;
        Fri, 26 Aug 2022 08:08:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526507; cv=none;
        d=google.com; s=arc-20160816;
        b=OGyjyHfi5KQzY3GS3gZdIoT+bE8v2Ub/EsiM2wK2zcG8w8iJupJvRzKLb8D6Og125S
         EXzemOaN8Qk/yRSiDx4Zl2wVjnVjrC74YWdRDws6JN5IJFMt+j+MlCfQ3BXaj7pTs0ZB
         X7knl2NRTYWxVWSzeRECy/PWcWpiOaaImSQZPHYAk9OAsCKeTKBNJZE/huZekTBBEhC7
         u/uuSgBWEKUJyzPlKK9xQMWRngyKU3bGgvtaAYZGBbJaENn4Dg7ikAKjWiF0csk3FeTW
         PALXQzzZCLK12aGFrBLnp9gHeB/fW8HW0krclWQ8X1JXS/TDj8Mj3lGc+zucVk2IG/3J
         iFsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=P3BIEQv1T/KwZafUGZKUBc98ocOSrUKFpAGAcrUMbqQ=;
        b=I13xJWWapCaoC5BO1KyLvOFIewEAKa4fmesg8KAX7etyo5qxaT+tDmtZ0eJK8kl46m
         RPc9L7sEGM55eDXz0zrG4FkTxQDLA8bsh1y3LJpxfRxQGi9uFoqkdcom+D0cauk6cTfM
         ExCVfhJKhHOEzDBFypRR1NW2pt1lTOyjv7NyrqqYDD+3GtP8bT650UYCCxFcID0L8gdv
         ydCBslfxJWYPseRekzotl98JHKn3e2RmYHsbFpusYdjqxQVYoyyEs+RBrSHm00MLCjAX
         z1353gfudxRRshs6DOcsjptCDUl/RmXYfujzLqVzst3KTz3TXsLeB+33qu2CijFLWjwy
         HGwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gfe3GoUc;
       spf=pass (google.com: domain of 36-eiywykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=36-EIYwYKCfAYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id z19-20020a05651c11d300b00261eb78846bsi70426ljo.4.2022.08.26.08.08.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36-eiywykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id nb10-20020a1709071c8a00b006e8f89863ceso715980ejc.18
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:27 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:c06:b0:701:eb60:ded with SMTP id
 ga6-20020a1709070c0600b00701eb600dedmr5913732ejc.178.1661526507100; Fri, 26
 Aug 2022 08:08:27 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:28 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-6-glider@google.com>
Subject: [PATCH v5 05/44] asm-generic: instrument usercopy in cacheflush.h
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Gfe3GoUc;       spf=pass
 (google.com: domain of 36-eiywykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=36-EIYwYKCfAYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Notify memory tools about usercopy events in copy_to_user_page() and
copy_from_user_page().

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v5:
 -- cast user pointers to `void __user *`

Link: https://linux-review.googlesource.com/id/Ic1ee8da1886325f46ad67f52176f48c2c836c48f
---
 include/asm-generic/cacheflush.h | 14 ++++++++++++--
 1 file changed, 12 insertions(+), 2 deletions(-)

diff --git a/include/asm-generic/cacheflush.h b/include/asm-generic/cacheflush.h
index 4f07afacbc239..f46258d1a080f 100644
--- a/include/asm-generic/cacheflush.h
+++ b/include/asm-generic/cacheflush.h
@@ -2,6 +2,8 @@
 #ifndef _ASM_GENERIC_CACHEFLUSH_H
 #define _ASM_GENERIC_CACHEFLUSH_H
 
+#include <linux/instrumented.h>
+
 struct mm_struct;
 struct vm_area_struct;
 struct page;
@@ -105,14 +107,22 @@ static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
 #ifndef copy_to_user_page
 #define copy_to_user_page(vma, page, vaddr, dst, src, len)	\
 	do { \
+		instrument_copy_to_user((void __user *)dst, src, len); \
 		memcpy(dst, src, len); \
 		flush_icache_user_page(vma, page, vaddr, len); \
 	} while (0)
 #endif
 
+
 #ifndef copy_from_user_page
-#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
-	memcpy(dst, src, len)
+#define copy_from_user_page(vma, page, vaddr, dst, src, len)		  \
+	do {								  \
+		instrument_copy_from_user_before(dst, (void __user *)src, \
+						 len);			  \
+		memcpy(dst, src, len);					  \
+		instrument_copy_from_user_after(dst, (void __user *)src, len, \
+						0);			  \
+	} while (0)
 #endif
 
 #endif /* _ASM_GENERIC_CACHEFLUSH_H */
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-6-glider%40google.com.
