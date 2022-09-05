Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJ6V26MAMGQEFBOEL5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 73AA45AD252
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:12 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id h133-20020a1c218b000000b003a5fa79008bsf7390591wmh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380712; cv=pass;
        d=google.com; s=arc-20160816;
        b=S21Y3hO7d5PeAqAQqMhSLCXIvfDGNm6M5szmVaQ/hl6taphj73mR7OELZD9rr13fnf
         BbHCfojQhZUV9MPohV6Kxi1Pryy8fwH2TvmEkFwW2C15PLrOG9KXLqIN4I/kByQaSWLw
         QAkO8tDuaJcLT12IprDOXjfG5iHWb3csJIIZXUbz+HCRMszNnptO3NAJCS2rFPQ0bb8Q
         zhXn9xypiyCcvI8mMiYZQ/TCV+4a+EmaPefNr7fgGFUhGyQh4JeVgDPky5Ak8dRYEu8k
         TDzYurxNwagCISXQo0omrdka8gpt4olgI7/XE5933jLvRXuABm3t58S8dwU3/afLefgP
         18aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=v4CcFhCPMAOYJ235x41cgx5olhTgGfBuf6vUKyiklv8=;
        b=gNrwExLjfeImvenYGmYMt6KglAzQjL9neyhUyb/CUuVdtJdxvzL4NjQ9zqY0CXoOCm
         kHShGwEFC3phGMA2VTSHzBDY7pzhY0CxWMyExMSyK7oe256hMqaDtEQCWF0BOx/E7B5E
         qMI0V10xxZMvqcbmp26bQ3DHC4K1zTueScyZu9uXth5KqYC1DM1yjDYSOTSOTlDzmpFh
         QTGAyfUYhiZ3dQpVxrQC7YZpurMOHIiHukAJDZ2nSY4hoGY8wi9cwNSKiCtZ+nPuo8EV
         UDtJ+T11yET9t8fr2BGrIRRSVryYnrHu2cLcuqU8zp2obeSiBtdAMz1rm05dtsJxiSq+
         Utxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cCxag6Kh;
       spf=pass (google.com: domain of 3puovywykcfezebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3puoVYwYKCfEZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=v4CcFhCPMAOYJ235x41cgx5olhTgGfBuf6vUKyiklv8=;
        b=e0KUqCC4Rkxm1lC0kfNUV+3CKr/AbuP4e7y/jG+Ec32DEmYYNgRTQIFTr5qwkh6roe
         Z4pqMtrauM1gzjzhRk9p9catKNjchUbeSzAIBNHiZTW96x3puLUb9oO5MgalaaiPh/0h
         5B8veMmQt8GBFXRC0fTruZrgP7xthUVi3azTqjGqgtqxibw0Pys3aTMg5TNQrvkACb99
         OGrCwZXX2Up/Fgryd2U4yWR7P8kexSCig80dpuUJB1oY0k5MpPtd09XpD6CeTJyuDRZj
         +n+TJby/wHE55JhVnxgycja7vPjk0NFppON+/Aodeix5332i+0xIjJ/q1bArSGgpQKBf
         VLqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=v4CcFhCPMAOYJ235x41cgx5olhTgGfBuf6vUKyiklv8=;
        b=GAarvnZZgF9HYhsn6FJ2tmGdSuiNV7RVVRgXEvTCudmIz5loLqpw9jEPCTEwi9yJDj
         uIWAXx7ZU+W0d1GW9SIDF4N8aD0h4O7NOZtQMsLdIlJMGvTbrTRjY1xdty7/xts+poF2
         NTw72tvStFD519rwr8Vcud0JoMOL5UBWa6jB49jE+JbBdVsjH82iIObml/1KE8y/xM1Q
         +Wa2p5UyXZUtTiQPeeN/t9a0W+0V+DflBqZ5wbZAB7L3okNPMSVEZ0oC33oVKrErTRkn
         BwhylU/5ox8O1TcEJSG1Da8tLzoOuSKemSXN3E2bSlIg7jpvrPpgo+1HFPVJT8svpPFy
         7gYQ==
X-Gm-Message-State: ACgBeo0sB07dr6+TvdTNbxAptYno0kX+zQ4cBpHbqNjggmx0lI1a1yiE
	6p1OhA8b5u7M7mQdjtKyFfE=
X-Google-Smtp-Source: AA6agR4z91gpQpYXEqMM17uH1paghGv+U5n/e0+dIw0/ntEkmnX81/MbdLMB1OMiP4YDfuM91Fbkkw==
X-Received: by 2002:a1c:7708:0:b0:3a5:5543:cec4 with SMTP id t8-20020a1c7708000000b003a55543cec4mr10859251wmi.47.1662380712113;
        Mon, 05 Sep 2022 05:25:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls1529277wrt.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:25:11 -0700 (PDT)
X-Received: by 2002:adf:df88:0:b0:228:8d8e:7407 with SMTP id z8-20020adfdf88000000b002288d8e7407mr2487654wrl.319.1662380711150;
        Mon, 05 Sep 2022 05:25:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380711; cv=none;
        d=google.com; s=arc-20160816;
        b=STJ9k4DKSzpZh18xDEY5RcRMiQujimkk2KaSMfCqyZJrB2hLMGw2R2U8Xv4DiKjRUd
         gufYgsTgICUbiPIzJg1UPPz/C0E+rglPzM4AGFtsOiFZ4TBIuSBAxNEFwuZifld+RB1j
         Rdl7XGzFW1b2y2HLThtLTLYrTZNycQEcnfgeTEfH3bBu9gEenl4kWTDJgOSRGBRJGIe0
         ZXLWN1YJMY4ZwGCqmudrqRtNt2c2cn1MIwCw+YRvrxQqfqi7R79Id61BjIH1464GZbmy
         pkbrUDIpEt65b8+RXzArr6Ox1Ea263Al0Yy+baViD7E/Jukm8P/DAhyfcS7ayqvSlZ4C
         SF/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fFq4uMFAQOrpNZLU6ydmQ4L19fVmnSZ8zUbgI7i1GQ4=;
        b=obyQTiuG7RYRzfptfnGzd30je3CyBX51Av1T863vhcyueUWOaTyVLnCFP4cuZFFy6R
         p4WCCZifYsqkGN0MO1AmYanYqOU6ZrXuGy351SEQKLH8FGu+O9wGX98ooVWkxxCvhGO1
         JNUC2PPyGsWWxu/erFmc4CHK7NbTVOOVIyfgI0mVFhOEajk9v2kaBOvGJteu/eZqg+ql
         qRHuOeieReqIwD0PrBeIaQTR+LzmuXmQKavyX84IEZuT8IwYfQfC8tc+o60Q8LvDjGTt
         cDneqrav2FVNxjG7sz91sHIdowuNWuLJoFgScD06VNwCmb6M5nTMFXFiO2i9+hu0dh40
         +izw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cCxag6Kh;
       spf=pass (google.com: domain of 3puovywykcfezebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3puoVYwYKCfEZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id j21-20020a05600c1c1500b003a54f1563c9si536446wms.0.2022.09.05.05.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3puovywykcfezebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id r11-20020a05640251cb00b004484ec7e3a4so5723727edd.8
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:11 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:2c5b:b0:741:6b8f:d3ab with SMTP id
 hf27-20020a1709072c5b00b007416b8fd3abmr26797162ejc.447.1662380710753; Mon, 05
 Sep 2022 05:25:10 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:13 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-6-glider@google.com>
Subject: [PATCH v6 05/44] asm-generic: instrument usercopy in cacheflush.h
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
 header.i=@google.com header.s=20210112 header.b=cCxag6Kh;       spf=pass
 (google.com: domain of 3puovywykcfezebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3puoVYwYKCfEZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-6-glider%40google.com.
