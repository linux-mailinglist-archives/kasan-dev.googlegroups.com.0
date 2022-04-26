Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5OCUCJQMGQEEN3Y6BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C59F5103E0
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:38 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id v11-20020a2e9f4b000000b0024f195a39a0sf1006152ljk.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991477; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vin9lBzHOAxNi0EHBxMGhugNHevwxYLzzLAJDNn65nG+3a9x39j23+2zHW59FgIqdS
         PtqA39laiWThRp4k3WO70kF0GpXZZQZSXg89tYBiuKtdS+2LGtA/FXUxWVJkckGC4Pgl
         p+Qlfj98NHPOwtz8jGzIzi9fgYOle22aZ/PZ3Ig4Ljx0KfCbUHhTEOHKmMV/hWUo+EdZ
         ppy9Q54TAEbHKjd45wdRlo21Csv953A+xYfaZUFCVr6EQYA9BKqOxYJGntT4kiYZw//c
         2AxL26MfyCI3xUSHbmHFuEhG0VHCI2pHGBXlUV2vX/SIFtQIcTSlik0ejZqEvVhhQJI6
         nYeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=TaQGfpdS+qYyZE9mOWcBcNtO+p3w5ZHjha0qyAyIETE=;
        b=oG40ZEwjJofbxrG8fCPLt2HgThXAM02FIOp3ffC0IohhfVJkoTZTF2HcInHhZS3+FG
         Cs/omnV0GLCx9MdlD5yQoHJdTa//xStGcrh6U5tMiXs5MAwWljfwU/JIyczJFECG2d0U
         d4aq8V15DL8tArI0twxkn5/gdiWIr5jcv12wPNp67EX9ZPurNbHG8zPGVJqlbOHAJrIj
         4EC3kOjzBry4xcLu4f5rAHlZl+HJ5yxC68l+7oI167HGSrGH273ysKi3uW/C0w45N39G
         NDTBfJqUlpUCOYTLw30FDAZqR5ko8eWzPLyko1Jw3P44iLCjZJRpamRQZm6rkxm9wS4T
         O7fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RcuVhtgi;
       spf=pass (google.com: domain of 3cyfoygykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3cyFoYgYKCXAUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TaQGfpdS+qYyZE9mOWcBcNtO+p3w5ZHjha0qyAyIETE=;
        b=NMMwfP1g7Use+31BnOJdxSkCsyvN20DqO/bh0pWcUwdyCTDDZR8p8NedX/qHEjqNt9
         80G6TTgOVVGEgIgx8moHsGcAJ0+ndQgJVKDq8Bzu0K0251OIywHpi8+jukHu4OD/7In+
         GDSD+vgmYNr6Dy9k5opJtPekdL4e0omCG4h0thgZ+USBsnQPb6lO/y5SIIL/1RJUeoFY
         vs3dfpOQPe0DALVx9QSeQZYz07FIDHxOYiPsLxahMO1JYvB3/uGm5akmScEoEiITnDum
         1K15RGpNAQ9SLTY06RzrhF1tbh1cDDxQ684c+jX1dHr/HEI297SpOB9mpuahnOIl06i/
         R5Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TaQGfpdS+qYyZE9mOWcBcNtO+p3w5ZHjha0qyAyIETE=;
        b=KDJLJzPOp+YBDe1YfpTTnS8dYd9FJB7ynx3ohwclIhFTRmMrsHzltu29Fh/q/M5ij5
         +Ugi3uvS+uj0lbLK8sPplzzZGFp+QGpFwmRfHUGIf8bXvyZufK5mWQbdWPmLPl+5jcst
         YY8/hpIkvubLidA3kCWq93M8Gp8cr/CekKFe5NXls3HB78gsgjNTlflrFMYiihV5eaIS
         aC0GKLZM8OshojjKLLFrBXH91PHen29qkQc1I7H+HwwboAwFOMkMd4CeHPHusAvUL63R
         LA1vciYpfVB3yT8Ms03YPNslBSFINKnokOU8kVdRMNiHADCadtmP6agL42Lxmh4s51kK
         Ve8Q==
X-Gm-Message-State: AOAM530xV4MpKAEE5zfBAOl3H+L4ZsX9uwQZEM1+CNeNzXtmaFUA8wia
	luBaczlWwJ7x4zR5dW6pR24=
X-Google-Smtp-Source: ABdhPJx8c0PS46yq4y6cosSgCVgwl4XWcyDhKvAGsCPlsylQcL3FXs8svpRcz8n4jjZ9i6gF4Gya6g==
X-Received: by 2002:a2e:bc0f:0:b0:24d:b273:e41e with SMTP id b15-20020a2ebc0f000000b0024db273e41emr14501492ljf.301.1650991477394;
        Tue, 26 Apr 2022 09:44:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e2a:b0:471:af61:f198 with SMTP id
 i42-20020a0565123e2a00b00471af61f198ls2092438lfv.0.gmail; Tue, 26 Apr 2022
 09:44:36 -0700 (PDT)
X-Received: by 2002:a05:6512:b8a:b0:472:56d:ee21 with SMTP id b10-20020a0565120b8a00b00472056dee21mr8391677lfv.343.1650991476301;
        Tue, 26 Apr 2022 09:44:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991476; cv=none;
        d=google.com; s=arc-20160816;
        b=jkZ6Rjl2L5FB8Oh7iBmCBNj6Uu5/rgN0eVhj3eg7koYnxZu2cLXZ2qdIgIlR/zSciw
         zaKJ5Bf7GazDJXcLvTc/k97Qv95UrALPzaVlRS/3KNfF0i+tQ9jZwIlIEdZWdq9i2Dv9
         gLUMdHikVFg0/dMw0ZpEtXlwtHK8sGDO84zxXHDlpP70QjrpeHf+gAKFV3Pqeay3cGBS
         HqyD4/avLWBgeXlR1AHA7Og9Tp6KH8lIgLXfjNKEobXPD3jjtVGVMFt/UJCjwmIyjki3
         Zd97M8NQLtRlzmKLZ7FW/EKAPQTwox23HvfsYuTdpPVZnVaMSaMYGAQ5960J4orW9pPa
         2cbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=cG4bw4Dybp9do4PvtZBZ2e2ITt4Wsjs9LSUgy4lmV+4=;
        b=aQcie8v3zSEhzCo+HAmbSGu56+tRM9dl+vdJgb/AVsFB0BKPf2uZwHtZL+tXAr+3xR
         uceIGc+aUIX22KyzlUGHs3dyBsm9MPt3M7AdFq3oXmI6bMF7PSPgQw6gpX1wzwiokk5B
         okbjefei3rXqo+00W2+lIRB10TLfyPtOP11sLFd4VfRLSrnp5FJO084W22g9/Xw+zciv
         vAnx4pvvY51lPCyfqV9EPcij13KLRj233cMP/XdgR/Xr0dHMS1jCWYLn/iKK8l3cftmX
         dJPElrHTaXglV2gG+B9uF164xLOws2wyURkOxmnxTX1Ot/VcocAXmRsIPW57fg4sNRpy
         setA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RcuVhtgi;
       spf=pass (google.com: domain of 3cyfoygykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3cyFoYgYKCXAUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id o3-20020a056512230300b00471902f5be2si866919lfu.3.2022.04.26.09.44.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cyfoygykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id jg25-20020a170907971900b006f010192c19so8621597ejc.21
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:36 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:2809:b0:423:e123:5e40 with SMTP id
 h9-20020a056402280900b00423e1235e40mr25792114ede.84.1650991475654; Tue, 26
 Apr 2022 09:44:35 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:35 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-7-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 06/46] asm-generic: instrument usercopy in cacheflush.h
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RcuVhtgi;       spf=pass
 (google.com: domain of 3cyfoygykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3cyFoYgYKCXAUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
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
---
Link: https://linux-review.googlesource.com/id/Ic1ee8da1886325f46ad67f52176f48c2c836c48f
---
 include/asm-generic/cacheflush.h | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/include/asm-generic/cacheflush.h b/include/asm-generic/cacheflush.h
index 4f07afacbc239..0f63eb325025f 100644
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
@@ -105,6 +107,7 @@ static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
 #ifndef copy_to_user_page
 #define copy_to_user_page(vma, page, vaddr, dst, src, len)	\
 	do { \
+		instrument_copy_to_user(dst, src, len); \
 		memcpy(dst, src, len); \
 		flush_icache_user_page(vma, page, vaddr, len); \
 	} while (0)
@@ -112,7 +115,11 @@ static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
 
 #ifndef copy_from_user_page
 #define copy_from_user_page(vma, page, vaddr, dst, src, len) \
-	memcpy(dst, src, len)
+	do { \
+		instrument_copy_from_user_before(dst, src, len); \
+		memcpy(dst, src, len); \
+		instrument_copy_from_user_after(dst, src, len, 0); \
+	} while (0)
 #endif
 
 #endif /* _ASM_GENERIC_CACHEFLUSH_H */
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-7-glider%40google.com.
