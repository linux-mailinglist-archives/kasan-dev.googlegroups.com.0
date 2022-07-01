Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY4G7SKQMGQEKCS72YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BA4B56350A
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:32 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id k12-20020a05651c10ac00b0025a73553415sf497181ljn.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685411; cv=pass;
        d=google.com; s=arc-20160816;
        b=geeccpB2Oe7MSV+Wak5qXXnLRy0l+afEGYo1uB8cBkGszFp3xzsnlGaXiK1J5un5gR
         HGzBrPI95YdhgBwbqJvVeWsIo7YHbmEJnE3pBkk07Z3AfrZD0LLTawbtTTAWvllzDcGQ
         oo/xO5KJlvFAiCjSWVeb/Der8BNE1IWF8Mz+0hbIHXZXNY6pWMLHvzg05EYFFWCCctnX
         n23+cwscjWZwxisbl+0uPMf4+5mhwsKAVALl8P7cEv+5z6MnQ9JBi+2+Z70sesvcesGw
         FrqIHuZR9hPFvFrV311zeoq8DRfwAn4u3mGF8ECkWNO/k+I89pJyGEIDzIaRgTl3UUDl
         MEVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=s6h8JCoaD9LtdZtkP7e4SaJdPfcGK187ZddebZMwhHs=;
        b=ytBy6uxDsnFYji9MvQc0HXfWVtuu7wXZO5V/L/+/dFEGyimbW9+b4WVSXxqS2+vp6D
         GeZsvMEypdObGeRF2czYHnx4nu2b83YyJhoMvz84ND+z4GIOE+F3VT7yIgO5DdQStFXY
         34QnYy9NzeDQ2KRcJzGUhwsURSCvS24ZgJdNZ/0wtQaO6RkN9QYwPrnN2xKDE4nnyrvt
         +ePffW07FDeDczuax0aowphYEdtEXsLAcapdH3Uy2rW1t1qnWA3FX2msxzB0epY9P7A8
         c7A1g75WguCjcrAwvahWv5VYd72whI4fxN/0qocg27NdtfWy1ZOvvjQ1z1427GL5g6e9
         GWaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S+rhPYqi;
       spf=pass (google.com: domain of 3yqo_ygykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3YQO_YgYKCYAkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s6h8JCoaD9LtdZtkP7e4SaJdPfcGK187ZddebZMwhHs=;
        b=jmo3sX5VG+atejWpW3leyqjnT0w2KR/IMTJYB+Xc256wTzs1CelzdXubyHTJ29Z5FR
         IEgD5GRH8L8AOGgicKCdcmFXhKEea6CCa9f/V1V7xzwb5hPDFNMnoaIQV8ySGX6ydMtN
         u595CjSOqmfzkXZUM9g7kvc1i4OVcUSkSXsuAc7RYAcQIgRijqMIz+QE6IC16dkAH8w+
         EDBJd1ncpttNvGIa/Fx88XoDkOpR/PvBVD/2H9yrX3SA8Mgk+tABeSCi+83wM62lrl6e
         j6BYQ1Vg+0wbcf3udYRWLVMZK445cV2/DRz0wKX2pQrC2WhT6WzlEqFnZ/qv7OVp3V/3
         A9yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s6h8JCoaD9LtdZtkP7e4SaJdPfcGK187ZddebZMwhHs=;
        b=ibu5YcPxQe+Pi0v2h8GNNjG3lCL3hAcb4VvB8kEvSsPJqqvsyuNA21WVuv0KxMIhns
         iBQCXSN2tl2qjXTFLTreUGXLneQOwJiu76ZmRK7ee2lJ1gLWar4/ALYcEPGbalEJgRLA
         6stbAZo/A2pzsuhfH+Qp40nXiGrZRFtShnpDkm+IetISk+51ePyQMr6ttWbHxCgJ25ec
         nrUlwR6HT7mru6jNKH8no7U1Cokg5MLfPXd58BGql/9cHksiuObPcJNkE/DtWyOkIxkA
         J3saCDl4YS/oHCfvIKw0ixkEdtlO+3x0RR/USy/lGOeMHWlnOCYXdXVsmI2e0bTTAjvd
         mMgg==
X-Gm-Message-State: AJIora8ioznx+JuWdSPJ7sTi1rWbJoANXZcUsXg5NJ5ZG3Uo/ryo7bvE
	e08MU2c38DtYQf+L0qSRaBs=
X-Google-Smtp-Source: AGRyM1tTKA6YG2/iBfk7GweSk15jC5iL9s2tXA8zASuFhLOMHfNOU25PdCvCepabKkpwYmq2VHvtSw==
X-Received: by 2002:a19:ac09:0:b0:480:6a10:4c39 with SMTP id g9-20020a19ac09000000b004806a104c39mr10143329lfc.115.1656685411633;
        Fri, 01 Jul 2022 07:23:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls85876lfn.2.gmail;
 Fri, 01 Jul 2022 07:23:30 -0700 (PDT)
X-Received: by 2002:a05:6512:2314:b0:481:1694:f888 with SMTP id o20-20020a056512231400b004811694f888mr8915930lfu.562.1656685410329;
        Fri, 01 Jul 2022 07:23:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685410; cv=none;
        d=google.com; s=arc-20160816;
        b=v/Z49d5tH33wF4nYezCUdk66BXu/TTkDFnw63A+MnzwtnyhZMQnp9IO6aOJJ/O3Jht
         H3bBZ6UpLdlaLJQUg2uUXv5FQV0UCtOLxrnrpxc0+T2d3oh4Z/ikpXy4DrFodT0tJChX
         v01MBSd+NBVsT7YIt6iyfA39UL8UKdA3sU4vy8TQ67RDoTujQB7MLEsre3rzetZNHB1Q
         GQWA1uyc8UM2h735et7rjZKwtbnjOo1MSK5VgfFPGaIbnkCStmh8UpiVlGMg6S3m7DXR
         yaMPD7WPYF2Pewuf+wuKteAZbhycficl0kDUgDQAkY89b89lfAjnZxmhPY+EzrHvXC4S
         69Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=pc6R18JS+sE1u3dlHmLsZDbE6VaTO3tMmut2L/JxCPM=;
        b=luhHANt94mMgfQBDpS8AgmFAtS+L8U79LwWr50jOYweT1vsXmLabfEI/oJdbLbbQ6x
         XfoV3E4BBTSjT8q5gdgvs1qLfTW5YUdcuWOaqc46KEgLPiX4F7CWtkorgQQTF2AqThB3
         GBPSpgBOf+RDmrsCVdizc3ChuxmUqN9mk/xrtYCqPxVtMnJFVEi95WOkopneBIzMUdsd
         ywguvsaO46vASXQrlNXIHXZHi6jpXX6a9pzdMOzCOQEl912CDHZyM9k0Q3KrDk+8qKSo
         yBEDMsyerIKK/v7f51yr36TK7IAfGjp7I7ErEa6m17qDVBjOwbj8MWtmMmnhKzclhSI+
         B8xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S+rhPYqi;
       spf=pass (google.com: domain of 3yqo_ygykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3YQO_YgYKCYAkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id p15-20020a2eb98f000000b0025a8d717b7dsi1048305ljp.5.2022.07.01.07.23.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yqo_ygykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id z7-20020a170906434700b007108b59c212so843722ejm.5
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:30 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:3514:b0:435:f24a:fbad with SMTP id
 b20-20020a056402351400b00435f24afbadmr18590781edd.311.1656685409756; Fri, 01
 Jul 2022 07:23:29 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:30 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-6-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 05/45] asm-generic: instrument usercopy in cacheflush.h
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
 header.i=@google.com header.s=20210112 header.b=S+rhPYqi;       spf=pass
 (google.com: domain of 3yqo_ygykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3YQO_YgYKCYAkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-6-glider%40google.com.
