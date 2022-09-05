Return-Path: <kasan-dev+bncBCCMH5WKTMGRBT6V26MAMGQEBKNUUGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B375AD260
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:52 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id y11-20020a05651c106b00b002683f8f9cffsf2811001ljm.18
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380751; cv=pass;
        d=google.com; s=arc-20160816;
        b=TqA5GFgYZh20hlZzEv9QHtjoRRCu7Eegl8T89IET6BuBZ9iWF/sf/I8Ah3jRywtrVR
         h2Pfwmjlixn1S4gG/Hdg8iLLApUg8gBeLRQMwth/wRYPyeY+EzZOdprb4hQtDXYBZn1z
         CkMzbIg9GlgoSn/+2z0M8dYSsVJgYj8EDu4M0m/ZtCvOSR7Orq2jC/25D4ZoRtTycTIi
         fo8gMwpIcKqfA2EInnfWdBbXRCSjpXMppXKW0zdzYHyqT78cjx8nNt9sVtvxRMBTsxWA
         13atOEZZY+aZaWdmHqSi4KRgoH+VOnnQvdirNb+joszbahngf4DWFdn2/S60u/NQt784
         J8xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6UqFIiDienqcSesH0ldvGDT2jWCa3/L5ym9o+5thxDo=;
        b=ewDm4uzsHMVYUezulXKU4TDFdYjU02y3NOMX2fGAlEAHUyhz8OWOKWnDtZPySLMUyY
         zZObtcJv2GdL6vVPtzCUIclWS5Hbe89fqBw+v4kUX6HcqMV6VtnBdPy0Ndt147M8SSIX
         bV8q3hWC4lgFDULMlIEvk2c2FpNjQtvK5sVbQ0sBOb6Fas5qhSa7f49tbn0iMMyOXBr/
         EoOuP1qsrrEsMfwy05uLrH1ulWRD9njL+TgGqdFOdybd/QKIhlZUznm+V0XhimbzU1D7
         3aBRYlSkWrM0KcIhJe7F8ELCPjAO6XD6JUdHFk2/0s1M4hxhqwgALsdvWEPcqlJGUs7m
         DMfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="FI/NN8FV";
       spf=pass (google.com: domain of 3zeovywykcro6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zeoVYwYKCRo6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=6UqFIiDienqcSesH0ldvGDT2jWCa3/L5ym9o+5thxDo=;
        b=H+PHxC0Uc+oJYPzzvnT+HIWrHxr2euVhBREZimYFjVJmp81sjpGFUXo4bCJZpVzi1t
         hiaMJ6b44GtLVLPrpajEGnnJ8Nf9u4+yMxI59ECafOOgEkurnQY4sb3GMQEniImZ1bGl
         ePqXIYiY5zbH+USucHW++3YnHdRwFy7OjX8Kh4Hi3PeNTiYK1XSm8xGILB65YfSEIsHs
         Pcg/xSRNsZcVZcDlp3zay5Unz+Fxyhmd0x/z/pQqKQKf1NCfSsXUxAk9DV0JjIuOtPFv
         UhrNLaZXN12mX4NSrGyK3MQAnSDL/s1B4WZa8ZCd1eTfD1tdXGHgMd2Ccmyt2xcej1Cf
         Mydg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=6UqFIiDienqcSesH0ldvGDT2jWCa3/L5ym9o+5thxDo=;
        b=h/Ti/gtA2SfKwKBZxyFACGZgadwcGYHIWSu7mA3W3pXeIrhy08IH27XPmzyYqes1zs
         hZ/odGdKgBdzfa4QMB1TcxizdiP9SqFt8ZLzYq/YL0hxyz3s8BAf7qHhp8ZXiRwe1El6
         613EIDDTw4US7vOjoWJqzIJK+iaJawD4aMuGwqQ2d+SCOL9dUB7Onom16UjmtQGr4oVr
         Fp5S9ewOScT40xoRRwYhAOn/SiGDZbwtqDtOfjn3pAu/rS9WNRSCo5VyCDNcH0DOCMXm
         knI3D5t5Zw/HRa8zoHZU0H2HpE9YqHBjVRO92mhge4K5G8+91Ls5/heFQJDUvSnWwdAV
         DxCw==
X-Gm-Message-State: ACgBeo1qWmINLgltuyyAR8AFbAjBDXqUtyYcw7CBRa/Keo6VZuFvx17y
	mBtLmKM6iUYqznGmXGhAcag=
X-Google-Smtp-Source: AA6agR7px7Vg+Qt06hit68FtOLtcioYmf9y2oxDOXH3sViG95VpXR24alDKgyKxIEZ4/FmowuWr5Sg==
X-Received: by 2002:a2e:9d06:0:b0:26a:89cd:de26 with SMTP id t6-20020a2e9d06000000b0026a89cdde26mr352958lji.453.1662380751498;
        Mon, 05 Sep 2022 05:25:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc19:0:b0:268:a975:d226 with SMTP id b25-20020a2ebc19000000b00268a975d226ls1563816ljf.7.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:25:50 -0700 (PDT)
X-Received: by 2002:a2e:9e11:0:b0:268:c7d0:9662 with SMTP id e17-20020a2e9e11000000b00268c7d09662mr5048962ljk.309.1662380750466;
        Mon, 05 Sep 2022 05:25:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380750; cv=none;
        d=google.com; s=arc-20160816;
        b=0+IivGGHG1+3pG0DE0pGCfdLgQloh0qVShwvH55kvNjwCg497m3gHAQE4CfvN+lby6
         Ye6jZVjN5jelPEniQW8UU+sirwBZcOGYFp4jtnklYr2lX+KIEyOgwiuvMdK0qdrgSBnx
         /rGDuh+1U3CHSVUwwvUlqR9kdmJ/4bcrTXZbtiW1FV0t3kH7ZnqtHL06haUw18atAYsc
         5KyW3sECcyUe2Ug+fVF/IzthvtjBmRzDCVRDpNgvVjQzowhoFMS8MAOR97ww6VwrrA9V
         0ZBMgcXU1jkc4kuOgp3RWC/mPgnulADIm0VRVO14we2FV81vbApGaPcx0D4k5mPb2duu
         /BLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=JDbXYbJWwPmgAZI0cqV5N9fdafuEA5LdQ6bM1NbJ2qU=;
        b=Slu+gknRB1PF+oW5A0Dy42mnAz0iVravyZRNmoNZgaXB/GkBZyzt3RLJrwQth9/Q8V
         kpvb/TACMOzAK+ekBMXHXoKJZUyIJgtpHHlVnXKRbd3B21LRH/hUg8HiH3kN65VgGMGx
         0smIUh3PS7yVw9g743U7lgCouBMGfvfRuo46q0r1E2RjTcJm3YlDTq5SsxQU6FDhHkWN
         gkzhtjiCoNJCdE97fh/+q0w2mRXdZMRxouDVhSBSZoDaUpwqtjY4zi5jD+pu8mtjRpgy
         7KkmWSXNHvecyCYpXJkHBsotoZZTStuDy62i+OeU3EOPLbJ4wdaiqTMqE/iPR5FUBFE/
         ee9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="FI/NN8FV";
       spf=pass (google.com: domain of 3zeovywykcro6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zeoVYwYKCRo6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id z6-20020a05651c11c600b0026187cf0f12si336745ljo.8.2022.09.05.05.25.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zeovywykcro6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s19-20020a056402521300b00448954f38c9so5718946edd.14
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:50 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:7242:b0:741:7cd6:57d5 with SMTP id
 ds2-20020a170907724200b007417cd657d5mr25769275ejc.419.1662380749795; Mon, 05
 Sep 2022 05:25:49 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:27 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-20-glider@google.com>
Subject: [PATCH v6 19/44] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
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
 header.i=@google.com header.s=20210112 header.b="FI/NN8FV";       spf=pass
 (google.com: domain of 3zeovywykcro6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zeoVYwYKCRo6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
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

This is an optimization to reduce stackdepot pressure.

struct mmu_gather contains 7 1-bit fields packed into a 32-bit unsigned
int value. The remaining 25 bits remain uninitialized and are never used,
but KMSAN updates the origin for them in zap_pXX_range() in mm/memory.c,
thus creating very long origin chains. This is technically correct, but
consumes too much memory.

Unpoisoning the whole structure will prevent creating such chains.

Signed-off-by: Alexander Potapenko <glider@google.com>
Acked-by: Marco Elver <elver@google.com>

---
v5:
 -- updated description as suggested by Marco Elver

Link: https://linux-review.googlesource.com/id/I76abee411b8323acfdbc29bc3a60dca8cff2de77
---
 mm/mmu_gather.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/mm/mmu_gather.c b/mm/mmu_gather.c
index a71924bd38c0d..add4244e5790d 100644
--- a/mm/mmu_gather.c
+++ b/mm/mmu_gather.c
@@ -1,6 +1,7 @@
 #include <linux/gfp.h>
 #include <linux/highmem.h>
 #include <linux/kernel.h>
+#include <linux/kmsan-checks.h>
 #include <linux/mmdebug.h>
 #include <linux/mm_types.h>
 #include <linux/mm_inline.h>
@@ -265,6 +266,15 @@ void tlb_flush_mmu(struct mmu_gather *tlb)
 static void __tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm,
 			     bool fullmm)
 {
+	/*
+	 * struct mmu_gather contains 7 1-bit fields packed into a 32-bit
+	 * unsigned int value. The remaining 25 bits remain uninitialized
+	 * and are never used, but KMSAN updates the origin for them in
+	 * zap_pXX_range() in mm/memory.c, thus creating very long origin
+	 * chains. This is technically correct, but consumes too much memory.
+	 * Unpoisoning the whole structure will prevent creating such chains.
+	 */
+	kmsan_unpoison_memory(tlb, sizeof(*tlb));
 	tlb->mm = mm;
 	tlb->fullmm = fullmm;
 
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-20-glider%40google.com.
