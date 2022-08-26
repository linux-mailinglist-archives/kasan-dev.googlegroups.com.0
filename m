Return-Path: <kasan-dev+bncBCCMH5WKTMGRB56DUOMAMGQEKNN5C6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C9245A2A62
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:40 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id k13-20020a2ea28d000000b00261d461fad4sf660304lja.23
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526520; cv=pass;
        d=google.com; s=arc-20160816;
        b=mfR1fqrUtaL0SiPWcrGGKItTU54xcMbbPfoOm614VacdkribUoThqurFDvWLdNwuL3
         nFWZ32smcv9RkReAYNhbRcUhPEQWaai2E2UWuj3NEJPb4qNlNLois975roqDk2GtOG6P
         TYMM6pZ4r4v7548KHInseJHe0aZW9Gdy2XOdazHGI3mkqKe8fzgrw2UUuh6+MSZ5LCV+
         JYTAF3uCbC6UWX1rVDyRQfPlDIisM3Xcb8yXNvf6dk5itLnPHvVuVBeqxy7VOfrCl6zp
         HgjWWM5YepppMnn1Su+xu71SxhEYJPX+qTgMM1pJudduPjP/ArsptuYb7J9ncn3YrNN6
         cyRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=QnGlBVd7Arc9tDij7WGgWL2IIypPHQQJ4U61SAQfdEc=;
        b=qYRiPsyexiDggMksGdIZk2oEPWwN1aWqcmsbO/vyLZzDf+tnPrbadf2ycV0qYCbfCM
         yXId21WAgYhCLXtLUMrA5KdpvrVgjdwB/6IO4lhk1bgT7mmUK5eXCBXwJ9HvnUYVvmww
         Xmpq6Lf0Cx2byDIAXnBaojF3cHt3tv66B3kkWp4g1VGKn8gt8w3GWKjnjxxo/Yj0sY+J
         B9FdhvamrNOizKyz05M3JRzPrTXIJTaGK3RIvL/P31RcpoKa5w45/4n8fwXaDrKBy7SU
         XK1n6v4a7NxJYm+Rq18IgsRPTUGpgN3AeCUDoX2P+AlbETU27wvHk0URn8Ck36/vDAV0
         DW/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ofrs8PCM;
       spf=pass (google.com: domain of 39ueiywykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=39uEIYwYKCfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=QnGlBVd7Arc9tDij7WGgWL2IIypPHQQJ4U61SAQfdEc=;
        b=a2UnZdpueF8CmI4U+PGEpHS7LQt2Fm/j/8G3fw+oLflOowp9UGfZCDYcJ79lHyFYRd
         z+EVQWWy9aVr3wNqNqGQ+gGO8VR36CceUKumzJuu5Sxvv3FG7J4iwi5GZxwhmE/n3+Hn
         mYu3MgQ0f/ycWt+IBfdFjESIqAdpCbnmEKWNTu6gIVZSkEFnMD8dmFa5ei51EMhH+oYt
         2X8R7orGH4JF6wEJv8ClpcqfQegjWvpJcyf9UWTfHY7jwgd2YOodroJ50QBoeKklClgB
         b1xiEQos8c9eJovrhigxf/A3oFufhZCSDJVZnleUBWTR6j+9d91SfUM6kW+SWezfnDjG
         w5Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=QnGlBVd7Arc9tDij7WGgWL2IIypPHQQJ4U61SAQfdEc=;
        b=rhxR50O2Bb8PumI0os/AvxVA5gFiTK1rRDeUhfTUoKdEd+ou9RyUlWl9C5P15sGepk
         rGF+CZr0KwchVhpwzBhjjLKAqs6yzklTqL48ZqH80olvmA7EBAvezdauL8cVYhgBt8DK
         bz+SllS26Ys/eKmVJi2L8WCFg6XM6w9b7REh3NydIlEFU0uyjXYTAXKUEaGN3S9/sxAO
         Xx6RyuRnaEB61PIZKC2304PmTO3BArUDx85D+rPo3Cx2CVl8ZrqrST53b2dIoiC3yKNl
         Gf909pKnVfA489vC1ynoVfuEi6QO9V8mOArK8H9TwNXy+oPQisf/XrQX567iS8FeM95S
         eg2w==
X-Gm-Message-State: ACgBeo3+UcTGE7elcdW4gH43Wnq9iNJA+WDRHPQe2e5zxnuH6Y4riI4v
	nnO8jKjhpBOhygveIgcG5kI=
X-Google-Smtp-Source: AA6agR50sP43jfD46Zeg2DatSKWAUHsKRpKzBsswz5mx7DPrnR2EbxoNI4Z3tn+pU/RcvUkxdcJN5Q==
X-Received: by 2002:a05:6512:2290:b0:492:e0ed:364b with SMTP id f16-20020a056512229000b00492e0ed364bmr2745203lfu.314.1661526520006;
        Fri, 26 Aug 2022 08:08:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:995:b0:261:b5e5:82b6 with SMTP id
 b21-20020a05651c099500b00261b5e582b6ls707974ljq.9.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:38 -0700 (PDT)
X-Received: by 2002:a2e:be2b:0:b0:261:c0d4:8264 with SMTP id z43-20020a2ebe2b000000b00261c0d48264mr2345417ljq.16.1661526518823;
        Fri, 26 Aug 2022 08:08:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526518; cv=none;
        d=google.com; s=arc-20160816;
        b=Bz+LiX0PjL21KHbczDwxH0RkEr5tU/ahrF7gxIIBWE8YhNRBq3H/Zgl25/VLrxgwvu
         Ex6a6v7seKUXP/Iu7VNYjBT0SKMbKWdPo/Q3ZaJLEAms610K9CCEPhbjHwE3vTyNLi45
         u8Mr3SmM70Hru+aEHLRambk9lvuDqviyeeC1eJ1MiskPd8WVDLFRw1+XU/iOhPtcdyJZ
         VBLIQRqqOvsdxcTUYp+2hiI7NB7sykS4PEdXgDq/SIzHmZVIVPoNUm0J0BTSCz+a05tt
         t8NuRSOrUmmKbdHFCDPJhb9bdzsB4l6NBWN2WcCON4IM6oF7+OIHfvrQPVejHlQNp8Ur
         m7Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lZyR+/TbY71+6irDHrQVY8i8lV0LAE0DR0x5Sx//ziQ=;
        b=GFOh/2WGBDTV0+7V37VQnM3hGUDleQJ5xktQOi1Rn8HyvWlhBsufRmfz3+3ID0YBma
         R/ub/Lki/vbDnSfwVU02iLxW3TosuhfeJVXDL6au5D10QsdRjSwQ2d4cNsSxoA3dsN3B
         iObTcuMrtjU7UlKdHs+rEsoRJuEFaPqnIk7VeZQJH88y98ap1N8yb3n/+UtbuIBtuWAe
         fWaiEcJJzmpfzmqx9neuLB+1jdu96fwE/1U8kzn2GfGR80QzD4W4mL0UDsfYDkq92nDy
         AYBtT5HGFycDQYFGUKhvNmkm41AxO/9oJS6vBr1bfQJmFp+QjGLba1iBvjksel6N0bk9
         uuQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ofrs8PCM;
       spf=pass (google.com: domain of 39ueiywykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=39uEIYwYKCfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id i22-20020a2ea376000000b0026187cf0f12si74897ljn.8.2022.08.26.08.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ueiywykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gt9-20020a1709072d8900b0073d82402ea6so731506ejc.21
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:38 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:906:f88f:b0:731:463d:4b15 with SMTP id
 lg15-20020a170906f88f00b00731463d4b15mr5703796ejb.299.1661526518263; Fri, 26
 Aug 2022 08:08:38 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:32 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-10-glider@google.com>
Subject: [PATCH v5 09/44] x86: kmsan: pgtable: reduce vmalloc space
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
 header.i=@google.com header.s=20210112 header.b=Ofrs8PCM;       spf=pass
 (google.com: domain of 39ueiywykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=39uEIYwYKCfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
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

KMSAN is going to use 3/4 of existing vmalloc space to hold the
metadata, therefore we lower VMALLOC_END to make sure vmalloc() doesn't
allocate past the first 1/4.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- added x86: to the title

v5:
 -- add comment for VMEMORY_END

Link: https://linux-review.googlesource.com/id/I9d8b7f0a88a639f1263bc693cbd5c136626f7efd
---
 arch/x86/include/asm/pgtable_64_types.h | 47 ++++++++++++++++++++++++-
 arch/x86/mm/init_64.c                   |  2 +-
 2 files changed, 47 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/pgtable_64_types.h b/arch/x86/include/asm/pgtable_64_types.h
index 70e360a2e5fb7..04f36063ad546 100644
--- a/arch/x86/include/asm/pgtable_64_types.h
+++ b/arch/x86/include/asm/pgtable_64_types.h
@@ -139,7 +139,52 @@ extern unsigned int ptrs_per_p4d;
 # define VMEMMAP_START		__VMEMMAP_BASE_L4
 #endif /* CONFIG_DYNAMIC_MEMORY_LAYOUT */
 
-#define VMALLOC_END		(VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)
+/*
+ * End of the region for which vmalloc page tables are pre-allocated.
+ * For non-KMSAN builds, this is the same as VMALLOC_END.
+ * For KMSAN builds, VMALLOC_START..VMEMORY_END is 4 times bigger than
+ * VMALLOC_START..VMALLOC_END (see below).
+ */
+#define VMEMORY_END		(VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)
+
+#ifndef CONFIG_KMSAN
+#define VMALLOC_END		VMEMORY_END
+#else
+/*
+ * In KMSAN builds vmalloc area is four times smaller, and the remaining 3/4
+ * are used to keep the metadata for virtual pages. The memory formerly
+ * belonging to vmalloc area is now laid out as follows:
+ *
+ * 1st quarter: VMALLOC_START to VMALLOC_END - new vmalloc area
+ * 2nd quarter: KMSAN_VMALLOC_SHADOW_START to
+ *              VMALLOC_END+KMSAN_VMALLOC_SHADOW_OFFSET - vmalloc area shadow
+ * 3rd quarter: KMSAN_VMALLOC_ORIGIN_START to
+ *              VMALLOC_END+KMSAN_VMALLOC_ORIGIN_OFFSET - vmalloc area origins
+ * 4th quarter: KMSAN_MODULES_SHADOW_START to KMSAN_MODULES_ORIGIN_START
+ *              - shadow for modules,
+ *              KMSAN_MODULES_ORIGIN_START to
+ *              KMSAN_MODULES_ORIGIN_START + MODULES_LEN - origins for modules.
+ */
+#define VMALLOC_QUARTER_SIZE	((VMALLOC_SIZE_TB << 40) >> 2)
+#define VMALLOC_END		(VMALLOC_START + VMALLOC_QUARTER_SIZE - 1)
+
+/*
+ * vmalloc metadata addresses are calculated by adding shadow/origin offsets
+ * to vmalloc address.
+ */
+#define KMSAN_VMALLOC_SHADOW_OFFSET	VMALLOC_QUARTER_SIZE
+#define KMSAN_VMALLOC_ORIGIN_OFFSET	(VMALLOC_QUARTER_SIZE << 1)
+
+#define KMSAN_VMALLOC_SHADOW_START	(VMALLOC_START + KMSAN_VMALLOC_SHADOW_OFFSET)
+#define KMSAN_VMALLOC_ORIGIN_START	(VMALLOC_START + KMSAN_VMALLOC_ORIGIN_OFFSET)
+
+/*
+ * The shadow/origin for modules are placed one by one in the last 1/4 of
+ * vmalloc space.
+ */
+#define KMSAN_MODULES_SHADOW_START	(VMALLOC_END + KMSAN_VMALLOC_ORIGIN_OFFSET + 1)
+#define KMSAN_MODULES_ORIGIN_START	(KMSAN_MODULES_SHADOW_START + MODULES_LEN)
+#endif /* CONFIG_KMSAN */
 
 #define MODULES_VADDR		(__START_KERNEL_map + KERNEL_IMAGE_SIZE)
 /* The module sections ends with the start of the fixmap */
diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index 0fe690ebc269b..39b6bfcaa0ed4 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -1287,7 +1287,7 @@ static void __init preallocate_vmalloc_pages(void)
 	unsigned long addr;
 	const char *lvl;
 
-	for (addr = VMALLOC_START; addr <= VMALLOC_END; addr = ALIGN(addr + 1, PGDIR_SIZE)) {
+	for (addr = VMALLOC_START; addr <= VMEMORY_END; addr = ALIGN(addr + 1, PGDIR_SIZE)) {
 		pgd_t *pgd = pgd_offset_k(addr);
 		p4d_t *p4d;
 		pud_t *pud;
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-10-glider%40google.com.
