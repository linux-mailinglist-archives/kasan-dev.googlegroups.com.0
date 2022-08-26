Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMWEUOMAMGQE635DQWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A223E5A2A88
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:38 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id hb37-20020a170907162500b0073d7f7fbbbfsf725476ejc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526578; cv=pass;
        d=google.com; s=arc-20160816;
        b=O+kFbkiUcBnoCnY5QGYxfzd3yjcoBRI3IMUnN7FnAZeHG4MI5wGM6k6relfk+IzK5r
         WWI1B/H8tao7JOPKDfahvN5u7txty3gaDQG5H7xQ0K/3heRWgp1vrpfr+V3Kt+i+79v3
         1xRUbBX2RhmFQwO8jnqr9qoFYr1AxtQHzKoI0s0ACG74LoaQ15Wf2Vba2qpdbVOLoSXR
         wb2AUhJOA35CyJh9yvuiD+YALQifQzFNnSYrd6/UAImda7qoI828YbbLpJpviQF0mOJe
         FiSYGcOwDbKS/cllyOEv/KDNtIy+m0icjKZ12MHMAfqieofyElxMIFBRttxdKAAajcom
         UgQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=lo4qH1gSCNmGueOIxZymI5x8/g9lLEoSjyfxgKXLTko=;
        b=ahH/tCy7kxLAB931Tp8Oi2MAYaT7xli5kDYwoFr5hGVt4n1kZ/YHc617NLIBL/TnTW
         hgXK4FZFCx46hAiJgC0rAuZGjTiCiPHSDGn3DEOQanqvC/KRa+d4WWzXLbtVsHhXh3dt
         DK4qckble+gPwbuz4OxNg/enVfXFPmxFH7bSf0fo1QuY7fhoOHfFD1p6QDHgm/fMPgB1
         SapTKCh/IFoMCKiL8vuIyq4xWXNceOtetzlzijzGvuCctGNjOJQRpFu0nTkAynRxuk+5
         /oElOt4W8VQQia8NHjRS7TEwOErHlutoL4SyiOb5EZOhIspzaQNp+jc3315OVMvVTON8
         adtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TJz1UTJB;
       spf=pass (google.com: domain of 3moiiywykctczebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3MOIIYwYKCTcZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=lo4qH1gSCNmGueOIxZymI5x8/g9lLEoSjyfxgKXLTko=;
        b=gqT30WJLjnIq69KvoRsVe6feyqRdGjDy7CelekpxYzaPzUyFDF2B4D5OAnQiEd2n8G
         amByLMA4NEP1r0mCG2YD6HRgp4zwDkYe5QiTLjpJsK+/h7MEdchhKKL/PVlL1Rdt99A7
         1GZUlO3+7jCEHfcws+0MHh8xZo57QdMz0hxDRzLDYoVNQFPPf4Bb2pxvD1jwJSy4xn3N
         kgKwz3P22IICMQ6ABVfAf9DXUflZm5pe4iVhCFsBay7Z8JO9gagO9a/hscWWi0s9hMi2
         VmOMOfWwCKJ/qL5Zr0+7+nF0ln25POWDFiNSJt9Jz9qX55s8HSP5zdZa9mvm0QmGh0XH
         N6LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=lo4qH1gSCNmGueOIxZymI5x8/g9lLEoSjyfxgKXLTko=;
        b=bkbq4j2q3qEjfGd5RXeXCht+wUH9+dj0INhu0MVcS+MOSIlCHGKARMuUsEBCZupbkm
         8ltvzQFGcgjnLh4sXNOmjLaKuo8P74KrmSb2MYmWP+fYuuscd4nf/aiXj049mv1rNbTi
         sojFZB3dm/WNlOGp2HKo4VVwE/2oeov4G6kz2/f2CmGzCYF8VNO4AZrerWkhOs553UA5
         i905KJlz7Ug53mAmJ8JUGGA0ANBJTpo3Vko9uL6VxS3WhsNtwg+4HZigXsiD8r8Z9snP
         AR9cpWb5tyZLK5odWVwq/Qn9yevvXC1CMiHLLE9atOw9vtx0EiwopsAipOayBmoJWljE
         ZpgQ==
X-Gm-Message-State: ACgBeo2QSuuq6sxOOIAiZdch4xtUJkhCh8dAuxqAU5X3CLblGKuog4+z
	LlYex30kRn8IcT/BOwKIziU=
X-Google-Smtp-Source: AA6agR4hpv4Esx1eeviigF19ih5J2xzkVztgthu0+BdOVKeH+799l4xK5HRcfKSYeMo5yI6jovUNNA==
X-Received: by 2002:a17:907:2854:b0:73f:40ad:4bf5 with SMTP id el20-20020a170907285400b0073f40ad4bf5mr2115052ejc.686.1661526578375;
        Fri, 26 Aug 2022 08:09:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1c56:b0:730:6d43:91d with SMTP id
 l22-20020a1709061c5600b007306d43091dls2147065ejg.6.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:36 -0700 (PDT)
X-Received: by 2002:a17:907:97d3:b0:73d:8b9b:a6c1 with SMTP id js19-20020a17090797d300b0073d8b9ba6c1mr5740939ejc.71.1661526576840;
        Fri, 26 Aug 2022 08:09:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526576; cv=none;
        d=google.com; s=arc-20160816;
        b=a2vwC8gSWQiC2g3voziH/uaJbHlAXW99Awgg08kePaB/6zHxROLtGeSMK+9jH6PNzh
         BRg7TxrGXelT8TggIPETtpBmrpNkmlKCemctztB5wvHgqGK+dy1S/YUjUF+j1Zu5myuK
         bl+EuAKEOkXjjxF23SYBBGkShS6fw006cAGgoT379QBS+CUY0zup6YWN2bPuEF0/L9Iz
         tUC9XQV38HCdpi/868VuX1MzHSj60c6H8oh00hTi4NiAYbds89yqITW/iCN0r5BoUjXp
         wIWVv7vEBnlRs/qyUEq7Gdy5l0oK86tCmcUxd7Jyf6/uqSlSTLKPokaQ4j0UjLkLnIe0
         zzMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RpdJ5KT5GAuxqWidUZuS2M2CiPNp+gZwFhAUBa4xHko=;
        b=wFkCzXrbLG/zagX7KL9IbpjPW6r2y4L6rLkcf6e2L9N0y5UeJj96TH1t8oxud4vfxf
         7GkAxSYgJ5yJ4LZqHXR/WAWIjoIdnKIGSjtKeyh7cV0WJPg9nRLosZ54eWKuKUZqcW6M
         Ma3DkFsQ1PDwJsrs2RBDAAs/o50CWvqID/FKeVP1csTgPSCyppsaueJKIWGmzjNJ+adH
         gmrQ/AJNZs3n5i/goiLxldx+XaSa3cyCtOaYHH4WiSpZfua0gEIU9epj3xJDeCASZGbA
         wqGX7CHIKYKfAga9PTWJy8cV+x3Vc3ClogherYQ9+dfcQaAfgmhT01G56l3TSp+cTKyp
         TkWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TJz1UTJB;
       spf=pass (google.com: domain of 3moiiywykctczebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3MOIIYwYKCTcZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id y26-20020a50e61a000000b00443fc51752dsi85001edm.0.2022.08.26.08.09.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3moiiywykctczebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f20-20020a05640214d400b004470930f180so1242988edx.10
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:36 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:2173:b0:73d:c95d:1179 with SMTP id
 rl19-20020a170907217300b0073dc95d1179mr5669815ejb.89.1661526576513; Fri, 26
 Aug 2022 08:09:36 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:53 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-31-glider@google.com>
Subject: [PATCH v5 30/44] kcov: kmsan: unpoison area->list in kcov_remote_area_put()
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
 header.i=@google.com header.s=20210112 header.b=TJz1UTJB;       spf=pass
 (google.com: domain of 3moiiywykctczebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3MOIIYwYKCTcZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
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

KMSAN does not instrument kernel/kcov.c for performance reasons (with
CONFIG_KCOV=y virtually every place in the kernel invokes kcov
instrumentation). Therefore the tool may miss writes from kcov.c that
initialize memory.

When CONFIG_DEBUG_LIST is enabled, list pointers from kernel/kcov.c are
passed to instrumented helpers in lib/list_debug.c, resulting in false
positives.

To work around these reports, we unpoison the contents of area->list after
initializing it.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

v4:
 -- change sizeof(type) to sizeof(*ptr)
 -- swap kcov: and kmsan: in the subject

Link: https://linux-review.googlesource.com/id/Ie17f2ee47a7af58f5cdf716d585ebf0769348a5a
---
 kernel/kcov.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index e19c84b02452e..e5cd09fd8a050 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -11,6 +11,7 @@
 #include <linux/fs.h>
 #include <linux/hashtable.h>
 #include <linux/init.h>
+#include <linux/kmsan-checks.h>
 #include <linux/mm.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
@@ -152,6 +153,12 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
 	INIT_LIST_HEAD(&area->list);
 	area->size = size;
 	list_add(&area->list, &kcov_remote_areas);
+	/*
+	 * KMSAN doesn't instrument this file, so it may not know area->list
+	 * is initialized. Unpoison it explicitly to avoid reports in
+	 * kcov_remote_area_get().
+	 */
+	kmsan_unpoison_memory(&area->list, sizeof(area->list));
 }
 
 static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-31-glider%40google.com.
