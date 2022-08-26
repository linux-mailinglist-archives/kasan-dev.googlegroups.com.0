Return-Path: <kasan-dev+bncBCCMH5WKTMGRBE6EUOMAMGQEBPPLVAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 404C85A2A6D
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:08 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id m1-20020a2eb6c1000000b00261e5aa37fesf664260ljo.6
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526547; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z6wxoxU7lxsiw/LnEKvVrnTyDCV27fF/fMybyBVRTp5MfFvpBomGzA67A4KOdbQORn
         l/QkNRdcd5iTLG80Cjl92MS8pkf1aLGuWvkeYJqFQ2ACM7IF37Pr08/jagR4eGvWGHp6
         Q8yEIJOZhueH3ajElVQG45Re5lbfXAIdwiXwIa5zX0mLz6PIpyWjgKfCYoVqx7UR3vqJ
         WC0vEr+CNET0h3ja+UiHfahMGx9t2rxT+cLszjMYLElDeoHJnNc7V3Q6ugWb/qyXSp2g
         cB0YLrGOBAYtlc09V1u7V3R5EOGlFTVyw4Bx/uoA6zbA1QJZvIWbfOBt2GOey/bI+W0q
         2gnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=hdn/TF+A4WtOFmJy/EHQ1R6onY4As3KDnbZJPRadHfE=;
        b=zs0++sWGGOw5yfVrzvDwoOBWY3hHgKIGRgBFG0cpyvD3ltN4umkfEZ6nDeeA5l/45s
         JjmzqLy7z0Z7/2SieHKZczyGUpu7d4bKKpjxmH9DMw6/RiBfYB2MdvOYxQEdiy32RolR
         Zyo6tUS7dsOLHIcIqlHqkQ7gYjHM2r/9bI7IkgQFl4IQDkxdLOD0DJxcCjMwudG7qYoO
         mN/kgelCXQ6Y25EQEj7ewQXKZyX0eaRCB3TgKhYHNi/mQ5UfVl3J8Y0qAhlsIRlooXZV
         IHCPJRooF8/531ptkVToVBuv+ftSqtO5Qp3hQPK4CToS/S0J3A2jShZyD1JPRWbphB/6
         S1wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sDB5PJpJ;
       spf=pass (google.com: domain of 3eeiiywykcrg49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3EeIIYwYKCRg49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=hdn/TF+A4WtOFmJy/EHQ1R6onY4As3KDnbZJPRadHfE=;
        b=Mn7JU1WFjBg7H2CsohzCOw62R3KNfoOYlt+tEW9rd3O4gMcjq50vWnKfu+jjXNqHid
         9mleFZSPocEwI7Ym87V5OxNx+meCeOpHj64NchPrrMJ4T3z8DeEPVyTTJxFv+uRI6Fu0
         +2JZeq77ZhOcXMdXca2y7egF37teAYZDB4kfvmbMCD0rADc1i/lwm0QigoA6/2bpp7kj
         XLIf2JQ9ujh7uvklComBqlXq9UPvqZfC7b/FiLUubZkptJsngypH/MKagYeEAutX7vkW
         SsvNcsvdYzv6j7MNe/ggvTwDYPTSFsN8brTlsfnr/IBEaK91m9LPhgIPByVP9mHA0r4h
         kDFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=hdn/TF+A4WtOFmJy/EHQ1R6onY4As3KDnbZJPRadHfE=;
        b=ysj7uf3+WIgScxTkx/Ohr12FOrd64IM9sKe/zd3LN2bIdbCOgjNG6EnxSZVk8UWC4y
         M+L8t/dvKmoamnVgHaQGWxTpeMM2ZUQoUPJVN+QV83V2QtlVyBJRo1EvwwlvG3ZS1TeG
         IA5xhIdE+bxRvq7CsL9qweuMHVbNzfqoODrVkMrmVdHTeg3AYUbcn5UqdLpIsfNG3f8y
         EP9xjjR4Gup8JOhvtqEViqG/xmJfhJl8XQVfhEeX8iMfV+aorWYpAlEKWYbaLZ8/nCOH
         fYjYhivDVjZSGumoZOqFgs7hBGGWx6KcbjK0bNt1uDc+3Cpy9f3hGirUxTKcrCfCfcSQ
         7upQ==
X-Gm-Message-State: ACgBeo23Cch5lqYbslyhFMiDdBN5noAoJ3vD/k+pLUR88wHfFQS+N0us
	/Qo4LC7Y6j74M8du+vzD/F8=
X-Google-Smtp-Source: AA6agR6IUIDpyKh94+6aBdif+jLQ5D92oPkO3DM68P7ZOjolKgPTwkvs/d5SBOS9SZ+88WIsZwb5Ng==
X-Received: by 2002:a05:651c:1141:b0:261:6ea9:ac97 with SMTP id h1-20020a05651c114100b002616ea9ac97mr2592952ljo.434.1661526547819;
        Fri, 26 Aug 2022 08:09:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c98:b0:261:ea54:6c9b with SMTP id
 bz24-20020a05651c0c9800b00261ea546c9bls692256ljb.4.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:06 -0700 (PDT)
X-Received: by 2002:a2e:7805:0:b0:261:b424:a23c with SMTP id t5-20020a2e7805000000b00261b424a23cmr2371460ljc.384.1661526546451;
        Fri, 26 Aug 2022 08:09:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526546; cv=none;
        d=google.com; s=arc-20160816;
        b=fe63XLxKQmQcRYAcaiVZi0f+IRLjvMVA+IAAJIt+RWDOrZxFRVm5ihfhAkYIfcT/WK
         2z3xCsOLnDKFhpsFcpt8WpOFaLsBZ6zhPAuU/vvR4KKHfcFJLO3TuLywGkmtqSTCENWP
         BgXv6hQrt4m5XrYOKPk+2tn4EtTRqwLpkLp7xZhETRc7qvULy1XSsz0ohYT5X1I3Ylw8
         cfmilcFCJGSlKzARNzvrw/OXc3+GUkKbVUIZkDPnjTggRjgfwtO/m0dHLv0Pwk4uMesi
         E8bH3MhMRtQQb0nVAUOr9l/Q79YpK5Zuoo9psJAp01yT/GSdPsdQyPYfoAiXjh7EQPYV
         Vxrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=9AAV0khTKYQgqo5/UGS2nmhcIjrHMBeghL7l+ejLApU=;
        b=MolT4RvTjD4sV0MjKIBLTJI8iId0zlMoMTwM/sFQywf3zV/Q26/tly9RaaHQDigbDE
         iIrpLWlePfrBGz75jSJnA8ZQ4WjGhNXKRyr96LQ1tTmI+W+Iaz811INTTP+AySXyjuOk
         oJqKmcn4cpJ9pAJjOKrFfITuaE1OMq6Svtu8nZiUM3Cjzee86teO9YQuCH0sq1gkn/gw
         JG5zN5oHSnBd0tBnjsXD1q0Wc+aggpystOhmDNJUlMiL4aQ3po2QVpIkmFpgFWlsUIv7
         Gpzx2Izz8tZ8E1qbia5LhMllLhi8+ynney3xC+RfypYYgY5oaZy5S1s7Cyeqr6V8YYhA
         f/Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sDB5PJpJ;
       spf=pass (google.com: domain of 3eeiiywykcrg49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3EeIIYwYKCRg49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id p5-20020a2eb985000000b0025e5351aa9bsi74149ljp.7.2022.08.26.08.09.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eeiiywykcrg49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hp36-20020a1709073e2400b0073d6bee146aso736311ejc.20
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:06 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:906:8a77:b0:73d:deef:8f76 with SMTP id
 hy23-20020a1709068a7700b0073ddeef8f76mr3332086ejc.765.1661526545890; Fri, 26
 Aug 2022 08:09:05 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:42 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-20-glider@google.com>
Subject: [PATCH v5 19/44] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
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
 header.i=@google.com header.s=20210112 header.b=sDB5PJpJ;       spf=pass
 (google.com: domain of 3eeiiywykcrg49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3EeIIYwYKCRg49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-20-glider%40google.com.
