Return-Path: <kasan-dev+bncBDQ27FVWWUFRBDPQ2KBAMGQEJ4JKVFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DEAB341FCB
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 15:41:18 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id u68sf21193023pfb.7
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 07:41:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616164877; cv=pass;
        d=google.com; s=arc-20160816;
        b=dcJgP2aJ/wue65CDrDWmbvAow/oZo9ZDkoSBFqxhWrNZ59qEiuBAHerNuG4crzcrpv
         +Pq4xICq/ZMw6RIPsL0bio+WZdehCq4N3sehhbByzBhZg2azEbDFAccUI0m01KSSRlWs
         bMkVcnxoarxFRmbJGj93qvz0TU41F02dEB/6cyQ3+PZvvZkQ5d9ukzufXRolEk4xmhHA
         7yB0uHgPQwloE6V19nwZ+Lh92ACD0DPE+JPejMSr5WyfTebYbBrqXT7yDt1Ms0AXOvNf
         /hvZAGkMhPqjoLL/nab8NK6zVTE+ElQVbeV8KaHJdiSwB9m/HhFb2z954GrbPuelYU+2
         ZtxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3l8iOLc3vrOGhvlezsbDNQ8JsF/WNeHzCL9tvi9iaVo=;
        b=yeIqpzcsvOSLf5lBCXqRS/G+3aAJImnq8whq+T4OVU2fMn1Vza24b0cA3X8ByC/AGz
         e6IQgPZTO15di65TkEoN5cPuIZqJUi7Dwg8IKeFFAvAdzJEPHPsuQQH5eytzeIlGdOQ7
         6t7BBWxg+y0MMrlVQmPtk4E7B7ElnFnTdGQcYs4NkZkXyHANA7jLP49fhNUmxzXdEgNQ
         VeZ5OIdBzf6cDkvndBJZ48F51q8pZkhykt7V1n2UJnQaeM7BzHn7dFzJvBvwt11j6ziV
         iyNBaOUj0a2lQHjPuB8b8bjE2SiQZhtISjY4ztMN44MqO4/xVHir0LVVFI50ILU0GQz5
         UdBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=RB9K609x;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3l8iOLc3vrOGhvlezsbDNQ8JsF/WNeHzCL9tvi9iaVo=;
        b=N9fN/uUF+rCREjapPizuLzJOTnMAkrhg/nscU4vD8G6Izh42TyEUCAUgsjwsVtaYHM
         tf9IvzfhsH8vGilMjnZPH/pG7ZgnZgvPe7TF9n9CI88gAsJ2fO8DDTC9RtQCJ8FwjhWd
         rtHZaznnnV5VK4RVHfBHSbXhEoy+0YOd7KvIu5GwVTgNLLR4uB1nF5Cf/27URRXo9/rx
         wxYoNwb0NknsAePF1YeOEEsUs1cvSKVusoQQM98xFTF/0Ld8NbNLy2cGKhD6HFuBbFIR
         qAl3LbK1y8FMjdSk8nN6uDv54KeoctGlpjDJdxb4P8Z0gMONupuW4FZnG5igFGHK6dN9
         SyjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3l8iOLc3vrOGhvlezsbDNQ8JsF/WNeHzCL9tvi9iaVo=;
        b=UfqEL+oLCGzOBDgPMdY4Y8xsi3YNDDVhVyzes8bqF438U5vqUOog5zRFAhbsjPAZSY
         Mr6brWdRVo6GEJHXwlrJaOVrD0negdhziY7k980sIYs38xqns4l9j2hNhCdekl+zVVzb
         n460316ICY+MAAg4aDt+n39lMQWu1XJzd1w/LKogB0EjIcXr9fY66psoMzuWR5f5W1BC
         7VK0tLWzbdjtLCJbWUvTTnidHuuecEOxeW4gbKSlvPrunBM6OCb9YjkOHZw2fmo0oyTu
         /Lt5acDq1v95eR/AvyKBaGsWStxjwXViWWNuzVqru7O4yi3qh46uBydEWblfFZ05hwbv
         /kFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530n0Gr6qSkB4l+vVyVYu6d9ixApFN31EiZZwhg6V3T2l55tKyvT
	7P6kENz5SGkewytSt/bjLeU=
X-Google-Smtp-Source: ABdhPJxLSanmjZGQWSAHQjb5/I4hC6z2oWafqzDodZf+7Ak/jG68UZwFdOnj1128NzcCF300x3m8+Q==
X-Received: by 2002:a63:f70f:: with SMTP id x15mr11468521pgh.109.1616164877295;
        Fri, 19 Mar 2021 07:41:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1315:: with SMTP id i21ls1084998pgl.8.gmail; Fri, 19 Mar
 2021 07:41:16 -0700 (PDT)
X-Received: by 2002:a05:6a00:2292:b029:214:7a33:7f08 with SMTP id f18-20020a056a002292b02902147a337f08mr42330pfe.15.1616164876780;
        Fri, 19 Mar 2021 07:41:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616164876; cv=none;
        d=google.com; s=arc-20160816;
        b=E82e9b9A/BZ9kHsQduSxkXly5gC2UG3jVb30MIn2HSfRCk/U50gIXOYhUrrOTEha2o
         8+tgpYmGNJBZXVcpyusMccdaCS1I1giCoJzFd0VEJuq4UC8XP8Jt/HYjg+ekO2+krX82
         y9Yf4WfejmJY90j68o+zhBak/Ps9oss/3iKGTw8VRkfyt0OJNogtEdKCJkkefwWSsCM8
         E8wTOGLZf+cpIYAl9BRcr4qb7bQe+hkYcZ6uLVztk2X0laVrwUAADU6qdM3l3rfH/7DN
         qNnwFgnaNjJca6FN79kasSkAdyzFvRjrcgnTD+zH3C7IyfCGfUsO08w1oxiLBpOZ7ZnR
         9bgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qKLiRC30kOdPHC3UyyAEWstGuLi3bp5QolFCwAhhC7s=;
        b=B3GKtNSHOJfdIlMnIwQCfV9Xsk3dI1yFQZLikdmhyDyWzV2U4paBRRRn5Ls7ofPZbG
         yM3hUWF1aNpdZdZa7b23HtfAZg9tSNkFymT46lZNKkttBQ8o1ydnjyeyxvEKSHXFVhtv
         wWmBmLGLLkNZydaysOe6HmxVmY2a6N4pva4EZ+4kLhp4cjk08LoVuev78/DnuiHtT2WP
         +9J1rnuQzU2hlrW2I3MNKeEJd25JGXbGhPAbVaGYS6tOoqHnRLKsPQc4L1x+IrBlQTrb
         zlNsWZZRWlM0mP3p1UsnVyELtVESDdQYxleudQmpe53r3tnwFzLpBRyTSiPTPbh3RA5E
         eO3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=RB9K609x;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id t5si360741pgv.4.2021.03.19.07.41.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 07:41:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id kk2-20020a17090b4a02b02900c777aa746fso4954928pjb.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 07:41:16 -0700 (PDT)
X-Received: by 2002:a17:90a:7786:: with SMTP id v6mr10062692pjk.16.1616164876553;
        Fri, 19 Mar 2021 07:41:16 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-674e-5c6f-efc9-136d.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:674e:5c6f:efc9:136d])
        by smtp.gmail.com with ESMTPSA id w8sm5204443pgk.46.2021.03.19.07.41.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 07:41:16 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v11 3/6] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Sat, 20 Mar 2021 01:40:55 +1100
Message-Id: <20210319144058.772525-4-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210319144058.772525-1-dja@axtens.net>
References: <20210319144058.772525-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=RB9K609x;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

powerpc has a variable number of PTRS_PER_*, set at runtime based
on the MMU that the kernel is booted under.

This means the PTRS_PER_* are no longer constants, and therefore
breaks the build.

Define default MAX_PTRS_PER_*s in the same style as MAX_PTRS_PER_P4D.
As KASAN is the only user at the moment, just define them in the kasan
header, and have them default to PTRS_PER_* unless overridden in arch
code.

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Suggested-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Balbir Singh <bsingharora@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 18 +++++++++++++++---
 mm/kasan/init.c       |  6 +++---
 2 files changed, 18 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6bd8343f0033..68cd6e55c872 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -44,10 +44,22 @@ static inline bool kasan_arch_is_ready(void)	{ return true; }
 #define PTE_HWTABLE_PTRS 0
 #endif
 
+#ifndef MAX_PTRS_PER_PTE
+#define MAX_PTRS_PER_PTE PTRS_PER_PTE
+#endif
+
+#ifndef MAX_PTRS_PER_PMD
+#define MAX_PTRS_PER_PMD PTRS_PER_PMD
+#endif
+
+#ifndef MAX_PTRS_PER_PUD
+#define MAX_PTRS_PER_PUD PTRS_PER_PUD
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
-extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
-extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
+extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS];
+extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
 int kasan_populate_early_shadow(const void *shadow_start,
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index c4605ac9837b..b4d822dff1fb 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -41,7 +41,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
-pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -53,7 +53,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
-pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -64,7 +64,7 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
-pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
+pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS]
 	__page_aligned_bss;
 
 static inline bool kasan_pte_table(pmd_t pmd)
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-4-dja%40axtens.net.
