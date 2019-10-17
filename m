Return-Path: <kasan-dev+bncBDQ27FVWWUFRBEUGT7WQKGQE2XND4FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CEA3DA316
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 03:25:39 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id w8sf808298iol.20
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 18:25:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571275538; cv=pass;
        d=google.com; s=arc-20160816;
        b=mjPpVa+GMdLnIvhPR3pJQDc8xQQQBtNYQhH63azqJU9G+HHxOMUm9TKt3QoYZwEPEi
         uA8shDB3Tv9mHpo0++4W1cFb2E35hiHfVHkEatsx7BMBzvUrt5b4DEk3B8yui0EPlWMy
         0xDoMP2pIx4FvjYLku3UiTv5nPRN6RSsNcbZ/cdUpmhLtOCq9UWdCbB9xI1TRAw8Fpio
         HiaiV5GRKrDRtKnCcxQh0r050IHxQUsCJ63HcW7HIyaEZVmUQgtqIV6JPTPUlJdwXKVW
         Ifpr+g+Q+kfTyJFF7/Px1XaTyhZ7YaN++Mj3Cpg139LYq2ns4wvTy6Ln7ysf7QJbedXf
         /ecA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0B2ooEO27jqHYg6jdota7MuwGOD4onbLjCqLACL7aUE=;
        b=qDkGrKiM/PlNHW6EHBODQ6qGm1b9H69fALecpogMW1SJWjjoRr8jkiAAAt7bU6JVf2
         EJgE9ESmmNVBn7yusdceKw1sWOV4GZfZGwBBvrmhhsZ0Ai62q3e7rKkHT3giySdHo5Co
         GLIqo45zDT+1OgRlvpDQsdFRqI5L3Hs3D5fWzfuw/MaWrOZ+jWoYuzsvYT82pqN9z+ma
         bqA+yAioUvs0fC4dkevYN5iJqqgbKFVxUapW1AKmsvqjkr0lwn8CjchIYAB4KwtXK7ev
         xWHI6Nqs+fbkrp/BzwnaePNl7x8ucTBS/nC/sVYLgrRrJlPhUfRmsJGPyttl/qTAJ+Uc
         r4Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kPLzGqgg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0B2ooEO27jqHYg6jdota7MuwGOD4onbLjCqLACL7aUE=;
        b=lYrAfHI000Uf1AFdezYyCn9U3aEVGVzVMkJ3JNTGpUT9WvwuWr/Bf5tJYEEs/YT809
         xCdaZiUceqTxoVlrBszZjOVxbCFKxb5Q9H3lwm7VEuSMuO050S4A2R9+aDOzI0/9UmuU
         YRsysDrbvaEkwhIgAqaWR24qJPzVPp2yUjY9hObHpwwWCYUxWRbqVMLsWO/behGjbhw3
         lmCed8gjBnJti7s6CM9Rc8nS3tjN2DiohWN5M3VEZ2dYuCIFKU+cGs0PO/jcnrCdVTqO
         SjjqXPPhr6vpwDaQXK7UtbhNckx3R66Hhb+GUD5zb476fYluAohyuc+JZoapFfB71u08
         iDXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0B2ooEO27jqHYg6jdota7MuwGOD4onbLjCqLACL7aUE=;
        b=CYEx52ohCrlwv77IBFtrjp43GFy6oJAyguO5yx3IAuXidUCDFaIULEa8M1DlKzif99
         P9HvP0Li1TLHf0KwmesGtgx4B9EKtlr8lfrl5dVSnH2Bayy0c6NRtbLscpR/arKf5Q0P
         QkQSV3wbaST3FgMH5z/AFp6HygCNNiGWFiVq6o2Ju4KxM4JFQKTyhxMHLmRQdHGQt0/w
         GL6Vxrm3VAlXZALPRRsYJW3109bnSwh3jXUlvMycQ604BcF9b2JddJ0CuYmOeL6UhYB3
         +gbTOJSCqa8KpgINjvzYdCSMv2uvSjhlSqgLtKwrRrHHE3Bwxa7QJ20Bq+NCXdqj6HB4
         Cv8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVWHpRZ6mniezMUT2/tj3kJI0xDDxPsfbThbCQsgwRvgBBPSduz
	ASqImprwDGoQP5yAlDYaA88=
X-Google-Smtp-Source: APXvYqylCDPXsmP9lnYPpn68qV5eoXakIPcl7C4nFRxUeVlDg83M2VC/7jxXHFnpDUqML5EAtWHyEA==
X-Received: by 2002:a5d:96cb:: with SMTP id r11mr660584iol.266.1571275538222;
        Wed, 16 Oct 2019 18:25:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:4808:: with SMTP id v8ls238371ila.8.gmail; Wed, 16 Oct
 2019 18:25:37 -0700 (PDT)
X-Received: by 2002:a92:a103:: with SMTP id v3mr989462ili.52.1571275537943;
        Wed, 16 Oct 2019 18:25:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571275537; cv=none;
        d=google.com; s=arc-20160816;
        b=UNVzANYe/hIbzcmK9uTW6gzJVLYX1K8dZgyFIljpZMiJOxuTOC5kqwkCOLGlrVKVq2
         3Hk3jqRMyB/gol33XzrmMZdd9gHcgdU+ERztqb9X0UdNh4zKdjQGH0wteVjRJ9nF2ipV
         LbJqYUXFtcTX95IEv9iXyetAQptxGwQ51WPoRwN4Wrb+KxmC5sCsgov4S/pCGg2L7XnV
         XRchtcSt69nKTt/2vInHrZ2QG6+HdE0TWar81x/vrBeQZaF7xqYfBSfHKKzWPVa0Wotp
         TsUSOMj8NQydQeRGy88Cw91T1qZer3HA57BSvx3y9rR4BtEAXAAFxPuVTZFo0incC2H6
         CG5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OYfGHq7Ua8XlIFWVnYrWlfnb+Qaiu3AuIcv4KZ3ENBU=;
        b=LhqgLX1LRWxnIKtq2qRoi9zZgGQtjCtdj85hyBlpcHhe4LhAY05FZnRqlrtJtIheii
         iMLgPFOSXkvSjCF21dYjihbmt1mcaRbazChU5xm5ytaPXYs3BGJDGvYaBUQq114V3huw
         aUOrO1LUfOpQdM0K/8R4g38pSR6JD09A9VTjeeZllcVvjjW9Mxj/XmdwtEsMmNkz/QQS
         Iq9gOiIlDTX+xtET9JX5JNEZXf8Gm8SrGiw8lwdlA8ukcwy8AbDsycr57vqHONM0BZYZ
         eBQnB3mN0gzWa+uoHp+81zPSwi2O4IPK6UTfDKz43Xu8/3sNTKewzqKOKZ7e6kMCQSKX
         N5FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kPLzGqgg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id i8si32641ilq.4.2019.10.16.18.25.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 18:25:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id t10so281227plr.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 18:25:37 -0700 (PDT)
X-Received: by 2002:a17:902:8ec1:: with SMTP id x1mr1189452plo.314.1571275537371;
        Wed, 16 Oct 2019 18:25:37 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id d4sm381964pjs.9.2019.10.16.18.25.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2019 18:25:36 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 5/5] kasan debug: track pages allocated for vmalloc shadow
Date: Thu, 17 Oct 2019 12:25:06 +1100
Message-Id: <20191017012506.28503-6-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191017012506.28503-1-dja@axtens.net>
References: <20191017012506.28503-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=kPLzGqgg;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
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

Provide the current number of vmalloc shadow pages in
/sys/kernel/debug/kasan/vmalloc_shadow_pages.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v8: rename kasan_vmalloc/shadow_pages -> kasan/vmalloc_shadow_pages

On v4 (no dynamic freeing), I saw the following approximate figures
on my test VM:

 - fresh boot: 720
 - after test_vmalloc: ~14000

With v5 (lazy dynamic freeing):

 - boot: ~490-500
 - running modprobe test_vmalloc pushes the figures up to sometimes
    as high as ~14000, but they drop down to ~560 after the test ends.
    I'm not sure where the extra sixty pages are from, but running the
    test repeately doesn't cause the number to keep growing, so I don't
    think we're leaking.
 - with vmap_stack, spawning tasks pushes the figure up to ~4200, then
    some clearing kicks in and drops it down to previous levels again.
---
 mm/kasan/common.c | 26 ++++++++++++++++++++++++++
 1 file changed, 26 insertions(+)

diff --git mm/kasan/common.c mm/kasan/common.c
index 81521d180bec..ac05038afa5a 100644
--- mm/kasan/common.c
+++ mm/kasan/common.c
@@ -35,6 +35,7 @@
 #include <linux/vmalloc.h>
 #include <linux/bug.h>
 #include <linux/uaccess.h>
+#include <linux/debugfs.h>
 
 #include <asm/tlbflush.h>
 
@@ -750,6 +751,8 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+static u64 vmalloc_shadow_pages;
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -782,6 +785,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(pte_none(*ptep))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
 		page = 0;
+		vmalloc_shadow_pages++;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 	if (page)
@@ -836,6 +840,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 		pte_clear(&init_mm, addr, ptep);
 		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
 		free_page(page);
+		vmalloc_shadow_pages--;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 
@@ -954,4 +959,25 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 				       (unsigned long)shadow_end);
 	}
 }
+
+static __init int kasan_init_debugfs(void)
+{
+	struct dentry *root, *count;
+
+	root = debugfs_create_dir("kasan", NULL);
+	if (IS_ERR(root)) {
+		if (PTR_ERR(root) == -ENODEV)
+			return 0;
+		return PTR_ERR(root);
+	}
+
+	count = debugfs_create_u64("vmalloc_shadow_pages", 0444, root,
+				   &vmalloc_shadow_pages);
+
+	if (IS_ERR(count))
+		return PTR_ERR(root);
+
+	return 0;
+}
+late_initcall(kasan_init_debugfs);
 #endif
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017012506.28503-6-dja%40axtens.net.
