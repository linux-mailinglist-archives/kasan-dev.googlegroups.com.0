Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPPSZPWAKGQEQUACACY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 41649C2DA4
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 08:59:11 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id j9sf6699582plk.21
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 23:59:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569913149; cv=pass;
        d=google.com; s=arc-20160816;
        b=L9ttPFm9VQidxX6rZEnreAZ5Qo1jAfp1hIjoSg+8f+pmS+zJ36igHBQrYZmGpcdKT7
         se9CQi3h07chADzpqSj8ipAFr1sMCtNQy8uOtVDzu4mgjT6++X6ZJtSyQvE2Ojho7Yx7
         jRrsl3tYOi9uzDYI8T29krl337kctldX4Ho51yv+r79JNVpK8d/nmWu4/S6xf4/swa54
         JGNOPDHvpDS307+qUBf42T2lVXBU/ma1SFwHLuUv/WmJL2sA3YthfRMikXW3av3mBU+9
         kUhGHU7ouP53zHH48QyRfLF8h2z9lsmmiAYNFRmiFmKuZ7786Ig82g7ZIi7eovLwTs03
         NK1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dcIAeui4hQJDvOEY5eEpT4ud+ITJ2O2UsENGXop/0rI=;
        b=T2Dgut9wBfwiFA6oBD+EOn8LWroaM+VybVGiczFAGeQJug02evVyQe6PXCQFkSRu3/
         APpYyESQVRb+vV7QDlQz6NUCif1fecw8yvkZoOLcqPdohxe3cJPv0PEaJ9qhfyDW9g/I
         66HBZQgNOX90zUyrYQEw5hOxyXwC5vbIa7uxGn2B2ZL3IhM+VIDbVr066OLDbSh8vDQb
         bQvjbXpV2jws2ZEWAm3z1QUghLQuRRqDMVPE5WQv9WReXmXGTEverQFQ5cxknvPRurh7
         GoVn/YzIMEowyULsewo4HMy/h8PUxSudBdsZssQPk1kdZ/yGCm4d7DiVe7xm1pt0STEg
         QfSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="W6/vpaq8";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dcIAeui4hQJDvOEY5eEpT4ud+ITJ2O2UsENGXop/0rI=;
        b=Nx07Jl7RcVvriMdOa9BepBjeli6JdEy7X50Qf89UauwU7DSA5RBKk29UYazeQswx3j
         QRsVN345dJ/T85wB7XYUnGwdNw6VSbMDgx2bf/fA/uaz9OBpascPvFLS5rynOxft89lP
         T9Ui5Nfagy31CljHzI1tkFnTFJD3LyBXCUfDKSiPxxFESWyzhy+oOgaBGXe/9/ATtKY3
         U41qH3/O4eO2G/7f3oKD0+Ib01cn+unE3ANTgw0xx3ZtlOVXvzUtMBUtKI9SBDT7xmoG
         SZNh1fmw1ks+YopjO2p3zbuRiHfU4MO13dUAcs1zeNXmzDolVpm/dziTH8HaR/LhXBUu
         TDEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dcIAeui4hQJDvOEY5eEpT4ud+ITJ2O2UsENGXop/0rI=;
        b=Yo6Yx0AZ40sEiGf6bzERldTycgYA0AoVaqNbsLA2ZBD1kG8nwqyub4qs3hP4IGX17X
         asssEfqshhpoMOa1dUtSd4UkIKhVofriTvCoD/n9bk97OzeNFN/v5jvFAjSUsKy74JuY
         Pk5bGLHdr/Ryl0G1Zxcu1UW3vZtpKdn+RBsxgeI3YiV6TmhMfTzFIofXuzIYADNd7Agc
         2AvZ+2uHSJsnJNWHORi1RdMV4xYeTLyCvSVC1b0pvnNQDIuEEixgyteqVZ3PjAhFviNg
         m688PRH+vftAR8rd0w7DsP/B9wfx5RaSHL9ylQmsQsEdJuzKLySkJ5UuXW1/5oNtLsT3
         JbdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU2p3ABNnXeuGFf4eD+Cq3Mlr3wPuHoe+g2Z40xgKmHA5dUdoV4
	6Z3LpEHRJVsufp3xVZUHNmM=
X-Google-Smtp-Source: APXvYqy0rAfBNgPUhHrKUK7lai5En2KYZYdji7HN1BIb3c8p8aMOoeIIJROpvWzg1uJ6ColYrOfwuw==
X-Received: by 2002:a17:90a:191d:: with SMTP id 29mr3840864pjg.60.1569913149384;
        Mon, 30 Sep 2019 23:59:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9b08:: with SMTP id f8ls628749pjp.3.canary-gmail;
 Mon, 30 Sep 2019 23:59:09 -0700 (PDT)
X-Received: by 2002:a17:902:b949:: with SMTP id h9mr10027732pls.35.1569913149032;
        Mon, 30 Sep 2019 23:59:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569913149; cv=none;
        d=google.com; s=arc-20160816;
        b=LW6BhWOo6SuBuqLJq0XzABJs4BRKpVqeRnS+YphQAn9IUvs2FmaI6fqY01nwhHGOha
         zrATbstVlj6+6MPzH86DVoYcTbqBqJkX4jPXZjYPYHT27mONV618XcHOkyKzU15D2BEL
         gaExTrD/8lY86CDodd0DxE2SwXrs3qpTMpdlpHVQHHAjiZIhbUgaAquQ2do6zYzAUJQl
         6uSo+wEw757kwosm75G47D8YSqPwF312EehDmaIQ9gJ7VtCdXcpHyapmQmH7HrrjfutE
         H0fWEGhyNyLk9mkp8CatAMT+QUTuIRYdwvFchBFDo6SXTcyR+9nxNsOB9/5FEMGeNOLr
         HprQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gfoubv0+TCtoMzcBmtFDPgTVp+GIySDcb+ulhvcFdKw=;
        b=I07zkE69PwtIT0oNgS/ZXzS4EfTry+/JqJIhFwkCz5bvDpKWpqURzf3BmFQQDQcL/N
         NHwUZEiq3MA3YOav1TCO5JNvZot3E/8PyJNptXfNph1mjo0igQ6v8A6JvATBdZMkS34v
         a0QLN3q9X7zDd8cvhGajKJ9si2Jk1wICL5tRl4051kkeoJ+i+qnClItFySEiJO9hfzed
         3vK11Jzme1dyHUaOMHx0+iARN3ukCb95gnzI8Hr4toXaQ/abApdiGzS6CHZzS1ggFKf+
         XZypAcWiXWy/j7V1wXI4YBkxOYYnsbavvOeeNFM2Yre5rn7ybZNaC6Nihih8rEIWab+n
         lDLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="W6/vpaq8";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id fh7si60991pjb.0.2019.09.30.23.59.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 23:59:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id a3so8904366pgm.13
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 23:59:09 -0700 (PDT)
X-Received: by 2002:a17:90a:3b01:: with SMTP id d1mr3700467pjc.81.1569913148491;
        Mon, 30 Sep 2019 23:59:08 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id o64sm4297758pjb.24.2019.09.30.23.59.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2019 23:59:07 -0700 (PDT)
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
Subject: [PATCH v8 5/5] kasan debug: track pages allocated for vmalloc shadow
Date: Tue,  1 Oct 2019 16:58:34 +1000
Message-Id: <20191001065834.8880-6-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191001065834.8880-1-dja@axtens.net>
References: <20191001065834.8880-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="W6/vpaq8";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
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

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index e33cbab83309..5b924f860a32 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
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
@@ -776,6 +779,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(pte_none(*ptep))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
 		page = 0;
+		vmalloc_shadow_pages++;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 	if (page)
@@ -829,6 +833,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(!pte_none(*ptep))) {
 		pte_clear(&init_mm, addr, ptep);
 		free_page(page);
+		vmalloc_shadow_pages--;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 
@@ -947,4 +952,25 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001065834.8880-6-dja%40axtens.net.
