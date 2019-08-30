Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZ7AUHVQKGQENWUQIEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id D7F18A2B84
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 02:40:08 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id t2sf3013607plq.11
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2019 17:40:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567125607; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWpFY+169OYW12oYplNRr+6tjEi0STSxt5ilqEwAeDw2MZijbTN/dMs280WVrCf0/i
         IcYnU5my4/gfpDBpJyIEtip9MmI11Dw3WMO83NC1db24fi9gEZClviVmWXn/paUyO6xx
         FOHsLOzb+Gp8C6sfIN/DLUJwdk2NZMwH7WONs6YxxeXyr80hnv6ckUbksW76aup/4JUs
         P66jMgAE0i70fRlhJSDqH8fx43E3EE6jCGMUJyoLaMdXSpsTPrRSqY0Iccp4Pp/ghma+
         Ie8uSFe0ual4eY3mBe3zwj5psIvz3935oTsgDOkztuexAtlmdbMmA9yIa/DH31+/ShhG
         V2fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HfMbxmxl1CWkQGV+NpLvQvW3XR5kV+pIJCDabqXL2qE=;
        b=Yg10QSjYE8zXYD+bsiiiMPghjNRXdkBh71OrPtUxafnzPdSKa7wq4V5PIPJQycmfkm
         SIzvVg5jWzYAJ7YrB4BmKXe1/pJfHpXzmNuHkO72kTkJcy783UEOt8aTuodpLQCVbh6+
         9Ate43irlpRWVRC6WliTLvQv/P4guMnLy60zGm1cDtvO8pC4pewhz+XUkEYN3d9BICAr
         rCzm6eM+1hGHNOo+e1AzfPJOPqp+73lM6FRh7OuKNpYLgYIzMCka+cfhk0Z2xwmSJ+YN
         DwwdgHOtuMU7RevBXhYlpDjPpGIeRSeUsLnq2gHWc3M9qXQjzbZibUO5IpBUkXZvY0hl
         QCcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=nD1A5jPv;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HfMbxmxl1CWkQGV+NpLvQvW3XR5kV+pIJCDabqXL2qE=;
        b=UzZ2iH0qWo8WCsVltf1/S0AXih+zkzGA6xvfj44fkjCTlVWgvvTmX7Ins6QtBVI1sK
         i1G3DWlP1sZXFXgN5cAHtvYeDBWEB2avN3VAW5BgOXqvth6dbP4dOTudMkpppPMTHMhj
         QphF5dhulvIgpDDkuwoRcrym5H3uNLNNfEUelc8voszsVkhqzPaSd//xjIubayguNhEL
         2ZvvWSgUaOPBs5hPksWy4jXeiEpg/KPKQMta6D1FihqImNN62U4bL1Ywob4J1yQI9P/7
         3XIv0uQX2SkFV65eZyyR0DbaOMvoELy5v4bZCxQFikoD1a//eoEsUsPNzItFLR6chwHQ
         43WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HfMbxmxl1CWkQGV+NpLvQvW3XR5kV+pIJCDabqXL2qE=;
        b=gqp2dZFYV8sQO4qDpIpCG8cGXOeBtDvIzCSnnfYMX7BtEaSuArZkwQ528z7X2MXBuk
         6jL4BIyZR0L0NMILzcyJtPwA5yTzgTuDRQKRCY468jgtVubr78+TzmT9J1tjK1ycw4YG
         47PYUrhmLqSliGpw0YN6okEbGvhFzW65/KucbmlLAjIl5UWnqVhC/fji4EHf1hIRr1FH
         DpF9HQSlr9wEDQlW4KlboygNUkBfewSwq1HAo45t9gTEk1+iACdjgPiFQSvIEnM5D9DS
         PxqKJU4eCbJsubrJ0okfQWadqkRHphLtvsGqd1heffjzedrIN5Lby8aEQ2ejLfEkWKtk
         NGrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXBLQHHnyLJ3jp/nYlxTDTU1ngvj1VRihwtKgNjwL9N0KGU3y/F
	lfcx1kYBOLminmjKaJD3Mhw=
X-Google-Smtp-Source: APXvYqwQWMSBvwtxdwVQX4SK84124fttJIM4GznJQkCaBXCFz2Ms+G7AemgFosasZEoTwuJw7Imc/A==
X-Received: by 2002:a62:28c:: with SMTP id 134mr15223079pfc.194.1567125607295;
        Thu, 29 Aug 2019 17:40:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9e81:: with SMTP id p1ls1379265pfq.2.gmail; Thu, 29 Aug
 2019 17:40:07 -0700 (PDT)
X-Received: by 2002:a62:5250:: with SMTP id g77mr15096165pfb.158.1567125607003;
        Thu, 29 Aug 2019 17:40:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567125607; cv=none;
        d=google.com; s=arc-20160816;
        b=nfJYKzBUc5HHC34B/Rb3zuggRmU2ww35C5DwivmCGOrSUAlq5benYUzDl8B0GOMsNJ
         vcK3+RTB6RGY0yIyjgYfXPk4RK0LDIhUQ7iAq5jstbiqn4mpaaMxPGUSTIs/wGaKhQC3
         roRFCr6//DymyrVYYezuh9e9i8yLstigrG9pZJUimEFvw2ut+TO2AQoqTUuhIDHE1Ii6
         mgQo3H5LcrEpIlBayDjXdvIQYDBzSISriCJnKhf2Ek6EK0ZDQUKPuE0hh8q0uxDcvozM
         GVlTjPCmWPcgP1KdkrXrBT2ah6rrKK9zCk4PWGOPF4MlK4rJB8SNmOqHixssxH9mvoT7
         otEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=82Q/JFIZnRXp0gOKtGutBaFqGjeRYEXgiO+lMUV240Y=;
        b=kPM4q8tZRjUlzUWf+s4y5/fR04BSkYA3X9i5Y8D9ZlZJvPVpoBDxKTR0gOumdyi7V0
         dpGjqoP4lOGwv9DCUld65UGIdltHnTPIxSzxe/cVeSPtMqU4RsRT1G7XZEFSi9bnv6NG
         8DvW0TWiQ54D/+W3Jly/9o0eFNu10GGtoz0fv83btWfyS2SogUbn4Yh6KbYMYq+I60HJ
         bOjkJZQwuNhhd8pZrRSiJ5IuXN+JpwRx97O96LQxyimZXPIfHyc4c/hPSkI1AbTb+uwu
         Y8mIXk4iNUEzHO7Mn1JfaCdszx67B48SaXHgWAJdQAciXJ5m6vPlUqD6EuUq5ra4c45H
         Mv2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=nD1A5jPv;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id t14si354886pfc.1.2019.08.29.17.40.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Aug 2019 17:40:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id v12so3303720pfn.10
        for <kasan-dev@googlegroups.com>; Thu, 29 Aug 2019 17:40:06 -0700 (PDT)
X-Received: by 2002:a63:1908:: with SMTP id z8mr10423041pgl.433.1567125606413;
        Thu, 29 Aug 2019 17:40:06 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id b19sm3452810pgs.10.2019.08.29.17.40.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Aug 2019 17:40:05 -0700 (PDT)
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
Subject: [PATCH v5 5/5] kasan debug: track pages allocated for vmalloc shadow
Date: Fri, 30 Aug 2019 10:38:21 +1000
Message-Id: <20190830003821.10737-6-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190830003821.10737-1-dja@axtens.net>
References: <20190830003821.10737-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=nD1A5jPv;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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
/sys/kernel/debug/kasan_vmalloc/shadow_pages.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---

Merging this is probably overkill, but I leave it to the discretion
of the broader community.

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
index c12a2e6ecff5..69f32f2857b0 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -35,6 +35,7 @@
 #include <linux/vmalloc.h>
 #include <linux/bug.h>
 #include <linux/uaccess.h>
+#include <linux/debugfs.h>
 
 #include "kasan.h"
 #include "../slab.h"
@@ -748,6 +749,8 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+static u64 vmalloc_shadow_pages;
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -774,6 +777,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(pte_none(*ptep))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
 		page = 0;
+		vmalloc_shadow_pages++;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 	if (page)
@@ -833,6 +837,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 
 	pte_clear(&init_mm, addr, ptep);
 	free_page(page);
+	vmalloc_shadow_pages--;
 	spin_unlock(&init_mm.page_table_lock);
 
 	return 0;
@@ -887,4 +892,25 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 				    (unsigned long)(shadow_end - shadow_start),
 				    kasan_depopulate_vmalloc_pte, NULL);
 }
+
+static __init int kasan_init_vmalloc_debugfs(void)
+{
+	struct dentry *root, *count;
+
+	root = debugfs_create_dir("kasan_vmalloc", NULL);
+	if (IS_ERR(root)) {
+		if (PTR_ERR(root) == -ENODEV)
+			return 0;
+		return PTR_ERR(root);
+	}
+
+	count = debugfs_create_u64("shadow_pages", 0444, root,
+				   &vmalloc_shadow_pages);
+
+	if (IS_ERR(count))
+		return PTR_ERR(root);
+
+	return 0;
+}
+late_initcall(kasan_init_vmalloc_debugfs);
 #endif
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190830003821.10737-6-dja%40axtens.net.
