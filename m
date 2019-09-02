Return-Path: <kasan-dev+bncBDQ27FVWWUFRBYPWWPVQKGQE5SMLK6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id AC0F5A54B9
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 13:22:10 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id y18sf4112617plr.20
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 04:22:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567423329; cv=pass;
        d=google.com; s=arc-20160816;
        b=VWYupeovbRxhQNCX7Pcf1jiOT4UuVLe1x2e7vKsNwk8AYCwcCwyquU6f3C9Ri+06lc
         yOlfJ+ieuifdRXLPLDQdpRexmtGff4kZ0X4xhI3R749PWMtkXgSvkqhujKXbBsM7XBWX
         VlVitTexxhooPbhuxtNlzKe3lnGFNVNCbNJj9rsXOoNY1/K9xCNuKmXBV1vJ+cA0UlZV
         CELs1ZNtjI6c9Ykop+GyE4C7qtpuvZnIbKWU8TdXA6H8tJy9XYTicwEwuQXTniyJB1oX
         5JmtMveC8Ol+UDlOKtS5YRn/k0ISNsNI3NlnJJJpa60RmiXI0ZEDyc9dHK2d0bfqyAB4
         we1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=z51zYTH9Tj4Z+ntnoRxYAYJrK2wROFJcTkIqPoji6vU=;
        b=XzT4Wp1uHj/wJeTM3MkZNWzfMuzMo48eM67UbBmgBY1PHJfRI0OzBYPnb83fC9Lf1i
         Pui83zoj7fuaNCUj0gSe3Mkt92zEIWFv4ZaBaOiC43ldSnk2OykOC6cDgAWou32A2PBJ
         tqeKYdje+w0unKRbkkzyCkK3qaW1dJ4bn4QWUnshaL8NnL6o/9hsHOHIGp6J8vPSCKNe
         eNYfSpK9o0EVg0idIVXzRlE4offPdpfFpGnBBF4rNYhL9Kwal7Kck6dJqFoQlV/lU+a/
         zehiEqs0nqxnsbSdgJkd3e4JB4Wbbsd5713jbd+3K0V811UGX67HMlpZDV15gxIvspck
         i8jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lJn2ZoGm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z51zYTH9Tj4Z+ntnoRxYAYJrK2wROFJcTkIqPoji6vU=;
        b=Pvk2RAzQLsqzy0AsShFBxEHp0dugE3cjFIdUH0Yn3bGVzyw0/4WU28MUQS8j4jboJ8
         ahG8piidAk/bafDDRHUwEeS8b0JtSqrxpOqu/IyIaRx5mUQ9CS52qP5fqH8tzoaomybe
         7DRT511k5RMC5B5mZ5HHxlYu/t631b2BgcCw4FSe3KX6j9WfPwkrLbEPHvzA2IhxOGEz
         zag0MKxwhnDRJvk808zK3dA4Fdjw0A0HYUTCg80Ka9e4f53OkcvThzdU6iRiJqET9ncS
         7clnkIqgmwRNVTjfNL0tYN59dQ+q2kGAno4eL2aktnmKmFkcVb1LBeDbUrR48weo7+JK
         tBNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z51zYTH9Tj4Z+ntnoRxYAYJrK2wROFJcTkIqPoji6vU=;
        b=k6MJDk5Nv2kZlcbii9oDT4nH9LU/S1RxGdWQhGjIlxmYCxh28ZgqF+IXAD8u8QB5Cm
         cMkziYo/xE5KNLgTDRENwAI7EH5uU0nSa0uaktpResR6fsiLQEx1Bo1Lagbp1KcPGN/x
         VyPk/QyUj3nShUo/1MR5TutwVXiaXNJ04UcViLFlZkoO3mPZ2i8taBKzydG5QHOnxyx2
         Wk4iSZJyuuyR7j++2sDHbBaJ3NNMpnP/9i9wKPGVZiRsy5bGoRYCHEhBDosk3v6unoNS
         ezhlHG+839c0B3cL+u5nBMd42sBDpREiGdWIYX4blyG0xVysx3+Z/XPqI/Vyv6VB8Ef7
         x0cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVAmVkBRJnus5J+uWSoesPP+qQH08y2UGWO+4b2lTBoVJH7L9kH
	OPb7JvhqhlB+pjHePwwbjI8=
X-Google-Smtp-Source: APXvYqzhx8EPOKUh4SkZTYv4g19S/qhf3AePJHk6X43uKUOwIjk4iCmvtMZkAb6BOPifVIDsiCwYiw==
X-Received: by 2002:a62:1d8a:: with SMTP id d132mr33662307pfd.187.1567423329198;
        Mon, 02 Sep 2019 04:22:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9611:: with SMTP id q17ls1503029pfg.16.gmail; Mon, 02
 Sep 2019 04:22:08 -0700 (PDT)
X-Received: by 2002:a65:528d:: with SMTP id y13mr25587154pgp.120.1567423328830;
        Mon, 02 Sep 2019 04:22:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567423328; cv=none;
        d=google.com; s=arc-20160816;
        b=i99tDuY0p83gAHoX10KOKwoJbkiH9bFpOcKQVs2ojcADVVGrk+9ICOUPf6h+bv9Emx
         w5pdD53BRerRwNCPjDmz00oX/U9WH/NvM8Va+2YfTfySGFGSQlKio9lJPHg+8veaZwpI
         rM77Lx1046HPhMlAgQ4m7uZfK94hLtU7CdVDypMXDA5TUnyK+ynC0CwflSZlCgXr/B0d
         1SBlLw7r08cbqiGJ5m/fELwpJI+CplpU0Pu49e1U+tq21mFeLVin8gy/xCb/f7qInL9r
         /zjlGvxEJXGF/ULKdRCFX7lrbfxf7Q+cbAdSsaTUafh11Iqn0GbBVlMRbUfOPJWGj7Nf
         50Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rhvVAb+7J0RMzU60BoXrtVVNGscRpJk5bY5+hc+pgTs=;
        b=fc7tQf++Y8vOf5riPXjbNpsTBFYvLupBdg0C1fpMsZ12I7q8OYIU/BnWkC8AsvF97V
         +wh0Qr1XDx554uW0Xu5mbvVSMBgO9CCSKunyfP77A8KilMvX/I//hDjzWa4qFwOwO5yh
         NwzR+HY4RVs2gN3kmuedYm3YVbPsn/0I6WL8GWG3AoFzXb3NYHfcKfusulaNQjldxdrQ
         HEHFMVf3DIIgYli3akHRgfIdzrSQ7XdOGNwotsdd6fnjS9SW1Zb05DXyxL5S9lscRoTT
         7/rEfyMZSNH5UmXmUL+SEt0GscJt/YM2CsEpHWBFFZcstKAYek8YQ4qBtUDwuCwEt4HA
         92tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lJn2ZoGm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id a18si677673pjo.1.2019.09.02.04.22.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2019 04:22:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id t11so417044plo.0
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2019 04:22:08 -0700 (PDT)
X-Received: by 2002:a17:902:74c7:: with SMTP id f7mr25317727plt.263.1567423328350;
        Mon, 02 Sep 2019 04:22:08 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id x10sm11662494pjo.4.2019.09.02.04.22.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2019 04:22:07 -0700 (PDT)
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
Subject: [PATCH v6 5/5] kasan debug: track pages allocated for vmalloc shadow
Date: Mon,  2 Sep 2019 21:20:28 +1000
Message-Id: <20190902112028.23773-6-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190902112028.23773-1-dja@axtens.net>
References: <20190902112028.23773-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=lJn2ZoGm;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
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
index 0b5141108cdc..fae3cf4ab23a 100644
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
@@ -827,6 +831,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(!pte_none(*ptep))) {
 		pte_clear(&init_mm, addr, ptep);
 		free_page(page);
+		vmalloc_shadow_pages--;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 
@@ -882,4 +887,25 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902112028.23773-6-dja%40axtens.net.
