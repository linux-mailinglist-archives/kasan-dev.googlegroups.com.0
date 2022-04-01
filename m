Return-Path: <kasan-dev+bncBCXKTJ63SAARBD4HTWJAMGQE7YF4I4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B8D1E4EF9CD
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 20:25:20 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 126-20020a2e0584000000b0024af05cbffdsf1156301ljf.19
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 11:25:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648837520; cv=pass;
        d=google.com; s=arc-20160816;
        b=rwnbhng2UkP14stp2DolV56Uanv2nDZbOKB/CBczcHxEc+SoIpsIaTtHNznJfo5Ipf
         rD2WseVadXuINbBz0laIJh+E0I6c+Oszu9rAscxKltp8HlH7WUpyvWPDIa4NjlJL4qkN
         5/BWmwAXCMhdR3sBwluvWJEkv8AN1aooAt0tBkv1h0Q9cgKgkmZZmqrYAXTtlJoBpwE1
         QeCv8zTT9gjS4/UItYn+7SINhlZwZ36jA/s7eRNF2hUmRv3LlQ7dh8INMVqDApd89Zx7
         AqHF4h2iYPdsYdwnLzypToPJ5x+0gi/TDZoCIaPAUH8Nqfj5L6ZNyk5VivR/WSzwRgN/
         9vZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=7iwYI8kf1z7ALMdg2nPHD697RhG5krEstX/Ebi3IFng=;
        b=cIeaNdwNNSDcxCW5y8/BoNr1RVYGpYR1+gFVI3C3S5kMUL8geZSsAaxLuoYD0oJO5D
         s+Yzvko9yLytBw4NcEdzaCdurVefoA4XoEJIMwqZmonDPcgEmWjDohYSuinjbePdRWTt
         gJCbBmmKmkHlO4jQC8lCC9/uZIkBCDGWwGmzfDzDgp1qsDeea9RPBmZwXG3OfXmYWq9x
         aPgE0W+lnAusUMTrBfHnzAGdNT2K3kQV54QeFCBKeUZg8DYsf9ndxP+LzUGrzz2mbh6/
         9fvMYgAtbJM4zl9JKBa59/3KYh2DFXXtorjWPGQB8INYSH2K7kpFeBxfSxpP+Fs7RytJ
         oPrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="CGE4/xLW";
       spf=pass (google.com: domain of 3jenhygykcukyzrtvsrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jENHYgYKCUkyzrtvsrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7iwYI8kf1z7ALMdg2nPHD697RhG5krEstX/Ebi3IFng=;
        b=N328TThE3kePswOu2qQ8xql4wsU+bRdRjDNDDHpbHt+1/dO2YM60O9iKtiNNo+JYiM
         gMSl3PEZfBJlbM07u1COtUGsrfNGkb8qTbx0t8Asn31YbYfKrOSjJd3qgpESQ3CaH7dY
         VjKFKjD2tAByx885lkKOi/0hnDkaXII/lRFRQJP6e/0F37h5tFEI3uud3IO+BC7GnbcM
         ydKnXkC9UmeHRZp75XVl1DTTnolNZND3KM69QfpWClZBtnVOxTA40/yw9jp5nZz28pUW
         ODuiYoXzazDV7KbIx1w3qcYMMAQ64DL/iFE6SgLl4RVEfeWjdOwhahF7pv84wCgiiauX
         BCbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7iwYI8kf1z7ALMdg2nPHD697RhG5krEstX/Ebi3IFng=;
        b=gVFyjzpFTZnhBnQPgm0GF3E1tz7SgB4qCIfJImzwZ/lpcH7ll3m09QD9zpgjA6m76D
         ni5uBziw262baXJDgnXjEV4eZfLi/jqNTh0BBvYmTyElFBgB0LRCBpCSkmRSxy+zLDwh
         czNs1YEoUNONwPR4q/lfTW+xefD2s6r+K/MiKsZacQ4AGYev8/nrI1j/t9bPkbEHpR4q
         1bCzWmRuaQwQSD4+uscjhAR++MCQ6NdosJiVvcdhLOnKmGwP+kCbctBozdBSPZomHLJ0
         pHhMJsU3S+DOTtG9iGAkV4mvanybowJ9WQwuAdkyiyCTfmhZHB+ad5ptuiGQ+rJJzwAe
         kajg==
X-Gm-Message-State: AOAM532QipfL2ynvgANivj6vJX5vIs+uZrtbXaXKteBbmqLn7mYX6WNe
	EQG6TOw2efbRrKAlUPzxspg=
X-Google-Smtp-Source: ABdhPJxEno1cGVqXD48BCLfLvHFAzayjkSv2S7u+5jy0YHtF5qW5nokJqpaWC1QKdxB3W32k6894aQ==
X-Received: by 2002:a05:651c:2ca:b0:23e:6a81:9591 with SMTP id f10-20020a05651c02ca00b0023e6a819591mr14490708ljo.54.1648837520067;
        Fri, 01 Apr 2022 11:25:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5285:0:b0:44a:94d2:1d8f with SMTP id q5-20020ac25285000000b0044a94d21d8fls140096lfm.0.gmail;
 Fri, 01 Apr 2022 11:25:19 -0700 (PDT)
X-Received: by 2002:a05:6512:33d2:b0:44a:2d7b:ade4 with SMTP id d18-20020a05651233d200b0044a2d7bade4mr15312500lfg.424.1648837517841;
        Fri, 01 Apr 2022 11:25:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648837517; cv=none;
        d=google.com; s=arc-20160816;
        b=qcpaHpdMgpd2+dqI4qT5klOnOfCOWG0+672NbTanZSdj2hayTG6ow+cE7dSbyh77CG
         GYuSMu3ZM80xqRGwPqIGu+KkZ4ITsAs1wiPTdiXAtRPtPxo/Nl+HZotNLucZw8ikigkB
         6ejAmnIEqf1kAa8CcSVkU3jW6a9Nrwjz2dVYnXhHO8szQ9qwZJb50YUy5pR2zAw/wwrB
         nK/zM8CGUMBaGQ5hDG1OmMPKrxcKwkc91T9t1Vy02ACRE0j+FUUmb6NONR0aFyFMIF5J
         PMMhU7ZxsIBP4nS5dqyRJ1m+xZ4U4Wt/x3yNwuyoELZtUealBoTtJoOdCCUQVHTUlSGM
         Yonw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=zbS7FZD4vfmPvNMcqFqSr87xT5C2GWUmtECcKw2k5VU=;
        b=qBpSNqIezumw+Uzp9xrEJ/rLemZmSMeSw1Ulwidobgb+fq9Rw55eDvkyyqeGO9jCKk
         YM1+5TlCeY8HqUqIyMGRQH9bYIJwx04ibzAjXGSa3XcBMufNJ3g4VuuxvJLZperliQAd
         D7SUrit3+t3B+rUbD/FmCxIBYQe4n4fkmElVP0sHfhV8TuXi/D29SBihjG08+Jv4D0hB
         nXQxl/NCUNl7ti9S+1MiGM6R3OIr1hCR3ji59cHGRzvp2kx1Fb5Dp6+hEjfU0q/Ud+2a
         mzMF27jusLJJo3WFwoK1tEzdHebRwZy6jLF49rtBuVFMnaa9dhLXUxtZqzK38kTlFXmP
         9oKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="CGE4/xLW";
       spf=pass (google.com: domain of 3jenhygykcukyzrtvsrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jENHYgYKCUkyzrtvsrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id d22-20020a2e96d6000000b002448b058176si245928ljj.1.2022.04.01.11.25.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Apr 2022 11:25:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jenhygykcukyzrtvsrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 2-20020a1c0202000000b0038c71e8c49cso3248993wmc.1
        for <kasan-dev@googlegroups.com>; Fri, 01 Apr 2022 11:25:17 -0700 (PDT)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a7b:c844:0:b0:37b:b986:7726 with SMTP id
 c4-20020a7bc844000000b0037bb9867726mr10199318wml.160.1648837516835; Fri, 01
 Apr 2022 11:25:16 -0700 (PDT)
Date: Fri,  1 Apr 2022 18:25:12 +0000
Message-Id: <20220401182512.249282-1-nogikh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.1094.g7c7d902a7c-goog
Subject: [PATCH v3] kcov: don't generate a warning on vm_insert_page()'s failure
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="CGE4/xLW";       spf=pass
 (google.com: domain of 3jenhygykcukyzrtvsrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jENHYgYKCUkyzrtvsrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

vm_insert_page()'s failure is not an unexpected condition, so don't do
WARN_ONCE() in such a case.

Instead, print a kernel message and just return an error code.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
Acked-by: Marco Elver <elver@google.com>
---
PATCH v3:
* Adjusted the patch format.

PATCH v2:
* Added a newline at the end of pr_warn_once().
https://lore.kernel.org/all/20220401084333.85616-1-nogikh@google.com/

PATCH v1:
https://lore.kernel.org/all/20220331180501.4130549-1-nogikh@google.com/
---
 kernel/kcov.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 475524bd900a..b3732b210593 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -475,8 +475,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	vma->vm_flags |= VM_DONTEXPAND;
 	for (off = 0; off < size; off += PAGE_SIZE) {
 		page = vmalloc_to_page(kcov->area + off);
-		if (vm_insert_page(vma, vma->vm_start + off, page))
-			WARN_ONCE(1, "vm_insert_page() failed");
+		res = vm_insert_page(vma, vma->vm_start + off, page);
+		if (res) {
+			pr_warn_once("kcov: vm_insert_page() failed\n");
+			return res;
+		}
 	}
 	return 0;
 exit:
-- 
2.35.1.1094.g7c7d902a7c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220401182512.249282-1-nogikh%40google.com.
