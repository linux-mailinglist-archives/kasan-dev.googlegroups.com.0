Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZU4UTXQKGQEXVGCYRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 60EA3114237
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 15:04:24 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id q14sf1628314pls.15
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 06:04:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575554663; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hp7mwJvemrRs2Exq+KKPAZ6f1sQYl63K/Tgv6khjlbO+kpT+QS0uIdg7L9mvIG1AhQ
         MPftL9ElUMsXlvf+llmgCNfZzKZN1Ux+8tF4G/OFjTewOh0ifegLh2pBQvKPauaUnZYW
         WPbtnPAGw+BBzSidqFtHAY3v/+usofP/asDYVdiJR+xV0p72LOuVjxmpgNFVH4D6u4++
         zWrXIfuhHpqVRmrQzRH2FwEE0AthB863YvSYtaCF3oTypobiFlyR4omWcIYqIPp1C07j
         CMBuSdetvGLhWiLJTHgD374H2a+w0JCYiGcb1bT1BTtbAvrHseiyLExyiJpm2viXk2JR
         ChGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pVxBOov44Ix/tifbDptU4Q7/WAZNIgwkd0m6zUSgNUY=;
        b=swh4Yyg/hmcpdCoP609AaOwpObCXnhB0J4ecUIDZCS0lzYTkO14+Kk3ilPWlDMtmIK
         XpmB8Izdgie24/6pkW/jSK6J7nIesynPh7A5syDKxWBHbh2kxUyBTAtfHX/SWZ94DRKA
         YzrGXjQIWsya+Pb/cthlmb6gGTqYJzaDMSHIcxi6zYikB3qkh45dmRTuIjUtkOqvO5HD
         Zwp2a9x+NRd78X+P2cI4afgnWyoMsuZrBoWwCtAGbEfaSxPTGkloHE+nhsDnX4Fr05aV
         qhHdF8C4eg2IKgSLFsDU7fY1fZtxqbCtmZ7OU8SIRH7ofAM3+tSka+Ie8eG5Ls5bJJKk
         laXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TdxvDXVF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pVxBOov44Ix/tifbDptU4Q7/WAZNIgwkd0m6zUSgNUY=;
        b=PKtBy0tBRC3huvZL3x3ztE9QB/ofWzgfwbRmZA4tXJWYXwnot8eAqJHdlU8IUvyZ58
         iEeKfI3glfOibQaa1wns5YwuR8QR7YMtSx8/5leIehmhIVSFS4Nfwzu9Ju0NfIbtmP+j
         q1i/YpFf6IZTn5f9+rLOCJaEdHpk8WDZCN4JYnHAzaCRPGnKVhr3d6tJuXZKJ4V6dasa
         TPGp1DBNqiSsc6jflEXUu9v9SnBNbWpU0AUnuu5FJeD1zdFiO2JkXHq9R6GbTGHRBMJ2
         UGTRYeIQ/fSomq/TbvdK3mk0hI+ADBsWRSUp6ocBEChpoorBuh9a3BtN/dirp5Y/fXNz
         6XGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pVxBOov44Ix/tifbDptU4Q7/WAZNIgwkd0m6zUSgNUY=;
        b=jx0a4sK5RceKO1JN5dxKafvJB0/EmRNE0GykcZaAh2tp7VjhJ7KaO5250hpDkh64Kw
         dtztUOi7E0nKeio4hGj8mb8mxyDQuzhr6Mqs+2MMLdM6LWhAhQWtBXZVDO/K9+r1T4ws
         zQPiYme0J8Q9bgAqPtzPyCFhAo1jqXn8lw74mrG5DEjL83HPzWc8xaEb6dJpDwEuzEE9
         +r80QiwsdhlMl5QYrmSdbuEa7nd+lSnzMNLyaEO/2RXeYGHFCAKg/M+4cKRC7S7xc9Pl
         MR9bigngud+Pr+2BUz5Egk7avC+dt6CQkswxcN/6wf8Uge5JtH+XQlYuiTJEt/F2VVoX
         5lmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXTHqporjWFfuQT3QBB6OL9lb1v4ExDHNMNkym0Wmt5knVaGd6x
	u2I5GNLu3ecHO9BNVYCPKU8=
X-Google-Smtp-Source: APXvYqyrXdKrOaxu+4m+VZv++19zhXRPsOWQt6d6GIdoB1TSF2mTiizoF3bGxdVI5ngjJ9pyugK19Q==
X-Received: by 2002:a63:2355:: with SMTP id u21mr9274125pgm.179.1575554662850;
        Thu, 05 Dec 2019 06:04:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:84d9:: with SMTP id x25ls876887pfn.2.gmail; Thu, 05 Dec
 2019 06:04:22 -0800 (PST)
X-Received: by 2002:a62:ee06:: with SMTP id e6mr6684749pfi.45.1575554662491;
        Thu, 05 Dec 2019 06:04:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575554662; cv=none;
        d=google.com; s=arc-20160816;
        b=lInj80NVJP22fjLt0N5LwobIx7uSjebkeWFMm8i32jYRazyuwRAuLZ+8ZJbYgwIbif
         vRJsIhPwoMtMvOqx+cUiQ0cqxUOv6aFpCs7ICSrIty2kQ6UulNYp0YFL9TQSl5B0QtHJ
         bfl002yWk3bExDxGqH+OCbwl0TOojjwnY2aCIp1usWjFJvIoytieNg5SvORwjp0mPlnL
         GQ8W61HaggScxEE7saUyqxD7tGxGowMNFAxa85gsqhbOvDRSNfD8r3ijPRhSXHBUcUNR
         0zrB99CivluZHj5MP0Jf/v4vn54xfGDpepfRGJUJNUQ29oqW4LrqozkDBl72yQR/pmq/
         BYjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U+rYuarcFGCelyfsuzmoID8VbDpvPXs1LM8fcwC/sPE=;
        b=ZiK+/o1pZAW/DZn//sbAOxRXx+FP647nrhUFG8W5e1ajCYhxnK6ZcS6/SLk2phU/9n
         1uEHVbsHKN7zxWaeyHuxXUkae1h4lz6e4eQsaHlx00HZx4Qd0f5/SN9uzRueHDTY82k/
         vlm6m02cdnWJwq6tsdul5kiiQMhBEjE4MbiqW4x7b9Y6cVygW54tYfTUA4qLlbYUz0nI
         XliYgFKMW0aVnz77Y+gPW68AHVFIrBdB9lglGHIHy+7Dmfbnn0O+9uzhXFQTU4vtkwNT
         dXyiCIxOZvROWd5kLYEwPeF31Skp3isAuPSxeimMC9R2XjRZ4NUoVk9XE02vYjP/R0oV
         KILQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TdxvDXVF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id h18si596014plr.4.2019.12.05.06.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 06:04:22 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id o9so1298531plk.6
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 06:04:22 -0800 (PST)
X-Received: by 2002:a17:902:904b:: with SMTP id w11mr5268735plz.204.1575554661870;
        Thu, 05 Dec 2019 06:04:21 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-61b9-031c-bed1-3502.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:61b9:31c:bed1:3502])
        by smtp.gmail.com with ESMTPSA id q67sm5745928pjb.4.2019.12.05.06.04.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2019 06:04:21 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	linux-kernel@vger.kernel.org,
	dvyukov@google.com
Cc: daniel@iogearbox.net,
	cai@lca.pw,
	Daniel Axtens <dja@axtens.net>,
	syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com,
	syzbot+59b7daa4315e07a994f1@syzkaller.appspotmail.com
Subject: [PATCH 3/3] kasan: don't assume percpu shadow allocations will succeed
Date: Fri,  6 Dec 2019 01:04:07 +1100
Message-Id: <20191205140407.1874-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191205140407.1874-1-dja@axtens.net>
References: <20191205140407.1874-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=TdxvDXVF;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
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

syzkaller and the fault injector showed that I was wrong to assume
that we could ignore percpu shadow allocation failures.

Handle failures properly. Merge all the allocated areas back into the free
list and release the shadow, then clean up and return NULL. The shadow
is released unconditionally, which relies upon the fact that the release
function is able to tolerate pages not being present.

Also clean up shadows in the recovery path - currently they are not
released, which leaks a bit of memory.

Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
Reported-by: syzbot+59b7daa4315e07a994f1@syzkaller.appspotmail.com
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 mm/vmalloc.c | 48 ++++++++++++++++++++++++++++++++++++++----------
 1 file changed, 38 insertions(+), 10 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 37af94b6cf30..fa5688093a88 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3291,7 +3291,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	struct vmap_area **vas, *va;
 	struct vm_struct **vms;
 	int area, area2, last_area, term_area;
-	unsigned long base, start, size, end, last_end;
+	unsigned long base, start, size, end, last_end, orig_start, orig_end;
 	bool purged = false;
 	enum fit_type type;
 
@@ -3421,6 +3421,15 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 
 	spin_unlock(&free_vmap_area_lock);
 
+	/* populate the kasan shadow space */
+	for (area = 0; area < nr_vms; area++) {
+		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
+			goto err_free_shadow;
+
+		kasan_unpoison_vmalloc((void *)vas[area]->va_start,
+				       sizes[area]);
+	}
+
 	/* insert all vm's */
 	spin_lock(&vmap_area_lock);
 	for (area = 0; area < nr_vms; area++) {
@@ -3431,13 +3440,6 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
-	/* populate the shadow space outside of the lock */
-	for (area = 0; area < nr_vms; area++) {
-		/* assume success here */
-		kasan_populate_vmalloc(vas[area]->va_start, sizes[area]);
-		kasan_unpoison_vmalloc((void *)vms[area]->addr, sizes[area]);
-	}
-
 	kfree(vas);
 	return vms;
 
@@ -3449,8 +3451,12 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * and when pcpu_get_vm_areas() is success.
 	 */
 	while (area--) {
-		merge_or_add_vmap_area(vas[area], &free_vmap_area_root,
-				       &free_vmap_area_list);
+		orig_start = vas[area]->va_start;
+		orig_end = vas[area]->va_end;
+		va = merge_or_add_vmap_area(vas[area], &free_vmap_area_root,
+					    &free_vmap_area_list);
+		kasan_release_vmalloc(orig_start, orig_end,
+				      va->va_start, va->va_end);
 		vas[area] = NULL;
 	}
 
@@ -3485,6 +3491,28 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	kfree(vas);
 	kfree(vms);
 	return NULL;
+
+err_free_shadow:
+	spin_lock(&free_vmap_area_lock);
+	/*
+	 * We release all the vmalloc shadows, even the ones for regions that
+	 * hadn't been successfully added. This relies on kasan_release_vmalloc
+	 * being able to tolerate this case.
+	 */
+	for (area = 0; area < nr_vms; area++) {
+		orig_start = vas[area]->va_start;
+		orig_end = vas[area]->va_end;
+		va = merge_or_add_vmap_area(vas[area], &free_vmap_area_root,
+					    &free_vmap_area_list);
+		kasan_release_vmalloc(orig_start, orig_end,
+				      va->va_start, va->va_end);
+		vas[area] = NULL;
+		kfree(vms[area]);
+	}
+	spin_unlock(&free_vmap_area_lock);
+	kfree(vas);
+	kfree(vms);
+	return NULL;
 }
 
 /**
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191205140407.1874-3-dja%40axtens.net.
