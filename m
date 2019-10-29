Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPH433WQKGQEYEFNMJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 761A2E7F1E
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 05:21:17 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id m22sf1319586vsr.6
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 21:21:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572322876; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y9BIunLpNBx/xwlYNP5CzCUXTupYCrpwx2w2gOgtA2LkRDUlc+FFx1he9ChsxTr1DD
         5gzvQeJi3c3mH53+EPToztd0KIdn2DpY8OxUMRaNrauBsz7Ra4lJ6iPOOr0w5rxcSQsJ
         /6moBsRoz1HHvAFAf4pV91iQatvtAHUQiMWREDtzWfjHAlmtsAjTamDgB43OK7F66Ogc
         sCQKAoCxemtGd7scX0h2djmwGw+XCOb5nfQBn6zVomeOwwAAYnx/ZwC7cc22WE98rvrR
         37m1ae9SkzD5ZtqdJsH1mMZqJRM7TFHTaxV8hoYzKcHitJgKXvxmwQsnDIxYyfx/mnAj
         zPiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b4Joub8l4z3FEU+sprG7/hvEd5Ez6ayLszrIZxLMs50=;
        b=acdsAlUH0ExDrt1Lq7Z41mFmVXSsyGOF0Omn+2odj0kRmXinBN9nvWlVSIP+uhiLSn
         aVBHo6rcWMaGyNj2Qp0Ebnz74P/oY2AC2gyuPjtKfPc2OeC0AgKbmJw5PRVOApm2vilv
         sckZNzSVKpvYpuatCdCoiBFskBkCWVCypMNlZtWcPOvsuBV1azI+ny/B5MsYCcb9e2rC
         Cad3nDDUNE4mxI6jD3cG705QkI9Iz1avqG8OIiXWvCrsZrQxOQ1juTOxFmwlupmI+P0D
         oSdR7XkZ0rX41521RUPvZtNajIbKH0WOp2tK7fkGgwGqoxNqyVzzUlfc2Mj8SIgF/RFJ
         feDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lcDyHdzU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b4Joub8l4z3FEU+sprG7/hvEd5Ez6ayLszrIZxLMs50=;
        b=eGZ09xBVhq2eMTgFjWEkSfAvM4PtKgUSPQRQR5gEtB87A2w4aGmYQprugPeXMF//+L
         Fh8DlvSZu0uYk0maOpd8KnmHcYN6VFsbJIsGbuFZvPT64C1YsKQUbLEQhhGGA3U8Hwme
         qQAyaT0OyPSL/M2yAU+yxREvOpD8ln/iB5ZWskF/4UtbRkw3KWK8iE0CE5f1cBhIiARq
         8iH9oVOpDCkyTY7D2iFthdKn3m/zcE8MSzEtOcz1BrRinaoP3U1edqthxihpTl2dSMyX
         wEbRbgM80GohyaP4uy1z8WA33jR+AYf2FIiyEBAQa9mAp4CUUlh665Sa6Z6ZqDGsH4UU
         aQKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b4Joub8l4z3FEU+sprG7/hvEd5Ez6ayLszrIZxLMs50=;
        b=HNh8wPsDd8LJd/evSk5JkkZMFP25Wmc2ed7nXbjw4hl9ndarj0/D3mS02GQiU3gbpB
         iww2w4E65CBC56LT54rR6CCaG9nwCzrV92yXVatYgh6/Xpc9hKL8eu3F/8lWvbO1YgLF
         8viX4OQ9YTUBq2WZbJ36riOdBtY6TuQlDt7tGuTB/eyATO6zJ6FxXYxbhFNyFUZfWVie
         Z1a1LcK00J+py5zJy+QUyRHUINW9AqNLrws5dAxZNO/k9u4VcEVP++wOP2PW5J3lioH2
         JvC8f93LOx9uIhnZ8CkAtJqK+5PykoDhB0WgkIe56kKV04rY7nWFxTecwi7WtHRN2exH
         6rCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU21gIoPWm6+cJHrPFkJywa2K4jlbAPQeu47M9pSoWp4IpfJ5np
	AxkePI/+ZlOo6mEWcgWJVtc=
X-Google-Smtp-Source: APXvYqxpaJfh3wKk9WbxG+9PgPnMHPEQHweUDcgvmiSSdShGXBEw5kBngbw1ThBh0f/GjcXvVRZkvQ==
X-Received: by 2002:ab0:1d4:: with SMTP id 78mr10737334ual.6.1572322876264;
        Mon, 28 Oct 2019 21:21:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f68c:: with SMTP id n12ls1819956vso.14.gmail; Mon, 28
 Oct 2019 21:21:15 -0700 (PDT)
X-Received: by 2002:a67:c09e:: with SMTP id x30mr543217vsi.61.1572322875679;
        Mon, 28 Oct 2019 21:21:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572322875; cv=none;
        d=google.com; s=arc-20160816;
        b=dqIn2pEmVTfW3JNgAcuNDMMvRE9Eubth17pIBhmcJUYZxnXz6dda01/k14CgvsI6Wp
         +qhSPR9QgUyQurD3RTBl1b9KDweqIu0WjhXjgFPLGgQ1unMzr3ODRrlbb1NKgwLfNY4F
         vJcUtkEog3K+0SZC0dHV7j6mrKF18OVgATcsaDkUTaJLtKIvvdEwaK4EJRB46ghoIk9W
         gGJwGXfPtYiRvTwksyIXnTrNQu5Qp3xz8zMJSyjjSqghvucLRcgIp3k6WU3y9394RweQ
         vLAZa4VXq7LrrV6KMBaWJ+5cpuyZ7yW0RPnpPXGGmd6sqzxCVfwzj3b2v0eLGrMrIr8a
         WIkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HNDV9DT7O32N2h9l7CrACdWJSzNVfR3Dv9pnUT55kOg=;
        b=SNjK7HrNefEUdB9VQBzLpJDH3XcurVwlj+i+z6iRg4siliU9z2yrEcbfLh70l20LrG
         8MZmudhXaVNbghzkKTUJRLpiwFIuEku+0C4B7TcFaCJeKA67ueWDVKk8nZbVsaPc3vHl
         tIscUmI3iH9yUhy1uPYDNp93IoiHoWXIr8nOlrLykrNkyXLjH5wlhZHpOzEDWJ5kLHh6
         gJI3X/LR2B1+pX4Jux54+MrrUhqd9LFfYruIDuts3EqvYUvRUrC/041d2imtVXOjGPnt
         GVPlqsHzCUBB3R+QXpysZbTNdwNkjz1zjgtQyqRsl8fj3VjXvCi+10CmeBaX7u/sF4x4
         rDGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lcDyHdzU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id u206si834815vke.2.2019.10.28.21.21.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 21:21:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id t12so2276945plo.6
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 21:21:15 -0700 (PDT)
X-Received: by 2002:a17:902:68:: with SMTP id 95mr1661194pla.117.1572322874296;
        Mon, 28 Oct 2019 21:21:14 -0700 (PDT)
Received: from localhost ([2001:44b8:802:1120:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id y11sm15418521pfq.1.2019.10.28.21.21.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 21:21:13 -0700 (PDT)
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
Subject: [PATCH v10 2/5] kasan: add test for vmalloc
Date: Tue, 29 Oct 2019 15:20:56 +1100
Message-Id: <20191029042059.28541-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191029042059.28541-1-dja@axtens.net>
References: <20191029042059.28541-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=lcDyHdzU;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
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

Test kasan vmalloc support by adding a new test to the module.

Signed-off-by: Daniel Axtens <dja@axtens.net>

--

v5: split out per Christophe Leroy
---
 lib/test_kasan.c | 26 ++++++++++++++++++++++++++
 1 file changed, 26 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..328d33beae36 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -19,6 +19,7 @@
 #include <linux/string.h>
 #include <linux/uaccess.h>
 #include <linux/io.h>
+#include <linux/vmalloc.h>
 
 #include <asm/page.h>
 
@@ -748,6 +749,30 @@ static noinline void __init kmalloc_double_kzfree(void)
 	kzfree(ptr);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+static noinline void __init vmalloc_oob(void)
+{
+	void *area;
+
+	pr_info("vmalloc out-of-bounds\n");
+
+	/*
+	 * We have to be careful not to hit the guard page.
+	 * The MMU will catch that and crash us.
+	 */
+	area = vmalloc(3000);
+	if (!area) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	((volatile char *)area)[3100];
+	vfree(area);
+}
+#else
+static void __init vmalloc_oob(void) {}
+#endif
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -793,6 +818,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_strings();
 	kasan_bitops();
 	kmalloc_double_kzfree();
+	vmalloc_oob();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191029042059.28541-3-dja%40axtens.net.
