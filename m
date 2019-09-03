Return-Path: <kasan-dev+bncBDQ27FVWWUFRB6P5XHVQKGQEFDBKA3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F653A6BF3
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 16:55:54 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id z4sf19285013qts.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 07:55:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567522553; cv=pass;
        d=google.com; s=arc-20160816;
        b=eUifTJ/87LrYmChGCOErLFDrcVVYIPIvtmmpxN2zbXGQlkiaM76TJyJaNHxbVDmkXg
         KMvn+SXGQdQgwiuWfeSfaDB09Mhcsnb44Uiq2WEBbSO16NHfH9KZAVMqHgJCi5ojnXMN
         MT9cilBNQo7xXaATBwCjab3y34Az+kVt7cuEGmllTXQX69EpTmJaxezJiqhhmYYlbsjs
         YdMVckvX1pzE7mg+jMnmYhFmmpQayAa9bzT066M+2Czgz1iz9JroKCxq8cVPGAUp+vAE
         h7LsECyPdulyZnBXvB15Dd/9kUmGkfi+LJCAnxN8h8MkCtKTZi0xy2YtedieYGuIHoR+
         TN/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=C3J+PRkzt8dIH7w5FCMst74YR+NH+cPUZbtKdxhhfbs=;
        b=A85Ik8Odx8B5o6OOomyIAMundHxv1Vo6bupUjUBqaV4eiIXDUzMxU2PsTRQ7iOL7CV
         BR8YgiUl6nZOegyhwghrVFZCjDQT18/LiG2aKFOtfV5vb3/JjnflqjREuoJVAScfvC6q
         DWpsyab6He3gC7EWNa80WTBp9MBHEqWNWzkuqy5n6rdaNKcQNod441+YYRVwRkUNc7s7
         Mw98Kvp2pJhQ3L61tnql2eMDsCL/geM2Kme2snzKDFQoGWsUjCNCDvSNDWMkO/OdLko6
         8gWAo+7S4OmXm0jv4kstLu6c2VVtq6y2JBl8/uRo+hUuivoDB4lJTHlDP5Zfbw9BAFvx
         EaQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=FR2A8WMD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C3J+PRkzt8dIH7w5FCMst74YR+NH+cPUZbtKdxhhfbs=;
        b=darR5RghzP6cqba3Q4xX4RcJjgx5JoWD8gBH9DU/MezUMuv6Ko+KwsCPtH5s7x8jnN
         YhR5Ewny/vvrOmG48Ylr44vjMS91L2xSGaD/QjBAM+P/YDjt6qTdqCpNp/fzTNkPi15a
         HdtLnkd3Bc6QZ6OYz+gWg1x2OBGW7OK2so5WejEWmX/c75uYeBQPUSIbAhFARvtQOJFr
         5JKFkqPD5LFdnYvRIsiHtXkvFh+QHlSF/sqPOpU560k+ZPNj0zXAzlLbLNV8Mpdwa1Nq
         JmWU/HZ7H4iNmgCxRv6srJowLU9gq0PnODPm01KgepjhqRB3bh9uR/BXehIQ9pjU23fn
         0woA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C3J+PRkzt8dIH7w5FCMst74YR+NH+cPUZbtKdxhhfbs=;
        b=Bh6/baW6LQbJZDBXRFJ8GNmPJ6rsTn60+cizhGYm2X9/OP6rX4//rsvdG9tEYsbp6V
         NSC4FfyQDDDrNIHMt7otollIqdj6ELn+741wEuwv/Pbg346OLdBH3llh+01LR4ZAf+Se
         3BjVlBvBm5xHyr6ne9xrZjV0cPWI4kxj3N+bkzm0La2Q1FW5DEvB34seMZkXnWm6E/x7
         gk1VRPjZj2nydOaEglRzVcQZ3f9KGiGgx7nWtlEg/lKvzINVE31n03bgGlYyVYNIg+WW
         bVtJpsavm5L1dNG9vz+eo1NU3Y6Txs23GvGg2gTAEZvTgKx0+y8ferfU2kZJksrqnNH9
         1J+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXPxP3ejsmzXzdNKZ2XTWni6xKb2MAqeX9/IcsCDFRXsxNDCfC4
	72QSFH1ZsBd8HmKiw5956Mw=
X-Google-Smtp-Source: APXvYqxbGo+WP8d9THH7BkZcJDVgeOrtbF9IgS82HLuf/dhjzHXv+lk9I/N7UrnbxoZTih84KsUknw==
X-Received: by 2002:ac8:4556:: with SMTP id z22mr13926720qtn.134.1567522553213;
        Tue, 03 Sep 2019 07:55:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:681:: with SMTP id f1ls4296877qth.11.gmail; Tue, 03 Sep
 2019 07:55:52 -0700 (PDT)
X-Received: by 2002:ac8:51c4:: with SMTP id d4mr34497878qtn.176.1567522552958;
        Tue, 03 Sep 2019 07:55:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567522552; cv=none;
        d=google.com; s=arc-20160816;
        b=IQuNdhHoe0OF4B9bKW4r7p5UBpSJpYSTAdeYAfAwE/wMnhjt3BbqqSK0oRv0mXqjW6
         UX+W4f+8xdxdYFZsabuH82z6zzMEkDZoSkTs2SQ+HUFaXET3ABQU3Ol1dfbj0nVacvCB
         W9ICiVxtLehutv8j8R2Ajf2p/fAtmnKSQPdtgciGPAWTTCDuUUPCNHZKy1Tb2GJQDk8I
         xC6EGl17PSpLXyY4lKBitpuxPmzdgwVwW8Pod1imS+QzmeNuWGBeIa59MB6K1OpVXB9M
         74F1teDFmMnyyBk/kgB0gMI93KCvfcXNF895LwJhiDQOWP2RxWX7L5xNm09GQG/Ijx9H
         isKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HNDV9DT7O32N2h9l7CrACdWJSzNVfR3Dv9pnUT55kOg=;
        b=kOuU/9wiVNrikLbGZmsO9oOqYh5WrQMjYJriWtwSGhkVpOE1Epc/ywa7EZ4hf9ijYy
         PVawMoYvpbnx3+O0Htt8KTyu75EwW8hCtSrqKvBbOFL8MyhqycIohQvaRcILvCzvWHCI
         ugj8ZDN+PXZ9HHdVmWhE2RyixCwMIjnLmukopPUz84V5cGcwtkYIG7BhUNNxMUeU4uuA
         XFqP/YH++4xu+I03f3rR4yqwEt/p3kLIuHCEcDSCk+GGIyV66/x4AGYslQLFPMpV1YPV
         WsH4xeYWw4EIIle2mjgkISxcybjv2kgN/UwxZ5ZUVWd+seytnSkry4z9RiC9/LVuONj7
         G2/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=FR2A8WMD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id v18si679405qkj.3.2019.09.03.07.55.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 07:55:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id s12so3942467pfe.6
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 07:55:52 -0700 (PDT)
X-Received: by 2002:a17:90a:fe0e:: with SMTP id ck14mr466805pjb.78.1567522551845;
        Tue, 03 Sep 2019 07:55:51 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id b19sm16216868pgs.10.2019.09.03.07.55.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2019 07:55:51 -0700 (PDT)
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
Subject: [PATCH v7 2/5] kasan: add test for vmalloc
Date: Wed,  4 Sep 2019 00:55:33 +1000
Message-Id: <20190903145536.3390-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190903145536.3390-1-dja@axtens.net>
References: <20190903145536.3390-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=FR2A8WMD;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190903145536.3390-3-dja%40axtens.net.
