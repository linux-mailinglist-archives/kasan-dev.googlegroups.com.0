Return-Path: <kasan-dev+bncBAABBV7TTW6AMGQEVGLHD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DFD4CA11CC5
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 10:03:20 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-3023b76e4bfsf3252441fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 01:03:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736931800; cv=pass;
        d=google.com; s=arc-20240605;
        b=Iu5VTUj0NKlDj5Q0bEDhNsu80Qiy9b7fQiPRuwfUCdgdMceon/ZY+1zfSr/xyf/LCS
         nI+PRAMl/c3PQmxjt6R7J+9lPpPhrGYmDAL8hGn5FYv49DPGCAAQLRqUIE1dLLt4kEEv
         +gv5NcruL97l54SCiBPOxf8r+QRJgiyPQQe6nrxbQOqJlcNs0vPvuqu5dzZZnEOv9oNb
         ftSoLGEnZjfTBYitP1E2wRaN5fp5xi7ApIV5GJL951S6hV1mcHifB61PgyeIp8VX8/6m
         WwyFU2Z0k3VhOnA6S3P3JzFhB95CzlaU3ic8+yHVGWwI6nq69KiG3rgVH+xRNz5je/L5
         byuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2UfC8h9Uh4IQwTrh8JM9F2rFSMpc8fGiHnx78yBUSAg=;
        fh=V2Cv3fDpjtpRMngpHs/4SW2/VO9+n3f9L+e9Kn51KOc=;
        b=VgA7/6Dnpn9M0tu2SKKCCOEY29BQLDFcRUsRmvsqxIf22qccA/o0Ne8vfC/6xc5nZn
         eDoqpONuFxXHAmr0hx59xhlz28ggz4EPaa65Cmo79xqDpXcmzpIfT2F99W46R7+t6f3W
         2TAzg/XZXeTwR7IcV/xpgNSKEhtveNMHF8DUXwzkOINl43/G8KQaeFuUAeoBZgy7UL6Z
         3sxGHOVMxv+IpVFUZg3V6dHWz5fIfmpMerSoVEGxYBMNPeAWuV0qtf6lKDHLD9ON8dAZ
         MGtrHxmIMQowXFjtkUc2Uf8V9bV//L8S2HmISsKqWRpLqXACRfKvPUiV8mT0jX8PApDF
         FB6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ucb1LDzD;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736931800; x=1737536600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2UfC8h9Uh4IQwTrh8JM9F2rFSMpc8fGiHnx78yBUSAg=;
        b=I9lUBT6a50LKawANuwGGGpoNqEyMDBttMrc1avtOyVe4RaABuC8gzNk8KcXWr5Pp1O
         42I72fBbUwIgA5CA1jrvROER93G//aMOVP12FNMu1AWcn6HYTlpO/DW7GM5aYyXP049r
         wZ56B/dewAF1Q38SJvhy/uL8B7nxINVJWCf4Va/dndPKrFr6+Iow3Ofva7r0St4QbEYT
         V6fJbMMl2/Ph/Ix6q3XdCEppa+oE+Fymbe6Wm7/XuPvb2sA+Kr4X7gP6/ypC6iw32N33
         uTpr4Z7WumTQ0ZX02rYfXnGunJmzUoMFRJ4vxq7neKxGUG1Rivill7H5bzqEUW2DNdDA
         kQwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736931800; x=1737536600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2UfC8h9Uh4IQwTrh8JM9F2rFSMpc8fGiHnx78yBUSAg=;
        b=RwWRyVGSKrTaRLzOwRnHke5s6trL6fqgn0ah61OhuKW2wa+G2SIv/mmDo5thlcvaEO
         wHfabkctN/k9blVgndxQaeCMyczN5ppu40sk5Te9L1hSrXxJ9Y+WQL3A/Kk0dNf5Sjjs
         IXbMO5sZ+F+htVBsq0AdAcin8pT1oEALWrDs+zLKIV3HpX0eHzKJTr961T/8rAHhBw+Q
         3b64rCV6ghXPbDb3/QwFh4IcKNZLj6dPSdHWijjdNGxyy+zjv0s+/GSMjnBgGcv4KO9K
         Wj2mHCrYqDlUwsyhlBjI4/NAyK0vcyw6gzHw/h1LBhBwqE/UbwEvsHLGq5DDrznmaJTB
         NHog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVALWgnnGjVU2W54+v/N25WWLRx5NTFWVX0YCVav8Emuy02c1c/XHxIOyNJtNZQdGGc/G9VpA==@lfdr.de
X-Gm-Message-State: AOJu0YyPomzhACMmemQtQq5DWEp1S9pX2OTDdrv+axu3/TK9NXBgQNsV
	1teQY8FuYrAD3J5HLjMSjUdsRQNpIheJi1W5iRea3oYBxgYnLK7i
X-Google-Smtp-Source: AGHT+IEFXkvNjQJJvTyYHPM/o2n+I+Wd8E4fXO4oK4LSdAstx3K83yE10yP4p9uWvVvxJgjL4YOEBw==
X-Received: by 2002:a05:651c:1506:b0:302:49b6:dfaf with SMTP id 38308e7fff4ca-306306289bbmr5562561fa.20.1736931799485;
        Wed, 15 Jan 2025 01:03:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7005:0:b0:300:1270:1b0d with SMTP id 38308e7fff4ca-305fce02facls2244861fa.1.-pod-prod-00-eu;
 Wed, 15 Jan 2025 01:03:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWuBl7njhVJ6JH0vz4LvwGzwBZNqlTR38+MYei54c48heozyOQ2dx32B3eWT2O1ZSB/GLpoCb4/lKU=@googlegroups.com
X-Received: by 2002:a2e:b537:0:b0:302:23bd:354b with SMTP id 38308e7fff4ca-30630577166mr5218791fa.1.1736931797522;
        Wed, 15 Jan 2025 01:03:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736931797; cv=none;
        d=google.com; s=arc-20240605;
        b=LM8xbKyit7FOkMiWiST8DqPIpFUpPQb9y8fi1a7Oq9uqa1soxUqb2YZZcVlIgXUseD
         WqWvwQ5NT1HzAS8RNW4cUeZG/ljbopWnMAGOClP2Fz4kuitwGfzjNhhDLtb907C0nGa+
         4KeWZmimB7KHzdchksocWiu6EZkdFZ+GSJKt0plNtLBNjy1oX4JZQvH9sRyVNRJ/eZwD
         0U59My91UUkO+ax6S+73V0bq1EN7PM/QxXHUSOby7DlUtCTZDyelzDCbiwMWT51XIt+C
         wmBwkcOmOhdKrxBgH1dp2YcsPTunBHNWWWPouAWaPUu8o9pYGg5poUn9tTOFXpD0gvs2
         J64g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=MTx6eVBRDQH0cIOXGIKWY1mU+eXC0+nsCNkZ+qhfRyU=;
        fh=lhmfq0oRmaWPvA9cvZGJfzNA25Hk2i3dlfqviYNk3Rc=;
        b=c/qAOqyLWrRFcx16HWNwiexmsE3YMBIG0dOsHVSXuWkmKR/bcpq4Pv7bp7czpPBuyh
         1UAa8hiuQeISPmKTVMpEoPSBaM3+Hxw/bwtX6TV2087db6MmjF/xylQv811dlVBTBhZW
         CXycIi8+3R/nIHb5Ahiw05mV27TUEsPc11cC0XZKpgE8PY8iwI8OpTe1N6CkZ6xW6Tnc
         qjiyM/W38WEmGJg0Kk2GH+wZ81XIj8IkZKb12g8l85PCYjDdhoTWBFP38+6uqyMPEl3V
         Yr2ejStefIa54/WdSy0S+5Wb3/5h/VmUHeqHm4AHpwYEHf6Uoc+P5I4QyDvWTbmkkUUH
         r2tg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ucb1LDzD;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [91.218.175.171])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-305ff17fd21si2399541fa.4.2025.01.15.01.03.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2025 01:03:17 -0800 (PST)
Received-SPF: pass (google.com: domain of thorsten.blum@linux.dev designates 91.218.175.171 as permitted sender) client-ip=91.218.175.171;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Thorsten Blum <thorsten.blum@linux.dev>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Thorsten Blum <thorsten.blum@linux.dev>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] mm/kfence: Use str_write_read() helper in get_access_type()
Date: Wed, 15 Jan 2025 10:03:03 +0100
Message-ID: <20250115090303.918192-2-thorsten.blum@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: thorsten.blum@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ucb1LDzD;       spf=pass
 (google.com: domain of thorsten.blum@linux.dev designates 91.218.175.171 as
 permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Remove hard-coded strings by using the str_write_read() helper function.

Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
---
 mm/kfence/kfence_test.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index f65fb182466d..00034e37bc9f 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -20,6 +20,7 @@
 #include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/string.h>
+#include <linux/string_choices.h>
 #include <linux/tracepoint.h>
 #include <trace/events/printk.h>
 
@@ -88,7 +89,7 @@ struct expect_report {
 
 static const char *get_access_type(const struct expect_report *r)
 {
-	return r->is_write ? "write" : "read";
+	return str_write_read(r->is_write);
 }
 
 /* Check observed report matches information in @r. */
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250115090303.918192-2-thorsten.blum%40linux.dev.
