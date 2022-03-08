Return-Path: <kasan-dev+bncBAABBPEUT2IQMGQEC2OZOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F4474D1DCD
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 17:54:21 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id f14-20020adfc98e000000b001e8593b40b0sf5648422wrh.14
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 08:54:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646758460; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ii8+JrY4QQDtJ9uIEqP0sed1jQlKAJY+BfrR0GspIjW8M7QN5EChwu1Nzv3067Hkdf
         NZknlXsCrwxa/id41ruP7nrwNqnB6sV1MPcdFwlYNaQajAYLIy2/Vi53oE6lYvE0vtqV
         tK/CYs+fUyNxhF0b02mHczmNFZq6UIij+kRTZotGBIkjWkfKi3VdsrMcltcQyeH8UR4o
         eeTTH5gyxCe9go0hSVljuZIV+XFQdCmhcevL23rK+KgmL5eEveZlKbk6Yw4vwkgrJeEh
         UAOzWPgogRXe2zvtkl2Wq39XhWY4AYkAmLz83lP5HW/bjWN7gSyaLa/5oK4CDhUNZNMR
         gLTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6OU2QJs+4PfLAjLEESFhgw0w2fvn3Cm0Sj7VYFtjlfM=;
        b=kzLIzU0zwFH+J7cJBG2e6TWXcCYQ3YJ53dp3YeLKyX6q1zlvDE+ievRo+1Ss4WHfi4
         Y+PPMKN2bxGcL4hOkXcGoksLsRvVU+EbShFkRXv7jT4UaOR3Q2jWs4jrSgRot0tGik5R
         RDVux7l0N47EZQve0wIyHi0L+S648K9IvO3SYKvzs2z4KvmcBp7GlwAytjc0+7yPv0DS
         LdsvRJLRwu2h+E/LH1s5drgMD315bz159E+WDvbVzscshYKrLiGjuGIGgGn7cAzn2Et4
         W+O1pWwf2U/TshPPqhJKn7Mq69f73kA7FOyzWLlW5jofQeLRQVP0hGTG4ea4HYB0Hzps
         Hlbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hJpgRdv8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6OU2QJs+4PfLAjLEESFhgw0w2fvn3Cm0Sj7VYFtjlfM=;
        b=lVKlDY7WVXm1bBWWPWyInp3h8JatATUpx42rQYziO5M+c2/Okea+pZu3OjUAdmrU7l
         0RlcPyGOV2VU9guNWK0e4/vfLuYlJr1EmaIxYjlp6yIQwaWWboq2ZXpKuZs9YAzSCfd5
         R9zsMaFewW24YFhGMsCuISn6swXcQ6Hv0Gy84bbNHk+4N+TzZNhFLJp0ZK9lwgT6lOmc
         51KexuPeIy2TMm/jZlslnD+3zApasosDkew+eEA9x68IYFfIGQT3l69Y9lIOktjx8L6F
         2pXr40FaLLG9p0rkt32dd4hrH5efa8WXwqbnttjovMarD42zoqZXzibADTr4WYIJfcUl
         fWJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6OU2QJs+4PfLAjLEESFhgw0w2fvn3Cm0Sj7VYFtjlfM=;
        b=v5LEGsCGcd5+M8umaJ5A598BhcbITMvEWYGMsengkLt1I1gZCCRCRM3HT/DXehdfsH
         a/Ums1SDrn00RsE3ythRSfQkD0JLRP/c3jgZRbMYwU5zhwU3QFhCgHRvh2qH22Fz+ovM
         Q2M/vu/FmsXSNaihsC2YSzmKRb5F56auUzvOTAjX76LxrS4WqutRfFQqkrjmWnTHfLTY
         Q1WSqakb6ZHiUGt0kZyBJ0V18zZOhVaLPUu/QWh0pycICrDzDFKurSzg0lyWgFLQ2UcD
         aevn07dJe2UpmLDrMBVQRjmTDXj+1OzDsEwcJi/U4gmChRWxPkXdJw/KjIaU7HiJUpbE
         H8/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331YQojPwuDBkzgz5W0XGXixtYtw76lY92C+DdK68daH73pEM4U
	tRq08IuPuuDMbKbszYHgQec=
X-Google-Smtp-Source: ABdhPJz/99kiD+4bB/akNi43Rnw9328Lo3BTuBZq/JFSTzq+toC8LzmsDsRIWL2ibycZu61UFl5WuQ==
X-Received: by 2002:a05:600c:1994:b0:389:bcf5:6e79 with SMTP id t20-20020a05600c199400b00389bcf56e79mr4285211wmq.43.1646758460691;
        Tue, 08 Mar 2022 08:54:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c855:0:b0:384:9952:e84a with SMTP id c21-20020a7bc855000000b003849952e84als1505639wml.0.gmail;
 Tue, 08 Mar 2022 08:54:20 -0800 (PST)
X-Received: by 2002:a05:600c:a0a:b0:350:564b:d55e with SMTP id z10-20020a05600c0a0a00b00350564bd55emr138580wmp.124.1646758459949;
        Tue, 08 Mar 2022 08:54:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646758459; cv=none;
        d=google.com; s=arc-20160816;
        b=04EtGWXCw3w12fC9DMOhMgc3jaViQ6d48Hz56vHU2f2BpOf97qZj2iIxhlsuvnl3Ix
         zwnZ3S9YJA6lH9CbUTLstZqY4vgUOE5Kqd9wtNHPyuhtGnC1Mk/ty5jyqZvnUqQmqjL+
         P+jwW5T4LEWyDpn7fTsAWBf15tdkVhMW0In6cG/pg1Pd00cotd0lQDjYysPjyu6Pu+qK
         uiYTrW6G5BKKJQMJMTpgSJsn1G7S+RHQXt+HMOfkRLZECa463otz+k0hDqnGvBba5IiE
         9nmV6zqqtYlkgFjEOYHOH63dnkXW+3qWjMkKISwTIaJlNoqsZ060GJAC30h1weOKd1ll
         DZVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=eqmkPSBm5WulTOgzZAJ0UbU+BwECVBvh4ECQqxckohA=;
        b=pWH0UyXEUGnFBQSRkmZzJ7o768WzC394mWiS2Rptu0pLG77KVDLyryIlrF5EWfOcoN
         kKQyj2IdOu5/j1KPfS48sphs2252qod0AIdzXn1sNAhfcD7ZvHpjdKgd9OHLK31olfze
         8qdbAF2dnoL42x7pTt+JcxZDFuwpz3zo2gCZ2b/D9fJbLYRio3Tbzpq34k4FZF6ZzWaP
         UBi9EFUP/+sVgWNRYBdOTYZ1KoK0cetqNQst0auDRdGQYF1wejXUwAlY9kJvB1MnjSjX
         FFpXkJ5BtAfng62sz6NUprJ8W+VqfExPuOqWpe7fo5j393zshUnkK+GcJxUKfvTfqwAD
         9wyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hJpgRdv8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id bg3-20020a05600c3c8300b0037e391f947bsi132353wmb.4.2022.03.08.08.54.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 08 Mar 2022 08:54:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vasily Gorbik <gor@linux.ibm.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] fix for "kasan, vmalloc: only tag normal vmalloc allocations"
Date: Tue,  8 Mar 2022 17:54:17 +0100
Message-Id: <de4587d6a719232e83c760113e46ed2d4d8da61e.1646757322.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hJpgRdv8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

"kasan, vmalloc: only tag normal vmalloc allocations" unintentionally
disabled poisoning of executable memory for the Generic mode. Fix it.

Reported-by: Vasily Gorbik <gor@linux.ibm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/shadow.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 7272e248db87..a4f07de21771 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -489,10 +489,11 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 		return (void *)start;
 
 	/*
-	 * Don't tag executable memory.
+	 * Don't tag executable memory with the tag-based mode.
 	 * The kernel doesn't tolerate having the PC register tagged.
 	 */
-	if (!(flags & KASAN_VMALLOC_PROT_NORMAL))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) &&
+	    !(flags & KASAN_VMALLOC_PROT_NORMAL))
 		return (void *)start;
 
 	start = set_tag(start, kasan_random_tag());
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/de4587d6a719232e83c760113e46ed2d4d8da61e.1646757322.git.andreyknvl%40google.com.
