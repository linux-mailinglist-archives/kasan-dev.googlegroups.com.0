Return-Path: <kasan-dev+bncBDY7XDHKR4OBB544VGEAMGQEIQFCU3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D51383DFCB5
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 10:23:20 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id p71-20020a25424a0000b029056092741626sf2107370yba.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 01:23:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628065400; cv=pass;
        d=google.com; s=arc-20160816;
        b=FbwiN0qj08wzpb49jPpRgBRtmMdn+ga6cV8wSnufplaYZQouTlaGBmcRB1jdmw5sQ2
         4syKFnykzuOHf6dySQbaIu4FAkdnQklRMQCGoyqZ8C9BMeQ9O8bwC1eugsz+klrdBlSt
         pd+6hX3aocIliyJlEhItwpmXsBC3HI2/rVabvoM3E1/20CBADmLVyVreYgf0/dsZu7Kz
         5Qe4Ou2NjLVg+cTBYbhbkdrl8JnOGfYb4fiaF336z2EOeGlEhwgUma07CNdVFKPNXAEj
         5h549QbPBSGWq0Xqz6eD6BfTfCSCT2YUFs3qxiLes62Rlas7J28kX8iTb0VBxp5bCNnm
         V/aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iZbcWGxqLYHa/tNYezklD9HgF1mwINvlpnUgrg42BSI=;
        b=tlLcncrw4n7UrVWCmPFd1rUH/caHyZDnYdqfa9jj7UgmckmnjKN/sXQ4VuOIW0bb29
         JRlTnGycDMoE2gQDG7y/ssgU+57CrTsTJY18ijGj9MdZvyo6gQ1JmEKQsMHz35F6LLFH
         XgB9mvtXJWpomqFtE7YJAS1PI7OPZgANjLjmB1AOqz1lUANz2+Pnd7lFXWoWkH9E4rGb
         1gSO7mEg0IVPFJ3o3nkTdGwmVgKHiLJND8IGV/y5NL66xLnGStVEnQTjXR8G0UWHy5bu
         mjGmJ6+OPypuE9zgcP1gcWdSjrh/Kb8lbECevQYaIJRCoLoscVCqHSmZXMKmfz8LySvy
         AXnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iZbcWGxqLYHa/tNYezklD9HgF1mwINvlpnUgrg42BSI=;
        b=fCyzsJ3cRRx1dqx2rK5Ca6HRoH5+fAQie9wEoBMOnMT/VbASAFm8XHCM+6wdVhPcll
         Xi9SnW/MyAJ5FnvKryTv0/bYLxVM/BFBn0tKzXSHSRGMWY+Xa6wxdwJuZvZJ29UJ6wLX
         Z6mnJYK8X9+QFtjNOZ863uywMj+kcZMwsbuHjiMnswuVxyRfV9V3lWEVqHlIsaIwX9ji
         ipctZPy6h/yrKSDZwhopvgtgKE+eXwp6GxxltwDCTonZr8U1Y4FriJaumCFXHGuXT9/x
         q+zx5uqH/9O2sMcz0fHOHs4f/p+Fp2Bhj+QLQ8s976fsCXcBD1oi9JXd3SY9xTSFiywD
         J8uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iZbcWGxqLYHa/tNYezklD9HgF1mwINvlpnUgrg42BSI=;
        b=BfQIE1G5OkYzUUCxPHmDAYGU1ogeGY7UnCclwblxFmznn0fb4xDPkIbAEHoX/jRXNa
         simH5bqJ6PBnhrLrNtCQ0ix0aL1Ur+KEZY4TtuupuzXa4RiVfY+FpbFV6c3MKffrRQ+F
         G87AsKEWSkBhBC35BaPsf8w6IZu06eh/hdqGtnzGDJGQl1ylDjsSQpnUapssFWAiklI5
         +YP6aOYwaVY++4Mpl6YoGQYr1nUZOJU2rp7noysubcMUXBV1MnUSB7LKJh/J1B8+KRMN
         IX/Dct4kRBp7wAPKRrtAOLIB0OIuOJCy0wU5SjAVEegbubpV4DM67gmIzpE9fL0fP5zh
         10Lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533z0/FmuA5HwbVWkNENCEtQcbVHL3XWKrIJaQNPS9hkv0l3Bouh
	JxFwO7chPG+CjukwpA7SblI=
X-Google-Smtp-Source: ABdhPJzxp9WPXF3Dyf99ly3Oev37bsyY68l3HYTGnldmd1xaPh7/f/Ty5o86bjuSyMvUawla/lndWw==
X-Received: by 2002:a25:48c7:: with SMTP id v190mr32578972yba.312.1628065400005;
        Wed, 04 Aug 2021 01:23:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c70c:: with SMTP id w12ls617457ybe.4.gmail; Wed, 04 Aug
 2021 01:23:18 -0700 (PDT)
X-Received: by 2002:a25:d312:: with SMTP id e18mr33358293ybf.14.1628065398736;
        Wed, 04 Aug 2021 01:23:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628065398; cv=none;
        d=google.com; s=arc-20160816;
        b=fFTDU/wKBVjGWXQk7aC8K1KZRKlAIiDdyrsNPUcgeALODRSf0BnzSV3ZRzPbbc7NRb
         n3MPt/kvSkn29H0u62fdOrzkfCspUqDex3kAvGXn6m3DywFGdhIM66tdOO7hwWbd519G
         0cloC+LmrzHvUOj3TInGbOc5WsLp8p1VtXgUS9VnBq7bsOe668pQujSOgFQZ/So5ltZ4
         yWDpYG0jrjv3nFx/SV6yAQyofcp4/TPgBN0sdg0wlyUr+4PmThFEDyARA39AIuq82KA8
         ljdAb3gfbBYLZv2uD9uXnVyMXLXo5yC2FQ/Vl+vfcssGsFEnJZXtrDe0TraCUfziW1WN
         3Scg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=cQSDe6PVlQtp8eRXxBttVzt/0Bq28j/RfN+ljxts1S0=;
        b=W6WGxNjQN9t5dHJK1Pr3sxX4mmnmXTxul1YVIKxWmkzWoDKt7cUUlwIF0AeXIVXEXr
         HKA0tCBtc84p1TlnGvVfvBs172QdOTlYHiLZLTOz1kEmC3T9o1gFybQ20xg8w4GLdRXa
         MMILGsuG1GBg+0l3hb8VbPEk6PhvYdlIVYUfCOWDMHEFCJsuamaYgRCrlSiQRvmZ/YAH
         d2JvDrALSDdu3XKzOUaAfgZTKjDMkNfP2jxbUDkDeOyTEUtPsD+Kc61d4RVF/K7DFy5V
         2IVPK8M+STHVhbdnMH6j9v+1qCX0BrH6k+B495vAQGZPCxXzBhfwrSWNhfI7oBlXjRHi
         gMuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id u17si96883ybc.5.2021.08.04.01.23.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 01:23:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: a968b4e8546544039583720400a08df0-20210804
X-UUID: a968b4e8546544039583720400a08df0-20210804
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1183806492; Wed, 04 Aug 2021 16:23:14 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 16:23:13 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 16:23:12 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.tang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v2 2/2] kasan, slub: reset tag when printing address
Date: Wed, 4 Aug 2021 16:22:30 +0800
Message-ID: <20210804082230.10837-3-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210804082230.10837-1-Kuan-Ying.Lee@mediatek.com>
References: <20210804082230.10837-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

The address still includes the tags when it is printed.
With hardware tag-based kasan enabled, we will get a
false positive KASAN issue when we access metadata.

Reset the tag before we access the metadata.

Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing metadata")
Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
---
 mm/slub.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index b6c5205252eb..f77d8cd79ef7 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -576,8 +576,8 @@ static void print_section(char *level, char *text, u8 *addr,
 			  unsigned int length)
 {
 	metadata_access_enable();
-	print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
-			16, 1, addr, length, 1);
+	print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
+			16, 1, kasan_reset_tag((void *)addr), length, 1);
 	metadata_access_disable();
 }
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210804082230.10837-3-Kuan-Ying.Lee%40mediatek.com.
