Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBDW4QH3QKGQER7VURFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C0C31F4CD2
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 07:22:24 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id w20sf503771oth.20
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 22:22:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591766543; cv=pass;
        d=google.com; s=arc-20160816;
        b=AvvVf5zm4FNCDipmynRm5kjFpGyYXlGMNSApFajV0jkjTHeK3uPaBlEEQ6HRGUuGPf
         VximyThAxpxJTFtOXhN36IxqABLtjbgjGc2D/+yC6bV8X8Et3k1anBjmJw7DMb6v7iki
         pKH2nZ+Smp/7MYSGLcmb/RxvKRMbomyDrdAytJVL9uZrAjpv3B7/JzNTdFFW7Ozc6x85
         BRIYSOrMqDccsKqN0S93OscJw0mJna9f8NhjLPi62d2jVz77YldoZr88luPuYIVPCw7R
         N9EJ3VOv0OFTdIEpaC3keWBC/fDRjZfEBtwSAcanzaR+Hrq2x7V+9KJvGcOpKr4IUIsD
         +8WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=HmHpKEua8bkGUu2WAeFOVqF4xXVPtvSAz4Iyi+1dysA=;
        b=L7JP81WBMsrl9RqpUVtLCDULkhbz4XxdquDK0jvksXFpsnKZnExo7S5AjPjmYsMdbF
         pnff0BkkznDfosSG9/YA9yWImwHcFcQlChaT1Ckpa6unLSiT33RxMSLD7ffz0w5pHbqj
         IEA4LBEcU9BZxvszQ9xE6teWs0Bko/UC9OFX0sEmG+xcwNLmD9EEYFzDO2+0ViXLeJS3
         Mmy5YtwiKSoe5JYJ0cL8jshYlSxtC1ve5hbAN+/u7vz9zj+dii5JYU/6nQtvgugznxB7
         FG57/7mh0xX4r4eiaw7skX1LuGAbpoM0zqyobqCzTw/SoYvkkGz0r5Xelft5QYFA2e5p
         ak7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=OCU+XXFz;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HmHpKEua8bkGUu2WAeFOVqF4xXVPtvSAz4Iyi+1dysA=;
        b=rTZMx6vPv3y8lme0dtaXrKR1cc05prp8qEAR7Uu2EAoVpLEZ4jmzbSnf8gzbN3XfK/
         OI+iOf4Jupac1t0m3+AHlx6C1ZD1xk53Brwz2qVUXvUixdJ//STF2U/OpIv/E8Q6hpmd
         0ya5f26ysuHHO/2YD/a6xemHhni6k9oGf31lnCutCh3sm3RQL+S/Pv+np6mYblnVssjU
         sH8iKp1YXZmmNRjt8yGFLtMZCQNTL8bTuAF2KAHRVthTCn2OyUbtW51LT0AC0ja601VA
         T7BKQKpKy9ewHxeI6VF7BX9jw+XCRz376wcT+471kEsK9lrtiLo8LqVBtfeK+ovpZCww
         wWlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HmHpKEua8bkGUu2WAeFOVqF4xXVPtvSAz4Iyi+1dysA=;
        b=kCnqXQkUzHeKpYovZmfGJKS/q3vEc2iSUhYydSoC6IPPFHce9gAjQeGO79UkDx7BvD
         MpWBX2yjENMsfveaKCnqEKZF+hrF0UtapVHlE0/IKKthr5YsLnyEsQlcVkglmcD1BfoP
         e7ddgWIT5I83o2q60FkZBkXWjyDftE/gtSACCqrqN99icTWg0SRmEU+moUwFu2dYXsHS
         NWDkNUx3boOFW3n4cbgvpT+9nR0iIfGi2tj1yrXTp5LdJBB8+8s11HMZn485S36WR4s1
         GB2s2y4Qu9Rn3O4HU53+S4hn04bcqb91jVljTU1zJYRc6WNEX1RH8xV9ggjwb+YLGc+r
         aong==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vD9r7rHUfF0lzxMrVsN9tzSKIdrjYYzIkLij39pCFXScszbp1
	f/QNnP22TgmaLTCTu3LV4+I=
X-Google-Smtp-Source: ABdhPJzX92+k5JEdIBoJdHuzfuxMwp9PSxyl3aoRYx1DynIk/AGUw636eWxu6nuYAoajcnCMGfcv+A==
X-Received: by 2002:a05:6808:559:: with SMTP id i25mr1244905oig.164.1591766542686;
        Tue, 09 Jun 2020 22:22:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1db7:: with SMTP id z23ls3579176oti.9.gmail; Tue,
 09 Jun 2020 22:22:22 -0700 (PDT)
X-Received: by 2002:a9d:664e:: with SMTP id q14mr1388298otm.49.1591766542115;
        Tue, 09 Jun 2020 22:22:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591766542; cv=none;
        d=google.com; s=arc-20160816;
        b=eLFLU1VgQPMJeK8jMy3O4d/AP2GtQ+Y2IpIOktoPwlETDL0Zx6B1ze3NcFJxeLIiJ/
         rSSULZNDY5rsV0761CGf5UjyT/gTxM3y86bSd0HS14Vu1x6tV05ig6OYIhNJ4bwerhNp
         FqXuxgfTEk2PauZchwOeHJ0PX0fHzNjMUa04eeIs3W1+vIg9ejwoQVFZD1S/D/s/i/Rn
         uJbHXBTdZ1e4gdqgpQWbLaXxOKxUKKYIA9bYemulOAY6a5pnGqSVwqtrgGRvBw0um+Jk
         jDvBgXoU6hPLE12qT29R9OIE1ZLiA/Xu0r3ZD9NcD0ogvakSHSGK+iFpZbNWoFIymfEl
         RSEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8QdWS47TQ1Szf9UCQ4isLDh5BjiBexfLw+qwLr2MzEw=;
        b=pu+0aqjvXIj6jHJo+qSqbhx+Dh8rSEk1ImLTTz1fmTGau8edF+fLC1sbGK/WS9PD4J
         MD1Lx5qKRAEmU5dbi7+4iY/DhfJm7GEt2FCue16THjHl6mKaUYBgOyGbNfSUYHSjv13m
         wSmUTC1uDpi4V/Nqgnn6WEGFhKhZQJNfE4XpVCvbQy0lbi5YcRzADq9u00rKh+Sb1ba6
         GJTAVsGiYIwyk+uP2EpNI69s8LJFJunvm6keIpmoypNnaK0Cuzm6luUu4i6sNOi51YwC
         eEEqnYCzQemsumLPOQVsl7JM+HTTZgczJhuOwRtQ+iciZy7hczWGUmCELrqptDxCDkUU
         1drA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=OCU+XXFz;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id c22si133416oto.3.2020.06.09.22.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 22:22:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id w90so824486qtd.8
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 22:22:21 -0700 (PDT)
X-Received: by 2002:ac8:1892:: with SMTP id s18mr1471482qtj.306.1591766541396;
        Tue, 09 Jun 2020 22:22:21 -0700 (PDT)
Received: from ovpn-113-201.phx2.redhat.com (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id d23sm11831827qtn.38.2020.06.09.22.22.19
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jun 2020 22:22:20 -0700 (PDT)
From: Qian Cai <cai@lca.pw>
To: akpm@linux-foundation.org
Cc: borntraeger@de.ibm.com,
	glider@google.com,
	keescook@chromium.org,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-s390@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: [PATCH] mm/page_alloc: silence a KASAN false positive
Date: Wed, 10 Jun 2020 01:21:54 -0400
Message-Id: <20200610052154.5180-1-cai@lca.pw>
X-Mailer: git-send-email 2.21.0 (Apple Git-122.2)
MIME-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=OCU+XXFz;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

kernel_init_free_pages() will use memset() on s390 to clear all pages
from kmalloc_order() which will override KASAN redzones because a
redzone was setup from the end of the allocation size to the end of the
last page. Silence it by not reporting it there. An example of the
report is,

 BUG: KASAN: slab-out-of-bounds in __free_pages_ok
 Write of size 4096 at addr 000000014beaa000
 Call Trace:
 show_stack+0x152/0x210
 dump_stack+0x1f8/0x248
 print_address_description.isra.13+0x5e/0x4d0
 kasan_report+0x130/0x178
 check_memory_region+0x190/0x218
 memset+0x34/0x60
 __free_pages_ok+0x894/0x12f0
 kfree+0x4f2/0x5e0
 unpack_to_rootfs+0x60e/0x650
 populate_rootfs+0x56/0x358
 do_one_initcall+0x1f4/0xa20
 kernel_init_freeable+0x758/0x7e8
 kernel_init+0x1c/0x170
 ret_from_fork+0x24/0x28
 Memory state around the buggy address:
 000000014bea9f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 000000014bea9f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>000000014beaa000: 03 fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
                    ^
 000000014beaa080: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
 000000014beaa100: fe fe fe fe fe fe fe fe fe fe fe fe fe fe

Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
Signed-off-by: Qian Cai <cai@lca.pw>
---
 mm/page_alloc.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 727751219003..9954973f89a3 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1164,8 +1164,11 @@ static void kernel_init_free_pages(struct page *page, int numpages)
 {
 	int i;
 
+	/* s390's use of memset() could override KASAN redzones. */
+	kasan_disable_current();
 	for (i = 0; i < numpages; i++)
 		clear_highpage(page + i);
+	kasan_enable_current();
 }
 
 static __always_inline bool free_pages_prepare(struct page *page,
-- 
2.21.0 (Apple Git-122.2)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200610052154.5180-1-cai%40lca.pw.
