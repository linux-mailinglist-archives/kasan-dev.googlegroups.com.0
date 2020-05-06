Return-Path: <kasan-dev+bncBDGPTM5BQUDRB7ESZH2QKGQEPYT2H3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id C88F21C6765
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 07:22:05 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id q18sf335823uap.4
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 22:22:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588742524; cv=pass;
        d=google.com; s=arc-20160816;
        b=VbTFzJ7PfkT5pOj20k6Sdsd6ZvIa8ZDcH8nIoRJijJ3txXrvIz4fC7ttbQkVyd4wQI
         bJiVBNeN45mK7NzsF7Wg7GHS7lwTH2mHNkRX7I6uunei9orS4T0DJAUryDMGRY0UtVhU
         q2NJR8hzBB2Cmkbvl08InHnbwwqZmBHYQxiqq7yJAYQZQKhuinMVpUIT+498AAV35ynN
         azU3C/fgOSQMVVFOfiSrxJ3f0REbyLNalQ1W+iP30QlanpdS1X73U3Khdva0rRFiwdL+
         Io+gH8yc75nr4cSwYrTQl1zvwLP9LSqzh/F+VTPfK0/3eGGSORlSp6V+ov9wdJoaAWyd
         mrqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ySofzapHv5/G6wlbaDaksJG9OeyeQuRyo/pfvQMlR1A=;
        b=qCZD9MYvgn1U1mLEJBMu+PiZPdUU5gfP8hstn3fcYePWG7lIlJ6mjD148dI9n1pBmv
         xBzs0ZxYcfDfL735D5kZ54Z4DzYYDf0v0BaI+9JkmK/nXfC2UyA6E+xXvktbp/vdhcie
         Bc1v+/WMh5BcIyihE44w9CU2bRvaE/lYTBfGLw+ArY1KP0qa9RsFnw1jotEG2m5gBbES
         Y6YvyuPXazlftyPcWPypR+exAGaBTmuwd4PVFLgRR+9M6x4g76BRikRLZn2H3G6wWOvL
         F1AkYvjh/kZg+G7n+x8udj1pGm0qtO9QrtDuCSV03YNDxDv+kHGTUMyavX/5U8ZLfcJM
         8RGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=s4FoA3LL;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ySofzapHv5/G6wlbaDaksJG9OeyeQuRyo/pfvQMlR1A=;
        b=MwF3bNcTljGW3N7R+AIo7YYNKED8KXl7K7GLk5q1ZfcWFeEsY0P6/6BA0uTJbbTPTY
         gf371MFst9JOHflQeurj4vJt6D4FCrSvG5LZNP0QdrhAgI/5r3ED7owV15oIhWAy/yBx
         eOiYdiQFM6UPTNJBig5WTzAZhJ9NpgO6oa62/CYY+zbZTDYrgtKVS/13adGoz5qw9qRI
         qcfZk62y0Sy5AgTb1//7BreDPjnqdlulSj85BP3aN5/bOqea37qG+pr6ZvizLWpn5EhO
         NLu63jDtmTNyVOG5jLDMa0UTDbAeV3jW0kbKA3x0Z2GlcBSppQGje9WavmgaV39t1jof
         Nxdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ySofzapHv5/G6wlbaDaksJG9OeyeQuRyo/pfvQMlR1A=;
        b=NcMB8jqkSujCfSctoD/q02ZdXeKRdoBwb5BuwN+oET7PLCNdU2aE6tcsHU1SO8b03v
         s5Bco8ywcoOlijhduQauMuxMRQrm43nAXbXcbWYXdMOEbiloASOFyS2UpvWhhGSUNsTJ
         J5O4WeiFH0E0vl0J226oZzanMwzEYZECGNSMlhNy44/nbXCfVIFELOoyKiF55zMW0LvF
         rwiVNoQqIrwhKBcaUAK0rhGk8+wNxRHnrl+NimW1WM3hwNrcoykRxyLUfx3BZCptXxB0
         DeDAIQE+wukODQiBOGRPjvMW5PqEwmg06tqHwJQBH7hduPSDonsoFrqN+HaUi+p84dVX
         FpCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubjlKHfpqy0iHpaaUsGexUsDNWCeWHeXIUB+frXT2MWE0m3Ak81
	J+qrG654dRmPqQbScktPoWY=
X-Google-Smtp-Source: APiQypLJKxedgnRLRLntMec4Rbdg1mJ6zbCVDHCz1g6wrsP/KcPixUoeZUrqBZtv41KH8pFmJiRicw==
X-Received: by 2002:ab0:7481:: with SMTP id n1mr4606175uap.89.1588742524650;
        Tue, 05 May 2020 22:22:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7f86:: with SMTP id a128ls125629vsd.8.gmail; Tue, 05 May
 2020 22:22:04 -0700 (PDT)
X-Received: by 2002:a67:12c4:: with SMTP id 187mr5854453vss.100.1588742524259;
        Tue, 05 May 2020 22:22:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588742524; cv=none;
        d=google.com; s=arc-20160816;
        b=eCnkwvu/fVNkVEF1AM2ufDv3DjSV4DL/aCUDIcRtMSgBat/495BCBnmOQRfreBm7f7
         xB7mVGBppmTyED+SmDLBHaRFuDJaoV3FrsgO4hJqgJxkp3Y4xsN2cRYydUrPkBfEjIrw
         vKtLSSteibvDHbSNCWlcXgz5ZnhzM4NefIWfriiWhOfIRkPBvV2eJCWeogmzIYMswQ19
         /EV+GYxroBXL8C4otmiQZasOn1DgcsuW5siLa54L+QHzcx1E4NTwHqFmdM7VEUn0khiI
         jp/Z3SbY0aKMMg0snsjfug9oIz8R1emvVHkoFEj5fmjQSkGr9VlgcMGzAxIP1cm/mAQB
         XsyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lTgBW2WWuXjTeKkJYnAtJb3HmcIPptLcokJVsELZxTw=;
        b=GVx+Vftp3jDsPkz1kjSkFZRMdFtNYB1cJ/kRP3Cm0jyRrX5eLc09OWkhA1fI8d31/O
         xFeBTDeAXo37S9MwZAgoAGWCYkCWyHWqEdJeHgin/1mV9xk5Fr0yF34/EURMzZ6Gwx1H
         IxYfG0LIT+mHV3/KwDEP8bogyD95/2x1i1MRHIjmfO+9WOgeERhO7aqP0e66zDHovx/X
         VLa6L+uRwyYTtlFE1a9kjm+eZy8XoLEIRZSUiwIl4nqpOoPZZlDLfMwuLBWH1KFEkpZE
         AN580zWWNUk1bUzTkSIbaQFMwVTshtVElD7WDJoylXIlV+h5NMuVwpbCu1UXhYLFIMDL
         BLIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=s4FoA3LL;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s64si78712vkg.1.2020.05.05.22.22.03
        for <kasan-dev@googlegroups.com>;
        Tue, 05 May 2020 22:22:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 5805d09711654a5ab534d95afbd9c7ac-20200506
X-UUID: 5805d09711654a5ab534d95afbd9c7ac-20200506
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 393041407; Wed, 06 May 2020 13:21:57 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 13:21:55 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 13:21:55 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 2/3] kasan: record and print the free track
Date: Wed, 6 May 2020 13:21:55 +0800
Message-ID: <20200506052155.14515-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=s4FoA3LL;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

We add new KASAN_RCU_STACK_RECORD configuration option. It will move
free track from slub meta-data (struct kasan_alloc_meta) into freed object.
Because we hope this options doesn't enlarge slub meta-data size.

This option doesn't enlarge struct kasan_alloc_meta size.
- add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
- remove free track from kasan_alloc_meta, size is 8 bytes.

This option is only suitable for generic KASAN, because we move free track
into the freed object, so free track is valid information only when it
exists in quarantine. If the object is in-use state, then the KASAN report
doesn't print call_rcu() free track information.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
---
 mm/kasan/common.c | 10 +++++++++-
 mm/kasan/report.c | 24 +++++++++++++++++++++---
 2 files changed, 30 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 32d422bdf127..13ec03e225a7 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -321,8 +321,15 @@ void kasan_record_callrcu(void *addr)
 		/* record last call_rcu() call stack */
 		alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
 }
-#endif
 
+static void kasan_set_free_info(struct kmem_cache *cache,
+		void *object, u8 tag)
+{
+	/* store free track into freed object */
+	set_track((struct kasan_track *)(object + BYTES_PER_WORD), GFP_NOWAIT);
+}
+
+#else
 static void kasan_set_free_info(struct kmem_cache *cache,
 		void *object, u8 tag)
 {
@@ -339,6 +346,7 @@ static void kasan_set_free_info(struct kmem_cache *cache,
 
 	set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
 }
+#endif
 
 void kasan_poison_slab(struct page *page)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7aaccc70b65b..f2b0c6b9dffa 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -175,8 +175,23 @@ static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
 	print_track(&free_track, "Last call_rcu() call stack", true);
 	pr_err("\n");
 }
-#endif
 
+static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+		void *object, u8 tag, const void *addr)
+{
+	u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
+
+	/*
+	 * Only the freed object can get free track,
+	 * because free track information is stored to freed object.
+	 */
+	if (*shadow_addr == KASAN_KMALLOC_FREE)
+		return (struct kasan_track *)(object + BYTES_PER_WORD);
+	else
+		return NULL;
+}
+
+#else
 static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 		void *object, u8 tag, const void *addr)
 {
@@ -196,6 +211,7 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 	return &alloc_meta->free_track[i];
 }
+#endif
 
 static void describe_object(struct kmem_cache *cache, void *object,
 				const void *addr, u8 tag)
@@ -208,8 +224,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		print_track(&alloc_info->alloc_track, "Allocated", false);
 		pr_err("\n");
 		free_track = kasan_get_free_track(cache, object, tag, addr);
-		print_track(free_track, "Freed", false);
-		pr_err("\n");
+		if (free_track) {
+			print_track(free_track, "Freed", false);
+			pr_err("\n");
+		}
 #ifdef CONFIG_KASAN_RCU_STACK_RECORD
 		kasan_print_rcu_free_stack(alloc_info);
 #endif
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506052155.14515-1-walter-zh.wu%40mediatek.com.
