Return-Path: <kasan-dev+bncBC7OD3FKWUERBRMV36UQMGQEHPYQEMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 350137D521A
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:46:48 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1cbe08af374sf10774665ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:46:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155206; cv=pass;
        d=google.com; s=arc-20160816;
        b=g9zhvsxMiFfdoqyh2WxI6QLK5v41U2SLXCRflp+an1ZNdHhVUg51e2a5lYmSxYJazF
         iABhD+jsjnCx/p66zDtgyoM/h9AqpLcKog09GjjA+XLRfxtu18d0Zpi+97viMe88c+nY
         SOce7BzVao2Igy33H2vTHJ1Ga0EK3u4pTf755OFKLN5NkbQOsUUbAgwjGbMYnPKvPvDn
         wGCD1hclefmo1uCWUQdF+OGc7GXuaLHT9IntvWo9fXedH4kZbJ12W67CcpcisqOV3tBi
         /b3qqtFWVtXqxJZNDzKcVbohPAjCL8hk72nyYaIQdpNisAymG2i405BpraDFGKFP84lb
         or7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=SrHkFcTrbJzhse7hQD7yDveIZMm/vIKnxn6j09jxlB0=;
        fh=o2gN/qWYmd2qcYE32XNooYCUChQRu1yXXuZln/kM9I0=;
        b=hFMMXjIBw+foYItufOkNbR1JTkBmu0HGIHnqNDh5OtiBk8Who6P9vIYAoP8eWc7FJK
         fL0INa2XruAedMYWtzvMk+5MyPMrUMR2dJI+/n+USvHOIYvNzBoO4Jwpg8hTNiG/wAMW
         AAmKsl3/mQDOzq6ZpWIXJFJhpJU3ZmegvsNikc+Vd15RhZQSUsCWUycWxy07c5SxCEBW
         dlu6uOfud9r5k4LVtLE7WLlv9okyI2dIJXXZjNJSAivOEC2EG6HYXZhWow1NiNmqhdTr
         IdOftn91ADD8wyD7F6YWZ+83tcmezPt6HwaaC+v3Rt41JnT007ncb3VS4WZzV1RH3rkD
         AtDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FuOiVWS5;
       spf=pass (google.com: domain of 3w8o3zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3w8o3ZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155206; x=1698760006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SrHkFcTrbJzhse7hQD7yDveIZMm/vIKnxn6j09jxlB0=;
        b=S278YzSEeiYK3zLTCvo+OWT04FpL2aZyBMULGqSFmA0C8b9Mjil/Typv9ob2w6+JpJ
         U7kRuBgfvZoEwZYZ2LvmnGwfOaCOeA5mevyIrXhVa1kY0SPLQ/N+4hFxv+JU3GksBufb
         JzoepS4YeXvcBYWzSOds1jk2VczgmQB4N8p/ICaPvk5a6KH8g2/rpnqjTuKceb5xDoH1
         KcQzvgdF/HXcr6szdmefiWXE5I7gkuMjtWLkxERoPt2v8GCJ79JI5LLF6x2VFiPfCJ3/
         DjQqr5sYpp3rJRTrm5+t2oADdsVkKbOfMDuSEs0LLEYFmmH9KAeiNJTqi4w+xZaaxNzu
         w3Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155206; x=1698760006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=SrHkFcTrbJzhse7hQD7yDveIZMm/vIKnxn6j09jxlB0=;
        b=ps6kLL6S2x/7/LnPJuAT24grHUPL0sb3y2Qc+21ibdrWk5Bx4J/QhgNjyA2ao7H/lW
         byYM11O9enJeewIyhUdQlvl7DeJm4+1o1jixP4grl2lr4gpfUQ2071zM2QM4SMTuepTh
         tHlCQ5QNBR/ck8UD0wKODZGHmWgMBzOKeM4aKYabgnDvJr4wcZQ5pRMdT6/vFEL1xP50
         BnlcAmzGExMcwTXwfBIinu3UO+ma2LXPBuesjXaxtWsppg3lMzgy8Og4XCBLv8ItnO6e
         WabL/qSe7icdERa/geYchx93w2nIR6K/xUKf+fsUrTCF47FJSUMnn5+fIaLQBbvCDUw2
         GGSA==
X-Gm-Message-State: AOJu0YyiqcY7WV7Je9cdQjadsqjXXm5oMVa4k/GHAtsrC+xdXeV9nyk5
	oeLzQfJNaQsuqS8EYZN2M9Q=
X-Google-Smtp-Source: AGHT+IF6ZOFiyx2l5xyNn6SIQbTHVWgB2gAegIG89AQ+tNvYCwpyr9H6wI054Z8SSR7zJCzdkOaZAA==
X-Received: by 2002:a17:902:ce8d:b0:1ca:c490:8539 with SMTP id f13-20020a170902ce8d00b001cac4908539mr12171521plg.18.1698155206127;
        Tue, 24 Oct 2023 06:46:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7402:b0:1c9:babc:efc with SMTP id
 g2-20020a170902740200b001c9babc0efcls1930914pll.0.-pod-prod-02-us; Tue, 24
 Oct 2023 06:46:45 -0700 (PDT)
X-Received: by 2002:a17:903:27cd:b0:1ca:bce4:fdd4 with SMTP id km13-20020a17090327cd00b001cabce4fdd4mr8568963plb.26.1698155204937;
        Tue, 24 Oct 2023 06:46:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155204; cv=none;
        d=google.com; s=arc-20160816;
        b=H3HFpHhKyfWsraq6HQDOqzChjFIiPyq11v3H2cQWg6n129rCSENwNkFZU/M1CjsdQc
         c7aT/W/8+6Vt7DneGtHIufFj5kU45EFEB/ksuYQJzNgF2AMWPl24mAqHD5Rm3x4F5Dm7
         MN66bEmfrldndYZcQad0qNhjk8ZtcLKbpVM9kXlAW7rNbZXNl5axD+fwWXU7/kOyw7Vg
         I1c/rXN/FOXT9t8lE5M7+rda3QOgmOvDaPWSfpTJAqSW0suDkaXuNReP4mJe26VcQ1mF
         GeUgwyKYIfXUqBVixaW0Xj/bP1VqRxfpuWFKwYnqvAn1gwgJNrF9c04mDXk7XUYNW2Rx
         9UTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=C4ig+ghmPhQV+NN9gQrUnAhQK6p3EzwOX4/nD/QGc34=;
        fh=o2gN/qWYmd2qcYE32XNooYCUChQRu1yXXuZln/kM9I0=;
        b=F1/e1hW8WqcC+iAEFYTSugRPJF6RcT7fbSc/g3C3QzHNww6j625s9qHtSx1NcGNV4d
         CGx2ZZIefBbLRR2IXfc91O6aa/u1fxyIclCspALAqAu9VJ8Mton3RHDwCJAOWENK1Mbh
         XGOQ0kP968DL0csESMjkSpalUjdMAPcXct7KBMgBDO9CH7CLMMyzi74vFGpNv122ZfUi
         uoUZCaHL8grtVzuS5mLLGjbGQDyrHHNS9xNcVPBAi7/ftJEB8JIZamsvVbGUQYUWEFyp
         oTJPxLRrUmmrRRiIx6WM74NiBTeRl24KyHKmoq97ggIVGtvWKwd135Qjwy4rt9RnWHsW
         WbPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FuOiVWS5;
       spf=pass (google.com: domain of 3w8o3zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3w8o3ZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id lh13-20020a170903290d00b001c9dae59993si549785plb.13.2023.10.24.06.46.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:46:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3w8o3zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-da033914f7cso1016658276.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:46:44 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:d7d8:0:b0:d9a:da03:97e8 with SMTP id
 o207-20020a25d7d8000000b00d9ada0397e8mr212597ybg.2.1698155203948; Tue, 24 Oct
 2023 06:46:43 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:45:58 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-2-surenb@google.com>
Subject: [PATCH v2 01/39] lib/string_helpers: Add flags param to string_get_size()
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	"=?UTF-8?q?Noralf=20Tr=C3=B8nnes?=" <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FuOiVWS5;       spf=pass
 (google.com: domain of 3w8o3zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3w8o3ZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

The new flags parameter allows controlling
 - Whether or not the units suffix is separated by a space, for
   compatibility with sort -h
 - Whether or not to append a B suffix - we're not always printing
   bytes.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Andy Shevchenko <andy@kernel.org>
Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>
Cc: Paul Mackerras <paulus@samba.org>
Cc: "Michael S. Tsirkin" <mst@redhat.com>
Cc: Jason Wang <jasowang@redhat.com>
Cc: "Noralf Tr=C3=B8nnes" <noralf@tronnes.org>
Cc: Jens Axboe <axboe@kernel.dk>
---
 arch/powerpc/mm/book3s64/radix_pgtable.c      |  2 +-
 drivers/block/virtio_blk.c                    |  4 ++--
 drivers/gpu/drm/gud/gud_drv.c                 |  2 +-
 drivers/mmc/core/block.c                      |  4 ++--
 drivers/mtd/spi-nor/debugfs.c                 |  6 ++---
 .../ethernet/chelsio/cxgb4/cxgb4_debugfs.c    |  4 ++--
 drivers/scsi/sd.c                             |  8 +++----
 include/linux/string_helpers.h                | 13 +++++-----
 lib/string_helpers.c                          | 24 +++++++++++++------
 lib/test-string_helpers.c                     |  4 ++--
 mm/hugetlb.c                                  |  8 +++----
 11 files changed, 44 insertions(+), 35 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/boo=
k3s64/radix_pgtable.c
index c6a4ac766b2b..27aa5a083ff0 100644
--- a/arch/powerpc/mm/book3s64/radix_pgtable.c
+++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
@@ -260,7 +260,7 @@ print_mapping(unsigned long start, unsigned long end, u=
nsigned long size, bool e
 	if (end <=3D start)
 		return;
=20
-	string_get_size(size, 1, STRING_UNITS_2, buf, sizeof(buf));
+	string_get_size(size, 1, STRING_SIZE_BASE2, buf, sizeof(buf));
=20
 	pr_info("Mapped 0x%016lx-0x%016lx with %s pages%s\n", start, end, buf,
 		exec ? " (exec)" : "");
diff --git a/drivers/block/virtio_blk.c b/drivers/block/virtio_blk.c
index 1fe011676d07..59140424d755 100644
--- a/drivers/block/virtio_blk.c
+++ b/drivers/block/virtio_blk.c
@@ -986,9 +986,9 @@ static void virtblk_update_capacity(struct virtio_blk *=
vblk, bool resize)
 	nblocks =3D DIV_ROUND_UP_ULL(capacity, queue_logical_block_size(q) >> 9);
=20
 	string_get_size(nblocks, queue_logical_block_size(q),
-			STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
+			STRING_SIZE_BASE2, cap_str_2, sizeof(cap_str_2));
 	string_get_size(nblocks, queue_logical_block_size(q),
-			STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));
+			0, cap_str_10, sizeof(cap_str_10));
=20
 	dev_notice(&vdev->dev,
 		   "[%s] %s%llu %d-byte logical blocks (%s/%s)\n",
diff --git a/drivers/gpu/drm/gud/gud_drv.c b/drivers/gpu/drm/gud/gud_drv.c
index 9d7bf8ee45f1..6b1748e1f666 100644
--- a/drivers/gpu/drm/gud/gud_drv.c
+++ b/drivers/gpu/drm/gud/gud_drv.c
@@ -329,7 +329,7 @@ static int gud_stats_debugfs(struct seq_file *m, void *=
data)
 	struct gud_device *gdrm =3D to_gud_device(entry->dev);
 	char buf[10];
=20
-	string_get_size(gdrm->bulk_len, 1, STRING_UNITS_2, buf, sizeof(buf));
+	string_get_size(gdrm->bulk_len, 1, STRING_SIZE_BASE2, buf, sizeof(buf));
 	seq_printf(m, "Max buffer size: %s\n", buf);
 	seq_printf(m, "Number of errors:  %u\n", gdrm->stats_num_errors);
=20
diff --git a/drivers/mmc/core/block.c b/drivers/mmc/core/block.c
index 3a8f27c3e310..411dc8137f7c 100644
--- a/drivers/mmc/core/block.c
+++ b/drivers/mmc/core/block.c
@@ -2511,7 +2511,7 @@ static struct mmc_blk_data *mmc_blk_alloc_req(struct =
mmc_card *card,
=20
 	blk_queue_write_cache(md->queue.queue, cache_enabled, fua_enabled);
=20
-	string_get_size((u64)size, 512, STRING_UNITS_2,
+	string_get_size((u64)size, 512, STRING_SIZE_BASE2,
 			cap_str, sizeof(cap_str));
 	pr_info("%s: %s %s %s%s\n",
 		md->disk->disk_name, mmc_card_id(card), mmc_card_name(card),
@@ -2707,7 +2707,7 @@ static int mmc_blk_alloc_rpmb_part(struct mmc_card *c=
ard,
=20
 	list_add(&rpmb->node, &md->rpmbs);
=20
-	string_get_size((u64)size, 512, STRING_UNITS_2,
+	string_get_size((u64)size, 512, STRING_SIZE_BASE2,
 			cap_str, sizeof(cap_str));
=20
 	pr_info("%s: %s %s %s, chardev (%d:%d)\n",
diff --git a/drivers/mtd/spi-nor/debugfs.c b/drivers/mtd/spi-nor/debugfs.c
index 6e163cb5b478..a1b61938fee2 100644
--- a/drivers/mtd/spi-nor/debugfs.c
+++ b/drivers/mtd/spi-nor/debugfs.c
@@ -85,7 +85,7 @@ static int spi_nor_params_show(struct seq_file *s, void *=
data)
=20
 	seq_printf(s, "name\t\t%s\n", info->name);
 	seq_printf(s, "id\t\t%*ph\n", SPI_NOR_MAX_ID_LEN, nor->id);
-	string_get_size(params->size, 1, STRING_UNITS_2, buf, sizeof(buf));
+	string_get_size(params->size, 1, STRING_SIZE_BASE2, buf, sizeof(buf));
 	seq_printf(s, "size\t\t%s\n", buf);
 	seq_printf(s, "write size\t%u\n", params->writesize);
 	seq_printf(s, "page size\t%u\n", params->page_size);
@@ -130,14 +130,14 @@ static int spi_nor_params_show(struct seq_file *s, vo=
id *data)
 		struct spi_nor_erase_type *et =3D &erase_map->erase_type[i];
=20
 		if (et->size) {
-			string_get_size(et->size, 1, STRING_UNITS_2, buf,
+			string_get_size(et->size, 1, STRING_SIZE_BASE2, buf,
 					sizeof(buf));
 			seq_printf(s, " %02x (%s) [%d]\n", et->opcode, buf, i);
 		}
 	}
=20
 	if (!(nor->flags & SNOR_F_NO_OP_CHIP_ERASE)) {
-		string_get_size(params->size, 1, STRING_UNITS_2, buf, sizeof(buf));
+		string_get_size(params->size, 1, STRING_SIZE_BASE2, buf, sizeof(buf));
 		seq_printf(s, " %02x (%s)\n", SPINOR_OP_CHIP_ERASE, buf);
 	}
=20
diff --git a/drivers/net/ethernet/chelsio/cxgb4/cxgb4_debugfs.c b/drivers/n=
et/ethernet/chelsio/cxgb4/cxgb4_debugfs.c
index 14e0d989c3ba..7d5fbebd36fc 100644
--- a/drivers/net/ethernet/chelsio/cxgb4/cxgb4_debugfs.c
+++ b/drivers/net/ethernet/chelsio/cxgb4/cxgb4_debugfs.c
@@ -3457,8 +3457,8 @@ static void mem_region_show(struct seq_file *seq, con=
st char *name,
 {
 	char buf[40];
=20
-	string_get_size((u64)to - from + 1, 1, STRING_UNITS_2, buf,
-			sizeof(buf));
+	string_get_size((u64)to - from + 1, 1, STRING_SIZE_BASE2,
+			buf, sizeof(buf));
 	seq_printf(seq, "%-15s %#x-%#x [%s]\n", name, from, to, buf);
 }
=20
diff --git a/drivers/scsi/sd.c b/drivers/scsi/sd.c
index 83b6a3f3863b..c37593f76b65 100644
--- a/drivers/scsi/sd.c
+++ b/drivers/scsi/sd.c
@@ -2689,10 +2689,10 @@ sd_print_capacity(struct scsi_disk *sdkp,
 	if (!sdkp->first_scan && old_capacity =3D=3D sdkp->capacity)
 		return;
=20
-	string_get_size(sdkp->capacity, sector_size,
-			STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
-	string_get_size(sdkp->capacity, sector_size,
-			STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));
+	string_get_size(sdkp->capacity, sector_size, STRING_SIZE_BASE2,
+			cap_str_2, sizeof(cap_str_2));
+	string_get_size(sdkp->capacity, sector_size, 0,
+			cap_str_10, sizeof(cap_str_10));
=20
 	sd_printk(KERN_NOTICE, sdkp,
 		  "%llu %d-byte logical blocks: (%s/%s)\n",
diff --git a/include/linux/string_helpers.h b/include/linux/string_helpers.=
h
index 9d1f5bb74dd5..a54467d891db 100644
--- a/include/linux/string_helpers.h
+++ b/include/linux/string_helpers.h
@@ -17,15 +17,14 @@ static inline bool string_is_terminated(const char *s, =
int len)
 	return memchr(s, '\0', len) ? true : false;
 }
=20
-/* Descriptions of the types of units to
- * print in */
-enum string_size_units {
-	STRING_UNITS_10,	/* use powers of 10^3 (standard SI) */
-	STRING_UNITS_2,		/* use binary powers of 2^10 */
+enum string_size_flags {
+	STRING_SIZE_BASE2	=3D (1 << 0),
+	STRING_SIZE_NOSPACE	=3D (1 << 1),
+	STRING_SIZE_NOBYTES	=3D (1 << 2),
 };
=20
-void string_get_size(u64 size, u64 blk_size, enum string_size_units units,
-		     char *buf, int len);
+int string_get_size(u64 size, u64 blk_size, enum string_size_flags flags,
+		    char *buf, int len);
=20
 int parse_int_array_user(const char __user *from, size_t count, int **arra=
y);
=20
diff --git a/lib/string_helpers.c b/lib/string_helpers.c
index 9982344cca34..b1496499b113 100644
--- a/lib/string_helpers.c
+++ b/lib/string_helpers.c
@@ -19,11 +19,17 @@
 #include <linux/string.h>
 #include <linux/string_helpers.h>
=20
+enum string_size_units {
+	STRING_UNITS_10,	/* use powers of 10^3 (standard SI) */
+	STRING_UNITS_2,		/* use binary powers of 2^10 */
+};
+
 /**
  * string_get_size - get the size in the specified units
  * @size:	The size to be converted in blocks
  * @blk_size:	Size of the block (use 1 for size in bytes)
- * @units:	units to use (powers of 1000 or 1024)
+ * @flags:	units to use (powers of 1000 or 1024), whether to include space
+ *		separator
  * @buf:	buffer to format to
  * @len:	length of buffer
  *
@@ -32,14 +38,16 @@
  * at least 9 bytes and will always be zero terminated.
  *
  */
-void string_get_size(u64 size, u64 blk_size, const enum string_size_units =
units,
-		     char *buf, int len)
+int string_get_size(u64 size, u64 blk_size, enum string_size_flags flags,
+		    char *buf, int len)
 {
+	enum string_size_units units =3D flags & flags & STRING_SIZE_BASE2
+		? STRING_UNITS_2 : STRING_UNITS_10;
 	static const char *const units_10[] =3D {
-		"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"
+		"", "k", "M", "G", "T", "P", "E", "Z", "Y"
 	};
 	static const char *const units_2[] =3D {
-		"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"
+		"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"
 	};
 	static const char *const *const units_str[] =3D {
 		[STRING_UNITS_10] =3D units_10,
@@ -126,8 +134,10 @@ void string_get_size(u64 size, u64 blk_size, const enu=
m string_size_units units,
 	else
 		unit =3D units_str[units][i];
=20
-	snprintf(buf, len, "%u%s %s", (u32)size,
-		 tmp, unit);
+	return snprintf(buf, len, "%u%s%s%s%s", (u32)size, tmp,
+			(flags & STRING_SIZE_NOSPACE)		? "" : " ",
+			unit,
+			(flags & STRING_SIZE_NOBYTES)		? "" : "B");
 }
 EXPORT_SYMBOL(string_get_size);
=20
diff --git a/lib/test-string_helpers.c b/lib/test-string_helpers.c
index 9a68849a5d55..0b01ffca96fb 100644
--- a/lib/test-string_helpers.c
+++ b/lib/test-string_helpers.c
@@ -507,8 +507,8 @@ static __init void __test_string_get_size(const u64 siz=
e, const u64 blk_size,
 	char buf10[string_get_size_maxbuf];
 	char buf2[string_get_size_maxbuf];
=20
-	string_get_size(size, blk_size, STRING_UNITS_10, buf10, sizeof(buf10));
-	string_get_size(size, blk_size, STRING_UNITS_2, buf2, sizeof(buf2));
+	string_get_size(size, blk_size, 0, buf10, sizeof(buf10));
+	string_get_size(size, blk_size, STRING_SIZE_BASE2, buf2, sizeof(buf2));
=20
 	test_string_get_size_check("STRING_UNITS_10", exp_result10, buf10,
 				   size, blk_size);
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 52d26072dfda..37f2148d3b9c 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -3228,7 +3228,7 @@ static void __init hugetlb_hstate_alloc_pages_onenode=
(struct hstate *h, int nid)
 	if (i =3D=3D h->max_huge_pages_node[nid])
 		return;
=20
-	string_get_size(huge_page_size(h), 1, STRING_UNITS_2, buf, 32);
+	string_get_size(huge_page_size(h), 1, STRING_SIZE_BASE2, buf, 32);
 	pr_warn("HugeTLB: allocating %u of page size %s failed node%d.  Only allo=
cated %lu hugepages.\n",
 		h->max_huge_pages_node[nid], buf, nid, i);
 	h->max_huge_pages -=3D (h->max_huge_pages_node[nid] - i);
@@ -3290,7 +3290,7 @@ static void __init hugetlb_hstate_alloc_pages(struct =
hstate *h)
 	if (i < h->max_huge_pages) {
 		char buf[32];
=20
-		string_get_size(huge_page_size(h), 1, STRING_UNITS_2, buf, 32);
+		string_get_size(huge_page_size(h), 1, STRING_SIZE_BASE2, buf, 32);
 		pr_warn("HugeTLB: allocating %lu of page size %s failed.  Only allocated=
 %lu hugepages.\n",
 			h->max_huge_pages, buf, i);
 		h->max_huge_pages =3D i;
@@ -3336,7 +3336,7 @@ static void __init report_hugepages(void)
 	for_each_hstate(h) {
 		char buf[32];
=20
-		string_get_size(huge_page_size(h), 1, STRING_UNITS_2, buf, 32);
+		string_get_size(huge_page_size(h), 1, STRING_SIZE_BASE2, buf, 32);
 		pr_info("HugeTLB: registered %s page size, pre-allocated %ld pages\n",
 			buf, h->free_huge_pages);
 		pr_info("HugeTLB: %d KiB vmemmap can be freed for a %s page\n",
@@ -4227,7 +4227,7 @@ static int __init hugetlb_init(void)
 				char buf[32];
=20
 				string_get_size(huge_page_size(&default_hstate),
-					1, STRING_UNITS_2, buf, 32);
+					1, STRING_SIZE_BASE2, buf, 32);
 				pr_warn("HugeTLB: Ignoring hugepages=3D%lu associated with %s page siz=
e\n",
 					default_hstate.max_huge_pages, buf);
 				pr_warn("HugeTLB: Using hugepages=3D%lu for number of default huge pag=
es\n",
--=20
2.42.0.758.gaed0368e0e-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231024134637.3120277-2-surenb%40google.com.
