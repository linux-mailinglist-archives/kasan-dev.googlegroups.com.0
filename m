Return-Path: <kasan-dev+bncBC7OD3FKWUERBGFAVKXAMGQEFM6B35Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 65639851FBF
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:37 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-363bc80467bsf21117355ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773976; cv=pass;
        d=google.com; s=arc-20160816;
        b=0qi762D+1IPos1QB+/bm7PdDmbVSuI8f2ljXcJ8Xo9ql0gHit7PjvQ7R7X6YvVqz2r
         oBq9FZAht2FVOHfUsrxY5v1hMKhfcKJt6UB+H6Hf9Jcxo/UXg101/0zrFX87fVHmERJd
         HxcxiReWVyIG6HFSiZPqglx1O/dfQmClrCfvP7XWiOr7BOxJLdEDmlJ4zjB38V0y2yOE
         b8Fai3ZFWfGgEgv2xoYmCH/wqw9hV7KMyRog/yqS1FtHMmaaZsjAFni8j/0PG8OwrHYR
         h7YRROrZuVLwi7vkgHIeJyLFjyi6B4hxAPNjfk6PUgf1bP1ZpKoqVQxe/K8h8y2jorGg
         Hu1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=EY5ZRT0oF8XO+69GfWggalgHlYm76M/z9Y8WR70e5YQ=;
        fh=ZuuJxFZMyqUkxJfarLdbqEjWUyuOMl/X0egt/hLJV0k=;
        b=Dpl97n/s3MFPg0/Z1q7wRv+9hWtnEFVpUlH0s7qrS4RKg3RVaOddybfWgqLwxCKPKb
         zp4y5q6HATEVFtFJZJjgiY5kk86j/QBc1gr1jRiCS7q1AwnSVEo5i71fy7s7p/i4jXEe
         2HaylY43D3iuDVuBcXbFtra5UZS11zS6th5C0RFFRJFZW8+GfC/r8Og4YDrV4jxuGFys
         9WmHstavvfex+WYzkMjRRTJUWfsBm/XKYhKnSZoZLrUG7sIB5JKKvi8G7IHr7SgHEq+r
         wMaW3BFSb1JF639bJfJEp7X/CjvH6yAgAVtX3eq9zGzPrp9HyNdDZS8vBFTrdgZCXcmG
         +nJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rMyrBWR;
       spf=pass (google.com: domain of 3fpdkzqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FpDKZQYKCZUHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773976; x=1708378776; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EY5ZRT0oF8XO+69GfWggalgHlYm76M/z9Y8WR70e5YQ=;
        b=AHLtT7OU1nU06VBqu0Rbc5dn4G1bev263P+TqrqAeXk/7nL+suYZe1XvThr1HCKSQY
         1oWAiE31GfX3SpntHNep1rIJ2Q2Rp+X91kRE7pzm8G5HzHa1CbjuBitGV3OLwOeBAGuu
         gEsjdgl3ykCicITUJq9JLmK6F3wgWFjLUi5dXbxCzYuuZdbm6niIgzPDWjoqxuQFJEiI
         S4ex1Fx26MNpuQmNcVE8tRYKuV2x3eqbpkg5LTckjob6Mm7DKLzJqMvqzKpIgXtop5rv
         abxN2/GdrQe9/JinpEKmREV+Q67oei2rgIBm/a4sKf1lgC/x6zCgNRd1mzjhtAz+XP3r
         dAFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773976; x=1708378776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=EY5ZRT0oF8XO+69GfWggalgHlYm76M/z9Y8WR70e5YQ=;
        b=Vb/iBP+TBnrYQn3hMaL6Dlwnoe4npxnQuJWDkveq6QiqptFW31iRWkE/3U5Hle9nGw
         2uVYh3KMswzfheXRw2tfrg28A2/08udcykyPB0QNLqAFKCaCt80dbkFBlcCJU6Ou20c7
         0waCSq62ALBrovGnAvMaXjkE/Nx9YASFJRhpkZmcRC9HL6YUCd5RzGiUwDkeUfUdL8G9
         DfGfWr+tMYzZ9aZw5ZKS7Uh8eAOqTp1ToiZw0tDoOi/fLOsy90Tpby5lDoLUnjNWxSn+
         N0S1gFC5cYJKJtXOVGjaiG3PuksuiQh6KXvx+U7oPSkBJi8GmeIZe84laHagvD3BJ0ZR
         5SNA==
X-Gm-Message-State: AOJu0YyyMo2dnb7gXCVfGxZAhbWKx0pKmfw0DeEC1kh67AsGN5uIARHY
	EJ5gO7KYwk5CL1GP6u19LbLCdw7s9X8+sZePGv5JYR1rRM6xOtlF
X-Google-Smtp-Source: AGHT+IHn0ds4keHYA1/bvyEl8/9r8JxawKMXqEvPZlnl4StOkJZC7ceaRp1w6L5khEp2+dmR3O7UGg==
X-Received: by 2002:a92:c5a4:0:b0:363:7e19:6b85 with SMTP id r4-20020a92c5a4000000b003637e196b85mr528227ilt.0.1707773976180;
        Mon, 12 Feb 2024 13:39:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3113:b0:363:846b:1132 with SMTP id
 bg19-20020a056e02311300b00363846b1132ls1217064ilb.0.-pod-prod-00-us; Mon, 12
 Feb 2024 13:39:35 -0800 (PST)
X-Received: by 2002:a05:6e02:2198:b0:363:86dd:b35 with SMTP id j24-20020a056e02219800b0036386dd0b35mr453401ila.10.1707773975404;
        Mon, 12 Feb 2024 13:39:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773975; cv=none;
        d=google.com; s=arc-20160816;
        b=pT8fO8TVoStfSEkevRUAWpcBIktO9oL4AOM4eTZdM07Ar78FZ7r+tgRmpkDVeuCCiV
         Cnk8LzHoqB0ARhab9FNnY42gA64ciRF9HIn8V/jCDjxzXqtmLlz06is6avP7ZuW+XHpL
         jlFr60S4uba4qEm0NSk4PKiKB3V7Mr80V4PpcD8QUZmJC9ANVui5s6VnR1wAA/ApColS
         F1OoRNSzJJcHuDmQtplwM5pKDzCCEGtDsNw2Kz7ToAOqWvzQrV9wO93dcsR6oTbs1X+/
         zQoWQ6PLJh0ngcfrK8snqCt1G/dZH5r3PZCWJmHGgzqYJlXZNwW+7ehU1VXhNk6Ve0QJ
         ElyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=UEMHu7rdWBA2FK/B5eccMh9Pcx3Z9fwrCFD55ivM58g=;
        fh=ZuuJxFZMyqUkxJfarLdbqEjWUyuOMl/X0egt/hLJV0k=;
        b=IVYhge9kJzoH3j3v7Gw+b4p8C2i28ymhK3DcXYPQwknKp6lLpMvwG4J2B0FPjPJB5b
         8Zys0AqAZU1M6aE7XoQ31emwR5rl7pIuJsFHZ+bdlf30+gY2whG3ckHk1FI1TwfTkepN
         KsvFoY76MWN1XR3ois4U+mqF+imn4ovw2QnogMgszwJJnpvliamrpJMlUvVAMLdSWm88
         ZR0WHoy/ZUMfq7gayAU6HHq4YGwNZChDuXdfC9p0zo4xecF7BqfEl7FA2WLB+sKHbhzf
         bFgHUWLRihzElkzf13mY14LmhnxSiqoACFKtD8gGOpXlPyl3pRR3P9034oMJpWZQ3WBY
         yPiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rMyrBWR;
       spf=pass (google.com: domain of 3fpdkzqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FpDKZQYKCZUHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVsh6amFlSF+DQXJ6bDXCv+VfHhIpp/LPanfGVesOBCOEH1nKDiQbdqcuTpg83furzXCnNbE+DEwy3NFBRZruYwbp+ipsFky1s+3Q==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id h12-20020a92c08c000000b00363cbe42a19si646765ile.5.2024.02.12.13.39.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fpdkzqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcc4563611cso344942276.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:35 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:10c2:b0:dc6:d2c8:6e50 with SMTP id
 w2-20020a05690210c200b00dc6d2c86e50mr1230828ybu.7.1707773974574; Mon, 12 Feb
 2024 13:39:34 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:47 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-2-surenb@google.com>
Subject: [PATCH v3 01/35] lib/string_helpers: Add flags param to string_get_size()
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=1rMyrBWR;       spf=pass
 (google.com: domain of 3fpdkzqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FpDKZQYKCZUHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
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
 include/linux/string_helpers.h                | 11 +++++-----
 lib/string_helpers.c                          | 22 ++++++++++++++-----
 lib/test-string_helpers.c                     |  4 ++--
 mm/hugetlb.c                                  |  8 +++----
 11 files changed, 42 insertions(+), 33 deletions(-)

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
index 2bf14a0e2815..94fba7f57079 100644
--- a/drivers/block/virtio_blk.c
+++ b/drivers/block/virtio_blk.c
@@ -934,9 +934,9 @@ static void virtblk_update_capacity(struct virtio_blk *=
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
index 32d49100dff5..1cded1e9aca4 100644
--- a/drivers/mmc/core/block.c
+++ b/drivers/mmc/core/block.c
@@ -2557,7 +2557,7 @@ static struct mmc_blk_data *mmc_blk_alloc_req(struct =
mmc_card *card,
=20
 	blk_queue_write_cache(md->queue.queue, cache_enabled, fua_enabled);
=20
-	string_get_size((u64)size, 512, STRING_UNITS_2,
+	string_get_size((u64)size, 512, STRING_SIZE_BASE2,
 			cap_str, sizeof(cap_str));
 	pr_info("%s: %s %s %s%s\n",
 		md->disk->disk_name, mmc_card_id(card), mmc_card_name(card),
@@ -2753,7 +2753,7 @@ static int mmc_blk_alloc_rpmb_part(struct mmc_card *c=
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
index 2dbda6b6938a..f6c3ca430df1 100644
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
 		seq_printf(s, " %02x (%s)\n", nor->params->die_erase_opcode, buf);
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
index 0833b3e6aa6e..e23bcb1d1ffa 100644
--- a/drivers/scsi/sd.c
+++ b/drivers/scsi/sd.c
@@ -2731,10 +2731,10 @@ sd_print_capacity(struct scsi_disk *sdkp,
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
index 58fb1f90eda5..a54467d891db 100644
--- a/include/linux/string_helpers.h
+++ b/include/linux/string_helpers.h
@@ -17,14 +17,13 @@ static inline bool string_is_terminated(const char *s, =
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
-int string_get_size(u64 size, u64 blk_size, enum string_size_units units,
+int string_get_size(u64 size, u64 blk_size, enum string_size_flags flags,
 		    char *buf, int len);
=20
 int parse_int_array_user(const char __user *from, size_t count, int **arra=
y);
diff --git a/lib/string_helpers.c b/lib/string_helpers.c
index 7713f73e66b0..a5d7d1caed70 100644
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
@@ -34,14 +40,16 @@
  * Return value: number of characters of output that would have been writt=
en
  * (which may be greater than len, if output was truncated).
  */
-int string_get_size(u64 size, u64 blk_size, const enum string_size_units u=
nits,
+int string_get_size(u64 size, u64 blk_size, enum string_size_flags flags,
 		    char *buf, int len)
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
@@ -128,8 +136,10 @@ int string_get_size(u64 size, u64 blk_size, const enum=
 string_size_units units,
 	else
 		unit =3D units_str[units][i];
=20
-	return snprintf(buf, len, "%u%s %s", (u32)size,
-			tmp, unit);
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
index ed1581b670d4..26a8028e4bb7 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -3475,7 +3475,7 @@ static void __init hugetlb_hstate_alloc_pages_onenode=
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
@@ -3561,7 +3561,7 @@ static void __init hugetlb_hstate_alloc_pages(struct =
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
@@ -3607,7 +3607,7 @@ static void __init report_hugepages(void)
 	for_each_hstate(h) {
 		char buf[32];
=20
-		string_get_size(huge_page_size(h), 1, STRING_UNITS_2, buf, 32);
+		string_get_size(huge_page_size(h), 1, STRING_SIZE_BASE2, buf, 32);
 		pr_info("HugeTLB: registered %s page size, pre-allocated %ld pages\n",
 			buf, h->free_huge_pages);
 		pr_info("HugeTLB: %d KiB vmemmap can be freed for a %s page\n",
@@ -4527,7 +4527,7 @@ static int __init hugetlb_init(void)
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
2.43.0.687.g38aa6559b0-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240212213922.783301-2-surenb%40google.com.
