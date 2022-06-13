Return-Path: <kasan-dev+bncBAABBINYT2KQMGQEYKKYMEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id F1687549EEE
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:20:49 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id z13-20020a7bc7cd000000b0039c4a238eadsf2961004wmk.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:20:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151649; cv=pass;
        d=google.com; s=arc-20160816;
        b=kRBADUG+0ilmAJv0VS7/b8JwMkBq/2QzWgMjR6JkwVmiGD6Mzi6jUVRXzmUhhMahou
         dtvUMSooVw0OmC39Ms5XiDv5XZqrGRiV1jctAY7re4OoMPWibnKuo5lF6uDrQFF66tkZ
         LycE9Ui/2r3bqOdZv9csZ4DUqIjTA5j0AJZvbzmFTiZP6O/qEsth+4CBW9xBVxERaHAp
         Zzg7GkcdguJiqI+PSs/OaLkvcektSVG/zTvpi39Z2omEcu66MTHJ/jYavsMqGXlS+ZTB
         4Hi5SyFgWxDcVfGVLJV4LWLFq6b74OO+YafTh6qOggA4JkDk3V/fsoQx4HoMmr+Kb/vc
         4HEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2lpnBqDJcfUJDEtZCimEJrUy9otBw/Hopy6zhtW4PjY=;
        b=eUNfX/ex73HNxNaRRXVHDKsbDSMQxQ0NiGZQPFH6OVbNPZS7qGZJSnbWSDxp1g8kZQ
         D+fkJ+D7wQ3jTDUFKhH2303Q0YdzlqebNFkCSTioNNj+s0xNN9xZujrhKqVoZs/kpEYu
         pYHyzigTqWSI7wkD6rOiQTgmcL3WrM43fmzaJxHx7qec/DwUQg85XcVIFDYCai0+1oj8
         bmqBhXP9pWHR1vtcXEiNh4ctLg99ZkZiQ9UE4gvP0TP6BURjXTMZaZ+ZAIlbIKZpqftB
         8QwN8j3EpbJHL6FAE+SaNVk1YndPAPW9Vt+m/6CGiwuRsBb57EF2LLGN83GLYE5eQiSO
         Ixuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hws0kYch;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2lpnBqDJcfUJDEtZCimEJrUy9otBw/Hopy6zhtW4PjY=;
        b=OgLBHO2yZh0wCBIm81VBrw76MPzd39bfG+qiGPGy/paM6TKPPW818xCHyrOSaI55g7
         351FC7d0Tk9JINBQKpFCpYHoXBFOeeT9LpcKf1l5/25cpDThr35QIe5gWM7q/A5Sys8F
         3IakaHYmidLONph0DlwJFVMezeA3L6VZFHrn1cV7JUn0BIL1sYijrNgSCrvIAh9FQJqm
         5NsDvh7gVfveYsUhbxqEeIsJ9hdP/xeLZ4f1cg/hTaSlDZIhRUGJK3O3MA81Vpwu0sFj
         8seT5xtG87tnnWbF8liUzjkWm9Rk/IcOgHnMMJXuI4q5/AFDrYSiMVKFbK7kpilMi7iP
         7JAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2lpnBqDJcfUJDEtZCimEJrUy9otBw/Hopy6zhtW4PjY=;
        b=J7bFvvtdkHFrFBiI3N5DbN2LYUbs4DkGUyQ2MfAyf2a/AbyO7RYlAq9/BF9zmeuoVq
         Do6HSGduP4tTxbwQ5b6d0Z1iFRtxCxmxu+7jRZ14J3BpnhaGVkNl4yo1hqm9Yucgh4MI
         2CE5iU+7lmOXhDLhE9wAJwi3c2X1ss3DTTVVPDyEemo4Ndn0JJgvzSqHtajVwyBPJLiP
         r8Um8X5QtgKyZvBAFI6Dk6lHNSysAqWa2tXDe5f491LThk+bkGZ4NIxA2BHMrKpEMzY5
         xoo1lEibAq5K6av/KLyajF7KKfoMJYVD3g+1HfXYS3kFykO/rzbX4djrtUIipevNP8sK
         dZxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora94vu6FsdmrdDfjZsHTlefrbB+KOCUwgwsNWhAFi5VbIlpWLuRG
	xuc8C4U/i2E2dSQfSZcMbN8=
X-Google-Smtp-Source: AGRyM1tJvFyXApcHuANZIZnCAiwJXtB8EevjTt29YJLMpxO28Pn7xfs+kU1MTuXmQLMrI8LIDg4GmA==
X-Received: by 2002:adf:ed82:0:b0:213:1315:1dbb with SMTP id c2-20020adfed82000000b0021313151dbbmr1390752wro.484.1655151649716;
        Mon, 13 Jun 2022 13:20:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d20:b0:39c:4b30:51b4 with SMTP id
 l32-20020a05600c1d2000b0039c4b3051b4ls123855wms.3.canary-gmail; Mon, 13 Jun
 2022 13:20:49 -0700 (PDT)
X-Received: by 2002:a05:600c:4c06:b0:39c:975a:a548 with SMTP id d6-20020a05600c4c0600b0039c975aa548mr430053wmp.99.1655151649047;
        Mon, 13 Jun 2022 13:20:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151649; cv=none;
        d=google.com; s=arc-20160816;
        b=YVDPP+mM13luhZy/3mDTJGre84gRf7r5uXYF/3eg5G70vffyHnQsGV57g9PZLvU4AS
         18EtXH5yPjS5SPBfqihAc3JeCTnYl6QCvvj/H2XRBsTmZSfJGjD/MdAaTtmHOAnbXBDT
         UIlkwX5E8sY5KuNcMNg2Zw6TqdfPdWTaiVk14OFhJ59E6c0Nk8fbCHRd/t94yzj9p6SC
         LD11KO696PnEOoePcPcMO7RXYAX4VIGFf2wWeoussb4xWnd0QJEkc3bUb1foxPqKFCJX
         hl0m46Fv9tgwvC7OaNMTlQQqCxbW7Q9y/CrnG4hKxgwkM+9aXrajtS2MPgQIfCbR6Fdi
         T2UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GpOGtaNQnKD78CBtw46te33KktguHzhzP5BMdoXtyCA=;
        b=Tm5iMm/ZPM5X1wstaxtIN0C30q0Npj5gRa5gFcWwEB/F6C55J2td0f71UH2wgYRUQh
         a/7geWLUANv+t9/9l/JuO4l+26oz7Qw5lf/Qtl+tsXUS/bgbs8lXmh59au4bdgkq+7cm
         rWfVzTDY9nn+O6gBI2yUMCvLEceFkAS+gyaHvUt7h60IFgIgMEBiCqhZDYKvbNSygh4W
         JM33s0TxCdJ2qgEPoey8UHP598ko36qJh65ZSA1aUcXndsv9LJFarmLkJ2aZmQgsZmHM
         YkqGrQg5VOnC3nHZ2YP1UCg3lJfxsu86S3OY8CQHmdYeCjJm1Tjy/5Q1N3SqndFCCT8O
         Vd6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hws0kYch;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id ba29-20020a0560001c1d00b0021a07a20517si178397wrb.7.2022.06.13.13.20.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:20:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 32/32] kasan: better identify bug types for tag-based modes
Date: Mon, 13 Jun 2022 22:14:23 +0200
Message-Id: <89492159bd43c01f7b13a72b050ff15f35e04973.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Hws0kYch;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Identify the bug type for the tag-based modes based on the stack trace
entries found in the stack ring.

If a free entry is found first (meaning that it was added last), mark the
bug as use-after-free. If an alloc entry is found first, mark the bug as
slab-out-of-bounds. Otherwise, assign the common bug type.

This change returns the functionalify of the previously dropped
CONFIG_KASAN_TAGS_IDENTIFY.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report_tags.c | 26 ++++++++++++++++++++++----
 1 file changed, 22 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 21911d1883d3..dc1f8fc0327f 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -10,7 +10,7 @@
 
 extern struct kasan_stack_ring stack_ring;
 
-static const char *get_bug_type(struct kasan_report_info *info)
+static const char *get_common_bug_type(struct kasan_report_info *info)
 {
 	/*
 	 * If access_size is a negative number, then it has reason to be
@@ -36,10 +36,10 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	bool is_free;
 	bool alloc_found = false, free_found = false;
 
-	info->bug_type = get_bug_type(info);
-
-	if (!info->cache || !info->object)
+	if (!info->cache || !info->object) {
+		info->bug_type = get_common_bug_type(info);
 		return;
+	}
 
 	pos = atomic64_read(&stack_ring.pos);
 
@@ -76,6 +76,13 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			info->free_track.pid = pid;
 			info->free_track.stack = stack;
 			free_found = true;
+
+			/*
+			 * If a free entry is found first, the bug is likely
+			 * a use-after-free.
+			 */
+			if (!info->bug_type)
+				info->bug_type = "use-after-free";
 		} else {
 			/* Second alloc of the same object. Give up. */
 			if (alloc_found)
@@ -84,6 +91,17 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			info->alloc_track.pid = pid;
 			info->alloc_track.stack = stack;
 			alloc_found = true;
+
+			/*
+			 * If an alloc entry is found first, the bug is likely
+			 * an out-of-bounds.
+			 */
+			if (!info->bug_type)
+				info->bug_type = "slab-out-of-bounds";
 		}
 	}
+
+	/* Assign the common bug type if no entries were found. */
+	if (!info->bug_type)
+		info->bug_type = get_common_bug_type(info);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/89492159bd43c01f7b13a72b050ff15f35e04973.1655150842.git.andreyknvl%40google.com.
