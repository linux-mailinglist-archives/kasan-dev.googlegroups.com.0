Return-Path: <kasan-dev+bncBAABBOOL3GMAMGQEKKN63XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E2C785ADABB
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:10:17 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id br33-20020a056512402100b00494686d31f5sf1984500lfb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:10:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412217; cv=pass;
        d=google.com; s=arc-20160816;
        b=MmtGvnq5BTwlKeIXKpY9nz6Ea2csK8j6yJhSOFQOGg+nixUaS2y25g2lEZc6hG00PG
         x7xJuHK/ZrPaPxcOpn49YOBnDfgnJZRO3j5bZiR/P3Qyv3oepzgjSJYS2J9M1+cyaKVV
         GAaQThLVpfBdKiNnIiK2k5LtV46Dy9wwl1mksSMEv95pQHPIJn/D3THb6xgCroJlgK2c
         mW7EXfz1yVQsp1G3IyNdz1TYSArfEN4W/Nlus8H+DxHelr9qMEe9zHeTHqSOpRoXvtHq
         mT3hcVwoEB48gOuT5MZvewm3bXWYMcF6XawyTivPJoOoobwakxY8Hn5zOtooOqx0b0xc
         Y0lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r60siJR/AwDmh/+OCz4DwTHldm6p9GTnxhhLre2O220=;
        b=pOJVmNHI8MDuvDbKF/PgIaN7SoQ4UgYdCc554Qx2MImIybrAVWoTWAKiQPRKI/Yis1
         DrUrSao6mRetpjZ39IVws0emMZ506crpUg+vtCMuJYWSJSWVeCVPbN2oPoPjz9hqILmT
         Irn3fT6gp9NTRVO4mX/+eQDe/B4hv7qAk54xgjhbEG5xIzbfAEL00IH4JN6Jzi+E1s4v
         JD8bhoKkyUbNfSQ8QaC3Y2Wf2L0wFWqbKjqec+g2NLN8Z8RsOqGvWUl1y6yojj1DIVTD
         G5wwHyA4HuaJHBo3f+fuLusZDkeAY0bTgNd8OoCWb1Yi8bI+Duwt7B0tb50PJaZF9F6X
         mhFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iLcEJBbW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=r60siJR/AwDmh/+OCz4DwTHldm6p9GTnxhhLre2O220=;
        b=keiUR1XkT2r7qhMrrzEphuuy/41T/hzlufpNXXLf6eX5xmGC1VpC6Rgr31Wp3my/Sd
         E5e35Q3qWhzisgn2F64qPlyrga1EGURkBI+LC2MRKuamGEJey80zq0nJSZkdcADhPfbZ
         g8uh18jmPAIv5AlDowQKc/xRKYDlFk5bv77hYd/DWsVGBxP/mso6TCgoIQBhPZU3CqVu
         PwIjhQ2ZM4zulmJh/LPlDYnkAbE5fSsJFHyTSlVYLENmkRkX8V+ilc4YzaMj7igZQUVv
         5seIxzTp0rYcVso5GFNnYLEqSXxrSZBlMM7/1SEpA2c23P6VKIGKD2Q92g2FtMj+fS4M
         nbbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=r60siJR/AwDmh/+OCz4DwTHldm6p9GTnxhhLre2O220=;
        b=zIiqmxNOoDMTMwDjOrX1X+0SFrt9ZPyPElqwRFCll0QxGvG7AlRbPaOVqTiRV12CID
         DdqM1ksEiJkxpGhC7fcK5DNNMoJ4I7yx8J2TrTHsYAa0FjABDW43VQmrRTw9RXDa6pJe
         o1/K+ejeXwV4+HovLpNh2ZIOkqtQrt0wzaIV91lsTHqWVUYJWMvfDzhYA5IrslFYn3Wv
         PDHRqe685xbKm2qjW1KvMLGLmR8oK0CTCot6P1zF3IH+kYetInymI5AROyaTZG4hylzk
         uVECQxmyG/RDFy0eUBCO5FwT9IdqUGxyGjLnaNnbxDqOFsKUAIaV06Mha1yD+oY5SmXC
         cMbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Dch6Klt1Z8/ElaMawPZahKYVejdT/zaJksCNmbWmxoM2inPrd
	XsFs0mpDL1KrB1d7GVAuBHk=
X-Google-Smtp-Source: AA6agR4Cguz2Ia/iXpfPKnTThdqUVp5Wlvd/YpgbZiGWguZh4pOHi1liRxfph+4t6mvlVAf6wUL8pA==
X-Received: by 2002:a2e:a788:0:b0:268:d10f:355 with SMTP id c8-20020a2ea788000000b00268d10f0355mr6086129ljf.159.1662412217313;
        Mon, 05 Sep 2022 14:10:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2016:b0:48b:2227:7787 with SMTP id
 a22-20020a056512201600b0048b22277787ls5360117lfb.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:10:16 -0700 (PDT)
X-Received: by 2002:a05:6512:3c8e:b0:494:918a:d005 with SMTP id h14-20020a0565123c8e00b00494918ad005mr9461451lfv.456.1662412216536;
        Mon, 05 Sep 2022 14:10:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412216; cv=none;
        d=google.com; s=arc-20160816;
        b=jNwfkKqknjhVuXvDWPNPVOR1hvGZWcvs8ZrRGf1jTm4bVo/QU1L+p4APKtzGV76TiG
         UHe3ju9nOfBO5UH9LB2i8VXLwTRCS3cdvGKkjNglQKLu6ml7oeybMXsieeIpE+fcaCVE
         MEXC/1ILTOeK0ym1abXTV+wTAefiRi7eRk6a/SAwwPzMJs4I8pvkJnVsuNn29qedO0rX
         T+JM9nrGHoJz4UYKSXhjJyR4a/Ak2n87NlV57xUJxJZ/jmAyMm13Oz6mFQknPua9ozGZ
         PnBROzM5mShA9WhhGD7Vsk5U7okAGIZ1gMN/F52CdnH1lR6w7wjf9/Fw3kcyL7wh1Lae
         FOiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vX65IvaMkEV2nE74f0VGWlIcO5REzzEOQVG3jlGiFU0=;
        b=0Ta1+hOhF99mjK1gqO26UBRXSlHjCwqeMy2Th82/kgjD6mSwPitxPJnolNAlrHUhBN
         yt1f+ify0QXopOQ2Hm3/7UEJJw86RsCU0dXpBrofnVJa3wk93Y7RrNfxi6ZfjBRsDLyv
         iLyY6JSFaMi08Gi9EeONdoPNqR6Nt1PhhgqLCPNYPqW/voTfL4EzzZ5gfr/q+qWtGweu
         R7uLj0UjLAUrtxbfx0gz9eDTQXFetOdlW40MUr3WIS9T1m+qcZB5FaZsOKliNBtAxnvq
         XPcrVLrjxxd/nh6lcAd9FnI5zI7hqxkXLqacix3zqdbRnzGNW3WsQM3c8aCcxhmAA9zY
         W93Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iLcEJBbW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b0048b224551b6si465448lfr.12.2022.09.05.14.10.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:10:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 26/34] kasan: introduce complete_report_info
Date: Mon,  5 Sep 2022 23:05:41 +0200
Message-Id: <8eb1a9bd01f5d31eab4524da54a101b8720b469e.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iLcEJBbW;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Introduce a complete_report_info() function that fills in the
first_bad_addr field of kasan_report_info instead of doing it in
kasan_report_*().

This function will be extended in the next patch.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  5 ++++-
 mm/kasan/report.c | 17 +++++++++++++++--
 2 files changed, 19 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4fddfdb08abf..7e07115873d3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,12 +153,15 @@ enum kasan_report_type {
 };
 
 struct kasan_report_info {
+	/* Filled in by kasan_report_*(). */
 	enum kasan_report_type type;
 	void *access_addr;
-	void *first_bad_addr;
 	size_t access_size;
 	bool is_write;
 	unsigned long ip;
+
+	/* Filled in by the common reporting code. */
+	void *first_bad_addr;
 };
 
 /* Do not change the struct layout: compiler ABI. */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index dc38ada86f85..0c2e7a58095d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -413,6 +413,17 @@ static void print_report(struct kasan_report_info *info)
 	}
 }
 
+static void complete_report_info(struct kasan_report_info *info)
+{
+	void *addr = kasan_reset_tag(info->access_addr);
+
+	if (info->type == KASAN_REPORT_ACCESS)
+		info->first_bad_addr = kasan_find_first_bad_addr(
+					info->access_addr, info->access_size);
+	else
+		info->first_bad_addr = addr;
+}
+
 void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
 {
 	unsigned long flags;
@@ -430,11 +441,12 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 
 	info.type = type;
 	info.access_addr = ptr;
-	info.first_bad_addr = kasan_reset_tag(ptr);
 	info.access_size = 0;
 	info.is_write = false;
 	info.ip = ip;
 
+	complete_report_info(&info);
+
 	print_report(&info);
 
 	end_report(&flags, ptr);
@@ -463,11 +475,12 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	info.type = KASAN_REPORT_ACCESS;
 	info.access_addr = ptr;
-	info.first_bad_addr = kasan_find_first_bad_addr(ptr, size);
 	info.access_size = size;
 	info.is_write = is_write;
 	info.ip = ip;
 
+	complete_report_info(&info);
+
 	print_report(&info);
 
 	end_report(&irq_flags, ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8eb1a9bd01f5d31eab4524da54a101b8720b469e.1662411799.git.andreyknvl%40google.com.
