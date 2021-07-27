Return-Path: <kasan-dev+bncBDY7XDHKR4OBB34J72DQMGQEEJMJ25Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id BA3813D6D0D
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 06:00:48 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id v6-20020a170902d686b02901019f88b046sf10974912ply.21
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jul 2021 21:00:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627358447; cv=pass;
        d=google.com; s=arc-20160816;
        b=CdEoPR2cLfOtJeRqrF1n8AjLKnYAXWGIfadnOq4tLMRZDdCuJxrJ+nUXfup6BIrwwH
         vZgScUJ3jy1oSmc3JBt1AMKMvTNY0hQZXkvcl2Cs8BOognWvB54pjehBtkjMWGhUheXr
         91ydtOZS8pKv0kLBzN8s3sFBjDP0m+dHew0camYUKi7Cv/2EaFgb//uNeR9qhJ6j7J3N
         ye8+zcaFx5pdNz9u/GhEdAAQ3Sh4ASWxUE8W0CT87b7MUJPPcwrKCbGp0JoY+hQqzEWh
         6INZNPqQAZE2inhZJyi1kcOdcD4blx7e1RDoMi18x6c5Ql4qCelb2CRbMgkWqCqC1ZE3
         nqZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=P6iC0KG4qF9uNb+mnbpxHnRsC1cQJ8fWX5aHcPHuqEg=;
        b=LUlLWgYOYXK6e/1A7Ryw+raxiHB0XUzKMIfDALLEy39O4F8UnB20MYtSS8kfFh08F6
         TSfKxUJZqW/p5Zp3LaGGPz5vmSv9gKIKNwkojD0Nj/G5ZmyoxU84YG5iaCLOgIt4RHEZ
         myQFoDRMZ5b1Yx/VrNN9e6haGK48tuhZDaO8i70SkFq//XBPI5+8usnQ8nww6BsSs8nm
         Bxu9l51mR3D+ji6t2edOZHv4xZsCwpM6BY3eD5/NaTw1u3+loADudHEL/W9i63y8LkoD
         0cCWNFivQkPi1ftO+URhql5zgwenhSc049xGLfy9bUgGcuKzzpjYIL5Dizxzua19KNDw
         WzdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P6iC0KG4qF9uNb+mnbpxHnRsC1cQJ8fWX5aHcPHuqEg=;
        b=jNUSK+Ih7dEQ9XXTDuGWKfrIKKGYI7RR7GIOqYtHx0HA0MtSU8C074cacwVnS7IuOP
         5pr3hoj0CnPgqqnpmueS5PMTnjsJTj8MHOnOLlgyUZKBe4XEE6LpRGGjkic4y0kOKSBd
         34T4HCYzYkPip2N/o3E7LUUMGmrKUopyxva01h3iyP/NJ/TX1a1sXqpafOLfzNLr/kQ1
         Qx+gktLoXHkc51PJZCCylHw/W5ZXTZg9D6I5aRj5G4mmOuyY55OqDJWlmiT2CS2RULU9
         bY0/qRTX1z7CmNKhFVQEIiiuPXHZeuuuBhpePOyD3Obf7mNSU/4fIcLjTY+NSUo+bYXz
         SsKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P6iC0KG4qF9uNb+mnbpxHnRsC1cQJ8fWX5aHcPHuqEg=;
        b=imOSQGsTscrNfC3FKskQ1EDHpQpqtXKp3xVuGu9VzFdlVHGxfV2EiFSdOjqO1HCfGv
         6suAl451f10SuF5sVxWscqggNWPCpOxe5eew1gF1d6DAlriEq8E7Ix1bTptDPlFMZp4+
         37ju6TPhyHa+9jcYZR4R8H/bzQKYt+FC1q5AsvUemlwgIbuyPtfu/gq7v2qkNIl+RYLs
         knccgMwznzZ2fD0kYBQartfPkmkX4yBjykiaHx8Zc4SRgZU3nrCN6Bdu3kNwapxwOp0e
         COMWy9uEZlcVq8nvENkWqxqmzOB2s/TxGwwAGdWgy48ofcdm8qr2GCDTwElzPZCGn7uf
         9q4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53116JbX/D4FJNms5cQoh7F6T6WusPCoXpfnOXZUZRyTefiE0sNd
	jBqdaBxB5VI8hSPDt+CUsho=
X-Google-Smtp-Source: ABdhPJwM0uOshBWL+cJZeUU9/rbiRFF102fMgfEXBLNysbEiFOWF+zY9wP7Ro/gIJMiVQwq7mQdTLQ==
X-Received: by 2002:a17:902:c10a:b029:12b:565f:637a with SMTP id 10-20020a170902c10ab029012b565f637amr17041983pli.57.1627358447177;
        Mon, 26 Jul 2021 21:00:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:294c:: with SMTP id x12ls6859594pjf.1.gmail; Mon, 26
 Jul 2021 21:00:46 -0700 (PDT)
X-Received: by 2002:a17:90a:5982:: with SMTP id l2mr13752843pji.18.1627358446580;
        Mon, 26 Jul 2021 21:00:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627358446; cv=none;
        d=google.com; s=arc-20160816;
        b=SXJbxC+Wd2mEy7dnyPkYNzdSD7F+08EPU1BnsPRxzGm3eJ5lY4mXG93ByJSLJBvKfh
         kmhJh+S/ScSrKHYIAb2SntNtDlg80rsvMZK0dJQsdRIidHxXo3jwQ/Wl3+uL9TBbaJOt
         X2GSSscXe4jNT3L/BFtK9u0HGATZ6gVgtTc3Ut4vVwJmXLgO216fWcFeq+JXZcVLUK/a
         E7u4W0qPZB3DbcAjDCKzVqSTT8EttXt666qFb0I0Yoh68K+H2BRShyfq2szk2/dyahGM
         7F05ye7aPSs3CrtxU89GwIYAFVQcEskB6RvPR1fxW1j0zgmoP97grkAqmJWH2YBVuqFG
         pyzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=+dhNLQwJBZaFDzsd70sVJ2R33ODovzhGvUebF9/mxLM=;
        b=vYtt6yR2tDj2fsfSK1iFi3ctZ1rf1BYivXCE1EHzjiUO2/8SYisN4vao+rzStAO217
         8ytoF/C3fPsc0qBwahrgoF8IDIiyCCa2qWCi7ETB6B+Kjol4JC5j875Ls0UxqYz5Q4A5
         7POOVTDmzGez2XA9jPpdzs55OMz6B/DiBjjuMRS6qlgivogHgxFDooZKj9H7FzhxrdDc
         r2WXu6BJ3vTpJ9OJCd/X2xmbdlVSGLjzbNXYYTdktn0aiWHm/uklLB6OzqYqHrODjIYp
         MZn0qW/jwCCY486qwACdroih7ufBfEh9fUeZtAxcl/TYGzsuKct92U92FhknVQNQ1vnT
         DBYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id 14si24796pjd.0.2021.07.26.21.00.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Jul 2021 21:00:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: c2a56f32e34b4b9181147212f965d081-20210727
X-UUID: c2a56f32e34b4b9181147212f965d081-20210727
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 875007197; Tue, 27 Jul 2021 12:00:43 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 27 Jul 2021 12:00:42 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 27 Jul 2021 12:00:42 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Chinwen Chang <chinwen.chang@mediatek.com>,
	Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH 1/2] kasan, mm: reset tag when access metadata
Date: Tue, 27 Jul 2021 12:00:20 +0800
Message-ID: <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
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

Hardware tag-based KASAN doesn't use compiler instrumentation, we
can not use kasan_disable_current() to ignore tag check.

Thus, we need to reset tags when accessing metadata.

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
 mm/kmemleak.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index 228a2fbe0657..73d46d16d575 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -290,7 +290,7 @@ static void hex_dump_object(struct seq_file *seq,
 	warn_or_seq_printf(seq, "  hex dump (first %zu bytes):\n", len);
 	kasan_disable_current();
 	warn_or_seq_hex_dump(seq, DUMP_PREFIX_NONE, HEX_ROW_SIZE,
-			     HEX_GROUP_SIZE, ptr, len, HEX_ASCII);
+			     HEX_GROUP_SIZE, kasan_reset_tag((void *)ptr), len, HEX_ASCII);
 	kasan_enable_current();
 }
 
@@ -1171,7 +1171,7 @@ static bool update_checksum(struct kmemleak_object *object)
 
 	kasan_disable_current();
 	kcsan_disable_current();
-	object->checksum = crc32(0, (void *)object->pointer, object->size);
+	object->checksum = crc32(0, kasan_reset_tag((void *)object->pointer), object->size);
 	kasan_enable_current();
 	kcsan_enable_current();
 
@@ -1246,7 +1246,7 @@ static void scan_block(void *_start, void *_end,
 			break;
 
 		kasan_disable_current();
-		pointer = *ptr;
+		pointer = *(unsigned long *)kasan_reset_tag((void *)ptr);
 		kasan_enable_current();
 
 		untagged_ptr = (unsigned long)kasan_reset_tag((void *)pointer);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210727040021.21371-2-Kuan-Ying.Lee%40mediatek.com.
