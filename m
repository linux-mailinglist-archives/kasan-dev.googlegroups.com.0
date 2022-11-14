Return-Path: <kasan-dev+bncBDHMVDGV54LBBZGUZCNQMGQE4BMUDHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C5DC627CAE
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 12:45:42 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id q17-20020a056214019100b004b1d3c9f3acsf8276925qvr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 03:45:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668426341; cv=pass;
        d=google.com; s=arc-20160816;
        b=sgG1YGm+4Vaz99/6UUsKp5/xr5weGki4Wl/EBp20PlJxBimyVU0yKCnSDc9ct76jZq
         FAJtAq6TanmuuEulaYAvq6SmwYvHHiak4sSXr2yFhnqhxM86Pt57E45sWDkXRdj2IkNz
         41wY3xRyHPY8zqUEgzkpSi2n3PXF0JBhMRxg/wOPCVpWHpPbdHefJl7LXJ5p66YQbA0F
         60UgyUod/pgyxTsQHXXVxMxkxECeymZcn2PVMnSucmFXbdTqCYiiIkF/g71MGs0kGsXY
         SZ6UYoH/mDv7lerJbe6fe5IRkV+DFgCSXu6NDIba2bVzgCs3BchlkqLgJFVJ1mZ2LkRY
         TQeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mEke9+xwjZNgHFgIAT4OkMI9LZ9J/k/vtpmxCAxNFwo=;
        b=AWC09JWQDCtluy9ZlzCV77kgw8vdTkSL4pkoqHP4iKFH1BAsiElZ04rLIJV0zyNL8g
         8lhPMyDP+as7gq3amHN/cSl2wTZVAwaoPqvh7ztGkCgxB+hYAwxj+lm3AfeXl5nimZHZ
         OsA0ndXpaxDB7kdgQbgUamN/RQWMKpteZl4wAAO+wzAtXcGNk9k5Y5w8+jm/BMe2RUyg
         Gt3RnsPa3U+QjEdOhJM0hrEquheuuMSW0Ej9VIA+q7rbd4LAlMyrxUiJwUFXwW3t8O3l
         h7sciATFeYzIDfkKfFIbIAjo/O6/44I3ezFqehHvEWGR2PtO4hbFfkfdQGSiHuPXZihd
         B+Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ivICbmQi;
       spf=pass (google.com: domain of jirislaby@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jirislaby@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mEke9+xwjZNgHFgIAT4OkMI9LZ9J/k/vtpmxCAxNFwo=;
        b=VEyDiDlvkDeh00QS++LiedcLAB8Hww2hGCWSi6k7ZQGEWpVJEZnhY9OvgDpL27RM0n
         wMKleqNZoBFQFo1uJz2jtQAeMZ1B0W01xcCMLpnOzeUyLFpjff57WFyOTGTsBcPbPI38
         A7Jv/Flzip7X4l7Uytl9oVtjirTOlrYrSFTT7mnuC4qICf1E+e5Ln9qRXkOisA6YrtCH
         Gl5va7Y2XcqYSGbt5GZOFKNgpsv/rXaHggeXArv9m7d2ygwMFYxiSohs9h1rj9xU4Jg0
         nfH/82D5/USnjSCSbhpGUyF78YXXMsVq44EgJKGBVQ2rMRzcbOGJlqh5SzmDdgrN2q1v
         /46Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mEke9+xwjZNgHFgIAT4OkMI9LZ9J/k/vtpmxCAxNFwo=;
        b=6C+s0qCQ2Ra+YgnrnHCxrnW7Zw/PcFqjncWu4gXQB0Ov77wCWXMS4x7KQnM9VCuAI7
         +r2vR7iArTdAAC+qkoM4AxZpL+b95gFfWO0MDjdLotkY9/PlLTUgJta9la9TZU3/ceF3
         EFwm7P1H6yc6tJqyD6xVZITXfhug7ifU2MgJTKLtk/qOXqTIiEvp3wKVgw95LXSgH1dy
         DEUPSzuZH2icCYN8cReA8HjItduQZMhYtalEsI7nPoj+caGFk8yT3pFWcsGmAPhVN7+k
         2Gg0lrj0ZtcJZCq1v1U+nShiAaA8EbAhf1yldUQc/pVa9LcCDLuBF7k+IzyxHQXxIA1U
         Xx0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pm7XldD+ZKUn1RBGvXX+NBjI2p3WE4N3e56qQIKBfx0Tcf2jK6m
	SI+TjLgH6sNMKgrKTRkXBvc=
X-Google-Smtp-Source: AA0mqf6VtjT7WbBoQhPS4S6+jDAqL7ncF3m2D/9wa8Z2QWOd7lueSdQZ4V+aOAcZpvnr5PuirwEl9w==
X-Received: by 2002:a05:622a:18a7:b0:3a5:6132:b3f3 with SMTP id v39-20020a05622a18a700b003a56132b3f3mr11818023qtc.472.1668426340970;
        Mon, 14 Nov 2022 03:45:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:99a:b0:39c:c64d:83d3 with SMTP id
 bw26-20020a05622a099a00b0039cc64d83d3ls6535296qtb.8.-pod-prod-gmail; Mon, 14
 Nov 2022 03:45:40 -0800 (PST)
X-Received: by 2002:ac8:7398:0:b0:3a5:2bb7:55d4 with SMTP id t24-20020ac87398000000b003a52bb755d4mr11752899qtp.298.1668426340515;
        Mon, 14 Nov 2022 03:45:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668426340; cv=none;
        d=google.com; s=arc-20160816;
        b=BOQ6bofCHDFpL72oMzCJDuOXNIrFb8JsTO6dnb4wqJJSe2baOAhlnzEFrd57vKSzzz
         0p+Kh/tH08/u4jyj6LVI2RUucgn+TeHs8ogjGSqeTf65gtWqoHLat7o8yGER5H1lK27w
         0ptV2EwVLFqrx5QfmSgVJeEve92QiRCFxTbp4jCE0hlYjsOVTw8MhbQKJxab93Wr7tD/
         wXymHrng7CIlvEnl/5uRYhhSviFAvtQfYVIqDWAZ7uUqa0hgfGHVAm2wx6bOaVC6hEqY
         LtvqIh/QZCJ71xniFpjGVjMC4BS55Y0XtYcPKmMSd3Dq7uGwh8ryJ1LBVWYsD5OTk2My
         UpYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BfbFJP9xIxthF4S61VznWCy99JUkc3m8GUdJ+Jei+2g=;
        b=mO/LtDZnzhVfeZufrt/zm7rnl9IBCTupLloY8nyvsDJ2j1sHnSHmKiC/vnpa7PHPgc
         2njklP8HRS4j/w+38LnH6kEt9b4VC5ZhyndqqUkZFBXgMYadt5cGJ/gbMjuv9pE6sE57
         aTp++IvfiBiPskMqWfC+ChiPd2EDQT5oPtuacvgisRzQg3u9M8QnYF31Olou7gIuJjni
         YqZH8J01+AC54baNlFi2kFE0NRLHVAUXXTvhBhfjb2V1vH9Gff2/dG61MthRUE5JjUes
         Lgigv499cjyzrSukoenKU48HakQhUyO96nz++ghnvHMmxKEHe6NQMvnZcIfZPlqx1UIC
         n6XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ivICbmQi;
       spf=pass (google.com: domain of jirislaby@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jirislaby@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e17-20020ac84b51000000b003a528515a76si356845qts.0.2022.11.14.03.45.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Nov 2022 03:45:40 -0800 (PST)
Received-SPF: pass (google.com: domain of jirislaby@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1983361090;
	Mon, 14 Nov 2022 11:45:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8E91DC43470;
	Mon, 14 Nov 2022 11:45:37 +0000 (UTC)
From: "Jiri Slaby (SUSE)" <jirislaby@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Martin Liska <mliska@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Jiri Slaby <jslaby@suse.cz>
Subject: [PATCH 42/46] mm/kasan, lto: Mark kasan mem{cpy,move,set} as __used
Date: Mon, 14 Nov 2022 12:43:40 +0100
Message-Id: <20221114114344.18650-43-jirislaby@kernel.org>
X-Mailer: git-send-email 2.38.1
In-Reply-To: <20221114114344.18650-1-jirislaby@kernel.org>
References: <20221114114344.18650-1-jirislaby@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jirislaby@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ivICbmQi;       spf=pass
 (google.com: domain of jirislaby@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jirislaby@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Martin Liska <mliska@suse.cz>

gcc doesn't always recognize that memcpy/set/move called through
__builtins are referenced because the reference happens too late in the
RTL expansion phase. This can make LTO to drop them, leading to
undefined symbols. Mark them as __used to avoid that.

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Signed-off-by: Martin Liska <mliska@suse.cz>
Signed-off-by: Jiri Slaby <jslaby@suse.cz>
---
 mm/kasan/shadow.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 0e3648b603a6..94c98feea9c8 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -39,7 +39,7 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
 EXPORT_SYMBOL(__kasan_check_write);
 
 #undef memset
-void *memset(void *addr, int c, size_t len)
+__used void *memset(void *addr, int c, size_t len)
 {
 	if (!kasan_check_range((unsigned long)addr, len, true, _RET_IP_))
 		return NULL;
@@ -49,7 +49,7 @@ void *memset(void *addr, int c, size_t len)
 
 #ifdef __HAVE_ARCH_MEMMOVE
 #undef memmove
-void *memmove(void *dest, const void *src, size_t len)
+__used void *memmove(void *dest, const void *src, size_t len)
 {
 	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
 	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
@@ -60,7 +60,7 @@ void *memmove(void *dest, const void *src, size_t len)
 #endif
 
 #undef memcpy
-void *memcpy(void *dest, const void *src, size_t len)
+__used void *memcpy(void *dest, const void *src, size_t len)
 {
 	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
 	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
-- 
2.38.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221114114344.18650-43-jirislaby%40kernel.org.
