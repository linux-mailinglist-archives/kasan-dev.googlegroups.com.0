Return-Path: <kasan-dev+bncBCXO5E6EQQFBBZMV5WOAMGQEY6LHVLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B283864DE91
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 17:27:18 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id bi19-20020a05600c3d9300b003cf9d6c4016sf1335524wmb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 08:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671121638; cv=pass;
        d=google.com; s=arc-20160816;
        b=POWChkU+teTQjkPsKzHHo6nrhrSXguXdVMGjPAx0u3Fn820raQ2NVZ6B8XPn2XASnU
         J2d2QUWuRczdQe+u7PNIWFXkZZo9zzLGy/okn/mNcSWXthiNc1LcVLp85W97jKZNnuj5
         JjcucwoaXm+ntSdEpsIdhHmbvR/q7tpLnZDKHnLTmdgMDTSbg5VqmlgQD2/Z2j5LnhBt
         Sp28G+Auav8l3+VFerghRVRFOnLWiHXivBsfYEa4XLzxnAIXtAPLp/Uv8c9DxBPE4o9c
         ai0vOsOGOnrIYIJ9MZNXKMlPu6pljVthb16cIszXun/4vNa7bLrugUZpca2c64UJTs5c
         Mshg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Xr8Dhp+F6fY1zBD6wHXWVDizCQ75kQVGVaCVYax7HNU=;
        b=S2ODhcx/RWuLvDdGQ5djoFbOj4xJ/mTZmK/bTD6npPR4tKw/eHGJ98VT8Rjcr6vCp0
         tS4llcts8sb6Rz09MJEt01YZglU7yylkUO6/dmn3IeEQq+3w4IGnminUHG++crKdEEQh
         XkArJG6JQVpPb0Npw2fnW4DFK8VIHKFdw/CHA5oFWF1bBrrvk7ZBmAfKb+xIWVWv1agU
         WvKBchNy7gjd6B+3sdNTp7jyGvfcvq4ehqzETuWLgEFAry8ZToed5s0/n16z5J8WUfy1
         66OjEm5oWNCilSwC5iLZTjFYOJX1YrQeA7M1XZ5O0hrmA9lZxKVlCfHfMNhqbwT5C251
         dnZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PhIKLFHQ;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Xr8Dhp+F6fY1zBD6wHXWVDizCQ75kQVGVaCVYax7HNU=;
        b=pUf5rwqeVRLN6SDqUpH6abGDhkF7zp6pJApRS2UxyDPmiatbdMz3dp37vFZ1MVOFlK
         xX1tX71sHhHoMt2BrUjovN4qQeETeHV/SnkcWfZE6pzTXhQ9DbeHiVEPifj0FwzhWWDi
         IlnLM6Xvk8wIwdLbe6RGQiVHLWuuRcMMh7deiVBB83dTRsN3YiPLcrWp6obIynECNnLC
         /IkKNzzVtfEFkEEje1nYuSjaNKDiACFTzL71V9u4jrHZ+goHxKG9D/oN3bCB1KPSEk1j
         LOhLW6na0u6xuXVrt5cUjrva2GgyAzrppZsVRzcdaqsKNnaDy64/4Fzezp4yiulc7SbM
         4mYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Xr8Dhp+F6fY1zBD6wHXWVDizCQ75kQVGVaCVYax7HNU=;
        b=R0lD5YvH+e5PsFQB2RzFv6bd4JWrzRJpTZ2Z74mTnPwee+vITXUswPonKWRaRz0DUG
         jHY6uyenW0w/hSnoLi/uchiAAa3P9RrcPtarU9sW6gbiEjjBnJC03CPRKa+6vhP16FzX
         cAP+fFHLVA9DkJ6y9oQCdw0mn8d21IsKUFoQ5FQ7HvMnUenPamwWm0oVgvbGIAOC7Z9Q
         geAXe2eU1DBmCuDuUThoNV33GCjW2UFLBJVeUnR0hQS9EqnXWxLlk3oDACFbUlxY1aZd
         udydnKq9nMhz4rhhtYv11wo/Ingp1yPqI17VWcOEj5cDEoUe6SYMIqW0KChMlx+DaX+g
         +ZHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkXtedw0HQiSKVmigcY5jPAUiJq8UjUqHaHLdQ912uP6DTuty10
	mB3ASkZzlURZlU2yzqleVYI=
X-Google-Smtp-Source: AA0mqf54nyTGScXR/m2edahH41kyT9XNMhWjsAsPZ/xN6sNLV/E57O175gJPkgltFTVu8OVQ3EVbPw==
X-Received: by 2002:a5d:6603:0:b0:24b:b74d:801f with SMTP id n3-20020a5d6603000000b0024bb74d801fmr1205866wru.567.1671121638141;
        Thu, 15 Dec 2022 08:27:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d231:0:b0:228:ddd7:f40e with SMTP id k17-20020adfd231000000b00228ddd7f40els2321671wrh.3.-pod-prod-gmail;
 Thu, 15 Dec 2022 08:27:17 -0800 (PST)
X-Received: by 2002:adf:f948:0:b0:232:be5d:5ee9 with SMTP id q8-20020adff948000000b00232be5d5ee9mr18081800wrr.64.1671121637211;
        Thu, 15 Dec 2022 08:27:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671121637; cv=none;
        d=google.com; s=arc-20160816;
        b=UY1RBlLkHxDKU3fJbX51sq6twURkTWg9hjTy51XF/tbwoecNeM+rZ35iFF5qsUPF26
         coMhZuWRIviH/US/WrypQSvx8Su911mmZXIF0xCKPW+9m1dn0TSHLtKymDFZO46IwPpP
         BYWDzPUGGjDU4UJfXQY89A9EzUUnqVYOpPmaYkmoxnleZ4tyEjVzDbINWoIdAgc9026r
         0tVm3HMxS68t/B+emapCfx5uyJxTN74R8EbUJisAS8k5dnsQ7hXxi6uJ+wp3X4nSwSoX
         860wx33VofGRCuFZLlhUJ1VHL5NaUiPSw1r7psAPeX++OfFyl2aWBhfkC4PZbsuQMVMS
         ZtvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/Iel13MP9rIkj4OT0LqhWZFBUWlSMXK5V+GEL7Ux6UQ=;
        b=jlRiZ4EWo5G4I5xr8vVkzPZRoLSJuBy1QfQmyX6plQmb6C7AA7UWI2sI/4RapW93n/
         7t2xuug57m4FWQz3X5JKrdNexapeOA/tGWGiXmgOAuoas0DEO7Q8tNJXkYWunFWKvb0Y
         i9REeqfQPd39y8ObM0zozVneP3xx7RfkWOkCxM4dy7SvfxloIQa5ZBM7XCjqktY1F68C
         8OSliXoDZNPZSLACaKZPwp01KT4xtq+sq1cWJRh2IQnWtMUYwdKxn8saXyNj5j4QGwn5
         UKM67kM7KxqalJ9a1HVfsU6UbcFxj2lD1hewlsLVNEHVa9JG/80+uFZggnDBAEIUKia6
         9Lyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PhIKLFHQ;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id f12-20020adfe90c000000b00239778ccf84si275267wrm.2.2022.12.15.08.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Dec 2022 08:27:17 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id D3536B81AAC;
	Thu, 15 Dec 2022 16:27:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CFDD6C433D2;
	Thu, 15 Dec 2022 16:27:13 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kmsan: export kmsan_handle_urb
Date: Thu, 15 Dec 2022 17:26:57 +0100
Message-Id: <20221215162710.3802378-1-arnd@kernel.org>
X-Mailer: git-send-email 2.35.1
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PhIKLFHQ;       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

USB support can be in a loadable module, and this causes a link
failure with KMSAN:

ERROR: modpost: "kmsan_handle_urb" [drivers/usb/core/usbcore.ko] undefined!

Export the symbol so it can be used by this module.

Fixes: 553a80188a5d ("kmsan: handle memory sent to/from USB")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kmsan/hooks.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 35f6b6e6a908..3807502766a3 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -260,6 +260,7 @@ void kmsan_handle_urb(const struct urb *urb, bool is_out)
 					       urb->transfer_buffer_length,
 					       /*checked*/ false);
 }
+EXPORT_SYMBOL_GPL(kmsan_handle_urb);
 
 static void kmsan_handle_dma_page(const void *addr, size_t size,
 				  enum dma_data_direction dir)
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221215162710.3802378-1-arnd%40kernel.org.
