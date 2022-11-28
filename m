Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBUJSKOAMGQEYHYZSRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E1E963A566
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 10:51:02 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id c1-20020a7bc001000000b003cfe40fca79sf3544637wmb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 01:51:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669629062; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fo+7wDgSfygVqAfGCVHpiBZ6AyKavutbkyqKqTgYD15EF0mziwezNpFwwI3R+trAsi
         qCKYS3EoXPLvQqohZfTxH+mr67JsmEMCdK5ejU5y+dI7WALkFWclVrtnZITIyJXjQNck
         trjyd+QgfQ2X1Occ8wIlbXLpL8O0kASvw8soJcra+4FT32I+YzVEI5BUPgfRyZaFBLu5
         897PywAzKXdpqWp6RiGA8zzmXhFAUKNvP+j5bjBN5JfkbXo1lnBgZfoGOYb0cOKT4X7I
         F/RnwOPUjMp4qosMK1DcH6XFH4y4IAXYmPpq66Mmi537jyquglA8F0Y1wUZPzYQnVDDI
         8M5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1GYCBe0kt+6pHGkOMYIjp0QSEjf/Hts2fSliGj5jk7s=;
        b=ac6iQOdBZqCv+9rFAZyzZG27yCAQIXlwND62hg8lOmolzbzIMZyAD76FklXohBwVCl
         2khyrw3pL/TqtbGaGc9OgPU+JGymguhdXDVRc7CvPrgh7DAFvPa+FHpzse5MHihF2Vnz
         g0rFdSBx/053uG2S7eVFBGF69XGF4NTVmxeBisJzWQyTW2yd+ZzC0Onc3blvje447kP5
         9ajxAlYTABlX/J1KBDkGnUROZISJdAyU2LLeKrKSDw65yYw305Dk8lpAC5l/R34tqbJZ
         R3nVD+gjI2cswTqS2FgXHHzBiF6xeb+m1zn6wOyo+1sirwh2fxxAOPbI4rxlfI2sLoQe
         W2XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F8rWO4eE;
       spf=pass (google.com: domain of 3hiseywykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hISEYwYKCcEnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1GYCBe0kt+6pHGkOMYIjp0QSEjf/Hts2fSliGj5jk7s=;
        b=RVzTlMbUDwJaYk55Dx+3GS1bQA62+WHWTkJqMBG54EISF6MURmh6ml86XnpxVq7B/4
         z6CRsXhUQel6+e/O4u3MY0HnWufhGa2pFmdUNg0SaV3ieItGpgTHnIApJf9ZkgmJIQlE
         XhUqCzyIoZQptBQ13DrQPyYw2SA2IB991p+bYSTPONO0G03FirV/e5yNUFwn86PgxPD9
         Z9hVR5VOzq1sGdaArlMOn5npH4lzyqrrjaTEaCnmDsWpD711Htimh9B/E93Hn3ip2dBP
         +O/A+i03HU5kzYNQdwckxpb/uXnvVGYuf8Pt1dt6XfsP6s1ybh4X+PmvV8SrHC9G7x60
         RTRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1GYCBe0kt+6pHGkOMYIjp0QSEjf/Hts2fSliGj5jk7s=;
        b=37KVYNrT+UyLflDjHBSa+BrcAIQxzvqeyHyQFLw0yR6yO7O9Jub3a+VvJoure0UDjW
         8+fhHGe0BxCbqI9BsBmHmNyuJOjw6XbakOjU8Tqaqv0kztW7nw4CPhL9c7l92W/dPWjT
         anrA1wbUbRXSATFHcBhiXzXHab2Ciw45y4cvVbeiBx4P22b6R90x/A6SmsnwZ/5TAE6x
         2RbgdeR1pmw0OxFl9j2H6Kuk+vZ9bitIhHrq+dUUeedJLn5WIpGo4RmgQ3k7APxTYsCh
         JsTk5n6zEV8GwUsmHwGFDTYhsplDFVy9nIKaoZpX6wV0JUWOx0y5OBCs2Vyr9HAQWXYZ
         ntVA==
X-Gm-Message-State: ANoB5pny+jmJh10Bamf4ZtEstQdHVVNFiDmqcLyW9dxhsZ9Hegbn4XZh
	EoV+M9sIx/VKPzz0DvETgG4=
X-Google-Smtp-Source: AA0mqf7lJHQw3ittEqBy6Swcv5LrMEk4VnPlnyj20b71d/Zokz8+aFxEY/RmlYx8fS3z8sc89j/nNg==
X-Received: by 2002:a5d:4090:0:b0:241:f675:c8cf with SMTP id o16-20020a5d4090000000b00241f675c8cfmr14287958wrp.480.1669629062257;
        Mon, 28 Nov 2022 01:51:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6029:b0:3cf:9be3:73dd with SMTP id
 az41-20020a05600c602900b003cf9be373ddls7556577wmb.3.-pod-canary-gmail; Mon,
 28 Nov 2022 01:51:01 -0800 (PST)
X-Received: by 2002:a7b:c456:0:b0:3a5:f600:502e with SMTP id l22-20020a7bc456000000b003a5f600502emr27925988wmi.39.1669629061324;
        Mon, 28 Nov 2022 01:51:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669629061; cv=none;
        d=google.com; s=arc-20160816;
        b=EZpXNFCC023TkuPE37FGqwct0If7DNPTr8orAinWnZZVKQq0wVgGMkk/7naV7rGAnG
         jaJooqz4oyl3v6UJIZZaG7Rhc43rC8GwrJDnPSi5xZUL8JB3uUBZovGp+OchOtff5slQ
         +ez2aOLuZMSA8fc8GNH+WDsLvqUGh83C0HfcPug4CkbFT2lmfEI/5ZokQ75WfbT+dAKx
         DUNqzyEBNt8MYd76ebILyiy4sbfINdE1mJm5Ky1Useik4gsyP3N+hiwjuXVvm+WqYXO6
         owc+zmvsfI7dYSYQLcRNTVFdibaZBtNeeE4WZTLx3Tf9jUhL0j5QAS28xAdE7NpVUpqg
         UuHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Cct04cXs5K6Oma9vXfMm60p6i+CfzdxpxLX+V58OiqQ=;
        b=ZAX7ZakyDaJgpM4M5v1jm/juAUa2y2h54F0qhCdhSBgfk8+f97xIvkOErLPzNeZpfn
         S1y+aTJ1hm/45hY05nPWcFwADdiTn9l4h/5zkA76uKipCUF8wGhuN47e6FTP3ULYQ3q5
         Xh9qxe6ujIJ2UMO3livdVSBedav1ZjvxTCmMevSd/gtqDN6Jl0jXqWmdNGGBlc1312gC
         CYkhsb4cmOdQHYfCMDquy3VJAq4o7EHENK9UOWiBv+sMIprAbaXd9nG3kYC+Q26msy90
         Ndf/jKTSpebVaAWoCyOZrwOeq+rBuLeDTCGSOpozx34eLpDp/wR7jAa5ViswUIvsDtV1
         5FxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F8rWO4eE;
       spf=pass (google.com: domain of 3hiseywykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hISEYwYKCcEnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id bj2-20020a0560001e0200b0023677081f0esi529509wrb.7.2022.11.28.01.51.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Nov 2022 01:51:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hiseywykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m14-20020a7bcb8e000000b003cfcff0057eso3541474wmi.9
        for <kasan-dev@googlegroups.com>; Mon, 28 Nov 2022 01:51:01 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:dc07:26e3:1eb7:b279])
 (user=glider job=sendgmr) by 2002:a5d:6dcf:0:b0:236:78b7:87c9 with SMTP id
 d15-20020a5d6dcf000000b0023678b787c9mr30120679wrz.556.1669629060947; Mon, 28
 Nov 2022 01:51:00 -0800 (PST)
Date: Mon, 28 Nov 2022 10:45:41 +0100
In-Reply-To: <20221128094541.2645890-1-glider@google.com>
Mime-Version: 1.0
References: <20221128094541.2645890-1-glider@google.com>
X-Mailer: git-send-email 2.38.1.584.g0f3c55d4c2-goog
Message-ID: <20221128094541.2645890-2-glider@google.com>
Subject: [PATCH 2/2] kmsan: allow using __msan_instrument_asm_store() inside runtime
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, akpm@linux-foundation.org, 
	peterz@infradead.org, mingo@redhat.com, will@kernel.org, elver@google.com, 
	dvyukov@google.com, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F8rWO4eE;       spf=pass
 (google.com: domain of 3hiseywykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hISEYwYKCcEnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

In certain cases (e.g. when handling a softirq)
__msan_instrument_asm_store(&var, sizeof(var)) may be called with
from within KMSAN runtime, but later the value of @var is used
with !kmsan_in_runtime(), leading to false positives.

Because kmsan_internal_unpoison_memory() doesn't take locks, it should
be fine to call it without kmsan_in_runtime() checks, which fixes the
mentioned false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/instrumentation.c | 8 +++++---
 1 file changed, 5 insertions(+), 3 deletions(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 271f135f97a16..770fe02904f36 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -81,12 +81,16 @@ DECLARE_METADATA_PTR_GETTER(8);
  * Handle a memory store performed by inline assembly. KMSAN conservatively
  * attempts to unpoison the outputs of asm() directives to prevent false
  * positives caused by missed stores.
+ *
+ * __msan_instrument_asm_store() may be called for inline assembly code when
+ * entering or leaving IRQ. We omit the check for kmsan_in_runtime() to ensure
+ * the memory written to in these cases is also marked as initialized.
  */
 void __msan_instrument_asm_store(void *addr, uintptr_t size)
 {
 	unsigned long ua_flags;
 
-	if (!kmsan_enabled || kmsan_in_runtime())
+	if (!kmsan_enabled)
 		return;
 
 	ua_flags = user_access_save();
@@ -103,10 +107,8 @@ void __msan_instrument_asm_store(void *addr, uintptr_t size)
 		user_access_restore(ua_flags);
 		return;
 	}
-	kmsan_enter_runtime();
 	/* Unpoisoning the memory on best effort. */
 	kmsan_internal_unpoison_memory(addr, size, /*checked*/ false);
-	kmsan_leave_runtime();
 	user_access_restore(ua_flags);
 }
 EXPORT_SYMBOL(__msan_instrument_asm_store);
-- 
2.38.1.584.g0f3c55d4c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221128094541.2645890-2-glider%40google.com.
