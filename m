Return-Path: <kasan-dev+bncBCKPFB7SXUERBQX25TCAMGQEDOSRX4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4250EB227DA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:10:31 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-76bca6c73f3sf10299052b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:10:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755004229; cv=pass;
        d=google.com; s=arc-20240605;
        b=JWrZEbQucCCAHD5VUdOCQGDZkojG7s1/hR1eW2JU9QTNHODEE7LRMZiUla86Mf2vhS
         r9yFyQ+6BW9jYkvWzMkeXdHFUxbQENy8u7YapFdd3k0RStXTJiJRzOPL2o4KVhWrGgcn
         5khTxb/+NMfzVrdb7yY3PeIptvQXl5Tb4p4wHwqTkY2d/HI7OsyD6zEfJjlYNA9FXufO
         xf/xqcL+N5g0tYgmRAzBjxrPvCWIdmBGgqPzgFWYY/0HBuZ73vKemTa4/LPoDMkN9sFe
         yw3whbuZ1qWwoAwDyTvQ/Zzp1AjSsZx97oSzomIuCZ9RNZqxC4WbYTCCn/xpAfOORgO3
         fixg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BamFcYei1jTm5rW/SsS1Vp3c84qWL3lfdvdHtpeBiIc=;
        fh=v5Ff1XjsnIpm6EnH/H/G7NQuGcYS7ZKRksj1FOy6NBI=;
        b=KVE/3+rvreaJh4Avp32MQK46R610w5mqd5iwHnZo+urJZt0TvGB7DG+D6zResTZGaj
         g67T4VYhFwu+gLI+wX1vn/gxY7fTJdlXtcfqyx4jZaATJdL5VpRfiYvZFFz7TFqsv9W3
         PWhoJb6mvw66CeCn523DnMCrVIMU366iI5sJPmbwhxYBJtB8ggaIBeOm7m3sun7Aal/k
         Wu2GiNxLTvnmWYMOTclyxehM47Amonv7nEB7qr1666IjNnSjhWhSRLlFxWJt2fuv/pLI
         l6sogxy1jSHCyztgR4zip9qbpOB9sWmaaSElzaiS7adVe+hlis6GMnl+4/tv6tqjtkXE
         kcdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AjFMu9mM;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755004229; x=1755609029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BamFcYei1jTm5rW/SsS1Vp3c84qWL3lfdvdHtpeBiIc=;
        b=nWb7cnWLGm2yP9iW+4zJQuhNLXbL2v2/X9Hk58sZBENe0P81Ovu3EWN27++7+FymFF
         Thvjl7T9/UTFM2xnR8UgWY6MkOu4cy9x2I7tgwUZifA3zE8cDKvWyLqTJTiz7IVZYWRO
         uFWs+Yg8VdLE5Kda8e+ew7ap94vBc4A+fylPF+bq0qY8xzg1yPSBJt5LFB6PrkDt5Hb4
         PTtOaSNyl1s3VQnXXc25GBfEjdrHB9j5ePXb7ZFtu1jHuca0xHXqhmKCkFsT0/bqklVF
         z5NcrtIfy3QxKDzvUuXPT1MAZfaEcH4MsW5lJV63cqNNaSfyFaXVEOcuq5u//YwLFn6+
         l20Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755004229; x=1755609029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BamFcYei1jTm5rW/SsS1Vp3c84qWL3lfdvdHtpeBiIc=;
        b=jj2elOsycF9oXg4kWu3sLbjvsPNYQpL1LZfkho84aFuT8Y2PkW3Kg6C2PqBbCzwk6H
         q61o7JO+wS0dmKw1uhLgvlnhrE1QdygRQOTKE9/ZJuBN+CYZmsGghe8/GIETdGBvbTp3
         9PjNbKwZSHO69k9IXUu6CZnDOElFwnz1QZv1Wpc9C54OZlxAWucf1JaVomecxPDplu18
         k98ChpcGNFpDU21TvJi7TXLUMeK3DB1nfaEX8QoTMD69ejY+wnJKp28h8aJ5gKlXmAr+
         7O91QuS4kBcfdfsY7g6zpvZgcMW5A2TSX/EMi/mlLzgdjUAROt2ozshQUFJb20Gh6LQt
         itcg==
X-Forwarded-Encrypted: i=2; AJvYcCUo8GZaFtRxDh/FclQaIJrCxJp3xlWbHvrp5JjyruT5cF469Bg+YEg+0jbnzWqrS7zCiWFbAQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZyXFg4Tx7pStnHCIDiArwBrwTHKZLZ7NyZ4FTtx5NQ8jIP1t2
	0MO+ybLyuJ+2cEbRN0HrOvkC7S7v6Wgry7o7qKkZijOs72Q0r1C3ls5W
X-Google-Smtp-Source: AGHT+IH0bJUOJlZ/Wl42HQtAL1ZXzJYD/0MyJ4XIhwz2dDHZm1Qm61eQgwg7MUL9ezT9SO3//u9FrA==
X-Received: by 2002:a05:6a00:2d9d:b0:76a:d724:d712 with SMTP id d2e1a72fcca58-76e0ddf2f98mr5411790b3a.3.1755004226911;
        Tue, 12 Aug 2025 06:10:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeHwFxyfrfS3mj9ABPAtLpCKBZcJBlurdoM4gqXaMlMTw==
Received: by 2002:a05:6a00:3d47:b0:730:7e1b:db16 with SMTP id
 d2e1a72fcca58-76c36f5a71fls6205942b3a.1.-pod-prod-06-us; Tue, 12 Aug 2025
 06:10:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuoWDahZpjLS/lI54CLVWJVetyoJ3ZyijPKpHoiRwZK3QfX/xVfDpNSW5OlprlyiGkZuab7FmVmCA=@googlegroups.com
X-Received: by 2002:a05:6a20:a10b:b0:240:7ed:402d with SMTP id adf61e73a8af0-2409a9934d4mr6607992637.31.1755004225559;
        Tue, 12 Aug 2025 06:10:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755004225; cv=none;
        d=google.com; s=arc-20240605;
        b=DjDaPCQHRYyNlHM4wtoRzU+3cJ27DM8nFeIuUKSxVGPHHR81Mr69ZOUQmq2ldPqp7E
         KBX2+HnYt7U5kmXMgAdNAH2W+ViBk5QJgndxlmjCUlcnxOyzjgXscl6R2pNsrbp/e8fL
         p0BE8z/l27IQMR1idFBkEGyFGv+M15bEXpot+rmUh21KVr4cYjbkEcKPqvLeAa12Eo3B
         fQfle12RifF57LIpCk2fR2zkqX7qPaO2IgZlVJHBhvti794imE8s2rt+/6KCJfW0UjPC
         OtAiSC9psXd1BNkYDQwqf9gbnDWbe6mN2rVv72J7J7jQuqLBeshKvpcUCpQ4AywF61hH
         3G0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Shp71aTpcjkRwp8fdFozCS7DFDAA9ma8z9v4/SjxSDw=;
        fh=tJzQ5qxkJm0zG4QpcVmXzoBYu5DFFVue0Z3QtfeLqEI=;
        b=UgDhVnBuLJ5Hff5jkIfVZZkvMDtKfSGTAsviw3k6XkAfkBX1xiIvY7Pl/5BWvN5Q69
         4alfdcTB1RBbQkfQP89Lxlv9KS6vEOHDfZ1PO5sFyoXL+t4L1EGWcDCqpt7aRvRFxYY1
         Sb/1LcyvcUSdts4YfwZdy8NOPgS8zYiYCbNb9EghjWYkImA84UhPlhpkP2/Fv38MKXAp
         figaHvbE3Hnz32uaPDBDKnTzYuUOcpSVEblgIjj6lX6IQ2qrr05xhLXm/avZZl9NY6av
         OiYQGKpoOqazkg0Fwv+zNhjuHvtrBZxU1fhhh/hkE5fXcXmvh8pEWpV82WtN5QCluYtL
         5rRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AjFMu9mM;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b42a1fb15cfsi407254a12.2.2025.08.12.06.10.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 06:10:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-584-DibAMnFxNhOH8o8J4OV6gw-1; Tue,
 12 Aug 2025 09:10:21 -0400
X-MC-Unique: DibAMnFxNhOH8o8J4OV6gw-1
X-Mimecast-MFC-AGG-ID: DibAMnFxNhOH8o8J4OV6gw_1755004218
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id BD2F4195608A;
	Tue, 12 Aug 2025 13:10:17 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D4E08195608F;
	Tue, 12 Aug 2025 13:10:07 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: snovitoll@gmail.com,
	ryabinin.a.a@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	chenhuacai@loongson.cn,
	davidgow@google.com,
	glider@google.com,
	dvyukov@google.com,
	alexghiti@rivosinc.com,
	kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-um@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	agordeev@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 3/4] arch/um: remove kasan_arch_is_ready()
Date: Tue, 12 Aug 2025 21:09:32 +0800
Message-ID: <20250812130933.71593-4-bhe@redhat.com>
In-Reply-To: <20250812130933.71593-1-bhe@redhat.com>
References: <20250812130933.71593-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=AjFMu9mM;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

With the help of static key kasan_flag_enabled, kasan_arch_is_ready()
is not needed any more. So reomve the unneeded kasan_arch_is_ready() and
the relevant codes.

And also error out if both CONFIG_STATIC_LINK and CONFIG_KASAN_INLINE
are set at the same time as UML supports each of them but done's support
both at the same time.

And also add code comment to explain why static key kasan_flag_enabled
need be deferred to arch_mm_preinit().

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/um/include/asm/kasan.h | 5 ++---
 arch/um/kernel/mem.c        | 6 +++++-
 2 files changed, 7 insertions(+), 4 deletions(-)

diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
index f97bb1f7b851..b54a4e937fd1 100644
--- a/arch/um/include/asm/kasan.h
+++ b/arch/um/include/asm/kasan.h
@@ -24,10 +24,9 @@
 
 #ifdef CONFIG_KASAN
 void kasan_init(void);
-extern int kasan_um_is_ready;
 
-#ifdef CONFIG_STATIC_LINK
-#define kasan_arch_is_ready() (kasan_um_is_ready)
+#if defined(CONFIG_STATIC_LINK) && defined(CONFIG_KASAN_INLINE)
+#error UML does not work in KASAN_INLINE mode with STATIC_LINK enabled!
 #endif
 #else
 static inline void kasan_init(void) { }
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 392a23d4ef96..d62f494e0808 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -35,7 +35,11 @@ void kasan_init(void)
 	 */
 	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
 	init_task.kasan_depth = 0;
-	kasan_um_is_ready = true;
+	/*
+	 * Since kasan_init() is called before main(),
+	 * KASAN is initialized but the enablement is deferred after
+	 * jump_label_init(). See arch_mm_preinit().
+	 */
 }
 
 static void (*kasan_init_ptr)(void)
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812130933.71593-4-bhe%40redhat.com.
