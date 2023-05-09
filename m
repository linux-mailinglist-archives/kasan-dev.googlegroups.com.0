Return-Path: <kasan-dev+bncBCXO5E6EQQFBB2V65GRAMGQE6UANNBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F8756FC9AB
	for <lists+kasan-dev@lfdr.de>; Tue,  9 May 2023 16:57:48 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-645538f6101sf14783841b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 May 2023 07:57:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683644267; cv=pass;
        d=google.com; s=arc-20160816;
        b=yMnhsJITc9s5FQnmk/B/cl4UM2+Z1shlsTOvbCGa6+MBk8FzCTwxS/GswJm+eB0V19
         xZSTECIn8yxvDDhik8y6N8aGXWfqUo3lCVHjNa859gPLZ9NffU3wOmjW6JkNBR9jF14l
         EOM4Qkc0zloaJbhR36oYetbZMtIWYxBiN7AdTn4gp+bTF5lXZfheWx5yDTDKfh6J+aW5
         B+j1NYqgpO4VqqY1bRHPf7UbcVZH+SVBYvvOHG7q4lldK0xcOxXv5iwnZOCHKk6drh+4
         aBiRTKSbIDUSuWMnEvCNS9aznmPex0ao9QD6j8Vus8QpiYF0CzwrSnqK0u9zKcznp0/X
         HURg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=LtUCHhbdWPW5+/K36R18BTcUQ7fTc+DweO023R14S8I=;
        b=va41F67zAjvcFs04GYhwS/nOZG6D+fC265R43aJe0prf0il45n0XJXKbItrX/WgVWv
         /cccW6243HWRsrr78dsHKx4o86iH/4cvalTsT/0t5Bsz/oiZaEHayx5Isc8s7IEhgXr3
         9qFgwHgqIUHG30533TXFaGq4icX1SWnRdtti6ErGNc1RW35mVKP6F+4WYmbthctDjb5R
         Ftv1WRJLVPmQ12bbWP9odxCnMqPatlHZnv5bzgUhGbpAoEjqfKEc704Z1hO2hHd05qZG
         0cGsYsTQmoAE8/81I+oYEP6vME5kH56tcb2tvCfHmYb02H2qcDR6FfK6Q7cECvTv0r0d
         Buqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dFY7jYTx;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683644267; x=1686236267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LtUCHhbdWPW5+/K36R18BTcUQ7fTc+DweO023R14S8I=;
        b=pJ/Sb9RrYtEXSlAkLSMeXL+9StxuDWuSypzldDMaLNANaP3Led5GMopFtPYJk0tpzR
         7BWCqC3WKPgF2eqLNRJ1nZlLfygqFZ93xdmE/ItSr2TBP2WeGJOotoRISe9NqCFiPFAJ
         CijQ1GnkBrjLwA9X5z4GmGniNauq1pnLfMmuVwg1oXoDJU3oIjWfR+g9+eUKCC8DgvfR
         1z4D4cEVL/osHIGWDQiMtO0STqOUnAxXQRGdx9yKuYwIwqLv3nRToYvnCrpETJPDRTBx
         H/KBfVnECgfHokQKZ+r30iIHhqvLh32sxdUJ+1gTyS/Nj18hS6m9CWmKILcwM46YHi81
         leAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683644267; x=1686236267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LtUCHhbdWPW5+/K36R18BTcUQ7fTc+DweO023R14S8I=;
        b=FsqlJ/PuXUHdYHNGj8uG2wX7UUhZ97cE5OY/a2qaoEodC9I2yNS54Rq7jDXmddwmd9
         0FTKNnqZ2aOdAdtZGui9aXewcUEnYCXsLf2ag6Z4l1tSH9ogWz+gKlmISQnHbbO124gq
         eKrArdGpFlIjP8suRiItHOOQ6VovOQIXLHx8TSGRTRqoFqR5qh4BoJAdGmFIyoARODPx
         +Udf08qMg/NQR5jEiywEsmIuHoGZcajdxI6/Ileo70IVMSoQVUkWAfqo3EiGtOMsLbil
         2JTDa7Q8wO29nUkut+3Ddp/4JJsWXQQd+X3Hsl1zmHlkCPoZ6cL/OmPyxIOHAVOCsJ+E
         yDFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw0pTIRi9k01tQfySx8CRdqqm2NnBMVhPKh4x7jiswkRjruKOln
	RPPzSM/3SWLECF68+01l/Fw=
X-Google-Smtp-Source: ACHHUZ64nRgRhIoEZahhuejRhVKGkvdJFr7Am/GLfxDZQZ8npbUIx0BLrJl5llua3c5kJSLn1wwlcw==
X-Received: by 2002:a17:903:785:b0:1a6:8a07:960a with SMTP id kn5-20020a170903078500b001a68a07960amr5685776plb.0.1683644266684;
        Tue, 09 May 2023 07:57:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a48:b0:250:980f:20b1 with SMTP id
 lb8-20020a17090b4a4800b00250980f20b1ls1099339pjb.0.-pod-prod-09-us; Tue, 09
 May 2023 07:57:46 -0700 (PDT)
X-Received: by 2002:a17:902:f547:b0:1ab:bfb:4b6e with SMTP id h7-20020a170902f54700b001ab0bfb4b6emr19397182plf.31.1683644265974;
        Tue, 09 May 2023 07:57:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683644265; cv=none;
        d=google.com; s=arc-20160816;
        b=ZvEA6z7VSqxvXQLLUpjqmUGuTMbl681svNs7FuMdT3ffn78VmGXkqxDSco9B6UgZaM
         iYElAlWu2BwV5VoS+r1ID/j/92v4H/Gz4H7d9nhmZHUL48rt6fi45x0xcZ6EiP8P6RDu
         RgtTdKc6c4sA782xoSFe2RE6bNY1IQsaHYhggNyl30lB3ANH6yrE3XE+TgdFs78FHAXO
         9EyoQPDBgVo3AH3eHrG53r64sxs8kX0KjPCurPUGUv0BL4oKIcv3MGjTwNgragudR07y
         g58V8EUyKWbRv/yTy1JVh7AGyLrNA66Y+rwoz897J9pi6tt9eftgj2gzmxZkFrwckO/Y
         tAJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ARJHbR0XP6hsc9u2qnJXZgeZBpff6BaM65APFiCJYVo=;
        b=dsFaw9u/Vphl2a5dAeq/3PI6C029S+kF9tTwiDVoI6hjcHYuv3cIeoQErG3NvVmrdD
         vnPi+hZNbYsrT8hpq20cK/zTWpFOEgZkIbo6hF2afeKwNEGAWZmQvWLJf+MCHOGTYhOb
         zqSa2kcb9S9LxX2PHN5rN47aiLNzeo3Y3KvsnjnJnvq6vtBk1YhX7e/pkHX6uhQK0f6r
         JzqXQPS9JgRHff6S9wPCuZ3ebRlXAqjEbtiQvLtCBmyZNIvwPlsO5PB/z5niSngpu98Z
         xu0bcs8vaBUkx25Xch83R6BpNyBjt6WTKHeCrfILZ3q9ybTHpPSZo1nyXHHwZ3IR8hy1
         a5Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dFY7jYTx;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id kk11-20020a17090b4a0b00b0023f99147cfdsi122115pjb.3.2023.05.09.07.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 May 2023 07:57:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 49CE16148E;
	Tue,  9 May 2023 14:57:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1E47EC433D2;
	Tue,  9 May 2023 14:57:40 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/2] kasan: add kasan_tag_mismatch prototype
Date: Tue,  9 May 2023 16:57:20 +0200
Message-Id: <20230509145735.9263-1-arnd@kernel.org>
X-Mailer: git-send-email 2.35.1
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dFY7jYTx;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
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

The kasan sw-tags implementation contains one function that is only
called from assembler and has no prototype in a header. This causes
a W=1 warning:

mm/kasan/sw_tags.c:171:6: warning: no previous prototype for 'kasan_tag_mismatch' [-Wmissing-prototypes]
  171 | void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,

Add a prototype in the local header to get a clean build.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kasan/kasan.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index f5e4f5f2ba20..cd846ca34f44 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -646,4 +646,7 @@ void *__hwasan_memset(void *addr, int c, size_t len);
 void *__hwasan_memmove(void *dest, const void *src, size_t len);
 void *__hwasan_memcpy(void *dest, const void *src, size_t len);
 
+void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,
+			unsigned long ret_ip);
+
 #endif /* __MM_KASAN_KASAN_H */
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230509145735.9263-1-arnd%40kernel.org.
