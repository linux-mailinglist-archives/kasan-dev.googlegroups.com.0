Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6WFWT5QKGQESSAEUEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 34EAC277BDD
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:39 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id e13sf287601ejk.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987899; cv=pass;
        d=google.com; s=arc-20160816;
        b=bxkFVeTlz844KI5r8anyMU6TrnT3MSw0qp9AAHIaw3fpW65/cL0JcynkEKOyJrwFNT
         XnFs0otbIz+0mYrTH7OXTACjBxHJZa+8hN+KS9UbwWUNFykrs3Ype25ZyKJbnRAMa/N3
         FxSZkhsZf8vpqVxD0xpgAhbD7TRUZJ632qqLXRjh2GvK3FLMn+FSJ2JHqlaq759Sqcnj
         t478af6V4RmzUd0qIDemFtpChV4Ef9THFnTI7WlH++X52F2tul1GaTlqtqtqI1/Pbm33
         EhB1Xz0PUMMop5Sbvpbxrp23yulvhXBCAMFe3IAyIJaXkEicDIy4HqGMwp0Lx3AmokRY
         sDIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=eUoukegbckyucQVO8YyFwmz5E5G9tmvjyKiDO8vjUO0=;
        b=UkFqAmhuK0xnfkkRPgoXh5hvCzGnq7KNTzam3TjA9aiOnz99iq5r6ItEWipjDizjwY
         KRTR7HTm/YknTwGXVFmgp9WyCNTgFvv+m+sBbAta7zXgqAEj9eaK7cSHH4HDZBpqEjZ0
         Njzh1Xxg5VbsCFt7lDR0pUj9distpv+O8oktCTY42EikRp6uwpOzxSBSR1UnkYLngDuy
         RsJiHBovPcOE+n/3mBTvIsspPB3d5NFAWkA6Q6SiooElSEgdmzExLJ72jqRDL8Ftr16J
         sBd1uH/roJpvYC4wmnG70j26QipGD2ARbeJCF/kYgaTFADX06AOxhq3f0Y5Z9dP2c1tj
         o8uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pi/15Azt";
       spf=pass (google.com: domain of 3-sjtxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-SJtXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eUoukegbckyucQVO8YyFwmz5E5G9tmvjyKiDO8vjUO0=;
        b=UmqPER9pcDe81CRFXXIn6rszuMxSB5LQKP5Nd3z6yvKtf4QVgWDIyVvBeS/ruoLl2y
         dgdLXFb0bmFXw6HaSViFXqVefMxQMUuZ89kc3hYUya8ljhbBspB8qX/dBOt6ujDSyK3m
         cFxUDbrVGV2a6SF+euZ3KG9y6zgcH8l1tAWdt27NZIbCla6aCEEUfdf7rJos++QtBD4B
         1AsNSGelwGsbI2zJ0VLCRtRa7+YomFmbFt4FX65W/pJtvG0plNrxwqX7i/84rBueE6yD
         K46+J7s5rJixbrhnqQtjg+KT5fLHOYihm/MoIGOJHKlPNBP+DVsxutd9kQvaKhK5UDHC
         JuQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eUoukegbckyucQVO8YyFwmz5E5G9tmvjyKiDO8vjUO0=;
        b=WW9UelVgQEVlfZKw7FM1dhrH5yTYIP4pzzRTEuuD4con2l50AejmurXi+l50akiQEc
         /p371ds0HyKh5lOr/Lf8Dj1H6ZNaUC+ifHhYAkDnTsgRhHb2B264TKAJwkLr34sxL1zb
         Onpr1iKEL68kpQo6OfgzZgm2F6wjtG1y/h7YcLK+VuQcs+7Tq6/PUv/VghkMM5AcZZbh
         vrT209oZOG3gPQUJ0d30vBINV4E0THEUzGvlRu3tr4CgczQX62qTIcuotpnPcyImRi3Z
         JzIrpKbp1bhDO/ysDfTohj8HbkTxBPYAD0eX7VyHQt/ZUZ9mStQi7dw5+EDf1xxfY6Dt
         LOeQ==
X-Gm-Message-State: AOAM533VTqRQNIPEEOLs2FLjdEoXcC6D2FNPsX3KSbdwetre8jSe7KnE
	u4bxS5D+zv7keUlCg94LS0M=
X-Google-Smtp-Source: ABdhPJzR9b/itWySiV4YeX5LprazaYI3R+i9BHs2vTG+rHj5Q+N8BV4iKaTogyGbJNuaA4bDzg6LEg==
X-Received: by 2002:a17:906:4151:: with SMTP id l17mr940695ejk.116.1600987898952;
        Thu, 24 Sep 2020 15:51:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c545:: with SMTP id s5ls707927edr.3.gmail; Thu, 24 Sep
 2020 15:51:38 -0700 (PDT)
X-Received: by 2002:a05:6402:3050:: with SMTP id bu16mr1014905edb.343.1600987898085;
        Thu, 24 Sep 2020 15:51:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987898; cv=none;
        d=google.com; s=arc-20160816;
        b=XLyw/3YEE+wmpj9t3IHAjukNXW7jllL8eLQZNTqyNzxnugN+byw4R3LCVqy/fQMIbD
         NNT9Av1Dk+uST7VgMl4K568LTnL7M1aMV0sRtd9JWgjFo4xzzY6QHdhorTcOl0nbQrTR
         qfW/47n7paVQP1NoJQp8S0gP0jHs+iP57VYAejvX1s+L9TDV0njeDawT86LRKh9AAYaj
         Ah5iyI+axzMblb23UR62NKdFj8A6aMRzkWcRL6Hhv2fhkpRe8IUba/HT5EotQHAes3c7
         T3MwZbgH/o762ZMWGQl+IxFqyf4esrtRIhsQaO0jGokzUHWLnyP/n8dt42brUfBxYaHV
         CZqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=6hEKAMD+f8HNSFJwh5TzY+nY9DWh+cKlQh2Jz/ohGSg=;
        b=Da5n6JGs8SecWFD0hzU6f8dx/UEAGMQh5kXBgnqqWpZC9DxoqyC4bCG3jY0gH5UDkf
         lctWEzCJoyIB9YZdKCukv9Lm+1CMRwA9RPUEE8mCMQWw2LgDdSXoJUmlrft+ofK7MvnY
         1xpTAP/vFNzPaHkJ2b8Q9YNRdvB8JjVqGDyOAgFWcvlgYMsVEGH4D6XZGaNX5480lc8P
         CYUYOZzZAUXOKCFEc14aKWs157TxwKmj8WTS6+ZO+Sgg21GG7YcMAZED321itVQ8Ku9a
         t6rzcjCFpA/QwI15LM1ji+aHw+NFrNk9mT62k0TkJmmG9xlrOvXzPDxwGe6BAyyKW/dc
         RILA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pi/15Azt";
       spf=pass (google.com: domain of 3-sjtxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-SJtXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f17si19218edx.5.2020.09.24.15.51.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-sjtxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id x81so316144wmg.8
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:38 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c4d9:: with SMTP id
 g25mr846564wmk.15.1600987897744; Thu, 24 Sep 2020 15:51:37 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:26 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <cac8b9713e5d3ac1ab767a9cc42c61b04c46bdfc.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 19/39] kasan: rename SHADOW layout macros to META
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="pi/15Azt";       spf=pass
 (google.com: domain of 3-sjtxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-SJtXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
these macros. Rename "SHADOW" to implementation-neutral "META".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Id2d836bf43b401bce1221cc06e745185f17b1cc
---
 mm/kasan/report.c | 30 +++++++++++++++---------------
 1 file changed, 15 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 67aa30b45805..13b27675a696 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -31,11 +31,11 @@
 #include "kasan.h"
 #include "../slab.h"
 
-/* Shadow layout customization. */
-#define SHADOW_BYTES_PER_BLOCK 1
-#define SHADOW_BLOCKS_PER_ROW 16
-#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_BLOCK)
-#define SHADOW_ROWS_AROUND_ADDR 2
+/* Metadata layout customization. */
+#define META_BYTES_PER_BLOCK 1
+#define META_BLOCKS_PER_ROW 16
+#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
+#define META_ROWS_AROUND_ADDR 2
 
 static unsigned long kasan_flags;
 
@@ -238,7 +238,7 @@ static void print_address_description(void *addr, u8 tag)
 
 static bool row_is_guilty(const void *row, const void *guilty)
 {
-	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
+	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
 }
 
 static int shadow_pointer_offset(const void *row, const void *shadow)
@@ -247,7 +247,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 	 *    3 + (BITS_PER_LONG/8)*2 chars.
 	 */
 	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
-		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
+		(shadow - row) / META_BYTES_PER_BLOCK + 1;
 }
 
 static void print_memory_metadata(const void *addr)
@@ -257,15 +257,15 @@ static void print_memory_metadata(const void *addr)
 	const void *shadow_row;
 
 	shadow_row = (void *)round_down((unsigned long)shadow,
-					SHADOW_BYTES_PER_ROW)
-		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;
+					META_BYTES_PER_ROW)
+		- META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
 
 	pr_err("Memory state around the buggy address:\n");
 
-	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
+	for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
 		const void *kaddr = kasan_shadow_to_mem(shadow_row);
 		char buffer[4 + (BITS_PER_LONG/8)*2];
-		char shadow_buf[SHADOW_BYTES_PER_ROW];
+		char shadow_buf[META_BYTES_PER_ROW];
 
 		snprintf(buffer, sizeof(buffer),
 			(i == 0) ? ">%px: " : " %px: ", kaddr);
@@ -274,17 +274,17 @@ static void print_memory_metadata(const void *addr)
 		 * function, because generic functions may try to
 		 * access kasan mapping for the passed address.
 		 */
-		memcpy(shadow_buf, shadow_row, SHADOW_BYTES_PER_ROW);
+		memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
 		print_hex_dump(KERN_ERR, buffer,
-			DUMP_PREFIX_NONE, SHADOW_BYTES_PER_ROW, 1,
-			shadow_buf, SHADOW_BYTES_PER_ROW, 0);
+			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
+			shadow_buf, META_BYTES_PER_ROW, 0);
 
 		if (row_is_guilty(shadow_row, shadow))
 			pr_err("%*c\n",
 				shadow_pointer_offset(shadow_row, shadow),
 				'^');
 
-		shadow_row += SHADOW_BYTES_PER_ROW;
+		shadow_row += META_BYTES_PER_ROW;
 	}
 }
 
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cac8b9713e5d3ac1ab767a9cc42c61b04c46bdfc.1600987622.git.andreyknvl%40google.com.
