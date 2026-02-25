Return-Path: <kasan-dev+bncBCKPFB7SXUERBIW77LGAMGQE2EOU34A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CGu1MaSvnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBIW77LGAMGQE2EOU34A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 65948193FFF
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:32 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-359124b11easf392465a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:15:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007331; cv=pass;
        d=google.com; s=arc-20240605;
        b=APPeuBkHyfpcC01jRiwslcJGBshHaaAgMYCOQwW4Zjzqa9UeNl9DnLV3gDpTl3V9cR
         hFKBuzvv7vlo89kO+V2z3gNUWU7CwUg4ymWs6H0KnE7KGAmj8Zch78gn4T4ARKkm93Zc
         UiGg8dRh2SxFXOxXP8PS027OIasnu00R2lOO8R2yLtZENRDY+RHzgPg2TyyNLF432sKC
         HsmVJZD/Hht9V4ZBj29OW3oKyC1Eoqf6bOwEC+tMVHN3SGuVFbgR32E84+IrOsyGfKAY
         fThSUszca1XP/LTt7n5nY015yhkdYzIiLeMAXFUII0stHm9xBQ1e/1vqysj7ujn8qH7s
         J6jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=EuqM1WrEuZ7HxOlOQLvC4j10yP8o4n8t7fjpbjRVNkU=;
        fh=iF+jTLioRFC3LqUa4bGHItx50anPXkI6FXSE2AYhDJw=;
        b=eXdEOiGDr5WlacOVT2lOQkQyrdQpHX6KtHzNz9pMlBCNL5fkziYSSS41MrjkJyiTew
         UASpv87VQzRtgdp0Sxp6PMPdR8SvThjfSqcl9l8X9wOLSMrxZ8MzQbMmk5862ud9rAta
         wE3DkOiX25YZpAFIszG+iMwg2alJff909jfDOOyaVOitZsLtlxZ0CWB9qBg1uaQAR3v3
         pCrJdBkrRbAIwokQ3TSpiAvKa70rAu0qxb4EFMu6+fHFe46sBkmP0KyQms+30hhrHDpO
         BOQ02864UPY8NIYjj/vtGp8oz1TYIS6AGl6Vsmp5zTYIphVHgaIryq+PdJRxq0J3TBFs
         aSdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MT+52IIn;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007331; x=1772612131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EuqM1WrEuZ7HxOlOQLvC4j10yP8o4n8t7fjpbjRVNkU=;
        b=TFixgN8oYJPJXqo8jQfle2F3+NTB7gs5Wwf/781hU0kEq++bm0pjl7jURnz+qryICF
         yk+hempc4xkLd4Wi28wASUh91XXDj4sVA8ZTs0+EW+BAhRnfuUSnHMSkudlRsPaTKH0l
         dGLHMGyAEKrasA0b2mlSxONdZQMflg125gnmUVuhsUUyI4W97xGrx3o+RUyyRREil0l1
         MiK7HtxGF7VpWfituseNXlOgETYGS10hM+6yubv6gv17GLwvj61SYoEVVrbwMCPPbOAs
         21E3nNYNDDxsSVCVj+GNvEfC36Kdo6VILMSGvpyRjKNVujcEAA6Rkn3+mNfTzDfluSjw
         iXrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007331; x=1772612131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EuqM1WrEuZ7HxOlOQLvC4j10yP8o4n8t7fjpbjRVNkU=;
        b=o8jhgYF5ZeSV469YX1vCl5XOIt80ql82wXDV2EhHoyDk0aX8qsRjYTTFCwZ1Glenum
         +oU7IylC78zAzuSypypu1Am2CTNpM6k5nCsYHgCotAHgy5a04sCGITpYRSlUeR/1pJ+f
         HDmauQe9UcBEEBz/bubcPeMCksQLhtStuk2np/3Le41qti1yIocil26O/47fulsDtLBV
         A6tKH8UCdZHI452NztOCmgYiV2tN6n/Ic04AlNaltnsw5Ju0sWhtnz0GkxUX5un9wWcA
         ghA6bPU7GRmNvT2aQDp4k6LB13YlSo3Ed6zQ4JoGdigKHfqG5vGl2Fq3AO3I7kE6nFI5
         H1+A==
X-Forwarded-Encrypted: i=2; AJvYcCWx+CQQskKkyI+WinbnGOxgPc3Lccavnzb7qc+LAih2a4BkfB8LRGAVOlld/S559YnZrUEvLQ==@lfdr.de
X-Gm-Message-State: AOJu0YxyHYiIJGDIS4YXNh2WRy+YCnYwH/JRln34aRGNUoXZaaPH+SLl
	mpiLGwl9r5lyeeu4NHtpQ2oKG7A/wUraU76/aPR5P2C1I5GrO3a3hGy6
X-Received: by 2002:a17:90b:562d:b0:34a:9d9a:3f67 with SMTP id 98e67ed59e1d1-358ae8dc5c2mr12885488a91.33.1772007330648;
        Wed, 25 Feb 2026 00:15:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EHRmzzPnsz7j0LiR0Ey42E9mH8haX1e0L4lczCP7x/dg=="
Received: by 2002:a17:90b:20e:b0:34a:4cd5:6c28 with SMTP id
 98e67ed59e1d1-3591075c2a9ls411711a91.1.-pod-prod-01-us; Wed, 25 Feb 2026
 00:15:29 -0800 (PST)
X-Received: by 2002:a17:90a:f947:b0:356:2bda:a857 with SMTP id 98e67ed59e1d1-358ae8a89cemr14818761a91.18.1772007329310;
        Wed, 25 Feb 2026 00:15:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007329; cv=none;
        d=google.com; s=arc-20240605;
        b=THH6+w19rnvNmWDB5G5VsWJikee+eYgyN2aocUZnxuZv5rTNTIY6GOq+ZaK3UzYCTR
         b8+m7tKnu8I2CTtlqcOhNZb/iYFabI+Htne+AxtyvbIOHsP+aNQTkpdUIw8njUI6GuqK
         Q/Gk6bEG0ujQ3Ml5u+UmhPX08ix5rreXfZqUDmIxNISBvyfuzczcl8z7ww/jfI3ERjiz
         51cC+tmcB2qUgfPuoq5lJ5dqLJuddqi4J2Kf5kFf+s9dT4EWPITClKCR7AZ47NabFGbT
         hUzMKTgWcjEd4rdaMyrval7Pqy0QBdGIOcNqdFPhLd5vjBvd5D1kdhPc9LZS/CKlAslM
         7agQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yJ/15auNTcs4bEnKE4TKOadihs1pA/T7OdgqiTtaDyY=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=FrXGRtpx2QpgEqH6+z6KG4QK8Zh8kPzHEBaBAiR4JscO3IBfP13fp4MnE/ODfjgzyg
         Wxa1OoKtDWhyWuEvKQpY9U6vTuaYHyg76rQeSQi0XCxOGbyBGf+lZXK5Z8Shqh0s0gIn
         uoKlGIYZANaZa0L2K4eFC+CR6qGagNmwA1FqxPBFMPSMIGOJ8Hye2rEiIaLA713/GEwT
         cO//eLgWStF8I7t7N1zhKrsWBLEhDpYVvHfBjhV8XBtT1S1/WNXEJmmB7ddYy4bTnoPg
         kytV2u0B+q/1H4ND25Nyi1I0LR508iTYEjFsJOkKf7nhWpxJ5RL5ErXhT2SxTBVncgRd
         C4ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MT+52IIn;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-359018821cesi74676a91.3.2026.02.25.00.15.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:15:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-110-MO7Loi8qMuGy7jOa06YqRg-1; Wed,
 25 Feb 2026 03:15:25 -0500
X-MC-Unique: MO7Loi8qMuGy7jOa06YqRg-1
X-Mimecast-MFC-AGG-ID: MO7Loi8qMuGy7jOa06YqRg_1772007319
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 320AA1800349;
	Wed, 25 Feb 2026 08:15:19 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id BFB231800465;
	Wed, 25 Feb 2026 08:15:08 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	x86@kernel.org,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	linux-s390@vger.kernel.org,
	hca@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v5 04/15] mm/kasan: make kasan=on|off take effect for all three modes
Date: Wed, 25 Feb 2026 16:14:01 +0800
Message-ID: <20260225081412.76502-5-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: 5e2h8QyOUabli2-czRyHdQRDs0hKFCuOJ8pwMLGMgQo_1772007319
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MT+52IIn;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBIW77LGAMGQE2EOU34A];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.981];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-pj1-x103c.google.com:helo,mail-pj1-x103c.google.com:rdns]
X-Rspamd-Queue-Id: 65948193FFF
X-Rspamd-Action: no action

Now everything is ready, setting kasan=off can disable kasan for all
three modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h | 12 +++++-------
 mm/kasan/common.c             |  4 ----
 2 files changed, 5 insertions(+), 11 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index b7cb906825ca..cec21a08446e 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,10 +4,11 @@
 
 #include <linux/static_key.h>
 
-#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
+#ifdef CONFIG_KASAN
+extern bool kasan_arg_disabled;
+
 /*
  * Global runtime flag for KASAN modes that need runtime control.
- * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
  */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
@@ -25,18 +26,15 @@ static inline void kasan_enable(void)
 	static_branch_enable(&kasan_flag_enabled);
 }
 #else
-/* For architectures that can enable KASAN early, use compile-time check. */
 static __always_inline bool kasan_enabled(void)
 {
-	return IS_ENABLED(CONFIG_KASAN);
+	return false;
 }
 
 static inline void kasan_enable(void) {}
-#endif /* CONFIG_ARCH_DEFER_KASAN || CONFIG_KASAN_HW_TAGS */
+#endif
 
 #ifdef CONFIG_KASAN_HW_TAGS
-extern bool kasan_arg_disabled;
-
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return kasan_enabled();
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 0d788a468e96..fc6513fa5795 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -33,16 +33,13 @@
 #include "kasan.h"
 #include "../slab.h"
 
-#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
 /*
  * Definition of the unified static key declared in kasan-enabled.h.
  * This provides consistent runtime enable/disable across KASAN modes.
  */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL_GPL(kasan_flag_enabled);
-#endif
 
-#ifdef CONFIG_KASAN_HW_TAGS
 bool kasan_arg_disabled __ro_after_init;
 
 /* kasan=off/on */
@@ -61,7 +58,6 @@ static int __init early_kasan_flag(char *arg)
 	return 0;
 }
 early_param("kasan", early_kasan_flag);
-#endif
 
 struct slab *kasan_addr_to_slab(const void *addr)
 {
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-5-bhe%40redhat.com.
