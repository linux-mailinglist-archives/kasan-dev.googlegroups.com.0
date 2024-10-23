Return-Path: <kasan-dev+bncBAABB5XT4O4AMGQEEPKMJDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 9221A9ACB2B
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 15:28:24 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5c88bde66bdsf3746512a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 06:28:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729690104; cv=pass;
        d=google.com; s=arc-20240605;
        b=c3wlvxAcXA5u+DTtXRmOaEb2WWOyRc2VGE1ZsYss6azkRvtSNsRLD5wZEnQQ30sQyF
         z30CMTZxLQe1tX676auhd4l1PV/JxIOeRlmewGA9+hwQu3T+1BhJrRZoXjjdSTgSjdwE
         XgnDFC2I0vK8pV37ChuST1gBzVxjzF9XcyXTkeD8lNjt1hwu0qXG7j/cP9OJm1vP/xrJ
         dEsNgvC0DcdHUY45zA8TxF5QuCRj3KN8Jr2KJ2EPM7eCXNSnIBXmsAAgK07PjQ7kqJmp
         hdqneBi8floo7BbmpPFpsREg96WOMO/L6WX4a5++f42Vh8dHI/6a4OBu4qVgc2hBLpHD
         mo1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=O5HRGfr4QxfmI5oW9tRHWQ/9F/PZNc7pmKZeF6Ok/rc=;
        fh=R0lQRcqKUvT9U9OsoVN52EFWn1ABTbdgrCg1c42C5bo=;
        b=dMz7MtHSKMbBqVmdqAF8NJDSNn1piOIuu4gDvuJTUi3DL9kszqXXt15u+WCncLZ4Wv
         aal/sHNy1HGo5Uaa9TMG+ueQq4nDIJQmXnCgCUiLTVAT2BNHjJdADKoIyOQL9RhiVkEC
         3q0h50ljl0lUC0u8XhlS78Tv2H7z6i291nvGSYesmL6ryHnYRWzNsM5LfHZHPsXA8NTk
         iF6XSheW1zGM00f1GB5fHDcS1L8g7UJt870FFtZ2T05uyFHLj94tmKhqJev5FMCCqYUr
         a7gD97QuzVIXZ5BciFN/4bz7FCr9xiQC8IAQ9CeAGBowytBKJSrVK14ycsphJ4vMZAiZ
         kVUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b=OudN8owg;
       spf=pass (google.com: domain of dominik.karol.piatkowski@protonmail.com designates 185.70.40.133 as permitted sender) smtp.mailfrom=dominik.karol.piatkowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729690104; x=1730294904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:from:to:cc:subject:date:message-id:reply-to;
        bh=O5HRGfr4QxfmI5oW9tRHWQ/9F/PZNc7pmKZeF6Ok/rc=;
        b=sFT/l7TuqNuGt5/FMCjPBe190RnvyuC5uy6IHTwzyMpXHwKNETO9rXb5aOuHvQc9DJ
         Wf4vSG11mnfMT3jYpcgdq4IeYOYU2W8ZoGUqHsJU9bKWkS+Ip8QRYdP6Ohnf29kc36OJ
         mb2CHhfOFfGPJKjo9/uge3JeP8Lc6CQ9nBOOqkabr//QYlYrWVOK8p2eTO0B5kX77UpB
         gK+2jDI9B7po64W2/gct5vgt+jUn16UgenxSzc8DbpRcgXYE8rzs1AbyB3CWTZV0LP5q
         YQa/VxEgpLd5VDW5xJudICmowF+FYQmcb/g25WzuzXXVFwQwJAsidSeC/PF50lu8umxX
         iYuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729690104; x=1730294904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O5HRGfr4QxfmI5oW9tRHWQ/9F/PZNc7pmKZeF6Ok/rc=;
        b=lq0HW5TfJmhNMPHabUlhCNrM9EhW8O7NTb+q8GOmDFHjnqmHvohb1THjwnDtWjoNia
         /0ItdaioJP/YB7XR9EmhJzhSmoN539i7WIFCn5HmdQGeSVeaa4yA1m4XqVh2F93nKcgh
         +b/J+o72ivsMJCq3oGE+ob5f2nMZnj0doe11rQSA5nL000Cb+yxWHyH0LZVSyonLfcFx
         wsjHEYkaxqnupmWWrhqm8ZnCtt3doWLNDbvBOOCWU+oltEuIFqg96t0PvC7mfjVAGJnx
         M4099VvX1PFE+Nyd8k3RwlaRl9YuQSSA7ZZ3wkLx6ajPJDDico56NgvZAVIJ5s0jTspO
         oEHg==
X-Forwarded-Encrypted: i=2; AJvYcCVmkBv1zvyAZ9u2QIAx/Orq57uPXuFFdOZpfX59xjqUkcEaGgTN8BNk9zjS5ykJmp9ISTOa8g==@lfdr.de
X-Gm-Message-State: AOJu0YwB4sj4GJHidNkWbXKyLpngebrCe4XyB3kY6rFV4IHkxC+NF35P
	mTqzwMG3XAR8AcxkLL9CLjyNQJl6sL2Dd7lhBW9BNgkBSUnje+cK
X-Google-Smtp-Source: AGHT+IE2z7Qp1OEJZeJNB54Iss3czIHWLVrcVOF0nnED9nQHrQe+UX98+7j2NzhbTiAWxfDFSfd5Hg==
X-Received: by 2002:a05:6402:42ca:b0:5c9:6f8f:d7c6 with SMTP id 4fb4d7f45d1cf-5cb8ace953fmr2241910a12.13.1729690103049;
        Wed, 23 Oct 2024 06:28:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d48:b0:5c5:bad2:2aa4 with SMTP id
 4fb4d7f45d1cf-5c9a5958f56ls220928a12.0.-pod-prod-07-eu; Wed, 23 Oct 2024
 06:28:21 -0700 (PDT)
X-Received: by 2002:a05:6402:378d:b0:5c5:cd4b:5c4d with SMTP id 4fb4d7f45d1cf-5cb8aca2dd1mr2200072a12.8.1729690101513;
        Wed, 23 Oct 2024 06:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729690101; cv=none;
        d=google.com; s=arc-20240605;
        b=Z2ERz+1maLcG9uR9QIvj0IkQpW3sJ0WE1k9bsdNTs0IVrFLHCLLGpZo4vvifQu5t0Z
         55lZkvGA9rJVaZn9Bx+IQbebkLfuiRTQCnmPtDSo+ptRYpj7P95eKY6Kri9wthN66tE6
         D4uUBQGhxcQc5rHmLiGxJnQcR2z355Xkf1MjMmQxZWIduqup7EO0+h/+E8gvNCU+I7Gr
         Rmd3FSVRXwn1rc+flXQdZupxeOGeBSodTLqgKnaaDyEUFjE8eeDcxhTdLAPENsyOOkcY
         vDLYQKKMPonHbcsWbaMcADsC09/s3RFrja9bk7EQTFqsFG0I5hACxPKxhYnJKOJSk3h7
         kp/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=3pOFyS/YAsAOctiWACFlhkUIICzQBNJM1BMSEUZeUOA=;
        fh=40lQKIU/V2m1F3dNw3ybzBatITk1I9JwM7qPGaVDTpU=;
        b=eNHlcLKKxiqVtlH+IuenreOIC4KvBVbXrwcemysT38KQgY+7Iu98+tnZGo017jxJKt
         JqVMShwfzb9+y1TEkuVyZaE2y9b37ZKQQVrXPEKvd3PafSdTh7nzzeUt/8I9Wh6xb7kS
         fAZPUycypJYtCG/uZla4hWBi7ZNxqLo/Wfy54jGkSP9GtYTuI9ivgZNYAP5T2nL4rTxN
         NMWIQhv1IlMvls8UJ9xz+y2JVj/ONjGPPaZINC1PRpn64WrAzkqE6jldXGb9OsoMQNnB
         cIPh345/KlSxfhP2NDagMJxgjVlROlBLel0mngjSwdXq+IPMj/J9SxwQAEHk6OQob+j8
         NeHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b=OudN8owg;
       spf=pass (google.com: domain of dominik.karol.piatkowski@protonmail.com designates 185.70.40.133 as permitted sender) smtp.mailfrom=dominik.karol.piatkowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
Received: from mail-40133.protonmail.ch (mail-40133.protonmail.ch. [185.70.40.133])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cb6a5d432bsi232883a12.3.2024.10.23.06.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Oct 2024 06:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dominik.karol.piatkowski@protonmail.com designates 185.70.40.133 as permitted sender) client-ip=185.70.40.133;
Date: Wed, 23 Oct 2024 13:28:17 +0000
To: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com
From: =?UTF-8?Q?=27Dominik_Karol_Pi=C4=85tkowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, =?utf-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
Subject: [PATCH] kasan: Fix typo in kasan_poison_new_object documentation
Message-ID: <20241023132734.62385-1-dominik.karol.piatkowski@protonmail.com>
Feedback-ID: 117888567:user:proton
X-Pm-Message-ID: c0891f609ba3f3fc7d04bab32535c6be1f0bb978
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dominik.karol.piatkowski@protonmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@protonmail.com header.s=protonmail3 header.b=OudN8owg;
       spf=pass (google.com: domain of dominik.karol.piatkowski@protonmail.com
 designates 185.70.40.133 as permitted sender) smtp.mailfrom=dominik.karol.piatkowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
X-Original-From: =?utf-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
Reply-To: =?utf-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
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

Fix presumed copy-paste typo of kasan_poison_new_object documentation
referring to kasan_unpoison_new_object.

No functional changes.

Fixes: 1ce9a0523938 ("kasan: rename and document kasan_(un)poison_object_da=
ta")
Signed-off-by: Dominik Karol Pi=C4=85tkowski <dominik.karol.piatkowski@prot=
onmail.com>
---
 include/linux/kasan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6bbfc8aa42e8..56465af31044 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -153,7 +153,7 @@ static __always_inline void kasan_unpoison_new_object(s=
truct kmem_cache *cache,
=20
 void __kasan_poison_new_object(struct kmem_cache *cache, void *object);
 /**
- * kasan_unpoison_new_object - Repoison a new slab object.
+ * kasan_poison_new_object - Repoison a new slab object.
  * @cache: Cache the object belong to.
  * @object: Pointer to the object.
  *
--=20
2.34.1


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20241023132734.62385-1-dominik.karol.piatkowski%40protonmail.com.
