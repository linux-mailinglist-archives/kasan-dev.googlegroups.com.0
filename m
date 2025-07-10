Return-Path: <kasan-dev+bncBAABBJ7CYDBQMGQEHZ7HBIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF2AB00DD5
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:31:20 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e819f9b4c4csf1745573276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183079; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cpc9lhZ4XbYmFs5jtlXQSDebD3Lvi3zOcItVYu1miFTao3w1sSXAe5Tprvh6WxFGIj
         Jm1iCMkYPLBkz/OTMk4runbEySMUiU+//tAsIphvZ17lLJdLVIWsohS2rEt4+sDzAvxd
         JD6GZDfNWLz9oleCMn+etGt2HN3rKpVml546odWhkpJZ0h8N94RVqAr/VLPOphSNAQt8
         V7kEicfcX3eF4BWhApdzCM0GQ22E3fmxxWTMTsyiBPBVP2lNMniludNK+l4xDGxcW+z0
         gvGH70SgsuDU18ArHtj4y9gF5Uihzt5zbwQRta4EjFpluuYxRMluftjHlngCpM3CHzme
         CrLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=VWHPpFs/H4jR+5+WdfW0WUDC3MHTxmZe+iCMs05NWVs=;
        fh=fNKdtU0jS/hcPfdEk5un5900dzKKUywdw9elox9qWlo=;
        b=A20l7TccjsgGGEIJP8CLBJQqphPSraoPK8HgB1oZVPORVWwHkFXUYoIz+dmkYHqGHh
         iNyjKB1Ae+mtLJC4sN/JNfOFOHEn1T8P6svveC7tEP/tBNn42Xzhoja0V5mpNRfnYP1a
         Ljog3Am0FDaLlR7IOVWor7rWSF1ynR3d5k4/mAfMySohJl2ferGj1AIqsKwDc22o+y/c
         Wlsqx7Qr8mKu+4nxDKz5hfgcdLiX57evltzaahafKbBfHc4/ZRCRfpJ4tcCHEt1yvoxY
         b4KOS8bEy4nmKEacE4m7nleNK9KsCDYODqNqKoSUXOo78sTmHnzCJsd7ADEejPDyfsiR
         3fpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lWuo1Zql;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183079; x=1752787879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=VWHPpFs/H4jR+5+WdfW0WUDC3MHTxmZe+iCMs05NWVs=;
        b=KVHJaMKZGZkML3u3c851pAWNDJbM0Sl2vmdu3LvBjcccOPgH/DgiJuJQ02DgQ9DHbw
         a5QI764uUVWs9VS4JQpRwit8oUVNTY8EInDCpSPyrMmTaEc5cc8T6iXJumRD8E5WrNlJ
         wOQ8L2YKgUk5MU6xsI3v11YGQOegobVlRU2/C6JfMXNJvTnRI8TF3KPPqObP5z4w3dHW
         bgnOV6821ppOjyGhL4QQ5ERLWQ7eCA6W0vExiDDfMEf62DE3zM7KtdUgY7TZGWIaSV6T
         fqSkJ4x/3NDlbxp05vR6j51zC+OenPNg96R8N06G4kqQWdmJUnxYQT4MIfEvYOkRmzcf
         c25w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183079; x=1752787879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VWHPpFs/H4jR+5+WdfW0WUDC3MHTxmZe+iCMs05NWVs=;
        b=Naz+1ZEw7hgrmQP/sJmKtIb4vB/tFvDLEZzJv18UFdGeTfHiMKX2mJ1EzGrsaLYNHA
         oaeaCo+Y3sx+LC3BcZrKk+4hKNwZqV9J1pOpWYkMOah4dh0Od6DA7L7XUKmcBdRyuP8V
         xOPf/4ISMJ30rlNoagRY9viaPeey4TpBjMOofnvON30/Xb7/uPHxpvGnVT0wuZXgDRiT
         MYh5ktY2I4Z1CYvamKu40Hdsw0xBkrXUWAk2Ll33o3AoFumgKebuday4Zwi/hqQSJGeQ
         /krbsf/M4/X2tSsWinfQupjb7KAcJC8hPVucglVVFOfzmTqqTpjHVGLj7glDqjlA5QLo
         iFew==
X-Forwarded-Encrypted: i=2; AJvYcCVwnqYIbAyoTTaWtCt6pP69OjNsxCB4wkGf0Xz1FSiG27pCsFQEOwNNyI6RD1LZ+atpqvOr2A==@lfdr.de
X-Gm-Message-State: AOJu0Yx0UMP/G8LsDbwFTwQ1+XlALmBzfHqfnaweaormtnvigzwupFWV
	yHtB7InSLzyOOwRn91Yd6Vpd05b2IW6sFEznSIfPWN9DVphVWwATOJmA
X-Google-Smtp-Source: AGHT+IERuwGMMQJ3U4pe8VJWPkmWUBX8GP3NjrISM4bLKgYFJBGHgbDgD1Ie6+1o5jpa2M1A/tlX8g==
X-Received: by 2002:a05:6902:1285:b0:e85:fb90:e7f3 with SMTP id 3f1490d57ef6-e8b859f0683mr877306276.6.1752183079348;
        Thu, 10 Jul 2025 14:31:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeisBPC5kKDLzooIsYhUwrK7+eIMoyW7vHHCgpf2/CytQ==
Received: by 2002:a25:f607:0:b0:e81:7cf7:5008 with SMTP id 3f1490d57ef6-e8b7782ef4fls1517800276.0.-pod-prod-03-us;
 Thu, 10 Jul 2025 14:31:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV08kCgoyeK67pLIds5iJNyTcHkI5wAFK8NiKnHjQJ3gR7I9fBM312Dpda4vF/h6q04+/uebZ0kuHg=@googlegroups.com
X-Received: by 2002:a05:6902:2605:b0:e8b:6c31:74ca with SMTP id 3f1490d57ef6-e8b85a7abe5mr868982276.18.1752183078518;
        Thu, 10 Jul 2025 14:31:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183078; cv=none;
        d=google.com; s=arc-20240605;
        b=EhkDho+Xg5vPl2FadUatof0uYrI7UR7x7mixuEavvaHfWkOoIx5ctRB4t59h+gpz1L
         apKRwflY+f7cQQ8YBZaTMTrYQRuKRvQNc1NYUMdeVB2AfeXEOEVeEmSnd3TI+Aj5Isaz
         M5vSydFN4xopk0ZtEtPIlhIBr/KMFhnlj51fX0i7EjyYGqJ6bDSnCMZh34yGBNoGtP59
         MCUxR2D59S8xn/2dJxGmUlhGc4g9k1gCaUz56T6wkAqEhrzx99D1lM1o5eY6uxwvU2UU
         blK1B6szC7moEJNqcWOVghIwjk/emqFQA7vgp01uT3IhD4qtlZqgVApKWXNiDpoMQrGh
         sGRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kxlwBtIVhGWZ8OoO7pHlpnuOe3FSmc3gWsDT8zjGSd4=;
        fh=3xnUY8A2Mq3PveV1ZEc6h+AgvXyG6cfw9LnpDv9FfXA=;
        b=kSgTgVVCQTiD58pseNt2rY15lIUOia8AnCesLT9V8Yo2sApX/Y8qL8twBxCvmCbONp
         cW+rsj47pzEhdGtko8Qk0rLFsBnMpnwAr2Ty4G23M/N+8Hl3vGPTGZeVV39fE8Pj/LaS
         5vZq5W1cpWN5o2y7FKbSFrM57Hzbbkb0uUSFenmaIVe5mjmaIKOpEQxE68FS7r62IbIL
         YXMuTFRuDHcX9p8epvxjp003R/QGZ8VzCGwzvHCklXvy6Y63D0nE1a97Blkl3C0D2RpZ
         EwiahKwRJTDdK6u7WdX4VQbiUawII5VOEiDr3CAO8TSNKtPev7783nd1k4HEZ8SfFFNo
         bu9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lWuo1Zql;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8b83c6a696si33853276.3.2025.07.10.14.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:31:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 15CCD470A8;
	Thu, 10 Jul 2025 21:31:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2D0DAC4CEF4;
	Thu, 10 Jul 2025 21:31:13 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:31:11 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>, Jann Horn <jannh@google.com>
Subject: [RFC v5 5/7] mm: Fix benign off-by-one bugs
Message-ID: <515445ae064d4b8599899bf0d8b480dadd2ff843.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752182685.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lWuo1Zql;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
doesn't write more than $2 bytes including the null byte, so trying to
pass 'size-1' there is wasting one byte.  Now that we use sprintf_end(),
the situation isn't different: sprintf_end() will stop writing *before*
'end' --that is, at most the terminating null byte will be written at
'end-1'--.

Acked-by: Marco Elver <elver@google.com>
Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/kfence/kfence_test.c | 4 ++--
 mm/kmsan/kmsan_test.c   | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index bae382eca4ab..c635aa9d478b 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -110,7 +110,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expect[0];
-	end = &expect[0][sizeof(expect[0]) - 1];
+	end = ENDOF(expect[0]);
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
 		cur = sprintf_end(cur, end, "BUG: KFENCE: out-of-bounds %s",
@@ -140,7 +140,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Access information */
 	cur = expect[1];
-	end = &expect[1][sizeof(expect[1]) - 1];
+	end = ENDOF(expect[1]);
 
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index e48ca1972ff3..9bda55992e3d 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -105,7 +105,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expected_header;
-	end = &expected_header[sizeof(expected_header) - 1];
+	end = ENDOF(expected_header);
 
 	cur = sprintf_end(cur, end, "BUG: KMSAN: %s", r->error_type);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/515445ae064d4b8599899bf0d8b480dadd2ff843.1752182685.git.alx%40kernel.org.
