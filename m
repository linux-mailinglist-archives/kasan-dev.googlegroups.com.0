Return-Path: <kasan-dev+bncBAABBS5LVXBQMGQERNPBIOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 178F4AFAAB7
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:21 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2efe2648f13sf1650545fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864780; cv=pass;
        d=google.com; s=arc-20240605;
        b=XOAMG7ZLohdVruzJS1dTorTikm6iDVK1hwjIhaULD+qbVcowfPIOtPSSm1wJHUzpcF
         CSatLbqgOuSPZt8TIYcWukh5K0UPJbjSTtiDu9kSgRpo8bw77mp1jeFu9xypCT0Bz/Ap
         NPiEMcZwQu6JhYVFwavkBrDuuP5CQIy6kN20A4FzKfP896KRHhxbpJZ5SE2A75rC9EDS
         aN2vYGcSnDh+qV0rpa1kjQxhOJFyEVh2u78skZlAfKm7d9O4+VBoBtLvNLxzPjNwoWeJ
         bVG9UOIfaTJTtzNhiLRB3NkiyeozHZ/lloDlBe4jzVp2fpAPogIcY3RacMXW82/fa9CM
         eNpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=52VcFwdCNVutfjj+FXsJSaw3+0IqgDUtHe2RMnSDLzY=;
        fh=027CE8wsaPNQABPRtFfQxxdFyKYvouFsPH5KGjWE9Ok=;
        b=YoMVDmCfJ9ouonRjuvFEO+cM071GzUD5AhZ19RkN8St59TAIKF4NVYYlX3+pcvv5Up
         3a1w/gQSxHrGgAYF23chEZMY1HqdAvBr7Ltd5hsO0sXAgH72tBCwPyUxd2bYOf20AuE+
         yi7xWG7FNYumdEPF/8LO3QWyorOzfSwErtk61kPPxoeFv/giRbxrlSMMruYXYrS+C94p
         dP1Sc4stup8U09qKztcrO5nO2AVGE9xtBz+wdrob6dbF6EV/8VrSGhO5fVD0KeFfTbeR
         Aq5a/pJQ74xdc3HYsdzyhkfNUVO6mpnp2bRMt2VxnnRKDcuaw7XmTIjnC+AtUIsCCUmN
         7Cbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jZKs1LG3;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864780; x=1752469580; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=52VcFwdCNVutfjj+FXsJSaw3+0IqgDUtHe2RMnSDLzY=;
        b=BF0IN49FwqXKJj2OKCk2a4LQm8jLq+gbSHJ0rqD4r+suNREDlP4yrylR8EAoIPTSjD
         nINctCXhYQlpmcn4Vj/6EY30GqKBbOOp0V1HaQ0HH978pglB7+rhk5mgoJYvNEuUhiEp
         s8Um/ihBSNqq9MwnFWeEBlRwXbu6bTUeF359ygTlAu8UbWkXs6unEAQkDIUZcmdAlkRk
         ZCqL9WKN1ReEJjSeFol1l/FAfpLWGbJ0dXVce4T4W/oWfxZDQEVuzGecY8IWxiMudf7N
         iDJmiZgApYnDbxjTiM8dfr/9vteBwrfWPA9EZjuDC2D9wZgdvVoht3L/gSBPHSbUhVfc
         qOFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864780; x=1752469580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=52VcFwdCNVutfjj+FXsJSaw3+0IqgDUtHe2RMnSDLzY=;
        b=C2+7iVCydWyIaK7CtQqN41PyoiDM/yFEYoxKW0dGJFrX7X/0Cfk0QMgjGlDc85r2v9
         vqKUKxqgNFYaxtmWhGPfxfnjmLYBr08olt9aHp8NjokX755mPlhEfj10oixY33v6IRf4
         YAlDk5Tak92CB6grRMaL6QGA2jm5FehmvZHxvrQCJB2gANNe2bvfHl0JRv4vw4XVs8gZ
         IKAzwr4KnhAIvf4PyPPBDtg2yltKRExmR1EIO4ELb1zgupIzmX0S+kml+k5QZHa5Ym2T
         tNwwzkcnM//c0yC/dRJVxyA2bo8Kx7T33Hc22mmOfYrcAbYf11kmJnrEG3VGWuFGLHIm
         Bk4Q==
X-Forwarded-Encrypted: i=2; AJvYcCUcl+nPHlyyAow90fMmwtOLByM8Updl8k4RFvTsbrQdcI2zubs9m9kS8tZ40NgSbL+Q6X3XVw==@lfdr.de
X-Gm-Message-State: AOJu0YznL8pvsDrIzBz1P/fvmLVpncK6mxKYg7AhAJaDsM//tTflK5aD
	W04/g3dFF8TVoMw47a/uVNj9+/Z5ODm+ANLA2yjNKiAIMdAynjxF0dgY
X-Google-Smtp-Source: AGHT+IHc2l6jf4IFUl5NwjXJC6r5h7ut31xuzQ3yqngNP4xIKwiOmaQYwiRKLrMLc90kDwHvnIeJSQ==
X-Received: by 2002:a05:6871:ca1c:b0:2e9:365:d0d3 with SMTP id 586e51a60fabf-2f791faf6d9mr8108927fac.21.1751864779723;
        Sun, 06 Jul 2025 22:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfB5KEjHLphhB05ITo1bHpWFVu/LLIzdGF+QAeo5FPuOQ==
Received: by 2002:a05:6870:85cd:b0:2d5:b2c1:db0b with SMTP id
 586e51a60fabf-2f79b6ea77cls779255fac.2.-pod-prod-06-us; Sun, 06 Jul 2025
 22:06:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVEVWiYMZCWYV8swL0TW3yEn4DAcVL6WrGrzGUKlVdmkgd5CBgow2j9gney1azwIyZTbkliD7HwaLo=@googlegroups.com
X-Received: by 2002:a05:6808:1486:b0:409:f8e:727f with SMTP id 5614622812f47-40d041996b1mr9001376b6e.3.1751864778864;
        Sun, 06 Jul 2025 22:06:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864778; cv=none;
        d=google.com; s=arc-20240605;
        b=RzL8kXwENcykp/m0+ScFbu0SB0z7W+J0zmuR8ZWONQGSlSbWMzpvEUL/4kMMzVqR8W
         VV31ch9eBHIlUNATN0oX0H74ZJQlBiL1yIwxITQv0soj8Ar8h+Um8HBL69gBP+nfaZLK
         DiJUZptzWAzMdoh5prgC9MlwzVs1QRayG3CiA+exwsp3AAvhXREVeADpoDQgvP2QsrM7
         1ICEJhcUL4l3sXze0O2GwCpsN7jdeiamJjVh/n3uf3RYoAh5zhLoswChXRtmsFjJW+nU
         u2uQQrftdo1vrk7kThXlqRX30x443uj/Fluy/VPb8531fmPUs9/UJLAiiYa1TwU0st6j
         yTdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lLUnQAO3/HtQe3sUDS+hIo1qlwo3a5ODAVyHi6Qtg/c=;
        fh=cPIdHODXI5gjaeKZe586ilhimI/pTddW7hsqmbBsd5g=;
        b=A2mxJIDXAE+B0iQWZMcFpPbD38bhQblG1wXZ7Ox/4C3aG1DwWfsHL+6Q1BGsjNbf2r
         ZBCk815GuGoeZguPVPASASnpterwOIcw2srKevwl5OYyk+nsvVbh/MNAc5orD51JWBU9
         Ze83b6V4J1Jtx1Sdbj8813C6DHZoVzZ3uOHPM1d8Hihl6M342Fg6RGCgJQDbjY9tcl4j
         a4Kyz/Pq4kWnXMnKG6/css0JzIh4eUmJotw9KXisS48ZjPSp5LxVtevccj3NvQBOH891
         n5/JVfL/T9nqTgki1+tTWHnO2nsIDGa/Mlqrd0ciWjwN1UTYUX4BC9yKQWzSV1B1bTAN
         MbOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jZKs1LG3;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40d02a8a77asi296365b6e.3.2025.07.06.22.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 3EA4E6114D;
	Mon,  7 Jul 2025 05:06:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C0ED7C4CEF3;
	Mon,  7 Jul 2025 05:06:16 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:15 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Jann Horn <jannh@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: [RFC v3 5/7] mm: Fix benign off-by-one bugs
Message-ID: <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jZKs1LG3;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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
pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
the situation isn't different: seprintf() will stop writing *before*
'end' --that is, at most the terminating null byte will be written at
'end-1'--.

Fixes: bc8fbc5f305a (2021-02-26; "kfence: add test suite")
Fixes: 8ed691b02ade (2022-10-03; "kmsan: add tests for KMSAN")
Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/kfence/kfence_test.c | 4 ++--
 mm/kmsan/kmsan_test.c   | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index ff734c514c03..f02c3e23638a 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -110,7 +110,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expect[0];
-	end = &expect[0][sizeof(expect[0]) - 1];
+	end = ENDOF(expect[0]);
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
 		cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
@@ -140,7 +140,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Access information */
 	cur = expect[1];
-	end = &expect[1][sizeof(expect[1]) - 1];
+	end = ENDOF(expect[1]);
 
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index a062a46b2d24..882500807db8 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -105,7 +105,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expected_header;
-	end = &expected_header[sizeof(expected_header) - 1];
+	end = ENDOF(expected_header);
 
 	cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx%40kernel.org.
