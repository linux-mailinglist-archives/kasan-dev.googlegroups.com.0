Return-Path: <kasan-dev+bncBAABB46TXOHQMGQEMAJM6TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 610E349879B
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:03:32 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id f13-20020a19ae0d000000b00436e91bb4b6sf2861947lfc.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:03:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047412; cv=pass;
        d=google.com; s=arc-20160816;
        b=kZkUEj+vGZr2TVxPnKnNIjOb+3UuOW+CEibVysMiUPlzHweu9lzVHIOAj63SH1ckQ7
         QxqXExC1sORvyd/KL5kc92sigFWNHtLdLs/ZbjIUsqAp21jUekkAraHn6hNMWl6xidXB
         CmdadM8kl7/rk040xjGnTuKO+C1BHZTFAdnNZfaFhiv/N3mXH17CNJmTy2srdQIBa/Xd
         0/mVJam53cqhh4egRs5gH2oZB/A/OFYL0TMtuUHOs3VeDsj6mDZDjWKJU79gNsZ775YB
         aI8J0mJ9eF7mT39MD0HBBKgEXOlMPveLEBZysGO4U2tHQSjBPuVQck8792qVQBSnPMI6
         1EwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FbblbEQsFTUg3X0QH7I2K655Fh5qwSGhTu7SqF5Q+tU=;
        b=J0Ic1BFU4vzeh4iNLfCBYQYX14uGerFUhQcUI71qkBuoZAFbJikJ2H+eDjlHblJazj
         R6kLVzXkHq/mAySuXMrfbvvc55aZj5Y/1lrCAbmQpFubNF1t2xIXFfFa6h0K12dwKRXb
         2XXAZV5f2wJIX8rbpULOBMdDtW8a4XHatvKI/5WRdrQx4Kf2H0lkcwHuZgPNj1qMN2CU
         EZDdURDVWfnxSCfs4Wb4CETW6IIzxB3i/PIHimATeo3d8G91v7ASN7KTZZ1bZitio14y
         nLHM3D8nP/Ur7J4IGo1Zw1ZUD8Ap11XC/nc+/cUtwvpzOlsKbj3b/z5ygpEyrGzYgEwB
         T+mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=brSquA7p;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FbblbEQsFTUg3X0QH7I2K655Fh5qwSGhTu7SqF5Q+tU=;
        b=SIz6RwT7/zUU12UhYDxSCHD+rtuP1rzPj8VjUoCgk4T6XVDZCbCcz6YVCUJd5Kg+sB
         wrNQDCLpMoyHCRJNZhHJ1pgSo7ophsn7pDpgPBOJ3Zh7cEvQwlBfAJ/o5f50W6u6Lg0+
         kksea07lf+Fon4OyFf81zbOYuXvUSGZp0HJkwgUXlLbeHb9EyxQmAvcdDJp3TZb7IKI2
         5S2Y9G2PFYpyJvoySmVy41/P09m3jZqmQyoNgwm696+Qz47npCoyWVzbl0UzMyouMDg3
         ZG2MlprwiOHAdV1tAGVmt0XPp3yrQ009R76K4TM4n7spQwbBCThtFfh+NCOvtGLXCqWd
         oUyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FbblbEQsFTUg3X0QH7I2K655Fh5qwSGhTu7SqF5Q+tU=;
        b=Qgdx0hRJdg5YK0Xe1ios9aLO6aMBKtRtrASBvUtoZFKj8/bv3KqCWWSNXvfDd7aLv1
         lDijsoN1ZIPRuQO4H8BJ9S2vaeI/ytUHJSkv8hBn+lgN+REM3wyVao8ct+InSFW3+2Ut
         EAxUjuF9nCakDCZs76erqJ1b2MHzZAaSDrLoXv2gSqzmzBhhHzP3uZyBNgbBGGXY3XwB
         m/SBrD3t9J1RVIbybwte19hh2suXklDBtkalzg/KeGvSaY0VQ5yWoehJ9IMAOsCkJGGC
         SREcMyaMkdo0chb25v+nPQFt9XGAyNJY7fkIjW4ElCgRnlBl7NLWUortBu5JN3qXw66u
         FdgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YLCTfcE2Oc1eUc5WGQGmbyh4sYkFBMBoafDzo7y0nJpSvVzt1
	oky4jnpsZd6sJhYtLW0Dw8w=
X-Google-Smtp-Source: ABdhPJzbHt+bkWFKVUdmjziPiX77Ov2Smxsp37W3G/nckTZvz1U/sDPL0+O7Vvy473UYF6UL7sGaWg==
X-Received: by 2002:a05:6512:3a82:: with SMTP id q2mr7509114lfu.638.1643047411956;
        Mon, 24 Jan 2022 10:03:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0b:: with SMTP id k11ls2480635ljq.2.gmail; Mon, 24
 Jan 2022 10:03:31 -0800 (PST)
X-Received: by 2002:a2e:86d4:: with SMTP id n20mr12055227ljj.348.1643047411265;
        Mon, 24 Jan 2022 10:03:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047411; cv=none;
        d=google.com; s=arc-20160816;
        b=gqZsLhbA/0+wuxIfspnomQZqK4jFbEAY14g3PziVin8Oh7ulSU58OaUBnudbhfSvV8
         VIehfKdvsi3uAKeKF2zv8UpNYqkzLse2tUERACUNXoDnEJ9EBucy1w6leilj9g512wLP
         mWcfmlLTQl2/K83bXsXeuOamUTREjBSbKIrj4EG+KBG/mgBDk0Spq0bS0PxDaSNRsyjK
         hSww0B6auxOh7dnw6KqhFT5Ko+DCsyUc+bhO//cd8CMk9ctcJduunxT2gk6P2O5SRvhD
         4nTk9NmfnwCt/pYYS6XXGvMz0jFowl1KHvuGL9zJKzzbbN2qbZu5EmoJAi/4otStdFuZ
         0rZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TniNgsonCV7N4x8CfBP962yTwJ3ZQbzv223ievd0EoQ=;
        b=PWDsFX+v0aiVmLrua1SmVdg7oXwCUp57CHPI1cfvJQn9h5jQ8R23WcOo0+QXGiXIxH
         8JifAyk70PFqNz7zgnE+ygn7md9jmqx53e+ql4dHA5jK436S+zle1wPHPGoBCflzG7wa
         YqagfevaJjwxC3YGb4K3eXiAyi1BlrGTOQZe6LYspgKHSN2UtL85tJE7NekvjqMWF3it
         5dsqKxTqrAXQ0b/PNQIqTh53cFm5u+4Eh1cTz7ZA26hg0Pp5VHhGhoMnTHwYUwu7ot+4
         DsnyRlNuTD7gD1Im0HdJ4Y+CPwRxWV5MQL/yrjh/sArXChT+mvP6RWa0eg/6AxAMKyVJ
         xzgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=brSquA7p;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id br32si71566lfb.11.2022.01.24.10.03.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:03:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 08/39] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
Date: Mon, 24 Jan 2022 19:02:16 +0100
Message-Id: <f4f4593f7f675262d29d07c1938db5bd0cd5e285.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=brSquA7p;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

__GFP_ZEROTAGS should only be effective if memory is being zeroed.
Currently, hardware tag-based KASAN violates this requirement.

Fix by including an initialization check along with checking for
__GFP_ZEROTAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/hw_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0b8225add2e4..c643740b8599 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	 * page_alloc.c.
 	 */
 	bool init = !want_init_on_free() && want_init_on_alloc(flags);
+	bool init_tags = init && (flags & __GFP_ZEROTAGS);
 
 	if (flags & __GFP_SKIP_KASAN_POISON)
 		SetPageSkipKASanPoison(page);
 
-	if (flags & __GFP_ZEROTAGS) {
+	if (init_tags) {
 		int i;
 
 		for (i = 0; i != 1 << order; ++i)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f4f4593f7f675262d29d07c1938db5bd0cd5e285.1643047180.git.andreyknvl%40google.com.
