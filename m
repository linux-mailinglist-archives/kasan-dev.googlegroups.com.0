Return-Path: <kasan-dev+bncBAABB4PN26LAMGQEIXVQYOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76B0D578EDC
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:12:33 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id r127-20020a1c4485000000b003a2fdeea756sf106125wma.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:12:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189553; cv=pass;
        d=google.com; s=arc-20160816;
        b=IrGWlsAuN2Kn8JH4wDlvJ36tCPacAt6SR1J/fCHQrCi8DgMe00AUoRLlkqsdAJHmMb
         5uUSn28Uz7MI9Ur2ZeQ5b+xcrI2pCga++6L1eRbvdDm9VPu9yBSunb5PEuyjEg6WZkko
         dDrjlhqbPacFfL4WeHjE5r/Ml583MOXw7zOCoMTHi0OXlvjWW6tgKMY0nEKKuS/VxUJa
         QKsUPRPcwELwOXoeJs1revA17MOKonIcUwXFw+o1zXBVL1aDc43JzDeaIkxwpLfPAZQQ
         LYpjJ5bUOPiPVcy/XBfsV4s/0oylxYy5VXtQ2rEVR/D92FghkCoXzZo0WdlOjUqTjMVX
         MJOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=odpf98BCWd3fJ+Wo8UJOtIqhl3QcXgpQ+Bq6toiPIx8=;
        b=PJtPS/n5PTardgFqe11z8I92724XO264k1ltTVwCLgLtQJkV9oPbjOYIdHufKYY7T2
         pBA44hDWGEDLWstIaM3/6alQvWsVxZ6KetUYDpA5NZkx2F147kCu02jTMxikD49GX5o3
         62OjBbkhXbTDPHmMTPDVVZblhwWtP5E00LMWZYsLuCSdaMAvu0i1sOG78zIOmLTCEJKO
         DwxvmJjvyTNBwRR4SNsluyH1u/zHwDRZrhFRRfuwrZnDwGXuak7emf4rWoZ6cv7H0pYx
         wZXKhekP69NHhkQF5Kg7snUibzsO1b0QmRNFQNYPc/0LSrAzaJNEIoIJ29y6G/EiVt2o
         6++Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iaswNaVc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=odpf98BCWd3fJ+Wo8UJOtIqhl3QcXgpQ+Bq6toiPIx8=;
        b=ppjU+ymUfZ4NVpxwpoZEnBDP1Zo2vOjwlqBZrGt6YU1Nw4ntrv+VELOPvRvyTpJMN6
         l6xVgLL4wlPjR3mNGArnQHNllWdPpP9o+94dzYmgqA8SZgJpLLasleY5s/uME7A6Zzyh
         cNBT4TGuEqWprOm4w+xq4THf0fVlWJ/gnnRV7C/mIuCrzutNwVWoMu/upqh16JbyeYrV
         tz/FoE5c1JukbuRUGWBwkA3mPMYVQE4gmWtqXIoyJCvxkRse95LoQk8NGk4NFkZdnXfk
         sS+kN0Ifdq6Yp2txTpdF5Tb2pGrsZAl3Ol/GR1+t3BxUibEA9DK2fj6rbrlcPgiOVBig
         p9lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=odpf98BCWd3fJ+Wo8UJOtIqhl3QcXgpQ+Bq6toiPIx8=;
        b=LC5VFnOLy0DQQvpdPcF7hY9KmsW/7YpOhIgVPa5Da/rwgKmZw5RGyEmbcr2qBqdbxn
         TNJ5EZ8XqYF4hwjB5oiE8G/VPRrXbtp63b1/ONy8XcD3V8l1ui7NgUuQbQle0RbQ+Jtq
         8pK26I4BpSVekmjczBvfMypWtfLAWyPGjEJNEwKT7Ceqj4SPSRCpkZ5XYdRKGgGDKArN
         LqhfdMscI31cgQZHn7XjzVi2IJPCJXk2MJr2bEYjaclG1p+hQvDoAj1RJuXWZ9fxo2dT
         RkjRN1ikmFIw3l1nQ4FpXMYmSZ6bZ2UGXaL/oK/SaZU8+badsI4elfaxnBxbA31l55/o
         GJwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9nddB0z2j1skn1jp02wZYSfJxj98qVtVbVqCXg/T5CbOFX/Ntd
	7qCO4lUTTrl/iqJgmmC5fXA=
X-Google-Smtp-Source: AGRyM1tVD3RluQDtkcFUDK8rcPIUJzUBNIebaHXvTu4ij2qcqan7n3MR27dWCI7fw1bMGt76ry47BA==
X-Received: by 2002:adf:fd8b:0:b0:21d:6913:84ef with SMTP id d11-20020adffd8b000000b0021d691384efmr24237415wrr.525.1658189553202;
        Mon, 18 Jul 2022 17:12:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:784:b0:21d:a0b5:24ab with SMTP id
 bu4-20020a056000078400b0021da0b524abls11980wrb.1.-pod-prod-gmail; Mon, 18 Jul
 2022 17:12:32 -0700 (PDT)
X-Received: by 2002:a5d:6f19:0:b0:21e:2dab:83b with SMTP id ay25-20020a5d6f19000000b0021e2dab083bmr1322295wrb.139.1658189552606;
        Mon, 18 Jul 2022 17:12:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189552; cv=none;
        d=google.com; s=arc-20160816;
        b=e14umXOOAIzrJVkWKbZM901EtQMwA4Tkuq4nz1kpbN75K0R8YjI/JRbyhAPoOkPr0K
         zyrM9UVuI/+ZC4P2/UqUsOl1LYOz3ply+/aVvMvxlQzPNtj5zzAIjNOXzLTMm9XZUNSr
         xH1TKTW8L2pgjdl1GuP/V2XStVFj2Nxo7XJ9MSS2uzZXMXHVKefw2FnFwf0U+CFi69A9
         dmJrILPvDQ/7DIpno4YfeR3IQ9sD2gNQujuyxDmh3pbW65Eu2Wmg62o4Tk2XmCqtNuf/
         KDYLYVbkWiDXmJFBj5VydUyGxG3CCPTqDwjAG6K6codCIEtnBQhMK4KTkRtC9XMVPmGC
         1BFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tSwVFyyCCOKYSS6nxmIV1PC3/qH9HgKDBeITqQWAPk0=;
        b=ypm1LNCIPRYz/C/mqi+Ex7dIfOixVlukrTQW1JU2znqbNIaA79Us6z0PMoTcl2JbLs
         jyzCgnBjeOmvtArBO+6hpD31AXxfTRFBEkElgvXYxHwYgHuaBtRpoQbO7LKU4rLPMBni
         wZlOBLHv9lG1ZP8Q1jvoCwtXd/p5ky/BIcGlRvSHYpVOSZxL5XKNw+dPiYtnt1VuXvyA
         8qRA5zXomGq2wFG2tlHocP+ea2TcJJI7bPRNKKYv2hq0sZRN/1GDMBE/VVFU0uzsHIyf
         89W0cedZioDZZVBLZZ5gXx4pRhlUhkzIVqF3XF17dkzOB94XgEXQybemgLONyPLAV+CQ
         fVmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iaswNaVc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id bg3-20020a05600c3c8300b003a314076fa0si178996wmb.1.2022.07.18.17.12.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:12:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 16/33] kasan: only define metadata offsets for Generic mode
Date: Tue, 19 Jul 2022 02:09:56 +0200
Message-Id: <902cc38713c94e729b3eca170cd53ce9dfb5fb47.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iaswNaVc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Hide the definitions of alloc_meta_offset and free_meta_offset under
an ifdef CONFIG_KASAN_GENERIC check, as these fields are now only used
when the Generic mode is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 9743d4b3a918..a212c2e3f32d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -98,8 +98,10 @@ static inline bool kasan_has_integrated_init(void)
 #ifdef CONFIG_KASAN
 
 struct kasan_cache {
+#ifdef CONFIG_KASAN_GENERIC
 	int alloc_meta_offset;
 	int free_meta_offset;
+#endif
 	bool is_kmalloc;
 };
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/902cc38713c94e729b3eca170cd53ce9dfb5fb47.1658189199.git.andreyknvl%40google.com.
