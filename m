Return-Path: <kasan-dev+bncBAABBDW5Q6UAMGQEXCYBADQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id F28A479F033
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:17:03 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-502d5fe6d50sf13863e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:17:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625423; cv=pass;
        d=google.com; s=arc-20160816;
        b=E5cRZcMOivN5c76sW5wBLrL6dwn74Z0MhjSaAGJYPR8mHRz4S3AfVXYmI21G0wlqma
         KN+GaPPld2rI3QFsKk/SxphI2bRz834naGgy4qdK18Pr8/pbN0aohThCGILvsxa/faDN
         q6X5HNvb8nwEnj+FlK+ubEsslOPSaxxx+DQ0+/ymXbPoEI7gbRmSKfrVzbFQJOgGPY0K
         0q0Nsu7rSZNmCdq0RIoq2NrFjpoYo2/nrnu2YYw+r8tknW9HIH1IRs4v633ZzWZb8Q9X
         TdkHySCCZqyDJkuKSIlejlT2D5zd10k4ACt+DLRV0zIGm12W3IzGTc3FitzfByJ1hc1w
         +9bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=My7KpUtiwKkK2Nz73U4o/VP/bINGF3oXauNUXmdoyKI=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=HQV0ealJgozxSa0OF2VGP2fJ1ZmkulG7PISMYRAzGSAGB5854PlkQ4pzlrLJzjotvH
         TgkZjL6DMtaiZT+f7DFbwLFNBkcdJrLQ5ef4kS+w7DZNftgd82nWaamtQbIgysl6ANPC
         xc4PwIVIBMbzDOs6fvrxuca4wWMYppXMFHsbB4RdFRhTFR72avb32NsZXCnIhQ5TiOY6
         ZoichFncfsB0Zk6QDfRpQDD6W/ZrgC0dALOBc4ZDs7SnMFQt9o9/k7SFaW2E+gCAUrv9
         QpdUPSubdtFsju7NvUivzMpuYyELsRzxgh/20OtcB2DJCl8MvhCKqfubj+ETdXaIAZb8
         i+QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=riuufySF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625423; x=1695230223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=My7KpUtiwKkK2Nz73U4o/VP/bINGF3oXauNUXmdoyKI=;
        b=GJxDOGtNSDKotHqkNMPh/4Hx4uqz2Uqe+rmn4MjBvUazhz9iUEquodRRQnfBvYJWiJ
         GzrRVjVxX6nZ5HdHiV6A9WyDhYuXkn2Fy10z/vlKke6dzw14SFaTTzxvn/GwIoaAtXnk
         NfPF6pfjE4FNv/Eu69UsSGvlUj2GUj/qubeDvgDrujoLP11CP9/Ib25ZGYmT0uPf1aMr
         7o+wPUaXxGpHudLPX8lbrv87qF/LhlVbj+11tK6jGkYpSeycvi9pTASDo4PT2xrW505N
         y9m7La0oS4hNgFx6JGQ49g9zf5w2fDXcD2mC1Dc/RE23tnsYFLxpJJF6Up3gFHahpJQr
         a/pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625423; x=1695230223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=My7KpUtiwKkK2Nz73U4o/VP/bINGF3oXauNUXmdoyKI=;
        b=GXZtPdj1JOroi5fnTFgagzhAqDwpjK7+DaE7sytCpgF0kgsDAo3ypiS4EeoI3K3hYt
         JzcbBUD2El3Wqo8SKT3DDwHu0DCcvYz4yX5ZBxNNF6cKXUZ7Vg3YToRlJUhI/tAOHUtE
         v136q4VXR+QRQqo/EjnHi/lviJU1FkHnMRqL4SyBkRGA3jp8HZo3gaACltSrUGBko1vX
         eznT+EKbwJkJseJ1hxGryTavxS4YWfOWBHasV8/yC8/PD1F9Rt/XzZ5kYPi+GoypfTF/
         v3g8OnOgogzbURjdQq3QzRx8rgulUHJzzCYKEia6hbhk/sMxDeY7swVNM9+H6svA5cpM
         Ekhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxtds8H0UnKJ5RxRI0PD2J1oIWifIVQNn5rbwxPq8xS5z9iRCep
	wIcILLkDK8FQJBfqzOSdezk=
X-Google-Smtp-Source: AGHT+IEcfiGhsMjoe3G5dL3wtJnxprczOwrxvg9mFNHDYPOQ8FsakRiqKGtP11uM2jsVHcxv9ngwgQ==
X-Received: by 2002:a05:6512:2215:b0:4fd:b1f6:b6ca with SMTP id h21-20020a056512221500b004fdb1f6b6camr3105821lfu.25.1694625422476;
        Wed, 13 Sep 2023 10:17:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:613:b0:4fe:56c5:2906 with SMTP id
 b19-20020a056512061300b004fe56c52906ls2729355lfe.0.-pod-prod-07-eu; Wed, 13
 Sep 2023 10:17:01 -0700 (PDT)
X-Received: by 2002:a05:6512:3603:b0:500:97e4:587e with SMTP id f3-20020a056512360300b0050097e4587emr2217328lfs.44.1694625421066;
        Wed, 13 Sep 2023 10:17:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625421; cv=none;
        d=google.com; s=arc-20160816;
        b=AJ/wuLOboc8vlzYsiPBt5JSWXuKghPczOdXU0vxGLI8mu+Qd7zvYpcgqJO3KBScszZ
         scSmdFTMppNYAnz8qmmVd0Lvb0105ZKvQkm0bBWIji62hyumpvU/g0T37glPL57m2i61
         S869uUtuhqaqpGCMVRjkENHoVl2zF9/sVKOvm+irWVIyGwVf0z0fL5/M+Aqf71o0Roaq
         FoQtkA5+w64XZAwNdWai4eSYx7rIyGuOqPTuObgdSDzmx2MyqdDS/GMX4tPS304oJO6i
         Hcf54d7aivU2cmf11pM0Y7QKqFWvwCNgQ/aR16gyMNf6FaV1wE15AZ6PoiUdPN5aBLtO
         Xo2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DC9UmNBNkxmGXhCZnNWnsoHzitcm2pHd/lCALP3GjjY=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=vgbhZ4eHPf9xfZ7EFVNA+s4D3OHQUnREe1dYtMwHOMQMxZU8SNJ9TZZnKB+TuH3Dok
         +BO0TLpPy5k01s8VqMX2A0PCI2iBt5oOJXpxMpQYuZekfMAIbM06R/I1rFkwDFgQuw0w
         RxkvLIaWgiVYE0hwYCEjmyvukC2xfQe17iFci9TPJy9wB40lh0VL0xKDp7mdEskJAQ7z
         pf/rdzh1nq4eACL32jznNwXxfjPTNBh4lfXaUlyKDFIbKrtTa4BGmYQRPTd5aqbd4XEs
         lchZ7TLPpwNsCIWBNSiHDuplkIaLM72nFhSE/Db8omZ9xQPvxLlme4fo+ax5XgZzJWEy
         oLMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=riuufySF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-219.mta1.migadu.com (out-219.mta1.migadu.com. [95.215.58.219])
        by gmr-mx.google.com with ESMTPS id c10-20020a056512324a00b004ff9d6b6cb0si882545lfr.2.2023.09.13.10.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:17:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as permitted sender) client-ip=95.215.58.219;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 13/19] kmsan: use stack_depot_save instead of __stack_depot_save
Date: Wed, 13 Sep 2023 19:14:38 +0200
Message-Id: <7f6b58fda637238ffc0c240e7fd3b3a6673d9d91.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=riuufySF;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as
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

Make KMSAN use stack_depot_save instead of __stack_depot_save,
as it always passes true to __stack_depot_save as the last argument.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kmsan/core.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 3adb4c1d3b19..5d942f19d12a 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -76,7 +76,7 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 	/* Don't sleep. */
 	flags &= ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
 
-	handle = __stack_depot_save(entries, nr_entries, flags, true);
+	handle = stack_depot_save(entries, nr_entries, flags);
 	return stack_depot_set_extra_bits(handle, extra);
 }
 
@@ -250,11 +250,10 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	/*
 	 * @entries is a local var in non-instrumented code, so KMSAN does not
 	 * know it is initialized. Explicitly unpoison it to avoid false
-	 * positives when __stack_depot_save() passes it to instrumented code.
+	 * positives when stack_depot_save() passes it to instrumented code.
 	 */
 	kmsan_internal_unpoison_memory(entries, sizeof(entries), false);
-	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH,
-				    true);
+	handle = stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH);
 	return stack_depot_set_extra_bits(handle, extra_bits);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7f6b58fda637238ffc0c240e7fd3b3a6673d9d91.1694625260.git.andreyknvl%40google.com.
