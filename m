Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRON52VAMGQEYH5G65Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 23FC97F1C86
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:47 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5079fd9754csf4765738e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505286; cv=pass;
        d=google.com; s=arc-20160816;
        b=YEkDzSgy5ghLV3scLfmmPayHmziDTlqdCnJBxolOol5p5yhsCmTdl9XlcAYzvmR8En
         O/9m+Pd5xsC4U7DOpVgeEV444suRPFuP2y2J7c9ncjoBNyOO/VJqX9pjcxwqgbbQgku1
         kiozDqno6PGJCX6QObD2VSormCw7DIedWr//u6pXbDLLytYZ+LUMzdYxhPQ5n1HjgDcY
         cgB06AF1zyOMxGVjMLveWjNvsNXBtISSj1/Hd6VSWjHHIIqwj3AcTUkqBJ7HxFN43N+a
         9on03GYF98gPRtlbTyLlz8AxOcdNHYPybL1egV52sP7Wc7viYicHQxDM/ho7CnyPSfSJ
         8PQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=lnAZtqk/+lY0UzQ6TeLIfkXwPZLqdzSfAh5zx0P4kBI=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=tM2wuQl7JyZBHCa+PcuVMZ8NrnJpJFb84i2PpNVwJF36vgCXtRG/T9/36s8FeQsGv9
         Gnfcix/6vn8/4HCrH51jl6mqAqw/m8yLuYH9xdoQaVnwE/v9FQMSSZ5js5y341OGpMdT
         2uHnLVWZPJCIbYe2v0GfrD1qTf0ylL51G17yXTB8GXZHhrFBvRXGwBR+9zmNh5sT2dwW
         dSGw+XBC175LtEeNzDwTIAfqOcmm2szV2Px8/alX8Q2P04Vw6AMBDq5Kr5LIQAZO7B52
         w8BqO3ZTlesSPbq0D0wmv8cIdV1RQVsJe8iz9OrRtLqEnVQ1zKLoJtpNFxIKF7CraBHz
         w6Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qNkpX3Or;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505286; x=1701110086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lnAZtqk/+lY0UzQ6TeLIfkXwPZLqdzSfAh5zx0P4kBI=;
        b=TRKncHf1ox7k79d30Nf7ntTX+soAeUOqirg2C2q6uUwqwJ5y4SVZ/g7W7P335ZR1TV
         bmrZBDpaaC0i6fZ4Tu4aPcjSrICFLq4Gj9pkygtTdy3o9JI5O7QZDv8tC0j/KOBgOCJT
         u/HmfjUyzsBEBJAmdhaVf7BZmjc45mNcjVKlUZ6O7YjqsaYY1r5/1n70nhP/kV4l7fdF
         j9skXrwfKdv3CHRHyUF39avRlY2d4utYkIUPw73AGb1a+DFv1B8g/xzG702U8KT4eIXX
         BQrZkGIHfyVChW0CkWmSPz/a4uS6oKloiqofSYcHXFemdYwEpFlJLbyu0u7zRfi1VR1C
         9+PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505286; x=1701110086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lnAZtqk/+lY0UzQ6TeLIfkXwPZLqdzSfAh5zx0P4kBI=;
        b=vzLEU7Nndeb+T/Z+lQuyDj/7S4CVqZQ/CpTq5wfehViFeZLJf95th0kvxFEaXmIp34
         RRCMfoFaK3VEnx2rxPOQ39kP8ST84ijW+E03jejjeJLQeROu9bzUaUdVKfsp2gFfRQvy
         QqNA75FivJdtZRzS1X1MuiCGZus/f1PVAbL7GXbd0vkrbWL9mT7xLYtIFotuPSLTk3KR
         oPuK6jbfTA7k6o9CODp7U0+6LMg0l3Z7czjfmOr8SUikw5NO1ZOOu/lPWoMPIgyfzStY
         fFYErXu+kwjvU8svV7XvVwdC4S9xi1ORevQGPTyyEG3uGLVvqwyGe0tixlYk59X6egkI
         XKgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyKC9bO2EPztdFvMoG4ZFGfi6WhI+z0ONierKxoaLJDpT1ISzqx
	fMExTzJS1sImLAjNbD2HH7U=
X-Google-Smtp-Source: AGHT+IE0CozDgKmig0AP4U3o5bm0MbX1u8Ffs0XfKUSj1TgrhfOZsd97TRWkV4z9zTT6gbhw5214tw==
X-Received: by 2002:ac2:5396:0:b0:509:d0c2:b5d2 with SMTP id g22-20020ac25396000000b00509d0c2b5d2mr5358722lfh.53.1700505286127;
        Mon, 20 Nov 2023 10:34:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2305:b0:507:cf9c:aa7e with SMTP id
 o5-20020a056512230500b00507cf9caa7els257270lfu.1.-pod-prod-07-eu; Mon, 20 Nov
 2023 10:34:44 -0800 (PST)
X-Received: by 2002:a05:6512:485b:b0:507:9628:afb with SMTP id ep27-20020a056512485b00b0050796280afbmr6005535lfb.68.1700505284124;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505284; cv=none;
        d=google.com; s=arc-20160816;
        b=zojk7IMec2JkVe+mQl7gqPww1xNSpl/bddZIXx2BrmJlFKFQtoWR7bd77NKbtzJz2l
         mi/n5GBP6OpL+JPBaJMATUAC1nRrj8mQfkoY8TjFk/taTCsCZTiYcHFdd33nSkj5fCOQ
         7UHouQjzpnW5XvuG5x3pL4WWON9XlnBH6VXiLqgMQy1pDwgVGDFdLE69Qxah7PP2H3kI
         adAnWqOHugb2NDvYnujaCH1WiEUYFVc/OUYwpHTHYIc40anOgIb1eSofPdg8zqz2E1e4
         6/7ypYY7X6UvFZlJk9m5d66dDqKuI+U/HjikkYJMxCvR/Ojtr+IzvyXje/RQzib02g2v
         YTNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=RPV7eFvOYqND65nC1EpsfH0qSohk6qGYOFkaS1IRDew=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=tQzLsKQKYom+rsHsYYGOIkRE37/Ws/rfh9tEiuW6XBEKPdFsWB1dNHrrH1fzPsXxMs
         RxhMDfAAezgrjuVrk1qKSI2+q/bAbNIGpmaNRdY7L29qOO0CzyCfFEQoZ+3Bazv78/n1
         Rnmup1DgTC0jIlTO+5ZI37ODHgMi2QORkjG1gxUHL62SK3A4LiHmV+bFle866/vKwNSE
         AkKazAwUeR5nn2QnS+KHoXebCkzg1XUGhQE3ZiHgO5h8D2KnmcR82nCGblKRH0u9UA+8
         bUZeYvZKImgGgO93halj3Gy7shEodFeXpooi9rjZARw7saCVxHfxAVGNyT6o1grscKWl
         qNQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qNkpX3Or;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id bi28-20020a0565120e9c00b0050446001e0bsi344641lfb.3.2023.11.20.10.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8E3EE21979;
	Mon, 20 Nov 2023 18:34:43 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3AD9213912;
	Mon, 20 Nov 2023 18:34:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id QFS4DcOmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:43 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:28 +0100
Subject: [PATCH v2 17/21] mm/slab: move kmalloc_slab() to mm/slab.h
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-17-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Spam-Score: -6.80
X-Spamd-Result: default: False [-6.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 BAYES_HAM(-3.00)[100.00%];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qNkpX3Or;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

In preparation for the next patch, move the kmalloc_slab() function to
the header, as it will have callers from two files, and make it inline.
To avoid unnecessary bloat, remove all size checks/warnings from
kmalloc_slab() as they just duplicate those in callers, especially after
recent changes to kmalloc_size_roundup(). We just need to adjust handling
of zero size in __do_kmalloc_node(). Also we can stop handling NULL
result from kmalloc_slab() there as that now cannot happen (unless
called too early during boot).

The size_index array becomes visible so rename it to a more specific
kmalloc_size_index.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        | 28 ++++++++++++++++++++++++++--
 mm/slab_common.c | 43 ++++++++-----------------------------------
 2 files changed, 34 insertions(+), 37 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 35a55c4a407d..7d7cc7af614e 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -389,8 +389,32 @@ extern const struct kmalloc_info_struct {
 void setup_kmalloc_cache_index_table(void);
 void create_kmalloc_caches(slab_flags_t);
 
-/* Find the kmalloc slab corresponding for a certain size */
-struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller);
+extern u8 kmalloc_size_index[24];
+
+static inline unsigned int size_index_elem(unsigned int bytes)
+{
+	return (bytes - 1) / 8;
+}
+
+/*
+ * Find the kmem_cache structure that serves a given size of
+ * allocation
+ *
+ * This assumes size is larger than zero and not larger than
+ * KMALLOC_MAX_CACHE_SIZE and the caller must check that.
+ */
+static inline struct kmem_cache *
+kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
+{
+	unsigned int index;
+
+	if (size <= 192)
+		index = kmalloc_size_index[size_index_elem(size)];
+	else
+		index = fls(size - 1);
+
+	return kmalloc_caches[kmalloc_type(flags, caller)][index];
+}
 
 void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			      int node, size_t orig_size,
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f4f275613d2a..31ade17a7ad9 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -665,7 +665,7 @@ EXPORT_SYMBOL(random_kmalloc_seed);
  * of two cache sizes there. The size of larger slabs can be determined using
  * fls.
  */
-static u8 size_index[24] __ro_after_init = {
+u8 kmalloc_size_index[24] __ro_after_init = {
 	3,	/* 8 */
 	4,	/* 16 */
 	5,	/* 24 */
@@ -692,33 +692,6 @@ static u8 size_index[24] __ro_after_init = {
 	2	/* 192 */
 };
 
-static inline unsigned int size_index_elem(unsigned int bytes)
-{
-	return (bytes - 1) / 8;
-}
-
-/*
- * Find the kmem_cache structure that serves a given size of
- * allocation
- */
-struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
-{
-	unsigned int index;
-
-	if (size <= 192) {
-		if (!size)
-			return ZERO_SIZE_PTR;
-
-		index = size_index[size_index_elem(size)];
-	} else {
-		if (WARN_ON_ONCE(size > KMALLOC_MAX_CACHE_SIZE))
-			return NULL;
-		index = fls(size - 1);
-	}
-
-	return kmalloc_caches[kmalloc_type(flags, caller)][index];
-}
-
 size_t kmalloc_size_roundup(size_t size)
 {
 	if (size && size <= KMALLOC_MAX_CACHE_SIZE) {
@@ -843,9 +816,9 @@ void __init setup_kmalloc_cache_index_table(void)
 	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
 		unsigned int elem = size_index_elem(i);
 
-		if (elem >= ARRAY_SIZE(size_index))
+		if (elem >= ARRAY_SIZE(kmalloc_size_index))
 			break;
-		size_index[elem] = KMALLOC_SHIFT_LOW;
+		kmalloc_size_index[elem] = KMALLOC_SHIFT_LOW;
 	}
 
 	if (KMALLOC_MIN_SIZE >= 64) {
@@ -854,7 +827,7 @@ void __init setup_kmalloc_cache_index_table(void)
 		 * is 64 byte.
 		 */
 		for (i = 64 + 8; i <= 96; i += 8)
-			size_index[size_index_elem(i)] = 7;
+			kmalloc_size_index[size_index_elem(i)] = 7;
 
 	}
 
@@ -865,7 +838,7 @@ void __init setup_kmalloc_cache_index_table(void)
 		 * instead.
 		 */
 		for (i = 128 + 8; i <= 192; i += 8)
-			size_index[size_index_elem(i)] = 8;
+			kmalloc_size_index[size_index_elem(i)] = 8;
 	}
 }
 
@@ -977,10 +950,10 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller
 		return ret;
 	}
 
-	s = kmalloc_slab(size, flags, caller);
+	if (unlikely(!size))
+		return ZERO_SIZE_PTR;
 
-	if (unlikely(ZERO_OR_NULL_PTR(s)))
-		return s;
+	s = kmalloc_slab(size, flags, caller);
 
 	ret = __kmem_cache_alloc_node(s, flags, node, size, caller);
 	ret = kasan_kmalloc(s, ret, size, flags);

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-17-9c9c70177183%40suse.cz.
