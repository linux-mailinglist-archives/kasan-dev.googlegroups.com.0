Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHWH4OXAMGQERRK2ZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54AD5861B91
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 19:27:43 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-512e13a6a70sf1012701e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 10:27:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708712863; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZBmZLbUIbMaWVk/MGOdQaC/MuJ1MffTdjqbh4x/FscDnOX9WxtHMgyYQJDEr6BmR4F
         IsyRBKn5emLKI6n7Oj72O5suLhOfAYnHzlaCfx0x+E1Qe18zVuTWS8EJP19BOKZ/8PgV
         tA6fmNJzTTzIQvFefgABL7llx4D09kqCZxx4qOaOoOvQyfhYW3LE49z4k7R0qleOriSH
         GQI24MAqGx5NcAcA40dlXhb5jDd7vW902fx49l4/Cb0/GBBM3cgriEXOl8sXjFvmKGP9
         ixjadBbbnegMLTvqVNxugV313yFbWNrr5wtyrM90a3IDZdIR/4macsDnb15wTjHqIEJd
         YQwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=9brSun5uWYqTST7KjZE+5xUN2DwlqS2HZno2xHbCJuM=;
        fh=dHHke+BGwZc7ha5sUgV2nXuRx5TRlMuUXp8YC67VtSs=;
        b=YTN50LO6ZW0Nv2wqi4B8O+wzUJLXTnKWZgbZ/5UYot6UKOerheyWb6KJhdW4OmtsA4
         ZFkkv6hpqkQtx8uxvOKxOAFe3yOvO5TJUrkCfkTR8xOGWKeNYsWlvm4bqIU6QG02kQ/I
         yuNr7bz/jU4wqTOz9FYTX5B37NLuhEiATFCH1Mzlf7j/ciW5WS7pxEQa8kTl7cdNQ3Pk
         ZX00ySrPzQtGatgJRf5ILW68dPkWR6arhSNA6cql0G3lk9U71C9aSFM2CMpdnyf1X1tr
         JCoGf9KwqRqzNWZcdt1iEUZKFd9xai1kYccbvxsriLQeptbLlNKwTmG2YKudxImkPxER
         SniA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZmoNfrpC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZmoNfrpC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708712863; x=1709317663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9brSun5uWYqTST7KjZE+5xUN2DwlqS2HZno2xHbCJuM=;
        b=bdYCOyPF/p0An5C5W3G1MJVuCIgmRraNle8HQhfk6Xo4Lzexr+Cd42Br7EJIDBEHGY
         VKTtuKmo46wIGSUBRvY+6Gp0IUJGoPk5hveFovuZKZRpssvaOqgJaYQSnJsvHcOaM2OL
         TWx9ZP/ezuwJrT7g3OES3Hif/hHVbl6+hqr/h360uFEZnZg1m8Pwb0E0+721qHrmhJNY
         3kUYwcQJFhcB/ZHKEN3C+4qa9vtDjovHpgECYjAG5OpD4/5MAb27WXNjLJX0IyQ1ccGs
         i1rr9BIXYLWsTcq2rAwG9DrvPW0hPddxDhzUB4ysptIA7AUj6/6PVwmO/GYd4lFZcYsb
         SVdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708712863; x=1709317663;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9brSun5uWYqTST7KjZE+5xUN2DwlqS2HZno2xHbCJuM=;
        b=Hop0JheD5aiB2/mp6pBCDE95F+9SgtYzcbM8J0OSEvgBC9bZ2X3TJ4dGhwU6G9yC1M
         RfhzeHxJameZLOTRvb8pvKinezHm+LGqvtyEmMIbPiKHPVuhlZyuuKznkotE5I86bgFx
         vqWc1ISfoNOml5DpgBbxLFcj+uOcvpv4d76Y6D3RWInd2g6P88P8VtAc3OU2+2Y8Qcav
         a7GwfuP5StJJI2ec9z7iOrJB+7J2JTM3Ae7Z8zz47rhgLzNFX0Z3VwbCp0aeuQDZPLqf
         K0Uyi9GdQGdhBF4jm0AxoAU0vBCQ1C2hksBbXZvTlLKu8qtuaRmJEeUYppAbbCduvzzr
         W5LA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZMj3IpygsBFi1pYZX4vCnRntElGL7CwKBaixn0+H3OhUw7FyJaKeIZgfNT9cQBoCwZDwqpQVCFpSXnEfHSgzIATvuYMOI0Q==
X-Gm-Message-State: AOJu0Yye88lIXFmSY4tIUh+jyQ8yT32L2Y7TTIGPuT0U88CnK0jb0SKx
	BeT4LKZhWd45SiOl0IotwTNpnQVMOKNjenKNfeHS93OHm5OiuCNB
X-Google-Smtp-Source: AGHT+IEdS9OlLYb5fCgr5R19TAHKpN2Y8H6M7/M3NXERbOAGq9fLtwKwZPSCcjRrKdBZlGz8TrfrSg==
X-Received: by 2002:a05:6512:3a8e:b0:512:9c37:97fc with SMTP id q14-20020a0565123a8e00b005129c3797fcmr358896lfu.57.1708712862343;
        Fri, 23 Feb 2024 10:27:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f05:b0:512:d555:991b with SMTP id
 y5-20020a0565123f0500b00512d555991bls339207lfa.1.-pod-prod-03-eu; Fri, 23 Feb
 2024 10:27:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVOU52hyTQRwi0i3RznnPeEl9pwmjFZk0Ml4NtkmSH1NBCM8zAy8Tzda51DB616WueIYWywXaLt271hq0R/UNY7Sa+7P9KWqIWk2A==
X-Received: by 2002:a2e:b6cd:0:b0:2d2:44cb:b0a3 with SMTP id m13-20020a2eb6cd000000b002d244cbb0a3mr431885ljo.48.1708712860254;
        Fri, 23 Feb 2024 10:27:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708712860; cv=none;
        d=google.com; s=arc-20160816;
        b=wmQKvq0R0NEUWx8LgD9OnCNnrb+ut/xUtmk4TS50uREcJ7oRqKmizscAyUbDWlVPc6
         tdB9Tpxcah6cMn7+Ge1ANGa5hy1nkRhnR9vM/1v+FYRwJCBe8EagJuMnNYKLgTbzLEA4
         FjuXuNCcHhNRMwuh40z88hq8L5O+k9IWlScOlyPgxnSJCftaHUC0bpk78soA0C2wXKUZ
         Esxx3XLqQRDKsjx84HH+12rNtcKaASjjGx6vtkcAJvcVnGdVuPm8/cUre6k+xGlikMnW
         wnmW9MgzkehFDsIEtiVst7E0rmsD33ilUkf3p58WBpCq0mROCL2ceDRGz6J3R4Iri1li
         gERg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=gdIIkjKNjW91Ug8+r97lNpU6eko4/0lhYa/nSEYrEFs=;
        fh=iiw6AxRn834Rp3X3mGFcQcmYTlAscmlxQxZZCAoI+ts=;
        b=Wd8HkJLZXR7gUMvdDSeqFIOr+Cly9nBEXciRBAagoxh0gsJAb6ezoaW40eosSYFvkh
         ZgwCwJ/LvNSeU2c2mYZLgXFRqGDgasLiNsLoSzbxtPr5SpuLIUi2y+PgZBKY70Qcuj+W
         TlOZuq7U1yUjyC+/hWTHmEb8nRYLA52Mbv9kJrFq/EbdbNPUKkVY9hZoV/0qiZNnLIW2
         dY09s3b385fKyPXEdthL8k326tQXyFoLqeCeoII2AcxZGUCBLd41cscM/oEETTb+JEPm
         WnS370iV/RFJLszm6hNIFRI2+FreULRJIxQ9Wct2bYnHeVH6UTicj8ZsQg8D0DO+GJLY
         sR9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZmoNfrpC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZmoNfrpC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id x22-20020a2ea7d6000000b002d25688f527si243576ljp.1.2024.02.23.10.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 10:27:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 46C87210F3;
	Fri, 23 Feb 2024 18:27:39 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 22A6913AC7;
	Fri, 23 Feb 2024 18:27:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id GOwlCJvj2GUaTQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 18:27:39 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Feb 2024 19:27:18 +0100
Subject: [PATCH v2 2/3] mm, slab: use an enum to define SLAB_ cache
 creation flags
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240223-slab-cleanup-flags-v2-2-02f1753e8303@suse.cz>
References: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz>
In-Reply-To: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>, 
 Xiongwei Song <xiongwei.song@windriver.com>, 
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.13.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=7536; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=Pwf3NzcoQQwCRBmd+qMj8XBoxm9DrwZf7S0mWjV+OLY=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl2OOVBVULzhmkRIvmLB8VcoT8BDIxH1Iid/dmv
 SrNByJn3OSJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdjjlQAKCRC74LB10kWI
 mix4B/91x98pri0nNwjdaIAvA0K80Xqlb+Ml7TNN2Kn4iCVaFEU3o+qL1kk2atqnc2Vr0QICmzo
 IvNPMcWRhiPc3oROrosQ4kYcUjO6sjMm3mYp99TavwSmBrdiPUltaY9UNW82evycsXiwESqgeV9
 F55WmiAtDFq8aRweNmizy9g6Ro1bWuAWFed1CHPiWBiQtWTtqrrz7ID1P+/TCYLqLKV02zPKlPe
 PypXdFNkBJd0G6hK9VmcZ5FJTs8/zlV6X3XI3Z58E14hErLUDVEqSROpPcTQ2gtbh3RlFQk2tYw
 XmSmzimiGjvjKKM/XW9Phq5UONbYVTDorTF12wTzkJ35NiVY
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spam-Level: 
X-Spam-Score: -2.80
X-Spamd-Result: default: False [-2.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-3.00)[100.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RLqdadssyy1w6u3twx3pq4jyny)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[19];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ZmoNfrpC;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ZmoNfrpC;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The values of SLAB_ cache creation flags are defined by hand, which is
tedious and error-prone. Use an enum to assign the bit number and a
__SLAB_FLAG_BIT() macro to #define the final flags.

This renumbers the flag values, which is OK as they are only used
internally.

Also define a __SLAB_FLAG_UNUSED macro to assign value to flags disabled
by their respective config options in a unified and sparse-friendly way.

Reviewed-and-tested-by: Xiongwei Song <xiongwei.song@windriver.com>
Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>
Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 94 +++++++++++++++++++++++++++++++++++++---------------
 mm/slub.c            |  6 ++--
 2 files changed, 70 insertions(+), 30 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index b1675ff6b904..f6323763cd61 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -21,29 +21,69 @@
 #include <linux/cleanup.h>
 #include <linux/hash.h>
 
+enum _slab_flag_bits {
+	_SLAB_CONSISTENCY_CHECKS,
+	_SLAB_RED_ZONE,
+	_SLAB_POISON,
+	_SLAB_KMALLOC,
+	_SLAB_HWCACHE_ALIGN,
+	_SLAB_CACHE_DMA,
+	_SLAB_CACHE_DMA32,
+	_SLAB_STORE_USER,
+	_SLAB_PANIC,
+	_SLAB_TYPESAFE_BY_RCU,
+	_SLAB_TRACE,
+#ifdef CONFIG_DEBUG_OBJECTS
+	_SLAB_DEBUG_OBJECTS,
+#endif
+	_SLAB_NOLEAKTRACE,
+	_SLAB_NO_MERGE,
+#ifdef CONFIG_FAILSLAB
+	_SLAB_FAILSLAB,
+#endif
+#ifdef CONFIG_MEMCG_KMEM
+	_SLAB_ACCOUNT,
+#endif
+#ifdef CONFIG_KASAN_GENERIC
+	_SLAB_KASAN,
+#endif
+	_SLAB_NO_USER_FLAGS,
+#ifdef CONFIG_KFENCE
+	_SLAB_SKIP_KFENCE,
+#endif
+#ifndef CONFIG_SLUB_TINY
+	_SLAB_RECLAIM_ACCOUNT,
+#endif
+	_SLAB_OBJECT_POISON,
+	_SLAB_CMPXCHG_DOUBLE,
+	_SLAB_FLAGS_LAST_BIT
+};
+
+#define __SLAB_FLAG_BIT(nr)	((slab_flags_t __force)(1U << (nr)))
+#define __SLAB_FLAG_UNUSED	((slab_flags_t __force)(0U))
 
 /*
  * Flags to pass to kmem_cache_create().
  * The ones marked DEBUG need CONFIG_SLUB_DEBUG enabled, otherwise are no-op
  */
 /* DEBUG: Perform (expensive) checks on alloc/free */
-#define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
+#define SLAB_CONSISTENCY_CHECKS	__SLAB_FLAG_BIT(_SLAB_CONSISTENCY_CHECKS)
 /* DEBUG: Red zone objs in a cache */
-#define SLAB_RED_ZONE		((slab_flags_t __force)0x00000400U)
+#define SLAB_RED_ZONE		__SLAB_FLAG_BIT(_SLAB_RED_ZONE)
 /* DEBUG: Poison objects */
-#define SLAB_POISON		((slab_flags_t __force)0x00000800U)
+#define SLAB_POISON		__SLAB_FLAG_BIT(_SLAB_POISON)
 /* Indicate a kmalloc slab */
-#define SLAB_KMALLOC		((slab_flags_t __force)0x00001000U)
+#define SLAB_KMALLOC		__SLAB_FLAG_BIT(_SLAB_KMALLOC)
 /* Align objs on cache lines */
-#define SLAB_HWCACHE_ALIGN	((slab_flags_t __force)0x00002000U)
+#define SLAB_HWCACHE_ALIGN	__SLAB_FLAG_BIT(_SLAB_HWCACHE_ALIGN)
 /* Use GFP_DMA memory */
-#define SLAB_CACHE_DMA		((slab_flags_t __force)0x00004000U)
+#define SLAB_CACHE_DMA		__SLAB_FLAG_BIT(_SLAB_CACHE_DMA)
 /* Use GFP_DMA32 memory */
-#define SLAB_CACHE_DMA32	((slab_flags_t __force)0x00008000U)
+#define SLAB_CACHE_DMA32	__SLAB_FLAG_BIT(_SLAB_CACHE_DMA32)
 /* DEBUG: Store the last owner for bug hunting */
-#define SLAB_STORE_USER		((slab_flags_t __force)0x00010000U)
+#define SLAB_STORE_USER		__SLAB_FLAG_BIT(_SLAB_STORE_USER)
 /* Panic if kmem_cache_create() fails */
-#define SLAB_PANIC		((slab_flags_t __force)0x00040000U)
+#define SLAB_PANIC		__SLAB_FLAG_BIT(_SLAB_PANIC)
 /*
  * SLAB_TYPESAFE_BY_RCU - **WARNING** READ THIS!
  *
@@ -95,19 +135,19 @@
  * Note that SLAB_TYPESAFE_BY_RCU was originally named SLAB_DESTROY_BY_RCU.
  */
 /* Defer freeing slabs to RCU */
-#define SLAB_TYPESAFE_BY_RCU	((slab_flags_t __force)0x00080000U)
+#define SLAB_TYPESAFE_BY_RCU	__SLAB_FLAG_BIT(_SLAB_TYPESAFE_BY_RCU)
 /* Trace allocations and frees */
-#define SLAB_TRACE		((slab_flags_t __force)0x00200000U)
+#define SLAB_TRACE		__SLAB_FLAG_BIT(_SLAB_TRACE)
 
 /* Flag to prevent checks on free */
 #ifdef CONFIG_DEBUG_OBJECTS
-# define SLAB_DEBUG_OBJECTS	((slab_flags_t __force)0x00400000U)
+# define SLAB_DEBUG_OBJECTS	__SLAB_FLAG_BIT(_SLAB_DEBUG_OBJECTS)
 #else
-# define SLAB_DEBUG_OBJECTS	0
+# define SLAB_DEBUG_OBJECTS	__SLAB_FLAG_UNUSED
 #endif
 
 /* Avoid kmemleak tracing */
-#define SLAB_NOLEAKTRACE	((slab_flags_t __force)0x00800000U)
+#define SLAB_NOLEAKTRACE	__SLAB_FLAG_BIT(_SLAB_NOLEAKTRACE)
 
 /*
  * Prevent merging with compatible kmem caches. This flag should be used
@@ -119,25 +159,25 @@
  * - performance critical caches, should be very rare and consulted with slab
  *   maintainers, and not used together with CONFIG_SLUB_TINY
  */
-#define SLAB_NO_MERGE		((slab_flags_t __force)0x01000000U)
+#define SLAB_NO_MERGE		__SLAB_FLAG_BIT(_SLAB_NO_MERGE)
 
 /* Fault injection mark */
 #ifdef CONFIG_FAILSLAB
-# define SLAB_FAILSLAB		((slab_flags_t __force)0x02000000U)
+# define SLAB_FAILSLAB		__SLAB_FLAG_BIT(_SLAB_FAILSLAB)
 #else
-# define SLAB_FAILSLAB		0
+# define SLAB_FAILSLAB		__SLAB_FLAG_UNUSED
 #endif
 /* Account to memcg */
 #ifdef CONFIG_MEMCG_KMEM
-# define SLAB_ACCOUNT		((slab_flags_t __force)0x04000000U)
+# define SLAB_ACCOUNT		__SLAB_FLAG_BIT(_SLAB_ACCOUNT)
 #else
-# define SLAB_ACCOUNT		0
+# define SLAB_ACCOUNT		__SLAB_FLAG_UNUSED
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
-#define SLAB_KASAN		((slab_flags_t __force)0x08000000U)
+#define SLAB_KASAN		__SLAB_FLAG_BIT(_SLAB_KASAN)
 #else
-#define SLAB_KASAN		0
+#define SLAB_KASAN		__SLAB_FLAG_UNUSED
 #endif
 
 /*
@@ -145,25 +185,25 @@
  * Intended for caches created for self-tests so they have only flags
  * specified in the code and other flags are ignored.
  */
-#define SLAB_NO_USER_FLAGS	((slab_flags_t __force)0x10000000U)
+#define SLAB_NO_USER_FLAGS	__SLAB_FLAG_BIT(_SLAB_NO_USER_FLAGS)
 
 #ifdef CONFIG_KFENCE
-#define SLAB_SKIP_KFENCE	((slab_flags_t __force)0x20000000U)
+#define SLAB_SKIP_KFENCE	__SLAB_FLAG_BIT(_SLAB_SKIP_KFENCE)
 #else
-#define SLAB_SKIP_KFENCE	0
+#define SLAB_SKIP_KFENCE	__SLAB_FLAG_UNUSED
 #endif
 
 /* The following flags affect the page allocator grouping pages by mobility */
 /* Objects are reclaimable */
 #ifndef CONFIG_SLUB_TINY
-#define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
+#define SLAB_RECLAIM_ACCOUNT	__SLAB_FLAG_BIT(_SLAB_RECLAIM_ACCOUNT)
 #else
-#define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0)
+#define SLAB_RECLAIM_ACCOUNT	__SLAB_FLAG_UNUSED
 #endif
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
 /* Obsolete unused flag, to be removed */
-#define SLAB_MEM_SPREAD		((slab_flags_t __force)0U)
+#define SLAB_MEM_SPREAD		__SLAB_FLAG_UNUSED
 
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
diff --git a/mm/slub.c b/mm/slub.c
index 2ef88bbf56a3..2934ef5f3cff 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -306,13 +306,13 @@ static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
 
 /* Internal SLUB flags */
 /* Poison object */
-#define __OBJECT_POISON		((slab_flags_t __force)0x80000000U)
+#define __OBJECT_POISON		__SLAB_FLAG_BIT(_SLAB_OBJECT_POISON)
 /* Use cmpxchg_double */
 
 #ifdef system_has_freelist_aba
-#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0x40000000U)
+#define __CMPXCHG_DOUBLE	__SLAB_FLAG_BIT(_SLAB_CMPXCHG_DOUBLE)
 #else
-#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0U)
+#define __CMPXCHG_DOUBLE	__SLAB_FLAG_UNUSED
 #endif
 
 /*

-- 
2.43.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240223-slab-cleanup-flags-v2-2-02f1753e8303%40suse.cz.
