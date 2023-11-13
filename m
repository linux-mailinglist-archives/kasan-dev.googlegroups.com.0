Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBXLZGVAMGQE5P7265A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E8377EA366
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:15 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-507a3426041sf5117957e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902855; cv=pass;
        d=google.com; s=arc-20160816;
        b=SmaEJmlkPokEXDD0xVFMKddbwof/spXRMXT+KEWIQXjBkzArZ6ix5AOqFxI1qco1U/
         6u/Tr0i4E1k3bllkbjwANGHgyWPRw+TVMVx+YPIybdVvms7g0VqQdzsAyTA0TVsGxn0Q
         rOfsI+f5gzFs+hzCMPSlPYVYhs912o4UdHKDpAljqB0f1FKlJA8kMnWKvimTOYYE4log
         qJor4U9hKkh8AR7n9Bxa0U5zFmiO3A3LFxP2YtFlF8EjplTUu5+Xg93dKlcshKwIiPaE
         EkvhYa24h06k16Dr1y0rlcRIdecIOQ5YReVNRyTsmllayjFuaTuvqUoE0KS4pb7D5ASU
         +HWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KcaPE2kqf5X+WJ7D9ywcn2uYsH1/D6Rr2zNUXyrMx+4=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=N2wcq+YObp4G8WlUmVGvHRQuknlUct7r2bqzwLkgG/sJoP18l4eoCxzpK/x9dqTbWU
         QnCKwsheoYxrRzm/Oa1Ckb7l0y9z/d+AlDNiUd6KspEF7MrLGaLmSMpwkLwXZdB1xjxk
         tH/j6gmdbleaJrqBYEAoMUgOfTbdEY+nO7XXXoW8G/UEBi1T+Zr+2+YzVw8034YfaYSL
         Xu6eM/D//yi5w/1kvzXzJmZvqmapYPAucOSMsCuTWN1Zu2PlJYr174LN1Qu8FM8KK3qh
         i26x2k/kcYwdYYqtSxtKwWzdD2Q3depcI5RNYhtWUNslhSasujWvRmhd3TSY1by6G6B/
         g4ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0Zk71Af4;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902855; x=1700507655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KcaPE2kqf5X+WJ7D9ywcn2uYsH1/D6Rr2zNUXyrMx+4=;
        b=JKXaxHjlbW6A710RFzVvg+vl8OX2JdGHVNC3ZLoUjnh8FGjC4Jn1ZdrcnwoVBNkeXy
         fv6BfdC+kmAKpaQF7iZ9c2rvj3s0Ln9rBIGaWgWbyK8owz5VQ9pxVZZ0H2ztQwWQ4Top
         ayj1fQU6BwgzZSQdkDrJc4dCaDkJC7wlKCek+cv4V3pdtXLKYpRRqXdVGNm3xpk8wgLj
         K8RO7jO6+g/KTPsy0FO4OChippkYC4YxbJGlh6cd7G1agiw1E9uH0IysFb4QGtohb1QU
         PUaU9686Zkt6Yvc034cr6Wuk96gss7m9cd9iDGYa4RqWX7tAQh3EA1TN/OuginERMmro
         uJig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902855; x=1700507655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KcaPE2kqf5X+WJ7D9ywcn2uYsH1/D6Rr2zNUXyrMx+4=;
        b=JS8PgSIkxnxqkcYOONyylXoDSWKCfs2Soi/TMsp98caq7DIcZQvW+hoVO7Dwo6qlQQ
         LhW8b9WE7vh3hzg/S3aDftg7JVEQZMjC77sbqHHUHXZwm+CfmeGfxvqK96UxvM2OA9u+
         4mk4ejejfLTrSn4FCPGVcOBEsIardjeCfwbL5ruN6CiI05ZL2376/b89AtrDPiIAvOp4
         IGEGTllXZtrdL6QfPJppYpTDcBoCoyWFjIiGJyn6kQYEE0YcGs7wOdqTtucAyf8s4tDe
         2aI9gqZBllFcewm+U8wQzLNGFwKrczIuewYSXCwzcSNOhP3rCDA3B52xFG4zQzI4yLD6
         AshQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxse4BlSEbEwoePY5XGLUePmPGudQu5pYGfcOdN+oJQAz23FhBU
	F1Bc0+e2251mNPllqznMvCM=
X-Google-Smtp-Source: AGHT+IEVTe+/zUAcZ4dewUO6CJHdWJnP5tNHRAXs6X37iBQSEU4VnejaaceH+4SCut8rCovEpbpXkA==
X-Received: by 2002:ac2:43a3:0:b0:509:3bba:e8a with SMTP id t3-20020ac243a3000000b005093bba0e8amr4668129lfl.39.1699902854287;
        Mon, 13 Nov 2023 11:14:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:159e:b0:507:9a12:cf84 with SMTP id
 bp30-20020a056512159e00b005079a12cf84ls184030lfb.2.-pod-prod-09-eu; Mon, 13
 Nov 2023 11:14:12 -0800 (PST)
X-Received: by 2002:a05:6512:2382:b0:509:1368:ddc1 with SMTP id c2-20020a056512238200b005091368ddc1mr6981974lfv.53.1699902852329;
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902852; cv=none;
        d=google.com; s=arc-20160816;
        b=u7ACcm+pXrQOpPUcpTsgkIE+gxd84ZHxHLmzAMOY31Gfa2BU61iburVw+WMEw/0T1G
         kt55YMfhJtlp3sH+d/8KJ8dB03Rv+D99V0AUJGKR4QALGZRfRb/LRKWqemh9G47vZ8Tj
         zD8ozZ1Gq44WnxDBzEspyJTcAeEIjHT4/l/LQd9pBSMVSnhSKIF2Uo+GJ5BUVHMWkNsH
         nM18XxtzAS1ptZt5CrjbdEXHe3zdMqiYN6d0Y7/zJuBit0ZhIYKPkabBC6cPJCfut1hj
         UdhdRZQR+0X2gTer57dZ6epLeJJBETqEr4ZY2NXbTgdghQkCXD0kN9/VyqFEAfk0mqv9
         j6JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=lpvt5s4LImzllAEMKC9yyjTODPwLX4+6Y45s6lDAdck=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=mlgKKekYkvAMGRcZWrGBHPYkkM8/Ngrc+bQWhcq3VWDRDisc1KO9D4RUlqVFtYoPuI
         pvgH8uKY5kYj8zVP1IyjimrTRO7BIJ9LPidNo9cDHkV3jRdXpFUKJEQLX9y+VwTaStwM
         MkrkGSISKnj8grLj3Gt75HjOHICjm7JgfnXhufDlo4YP8MnphnfM2Vy97z0mIsiB7elV
         ZRPXRXbw0f6+5H3mO7hYxYYxNOqPAsBtCzqQgol67HWf2IsZuZyDachGY1MoeeDUuQTU
         CbMeI1KTUgwafqYI6MtNVUkf7FWDrlOlRrLF5gyYpEA5870hnZX92IHwAN8Thcf6/n91
         8KlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0Zk71Af4;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bp29-20020a056512159d00b005090fd18c05si232087lfb.11.2023.11.13.11.14.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id AE5771F86B;
	Mon, 13 Nov 2023 19:14:11 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 6270F13907;
	Mon, 13 Nov 2023 19:14:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +BNfF4N1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:11 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 07/20] mm/mempool/dmapool: remove CONFIG_DEBUG_SLAB ifdefs
Date: Mon, 13 Nov 2023 20:13:48 +0100
Message-ID: <20231113191340.17482-29-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0Zk71Af4;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

CONFIG_DEBUG_SLAB is going away with CONFIG_SLAB, so remove dead ifdefs
in mempool and dmapool code.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/dmapool.c | 2 +-
 mm/mempool.c | 6 +++---
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/dmapool.c b/mm/dmapool.c
index a151a21e571b..f0bfc6c490f4 100644
--- a/mm/dmapool.c
+++ b/mm/dmapool.c
@@ -36,7 +36,7 @@
 #include <linux/types.h>
 #include <linux/wait.h>
 
-#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
+#ifdef CONFIG_SLUB_DEBUG_ON
 #define DMAPOOL_DEBUG 1
 #endif
 
diff --git a/mm/mempool.c b/mm/mempool.c
index 734bcf5afbb7..62dcbeb4c2a9 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -20,7 +20,7 @@
 #include <linux/writeback.h>
 #include "slab.h"
 
-#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
+#ifdef CONFIG_SLUB_DEBUG_ON
 static void poison_error(mempool_t *pool, void *element, size_t size,
 			 size_t byte)
 {
@@ -95,14 +95,14 @@ static void poison_element(mempool_t *pool, void *element)
 		kunmap_atomic(addr);
 	}
 }
-#else /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
+#else /* CONFIG_SLUB_DEBUG_ON */
 static inline void check_element(mempool_t *pool, void *element)
 {
 }
 static inline void poison_element(mempool_t *pool, void *element)
 {
 }
-#endif /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
+#endif /*CONFIG_SLUB_DEBUG_ON */
 
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-29-vbabka%40suse.cz.
