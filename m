Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCU2ZW2QMGQE2KZ4QRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 607CB94A587
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:39 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-530db30018asf1058124e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026699; cv=pass;
        d=google.com; s=arc-20160816;
        b=npbkh5ZDc2kO93OKO1gWkd+gzIIPlzlP+p+SeYh7NrdNQ/ZkOon5mqFthkJaR6Btlk
         +yLGbo/9KjuHLF1A7JmMiqlpYc9s7ILjrBMH8gN+7+7kP77uquRLxYvlmklVWXGLyBzz
         /STjQvXMWkD+95idu/4ppOtPe9bTSv677b1qjaMsLRw+bEWCmCizqtYR+/u69/BDoSwO
         xAIURtEpprDbe1HwyooXYhPWXJMvWau4hOsf9XFoicJuRjYlIGZZLlaN7RV8zHx7ikDC
         JEbmbewmljZNMl+9+Fh0LmgiXn0+/JR1ywAj4P0KTZJMun5xcJglUbOs+icI04z7tBjY
         x3FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=0WqdALhFJMtTCAGSc/NKxhikFyr/sdudCoIc0zgDZEI=;
        fh=blb7neSSbISzcO+tInjX+vjGolE/0M5FFnNwZWeoo9w=;
        b=ukKyqgLtwYYwdYppm/kMbPyw9X3Lt2rNE/w6ZyBH9HJNe3k5l8mCN20I2yehdnraYV
         clxoyhbzvhlglKeKZKlRSBU3Q4KQuyydFQwlTwVvkldWi57KAsQGyK0S0BlNyEVKDbmq
         +ZNdZxszIX4FniExlXvJMcr0zhBcDLlx+aYkvG+pnJGRwAznP31A5muEZAl2PemCaY2u
         ldXMxOSYCcPo21AH97YltNP4sgMtHmsptS5gywSbH/dXGIAj/GCF0MAQcU7eNewTT9wJ
         7hUnTZQ4mJ6rztP2WZe6LeHBfcIVeFulfU6rEZfNn3Yif8fIzfBRz7YDnfdgvTXvC3sL
         thfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YxdH1qXX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YxdH1qXX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026699; x=1723631499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0WqdALhFJMtTCAGSc/NKxhikFyr/sdudCoIc0zgDZEI=;
        b=Ljche/FZE9CXi5qQBOW+ya6mDOLE86Rnl9pC6hMSqi7AjvKRpgxSpq9SdAPmW5RuE3
         xIHc42Hv1VfS9ER9sRWwtXXotFM7Mq/eiY5EuRjI+PtuPlEbHyCsq7o1eJj+c6/hdQsE
         2mRuKknJkNiXc/hi28nmn/soiefZl0vglYPbScTMvytXmYpMcurPxH+wNMaiDKuG/mP5
         S5ROEZZngNgxSHawnjI1lUnBeETIgeg8iR8+RydF1gyoq3+BZC4U6kN59bydI1phsKFa
         N2M/WIEO2w6tKdhksH9cMVOy13PwL0dBDI1YNTcmFc8QBQlc+GmHlMU1W8ZddlElWjkC
         q8Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026699; x=1723631499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0WqdALhFJMtTCAGSc/NKxhikFyr/sdudCoIc0zgDZEI=;
        b=KtReFVo0UYQKMdxfRtrgI483H+cVZDSlMTxOzv4CF0aYL1XF5k7NYBDC6kIKFxEM+z
         UIh4aQSJ9CH73/+IWbDlFTfONULc1PzF8J0g5tjLcgetqIIHwOmtAD9PvmpOibyAf4bT
         6PGQ0gBpKpTqJW2CYzkFjPhZEX3yBtW6z0r+EOH1RkuO2NBAXTXChe0+AdLp/SawoS+B
         hAPlI54h2cA7UKCom6usVDmi/Nw8KhdwO83bsrag7SHt390ZozQ1xVVqotCCAkGPwM2B
         cleEEoCMAr4dRLYUiOh2kr2truhdLlb/Zu2n6ZI3j6BmArY2AVb4aKNxl90JrSVFUlfP
         X5Mg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVX2OMeMAIwxwKh9gNWslD4RXZK1S5wAF1BKoRjRtKQOGqSrQe3DmsGzdBPAzxI4+q44hhwy09S5qbeGjqBWmU1VQV7s8zbwA==
X-Gm-Message-State: AOJu0YxTGkLGxLM/oAYgMPDH/zIuHlq4NrgkOnmOIlQu9PLgTQok+hwq
	JL3GeMfaI1BvdJTxnWGmEw+G4b98WHfrQrJW09t/hR2YCLujUL98
X-Google-Smtp-Source: AGHT+IGXONouuIKhHV19RhWRHtAFdCUrhuz6GAUsmfv+YYs6+BWJAuOqKT10y80Ny8RnUsNq3J1CQg==
X-Received: by 2002:a05:6512:2393:b0:52f:c148:f5e4 with SMTP id 2adb3069b0e04-530bb3744f4mr12002691e87.21.1723026698392;
        Wed, 07 Aug 2024 03:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d21:b0:52f:cbbe:1afc with SMTP id
 2adb3069b0e04-530c31fff99ls15585e87.2.-pod-prod-09-eu; Wed, 07 Aug 2024
 03:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzic9NFy7rhT55myqXtgpIXjefBq2n1y+jWiiZfmqSY4t2yYy3TvWwfbp1tuoj3xKIp5DLnKVE7CIjiIOPV8r1LlIwCIIdzn91hA==
X-Received: by 2002:a05:6512:3a93:b0:52e:ff72:38f0 with SMTP id 2adb3069b0e04-530bb36bb71mr13922734e87.1.1723026696251;
        Wed, 07 Aug 2024 03:31:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026696; cv=none;
        d=google.com; s=arc-20160816;
        b=snnq2nEZ1/YDAjscU4aArKJK6wkdISJMk1piSBE5yrNGNvOHHUTlNJHgzuN6GTzzU+
         jQV9P6tDY+2zhsgiQ5Oe7hPjahkeQdB1v5IJj8LQOGaG2+Z5Ttq/8jAfy5tXiuZGQLXl
         /cQRwgMtym7vegZuEmCUX5wqeHI+BygHzBdu1kZfjWeVTzoWqGh52Q6jQFez/2Im3HaX
         v9wDoJFUEH1M8O0RQRF7fgK59F+qMR276svUU86euOM3oBOJcsHm+zwAPhzXXzQELG76
         JqCQHu7eHsqLujkKC3depbxCbdQtMXEPWOdOdoAQsd+MIz2TAkPtM18KV9ZH73q8cuOr
         Aiqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=EuVEO95mFBgy7A/J87dAp3t2Ac0+1I7QV5k30Rj6i0c=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=CT0mWlnsG4FpLchRnpzrsVM4aTnJR9jE8U8k5Pr+hO3N/qdwMJR/qEIKvoIpttjFbT
         WhcHcWH21G85zdCC/Lin1d8YMwkft6oZSXaLnI0ykMP7VnjqDrb6pUeMPrTn9UOknw9m
         EjqILnZ6izmQCrxboC5I0xqkpG6mDOID56h43gvHCp+gr2hBIvt8kBZKirtz0BEo3Qal
         mDVTO6sANPO2bIPMwXu03s4VhMr7Q7qkCPQeoY9NjMIcM+/TZTo/36gULV2Ez+KSOcgv
         goHdGDB55Fj4ED1QNOG3ITykO7DXMc3kTOHsHcQFknUBiiW+6MdoK9i/y4d8ju9qADPW
         6meA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YxdH1qXX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YxdH1qXX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530de451e43si25151e87.12.2024.08.07.03.31.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E058D21CF8;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8837F13B0B;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id kGj1IAZNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:34 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 07 Aug 2024 12:31:20 +0200
Subject: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
To: "Paul E. McKenney" <paulmck@kernel.org>, 
 Joel Fernandes <joel@joelfernandes.org>, 
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>, 
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>, 
 "Jason A. Donenfeld" <Jason@zx2c4.com>, 
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.1
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_RCPT(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	FREEMAIL_TO(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[goodmis.org,efficios.com,gmail.com,inria.fr,kernel.org,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,google.com,googlegroups.com,suse.cz];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	R_RATELIMIT(0.00)[to_ip_from(RLtsk3gtac773whqka7ht6mdi4)]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YxdH1qXX;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YxdH1qXX;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Add a test that will create cache, allocate one object, kfree_rcu() it
and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
in kmem_cache_destroy() works correctly, there should be no warnings in
dmesg and the test should pass.

Additionally add a test_leak_destroy() test that leaks an object on
purpose and verifies that kmem_cache_destroy() catches it.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 lib/slub_kunit.c | 31 +++++++++++++++++++++++++++++++
 1 file changed, 31 insertions(+)

diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
index e6667a28c014..6e3a1e5a7142 100644
--- a/lib/slub_kunit.c
+++ b/lib/slub_kunit.c
@@ -5,6 +5,7 @@
 #include <linux/slab.h>
 #include <linux/module.h>
 #include <linux/kernel.h>
+#include <linux/rcupdate.h>
 #include "../mm/slab.h"
 
 static struct kunit_resource resource;
@@ -157,6 +158,34 @@ static void test_kmalloc_redzone_access(struct kunit *test)
 	kmem_cache_destroy(s);
 }
 
+struct test_kfree_rcu_struct {
+	struct rcu_head rcu;
+};
+
+static void test_kfree_rcu(struct kunit *test)
+{
+	struct kmem_cache *s = test_kmem_cache_create("TestSlub_kfree_rcu",
+				sizeof(struct test_kfree_rcu_struct),
+				SLAB_NO_MERGE);
+	struct test_kfree_rcu_struct *p = kmem_cache_alloc(s, GFP_KERNEL);
+
+	kfree_rcu(p, rcu);
+	kmem_cache_destroy(s);
+
+	KUNIT_EXPECT_EQ(test, 0, slab_errors);
+}
+
+static void test_leak_destroy(struct kunit *test)
+{
+	struct kmem_cache *s = test_kmem_cache_create("TestSlub_kfree_rcu",
+							64, SLAB_NO_MERGE);
+	kmem_cache_alloc(s, GFP_KERNEL);
+
+	kmem_cache_destroy(s);
+
+	KUNIT_EXPECT_EQ(test, 1, slab_errors);
+}
+
 static int test_init(struct kunit *test)
 {
 	slab_errors = 0;
@@ -177,6 +206,8 @@ static struct kunit_case test_cases[] = {
 
 	KUNIT_CASE(test_clobber_redzone_free),
 	KUNIT_CASE(test_kmalloc_redzone_access),
+	KUNIT_CASE(test_kfree_rcu),
+	KUNIT_CASE(test_leak_destroy),
 	{}
 };
 

-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c%40suse.cz.
