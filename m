Return-Path: <kasan-dev+bncBDXYDPH3S4OBBX5VZTFQMGQEWCN36FQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YK88CeEac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBX5VZTFQMGQEWCN36FQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:21 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BCD1712C2
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:20 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-47fff4fd76dsf14005265e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151200; cv=pass;
        d=google.com; s=arc-20240605;
        b=QQdFLyCFY4GBqlkTpr29+1oEJs9/do8jrfoDIiUY9b2KECpVdVk2/C3/JwKLznZu9X
         4Whr6QAQjX8x0Bgjmoym2TsahVRLryUkUyf3dLxwQdL3GUhBZIIe34ZjPLQ9IoDh3J6o
         ikp4qDK6So7M/Y2VpZgmc0NVUEF0ghXOg8OdsPmkIWT0xpAZI0arfhBoHjUWFwvlajTk
         002iJvNzLkdWVQ6y8rklDh9EhxxlCqlbUy952f+qw5F5dTxeHfvQGIMO+S35Nmo1Bw0k
         PgbBq0pAgzYRNxkYkiH+zErg7Z0LFHZAfykQSvVT9GeMO+nL2G0IlquqRVtjjmsmmBlx
         VxMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=NJ7Roe/BPRBlbL+CPxjwHMRNkkyPDDepxlzP2862RRI=;
        fh=jwVcqVLdTazAw+sMEgNFebjOetsy0p/AEhpHdmwa3vU=;
        b=kqx5RfqDEwPuiKZPzmEKUkBvvc9LyceqKJqDHXmjuRldHf26e5KUFCZpzDh9TooOBK
         QUZdjynw299wOQbchVGYMCHaBH+mKEfViv/YeZCwqE/LKrs60UqaAU6u0TgfnXVYc0Yw
         iByFybdkQA1GAQT20Ys67cJwbGeFNPm+EqYWGE4oHTsPH6W4xPlYwt49P9h28aGdvPts
         rMqyMAGFJ7c2+UMnkOTwKHD/lXbqTVyAYa3LBCl6j5igThSLm8WqPeaWdd1EPo70YVYF
         W5PeAv1ZlAFXj/TpNZieTPvOm4nH76XCPIF0eeApY8IQznUEfcvVTMHBjX/S7KyJPQ5R
         QNrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TwaNSJ22;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151200; x=1769756000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NJ7Roe/BPRBlbL+CPxjwHMRNkkyPDDepxlzP2862RRI=;
        b=OWt6sHB+dL3kF6TUS9Kd1tDL8QmnyiuFABgWdhsQSuCD3R6076nCNNjpZyqRZEZsto
         uNor4RLhz1uexqAIRI88Q8pYlvEQTCZ5Ik4GAzdFDp5b20jaXvVtrSBMwP+wDrmuc231
         MP9GCA0Q02ZoHc8B3RBAnwLNCbu3lR/5pux3Nyh/R6H3AxEV4mma3Y9XOezRPY364GDn
         GQqTvlrZJR83lqQi/X52WbvGrqEKh0DSkdVIrT5HbOJP47jGda2AgEEfvAHUttTOPlX4
         GQ/P7kYAwNQSSI5HCkoYPTemt33r0ATvuTeu7Lwy3e4aaW7h//68ENFnt3ipkQPtS02a
         xy+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151200; x=1769756000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NJ7Roe/BPRBlbL+CPxjwHMRNkkyPDDepxlzP2862RRI=;
        b=BUyqRABhAUE5/x2PwoCQeTjBuiEo5HDNan52iJa/t6G9NbLVgDxaT+KB8xjh3aJXy7
         wvDQLo3Rt3qP+gulNiRZxkckiZ8yPcFqsAJZLKadRzJTOt0LLSb3jh6yJH18pczRBIvV
         F9XkuTWbfHhtEbmhJWyFfMOxMJZeWRMhsSTUXda0jg7Smp2+zDq0ei4uwJK43dESnnSF
         ofpJAmsG0cM8pWkoYBmRFk6xn1MCRzri+rAEumu+RtbRSqxqSGNbE9Uz3fUsmHNrmIhQ
         gspBbeVWQ/pPSmQJrw2ga5izSq9Ts2M3thqkZ/FirgB4ND5cXXw+YwOA3Uk4TuBmckQn
         jpOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+4ivWUrdnHSWfKGNNSOr8w9/1a3hfKrrwDX5qVrlbEmRI6Yfd41mPvUw9HVONja4FLZ/79g==@lfdr.de
X-Gm-Message-State: AOJu0YwSk9cBJgBUEqlfCNIeehb82BLnDaUeZSYUa0awVJHVq0YqG4oO
	8/m4/MaYgSkOW4FgM7Re2EA9zFOCGqknMv3o7cj9TuuTSea2FvpYNF7r
X-Received: by 2002:a05:600c:1992:b0:47a:810f:1d06 with SMTP id 5b1f17b1804b1-480511e40ebmr5675005e9.4.1769151199817;
        Thu, 22 Jan 2026 22:53:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GGkQxW0aSFr9co+s0i1Crw1hFEL7I3l6IiybhCB02Z9w=="
Received: by 2002:a05:600c:4fd0:b0:477:a036:8e7b with SMTP id
 5b1f17b1804b1-48046e38567ls10638695e9.0.-pod-prod-01-eu; Thu, 22 Jan 2026
 22:53:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXp0DKxvReWkHwdGhS0+jqYmEYPCNwhsfxXzoBdhiBzdRsaiAQ4Qz8n3caZLvumLSj7Q/LSiX9+abk=@googlegroups.com
X-Received: by 2002:a05:600c:46ca:b0:480:4a4f:c36f with SMTP id 5b1f17b1804b1-48051249f8bmr4853065e9.21.1769151197364;
        Thu, 22 Jan 2026 22:53:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151197; cv=none;
        d=google.com; s=arc-20240605;
        b=FX0oIPw9+PvyPOfFUgzvfxE/fHjpWYD/zT20ChZ/ZQaxL5I8A/bFtdXUHHGP4rMSAM
         db3OS6b9w6xqQlxAcbaBezrDQxGYojR0yTXzUid8p+td31IQfNNHlK8EQTCmP9rmxIU6
         KK+s8x0GQ0kgKQe/C4u95VEwrlmfBC1Kb43HNLj3xuQrmX1xDaHRQsNBe1Bthjab3kaK
         uTbZxk2DB74PqpG//2xBE2Fw3v6sXRRzZkyzO1pd1oXwTUThBLK/vqMlbY64Yd7f4v49
         xT+xD83dG1/iN02S0lD9xDEftwZbboYM8omHY3mYzrAMMlMbSNBkEtHYEaLzWz40oBi2
         9waw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=N3DPRc87aFtnpwc8583i8li1YmCTDsn4GBRi/xoPavM=;
        fh=ZDxAv8XPBkZG++ei96Z+swcHRAJrJtblU7Ri5E43an0=;
        b=EQHTcxATEP+l8eRKiLRTzzPbRgp2AIhrKIpic4dgLfS77+AqMNhDVN8Xb/OF6w4XBQ
         UCENOyWTi0p6iwvRBWyd0jxcDeZ5LGmNzYJatFpA05ZGfAMw/SdgMyCsoF1DKB5zBPnk
         Z+reY5FmF/wr0BRQxkWs9zyvr6oZUQZezXYTx2AMDy7PSdQT3Ifvhhx+uv74C5N5vFFH
         ky6ca3Zg6JfJcjyYq3+1lgIPbn77VMJ0YyI3H6r2gQchO9CDQ74rDUjNQBZtPEdPxF9C
         RS5Nfr6QYmg1xySUV/29+75eUScKYafFr8H3NbhcDEaMvFL8Mii3TmM0/IpRBW9/4K1O
         66Sg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TwaNSJ22;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435b1c06e32si34452f8f.3.2026.01.22.22.53.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5590D5BCC7;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 277A7139E8;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 0O5fCdUac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:39 +0100
Subject: [PATCH v4 01/22] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-1-041323d506f7@suse.cz>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>, kernel test robot <oliver.sang@intel.com>, 
 stable@vger.kernel.org
X-Mailer: b4 0.14.3
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TwaNSJ22;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBX5VZTFQMGQEWCN36FQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz,intel.com];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.975];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,oracle.com:email,suse.cz:mid,suse.cz:email]
X-Rspamd-Queue-Id: 9BCD1712C2
X-Rspamd-Action: no action

After we submit the rcu_free sheaves to call_rcu() we need to make sure
the rcu callbacks complete. kvfree_rcu_barrier() does that via
flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
that.

This currently causes no issues because the caches with sheaves we have
are never destroyed. The problem flagged by kernel test robot was
reported for a patch that enables sheaves for (almost) all caches, and
occurred only with CONFIG_KASAN. Harry Yoo found the root cause [1]:

  It turns out the object freed by sheaf_flush_unused() was in KASAN
  percpu quarantine list (confirmed by dumping the list) by the time
  __kmem_cache_shutdown() returns an error.

  Quarantined objects are supposed to be flushed by kasan_cache_shutdown(),
  but things go wrong if the rcu callback (rcu_free_sheaf_nobarn()) is
  processed after kasan_cache_shutdown() finishes.

  That's why rcu_barrier() in __kmem_cache_shutdown() didn't help,
  because it's called after kasan_cache_shutdown().

  Calling rcu_barrier() in kvfree_rcu_barrier_on_cache() guarantees
  that it'll be added to the quarantine list before kasan_cache_shutdown()
  is called. So it's a valid fix!

[1] https://lore.kernel.org/all/aWd6f3jERlrB5yeF@hyeyoo/

Reported-by: kernel test robot <oliver.sang@intel.com>
Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
Cc: stable@vger.kernel.org
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Tested-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index eed7ea556cb1..ee994ec7f251 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -2133,8 +2133,11 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
  */
 void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
 {
-	if (s->cpu_sheaves)
+	if (s->cpu_sheaves) {
 		flush_rcu_sheaves_on_cache(s);
+		rcu_barrier();
+	}
+
 	/*
 	 * TODO: Introduce a version of __kvfree_rcu_barrier() that works
 	 * on a specific slab cache.

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-1-041323d506f7%40suse.cz.
