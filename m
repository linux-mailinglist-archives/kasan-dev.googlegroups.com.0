Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3M3VHFQMGQE7NF5Z4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 74C51D32C4F
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:46 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-64d1a0f7206sf2019354a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574446; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZAH+EU02BLNw2gwfrTfXUxwDiwxa6kQmA/PU6/TW1AyaahVjkM6/NAX5k2K4MJEFKU
         bdK/30FaxOhdyaz4gLJ6GrtAhYG0IWNSPep+SlLsCCmzAvSxolw+eyjdfnxKXLWFQrat
         22ZlKrDhxLLj+yjEMu5iJx5uUdflKFq6Qp2RZUWKtsmOMo1TUXcQVpua1hamNIH70/f1
         EXZARABoWRakcmSQ2+R+LbD9ALyL4RcIgOs2dmf1wuwlsMCbLNZfBivXoMpn0o1YUS/0
         arWBb0l1Mm5GJOihsQjjkAF4Eh98XwWvwHBEM1R90WFqd7Ai4wUKU+FZBii1GmoW7Obh
         lG7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=/w+Cdq+KI2WyZ4YIKBr4vlIIuGhAeyQWPG62yG24Ays=;
        fh=2W9sIsAYzzI2XuBdvFffUS5mVwDsNl+rad7X+jqMs1U=;
        b=dW7utvldgsq2EIit/twxF1WSJh7vhCff4UnH5hu0BTFFxxqjXnomyljdRj7POqBHas
         A2QAshbm4fMjKFPZ8c8qbZntry5BgsktRm9AYML49MLk9LtFSAn9yja0KAAwndQpehtx
         AWPDQCbhLhyqSYl8nSCkKFawGaFhYrNE3OaXDd3zPVx9AIgIO9jV9XCLj9SvGRjqUQmE
         BsFrncpLq9g318PZ93LdT6hia64JDYpRtVUCgxC+BGf7hapho3YWdtIuaJPmvtfcaMVC
         WabYufgFCb1zdLCnU6RwG7c8M+U8prv+qDLnUKvGRzaGHQ5u1+/OSk9TwmYEvKdnRN1L
         Q5OQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VIx4ysKc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VIx4ysKc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574446; x=1769179246; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/w+Cdq+KI2WyZ4YIKBr4vlIIuGhAeyQWPG62yG24Ays=;
        b=wU8NaGOVVBPsG9Op+iWDM6Vm8grQ7UWhbB53pc/5Q0kTLiyvkWX8bTmK/2NkHVQFWU
         2U6J36vfjhDc34umZIJKH2kannckmt0VmxOLmkbNQs8F3eUjibv6MFpf8XXWULpY1nQq
         MubWVafXGmVLsMZKlutVsCSESYmMPb35v8/i/ocK5pPpn2RbZKivX2n8oCv5sapfCvjW
         DtP4Ma6ZHZIHMiS4yW+p7qcbjdtg8GwdLNhfH4m2S8KyBKUy/dGeGy4QfYblLR+mE2V+
         FlEfMgosI46uKahZEBjM6yi0TydQ7cpp4nKfBROwVCKKb8rGBY1Q5QtzEwGf97MXHVyV
         6Ckw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574446; x=1769179246;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/w+Cdq+KI2WyZ4YIKBr4vlIIuGhAeyQWPG62yG24Ays=;
        b=VjoawRppFFR57sUOMPkIdmmIVStF5WMWaTvJAzzKSeXiRufwkQpz3e/kY7tUtHX4Ns
         ETb2DHh7MXy+nCjc5eZPZlLEZywCJp88xVK839I+JKnapisWbVzj2rAb2d8fY8Sy/www
         77kEO4xAzJi1EaL6L24jlsdteFpEh7k0yfQPV0BOHA+OMGTmrlfyjUOs3u05CLAVnoE2
         kMXdg23utLADfhTU43jz4SCcSiTYGcX5elZ+tRXYhpU94nmKArhx0lqSSdUJ8RPc0B4J
         KeIkb9Ex8bBRyGzLe0atA52dofv9Rp5duyXODLe2VIkpgeirKjQJeZR4Kix8JCqTl94b
         C1pw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUm7KmrtBg220mHAroYauNn9hIcbGVoWcJWhODX+vHloIz5ePg+gL3e+YkUinUjMp5yz6s0PA==@lfdr.de
X-Gm-Message-State: AOJu0YwDAVRwp3wphy2/g83wkwl++xeHLZsNfPFtvlojEUiIT112dAWo
	/IAQPT+tnVYEMsRj1jbOgOB22YaSZqvgRPWzxvB7usuT9N/kuik//0l9
X-Received: by 2002:a17:906:eece:b0:b84:40d3:43e7 with SMTP id a640c23a62f3a-b8792d3bcc9mr226162766b.6.1768574445577;
        Fri, 16 Jan 2026 06:40:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HJcbxeig11/nu8U4q0oSWjVOuqWEuwRqiYM/uCcGTYmg=="
Received: by 2002:a05:6402:20c2:10b0:641:6168:4680 with SMTP id
 4fb4d7f45d1cf-6541bd8e6c9ls1444404a12.0.-pod-prod-02-eu; Fri, 16 Jan 2026
 06:40:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVEAWDXK3CUFBI2KQUAOQvqm1xwa8QC64FCE5u25Hepx1e2NyWgRXZUUTaKdpoSmCHPWPnuLdDvALI=@googlegroups.com
X-Received: by 2002:a05:6402:399a:b0:64b:6e20:c92e with SMTP id 4fb4d7f45d1cf-654526c9083mr1893865a12.10.1768574443526;
        Fri, 16 Jan 2026 06:40:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574443; cv=none;
        d=google.com; s=arc-20240605;
        b=bvRghoKWJWdKsxL7bM0I2XDF2zKshE3wcb6qAJObFDNufDz/ji91z+8OtfpOtjxB6w
         7Iyo8AYdkFsSNnn3kskMREE9ianxrWYttEZpBLD1J3OGGaOjXBrbF94GptMtMvWEE6oE
         s0HIT8lBOjcBUN8v5Vq2hjZl36BfpbiCpflDPcnqx02R6FiNwL0n1jeU9XtsXx18PpYG
         WxK9E0MCXrh+bQHMNASNID3qTG0IeF+j8EMWezTdFUE2qpL85SX73kBEPOXS0Rz32kak
         nYcXlCGDFFd2KD0vyPqLajV69Buz28eDI7SCdGo/JhlrRC7D2695B0+6sMEXInh5F/a9
         RpUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=N3DPRc87aFtnpwc8583i8li1YmCTDsn4GBRi/xoPavM=;
        fh=ZDxAv8XPBkZG++ei96Z+swcHRAJrJtblU7Ri5E43an0=;
        b=VZ5CSv4wj6s9HU3woJRJ1aoyf2RV1F161BYhaVJKUvWqITlwMshmHCNAV1z3PCIMJP
         6/JBpAsasYjLvWXj9FMBQLpfptj7FlhGHvOOHOewa5txXAzbd+ooefClDbMQtpDv1UBR
         3AhII0p2mKnu/fADAK1WqgSSUpX9xYxyKn3epSRf+eu3Nd3MINcRuiExhIrqUzDGad22
         rcIhxAfl6K8Se2E6CS6JUzlNzyDmRwygYhr5GDTHXF1pribG8ns8L9zzEMv1bO+RuT2E
         CsZ88YPqrQfsZ3nkeNgvLrJX+q0NxPPcSSfBuX9LK25h4cg7IsNkf1cW0/m6GAySvrks
         Ztdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VIx4ysKc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VIx4ysKc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654530dc8c4si46605a12.3.2026.01.16.06.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id AF381337C8;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8A1043EA65;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id uMFpIeRNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:21 +0100
Subject: [PATCH v3 01/21] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-1-5595cb000772@suse.cz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
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
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz,intel.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: AF381337C8
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=VIx4ysKc;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=VIx4ysKc;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-1-5595cb000772%40suse.cz.
