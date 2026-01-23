Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZNVZTFQMGQEMPH4VVA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0FcyLecac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBZNVZTFQMGQEMPH4VVA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:27 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 55226712EA
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:27 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b70088327sf1120406e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151206; cv=pass;
        d=google.com; s=arc-20240605;
        b=G77kz2kQQEX/uLwKjgqPincpdVeWGx8zagKbVgH500+K+++4B+PqoFzGU0eF3SPYP1
         4UcEq986/HxqnlbS56o9vo2JvW8PuxOv19/5TldWB/pU2XM1wML7cWqeIZcf3PCgKL+g
         ZXVO0YyqUasv2xbk16sFF8UbjnjuqyCKWIWKZmT2QMBUsq1+L1i4Magr5dak8hiN36rl
         pRFPh5yPO2KM24zDoBspuM018wt5bwIy+fA/HQDCLd4r8e7JPh020yjenRtOagyLR0Pi
         GkUhvV3ly1D63yodLqWlS+9aNHUPS1hiitKp5+S3M/pl8AT0ciFgbmYg9S0p4bVIo2b8
         vDkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=SBRBV37EEJIVD7EsH7jBImIcvGKqFdfkYxxYqhX5Z3w=;
        fh=h5Y3hhPOLpIZ5dwd4ILPJX57Ab2jP9nmrxziSp0AUPM=;
        b=RES8oIyTWdneHLEw6MZsnPZ8om18u3lOU7vtX1uqEqIgA78yqyp4RFHoFUesJdWZOG
         /QfdM3Y9N2uc/Nfigvf6WvHnj8Q/OBZ721TaG+ZYM2vmTsMLuCE+oE4KLbp5mnq5zOZK
         F/UJ8lnPVX/rQJ1fhOdC42Fq+r4XhEuhCjh/u2+NdVbAVvJ8dyMGuiOg2achFTCps85F
         pMtLuiUv1h5wsnykRV2xqtfZqxxIkm6K4novc9zYwGhDP6fs8W/oXRmiH775dMBgAi4F
         XILV5saFfHsLEgU0/XoJB/mw8+0VKqRwqJTjIagfXhx5aIToBfuvqN5uzneN+990eIIi
         h+Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=r9SDwZF4;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zJYEOQ6n;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151206; x=1769756006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SBRBV37EEJIVD7EsH7jBImIcvGKqFdfkYxxYqhX5Z3w=;
        b=FhsSSm5HjUvLnz6WGVSxOCGL19AH3Cflf2rkqa/jAIfJ2Ypg/x7KUJTOHn5UW3iYCJ
         /0Sf1LLTXSCEo7pCsP91OKj/cGi6jlJwe9/Xvhs/M4HfhYodWVF90ZccFYAP1IlmUtI7
         P8JB8l9Aci8Ja1JV3PrYUJCUkI4DF57EIiRXgIT39n3+mr/t4ZYsqOCUGkfvnFlnMhCK
         jDwCIEyn3y2ZhVuah5O+VbYg67LEyFyMRhA5VC6zS+6o/hSUxbqve/WpydIIiJySpGKy
         MoWqUTpYRRXMEyIykx027rXko8ZbVTT7uNkHL/5DLzrMEZ8WNTgm5ujTXaQQM6jcwlnC
         ojIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151206; x=1769756006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SBRBV37EEJIVD7EsH7jBImIcvGKqFdfkYxxYqhX5Z3w=;
        b=ids6uDJ419RNz6xCnB90yEk16A+ukcDgncyfXhLzMsgfDnzh3rHYV+LBYfXzPhX3Zw
         sso9zcu/83Ddol+VEZhHudmyerdqew4gWUhR5MllFyifOjSwPy/oj0X7s5KcgASt6k0r
         cJA0unm2EnKPREce2p/V9hbYOWOT22DnsueurXIjtlklQ+OcIe0mfjMaBYFXH1em8715
         g3JR+Lm5M3C1LFXFtNmuBNUYz/mrWx9S8+LiCa9lSDjzvvP5DafK/8NPwcrliajjAlwW
         vN2bnjxPvXlgi89/VfouqQ2S71qQcFYpwZ6NpHDyFpfQPk+CF5ZMb8WrNduGdYdBtOk9
         c+Tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvFErqte5rCCELpQoR7uxncW6Ma66/lzV8oZaDmUE0A+ENX8EQZ/k/H0Sc8WH6YdJ3M/bI1w==@lfdr.de
X-Gm-Message-State: AOJu0Yw8NuudcLs3cWWIpuLVIoooAxBo2GCB5b1Gs2v5kXj6hns6oYMG
	ms7fgimOIv8QZ8WenScsVNENBEb4nyg9q0rJls9JdX5xXhPj5L3be9l5
X-Received: by 2002:a05:6512:234a:b0:595:9152:b90e with SMTP id 2adb3069b0e04-59de4a2631emr606212e87.44.1769151206374;
        Thu, 22 Jan 2026 22:53:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E1C4/rsTZ5idrGDJigwPBulEbfIHcuWWTeCyqpybKYOA=="
Received: by 2002:a05:6512:3e1f:b0:59b:6f90:51ba with SMTP id
 2adb3069b0e04-59dd7840222ls540553e87.0.-pod-prod-03-eu; Thu, 22 Jan 2026
 22:53:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVCG8rHvCZ1ffjMpR3bRvzGE+iEk2iursS3DPwLPVvuM2IWiuEAVoUTM6e3MuQr/C/fO+ygVLsJC7Q=@googlegroups.com
X-Received: by 2002:a05:6512:114a:b0:598:eed4:ec6c with SMTP id 2adb3069b0e04-59de4905014mr664553e87.13.1769151203672;
        Thu, 22 Jan 2026 22:53:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151203; cv=none;
        d=google.com; s=arc-20240605;
        b=ELhtCFKlkdhwNpD3K37K8fDkk7t6EIznKOl35lb9tlRKeZ00svvqx9tnvJJ6RK9Gu0
         LtjO01w6vrGejx0v3dIPArr+EO3QJT/gO2c6FLw012xLH5FcUxWSm464I8CrcQsjs4OE
         W+PPvER6HXNTG3WDRSlZpIcTnbQ3qGLgZlktjOVPK+Udkh1UD1T5XLIia1rY6Fztspy/
         kpL2INcEFVNSg5HXFzpFQ/tS/0qOetYAYuAYx1kjdqOeLmflTO6j/0WGRiF/jrlPSK06
         wDQF+y/Ub27tmSJkkyAlruhDweziXEcBe6HRB69UiG5DogXktcbptHl3BGMSBMg4iqiW
         UE8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=rxNrmkpJY7trZ5HkdIEifD6rdzJ14H6U8LzdlLiW4qU=;
        fh=DmGJ5j38BsynyY6+dJMx5yI1x8Phr7TDRxdYvwngEac=;
        b=Uft4GDPzZB2wDXZxC669lvKVg3DshyRF7QTwLDYhGM+kAZ4zXbRYYh8oIv+awKl+uC
         exHed+hrF45xZuhr6ZXigwwxRTQU0AjIRYJZreCBNd2J9aMAc90aRU+ViwfBvt2pP3qq
         aL890g9nhmp5TzoStvftbCixNRvFrSGCgCsSw9Bfq/fksRX3KDAyHyEh9TgmkvpUIxwJ
         j1lRz+qZEiSiJuCXHntlAf6JQBOoe45ZIj6/AOIUeit79whdKwzQhbh8IzUj3NRrNeIz
         1/Pr5biVee9b3MIeHGQLry/ADvy1JOk2byHqTwqZMZ3of+Fw2FLUdrJuXlS2updAmbKi
         a6/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=r9SDwZF4;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zJYEOQ6n;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de45b1da0si27987e87.0.2026.01.22.22.53.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 75F555BCCC;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 42C03139E9;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id qOsGENUac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:40 +0100
Subject: [PATCH v4 02/22] mm/slab: fix false lockdep warning in
 __kfree_rcu_sheaf()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-2-041323d506f7@suse.cz>
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
 Vlastimil Babka <vbabka@suse.cz>, "Paul E. McKenney" <paulmck@kernel.org>
X-Mailer: b4 0.14.3
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=r9SDwZF4;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zJYEOQ6n;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBZNVZTFQMGQEMPH4VVA];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[19];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.974];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.cz:mid,suse.cz:email,mail-lf1-x13c.google.com:helo,mail-lf1-x13c.google.com:rdns]
X-Rspamd-Queue-Id: 55226712EA
X-Rspamd-Action: no action

From: Harry Yoo <harry.yoo@oracle.com>

kvfree_call_rcu() can be called while holding a raw_spinlock_t.
Since __kfree_rcu_sheaf() may acquire a spinlock_t (which becomes a
sleeping lock on PREEMPT_RT) and violate lock nesting rules,
kvfree_call_rcu() bypasses the sheaves layer entirely on PREEMPT_RT.

However, lockdep still complains about acquiring spinlock_t while holding
raw_spinlock_t, even on !PREEMPT_RT where spinlock_t is a spinning lock.
This causes a false lockdep warning [1]:

 =============================
 [ BUG: Invalid wait context ]
 6.19.0-rc6-next-20260120 #21508 Not tainted
 -----------------------------
 migration/1/23 is trying to lock:
 ffff8afd01054e98 (&barn->lock){..-.}-{3:3}, at: barn_get_empty_sheaf+0x1d/0xb0
 other info that might help us debug this:
 context-{5:5}
 3 locks held by migration/1/23:
  #0: ffff8afd01fd89a8 (&p->pi_lock){-.-.}-{2:2}, at: __balance_push_cpu_stop+0x3f/0x200
  #1: ffffffff9f15c5c8 (rcu_read_lock){....}-{1:3}, at: cpuset_cpus_allowed_fallback+0x27/0x250
  #2: ffff8afd1f470be0 ((local_lock_t *)&pcs->lock){+.+.}-{3:3}, at: __kfree_rcu_sheaf+0x52/0x3d0
 stack backtrace:
 CPU: 1 UID: 0 PID: 23 Comm: migration/1 Not tainted 6.19.0-rc6-next-20260120 #21508 PREEMPTLAZY
 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
 Stopper: __balance_push_cpu_stop+0x0/0x200 <- balance_push+0x118/0x170
 Call Trace:
  <TASK>
  __dump_stack+0x22/0x30
  dump_stack_lvl+0x60/0x80
  dump_stack+0x19/0x24
  __lock_acquire+0xd3a/0x28e0
  ? __lock_acquire+0x5a9/0x28e0
  ? __lock_acquire+0x5a9/0x28e0
  ? barn_get_empty_sheaf+0x1d/0xb0
  lock_acquire+0xc3/0x270
  ? barn_get_empty_sheaf+0x1d/0xb0
  ? __kfree_rcu_sheaf+0x52/0x3d0
  _raw_spin_lock_irqsave+0x47/0x70
  ? barn_get_empty_sheaf+0x1d/0xb0
  barn_get_empty_sheaf+0x1d/0xb0
  ? __kfree_rcu_sheaf+0x52/0x3d0
  __kfree_rcu_sheaf+0x19f/0x3d0
  kvfree_call_rcu+0xaf/0x390
  set_cpus_allowed_force+0xc8/0xf0
  [...]
  </TASK>

This wasn't triggered until sheaves were enabled for all slab caches,
since kfree_rcu() wasn't being called with a raw spinlock held for
caches with sheaves (vma, maple node).

As suggested by Vlastimil Babka, fix this by using a lockdep map with
LD_WAIT_CONFIG wait type to tell lockdep that acquiring spinlock_t is valid
in this case, as those spinlocks won't be used on PREEMPT_RT.

Note that kfree_rcu_sheaf_map should be acquired using _try() variant,
otherwise the acquisition of the lockdep map itself will trigger an invalid
wait context warning.

Reported-by: Paul E. McKenney <paulmck@kernel.org>
Closes: https://lore.kernel.org/linux-mm/c858b9af-2510-448b-9ab3-058f7b80dd42@paulmck-laptop [1]
Fixes: ec66e0d59952 ("slab: add sheaf support for batching kfree_rcu() operations")
Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index df71c156d13c..4eb60e99abd7 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -6268,11 +6268,26 @@ static void rcu_free_sheaf(struct rcu_head *head)
 	free_empty_sheaf(s, sheaf);
 }
 
+/*
+ * kvfree_call_rcu() can be called while holding a raw_spinlock_t. Since
+ * __kfree_rcu_sheaf() may acquire a spinlock_t (sleeping lock on PREEMPT_RT),
+ * this would violate lock nesting rules. Therefore, kvfree_call_rcu() avoids
+ * this problem by bypassing the sheaves layer entirely on PREEMPT_RT.
+ *
+ * However, lockdep still complains that it is invalid to acquire spinlock_t
+ * while holding raw_spinlock_t, even on !PREEMPT_RT where spinlock_t is a
+ * spinning lock. Tell lockdep that acquiring spinlock_t is valid here
+ * by temporarily raising the wait-type to LD_WAIT_CONFIG.
+ */
+static DEFINE_WAIT_OVERRIDE_MAP(kfree_rcu_sheaf_map, LD_WAIT_CONFIG);
+
 bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 {
 	struct slub_percpu_sheaves *pcs;
 	struct slab_sheaf *rcu_sheaf;
 
+	lock_map_acquire_try(&kfree_rcu_sheaf_map);
+
 	if (!local_trylock(&s->cpu_sheaves->lock))
 		goto fail;
 
@@ -6349,10 +6364,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 	local_unlock(&s->cpu_sheaves->lock);
 
 	stat(s, FREE_RCU_SHEAF);
+	lock_map_release(&kfree_rcu_sheaf_map);
 	return true;
 
 fail:
 	stat(s, FREE_RCU_SHEAF_FAIL);
+	lock_map_release(&kfree_rcu_sheaf_map);
 	return false;
 }
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-2-041323d506f7%40suse.cz.
