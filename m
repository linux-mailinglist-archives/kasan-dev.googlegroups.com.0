Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWNVZTFQMGQEJG7CFTA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +LcBMNsac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBWNVZTFQMGQEJG7CFTA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 64ED0712A7
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:15 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-59b6dfc0cbasf870239e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151194; cv=pass;
        d=google.com; s=arc-20240605;
        b=VarrEVB2yfGy8roKILcg02/q2yFBg9KW43gLJAoS0XaNN2YGqX+qpAlkWHsYDduD74
         axmyJVJRpGsDppoObuMrG4VZMg75YzjCKabPptX4g2kuWH4RISuX2agrPJi/OJD+J5pw
         PaUmH8tkie6M7jZZ9PV3hG8f//H0WwWIkOpSGNNypjZh37wQC/fl5gp7hIkfrOa40hWs
         63zZGgVCqRxkJnlrn+iApZ0VSs85lwjWh+llrtzjkMfv7uvrsX3RVnyIIFjbCx0r4HIT
         4bIcp5LOGBWsXONz+Az9NA6XKVnKM/4xdxexcirZDv97UgD4ZxZFd9G1WjgXXwEsoRHM
         cFCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=UQRujvuBovm0EYkwg7Trez8MjTDB4oCw8ARvCFE2CNo=;
        fh=/Z2RsiJxOuGCi5ArJaA0BPNrBYwomBSsh+mBWFaw/4Y=;
        b=eb/XQYAf290dt9b14xRH/ZBiO1x7DJFdUI8j1D5CwV+V3V+Ws270sSifk7fdoJaQa2
         fEF7fhmugxl0F+JRy0oUOXGLD2jl+ZJ90wYUtHQDbFivlK2E2gkB3g57X6BNW60+txYg
         lhddQ+x6Sp5LD4gDWibm2yfKJXRHPUFz+/Z8PNXKyXKl6KKwv5CB4QaxE51aDj/Xwrkh
         tU9f7OFss5LAql5wXjEN7tsKXXgwpM896yQRlCxERmXyZMEqXfBSKDSX9GxcgcexZeod
         dTRO3J6jkkGXG0GQ4p1vJL/J2hbg865+HFEgzcl8mFM3xVOIqTk6AZ1Gf3wKGClKGuZU
         oHkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zgvEHHPy;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="ToZZ/BfT";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151194; x=1769755994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UQRujvuBovm0EYkwg7Trez8MjTDB4oCw8ARvCFE2CNo=;
        b=LzcWC3TY08R7UAooeNU9U9z0AsXb896LwuqDJ+c7AEsraBbkyG6uJqS9eR441+naZ0
         Zr1PARWm5y3w44N3t4XaLft73+6o1yz3SqLlCMOj8QJpsJ16ALWkSczl0OxfOozT2KKw
         OGxdVUr2XCAX5weBj4gJIP++Qga1YyovBLJeXNdegNf4AEOZjHd6/zYOnlk2rs/FLGfY
         2j4hYDZsDtbbG3fhRXbOP9s97mLGAF8b1CXONZyuGODzuLQaRsh2V0j7znq7veSDLlPQ
         UETSk27wXpJ+6jCkb8zp/9++1oPdbhjfVTsAzb2b+h9CVGaJJ2eN3Gy/n+JhfXCvpvvn
         K6RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151194; x=1769755994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UQRujvuBovm0EYkwg7Trez8MjTDB4oCw8ARvCFE2CNo=;
        b=Hq7oN7pNeB7MPk73yRWEJhZCON5z2kOBSBl/QE0COL2UxxMM4Swj9BcdQXmiJ3A9Z6
         TcfjVt+Gx6/JPn8qevTXOFgaNveuTIDOxIBKIpjALc3FyBZJ/Aw2UH3ncJUwyKTEJOIi
         9aFj3zv31mvUdc2jjWEmEFwI5+nh8BLGlJ9AMApqFU1UoENUC9GTRTDYhVqT/LDixC2d
         QXFNhGvevLVgx94n+1BOFkEHllgvhFB1TZHBG55eFITcgUweKYlcm1FCZxb72SdhhNYS
         lOfIQLdUN4tQbxo+eBoGLpKuzxoq+MofFoe7gNh0NNf2cN8I+RxC927b8U4+Q+6y9v4d
         umlQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrUrIgm4ZoocJTuAgvQ3XjsoodpZDMmDgHoiHzTht1l4z7w/pHPq5qOxDX5ekHUQyRRib8yA==@lfdr.de
X-Gm-Message-State: AOJu0YzOKca+I/DJqyXCQvVPtRiBztDzAaIR4Qgyf7p8ipfWkgKe+Uty
	CwoCouPiFIQxbgmxjKi+UoL8Lvhyq+xcmDXns0YUcUOGLexrFI5oGz8g
X-Received: by 2002:a05:6512:1255:b0:595:9d6b:1178 with SMTP id 2adb3069b0e04-59de4a2b43fmr554215e87.40.1769151194207;
        Thu, 22 Jan 2026 22:53:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ET4KeGOF0WCreWAOK2OoIilth/gWs/zbWqb7xREUUemQ=="
Received: by 2002:a05:6512:3e1f:b0:59b:6cb9:a212 with SMTP id
 2adb3069b0e04-59dd783f5abls549408e87.0.-pod-prod-04-eu; Thu, 22 Jan 2026
 22:53:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUrlA3PXC+femeciWS5jOG1nHiUfyEQEgEI788qOrkhhk+BGlbvg7dyFZ/+o7cOW4S91nJLD6sjlzw=@googlegroups.com
X-Received: by 2002:a05:651c:f11:b0:383:55c:89d4 with SMTP id 38308e7fff4ca-385d9f53342mr6460571fa.12.1769151191331;
        Thu, 22 Jan 2026 22:53:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151191; cv=none;
        d=google.com; s=arc-20240605;
        b=cmbbMiLjMPPkYDMfrQGeWqwZezkpEQJOAwqSCPTmvzn5DW24CtKMHwlUFNyBxMRckd
         Jdn1qSOftWOYQ1eTyVD5t6ZAwCYp767JBKRZwCVOsxUa/+IsZ2IBEFGZSto2SyC9UD1e
         rVr05E8mXxJiauw1ty0MgiGJrw2wHOh78qM0ehANpOICCIPSStG6lqOBJzKzeNX2RN5Z
         ebMtEV9puJmcIN0gEGZ27AUetRM3S7EED4n1APLII9XQRgaTzbf8AXLZyHyTQdze+I/i
         hY5rG4TS3nu8JWqjWD2bjJApwJXJuNEoNek3Yd7TprWPpxVQ3EoHqs+SNb3Tk9+ds/x9
         4C2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=xHBC7+XIDKcDoXobVjIIeaJAGTBPlExl+xM4MpgZv40=;
        fh=n1p7BjDwAYNKIQExgIWyR/GTqCxJhEWfWswE+b65/G0=;
        b=lWIs5TNryE16B5ey3Xrv59bd8c/R6Np6NqpLJ/nAAOo7kw1VIVnIAZSj6kRCLF21XG
         vI9DuLZ5bNZ1pqN2lssSubn3gF0OvZimNOdFS3LN7AfeNQM9VOz80A/2AWLx9BsPwKEs
         ZAuGWK/USh+UkyrvPtZDG1lZqZ0dIaWzKrJm4rR0e5J4Npvc/paKiS5IiCOoMTTXZXyw
         yuOwmahnZwiKxLfIo0qZkA6G06Lm1L0qyO5ITmAsmNEPWVbIA9i3mazPLdpfQvBl0aZq
         l6ZBtgPbE24hsT5/sKnTuhq1yu/3NTE2SYxg4bv1fvdy4bQxD3g7zuC4oiHvzWQPmqUa
         ZcWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zgvEHHPy;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="ToZZ/BfT";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385d9e542a4si304361fa.0.2026.01.22.22.53.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3953C33768;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 06A8B1395E;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +aDbANUac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH v4 00/22] slab: replace cpu (partial) slabs with sheaves
Date: Fri, 23 Jan 2026 07:52:38 +0100
Message-Id: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIALYac2kC/2XOTQ7CIBCG4as0rMUMQ+mPK+9hXNApWJLGGlCiN
 r27tNGo6fIjed5hZMF4ZwLbZSPzJrrghnMa+SZj1OnzyXDXps0QUAkA5KEzOprA7eC57nteFZq
 EbCkvtWJJXbyx7r4UD8e0Oxeug38sB6KYX98tlKtWFBx4Ya1GqutcEOzDLZgtPdlcivjRBQix/
 knEpOsKUZFtFJD91/JXF2stk1aqVtQAQFniV0/T9AKIqE+lKAEAAA==
X-Change-ID: 20251002-sheaves-for-all-86ac13dc47a5
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
 stable@vger.kernel.org, "Paul E. McKenney" <paulmck@kernel.org>
X-Mailer: b4 0.14.3
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zgvEHHPy;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b="ToZZ/BfT";       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBWNVZTFQMGQEJG7CFTA];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz,intel.com];
	RCPT_COUNT_TWELVE(0.00)[21];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.985];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,mail-lf1-x13f.google.com:helo,mail-lf1-x13f.google.com:rdns,msgid.link:url]
X-Rspamd-Queue-Id: 64ED0712A7
X-Rspamd-Action: no action

Percpu sheaves caching was introduced as opt-in but the goal was to
eventually move all caches to them. This is the next step, enabling
sheaves for all caches (except the two bootstrap ones) and then removing
the per cpu (partial) slabs and lots of associated code.

Besides (hopefully) improved performance, this removes the rather
complicated code related to the lockless fastpaths (using
this_cpu_try_cmpxchg128/64) and its complications with PREEMPT_RT or
kmalloc_nolock().

The lockless slab freelist+counters update operation using
try_cmpxchg128/64 remains and is crucial for freeing remote NUMA objects
without repeating the "alien" array flushing of SLUB, and to allow
flushing objects from sheaves to slabs mostly without the node
list_lock.

Sending this v4 because various changes accumulated in the branch due to
review and -next exposure (see the list below). Thanks for all the
reviews!

Git branch for the v4
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=sheaves-for-all-v4

Which is a snapshot of:
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=b4/sheaves-for-all

Based on:
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab.git/log/?h=slab/for-7.0/sheaves-base
  - includes a sheaves optimization that seemed minor but there was lkp
    test robot result with significant improvements:
    https://lore.kernel.org/all/202512291555.56ce2e53-lkp@intel.com/
    (could be an uncommon corner case workload though)
  - includes the kmalloc_nolock() fix commit a4ae75d1b6a2 that is undone
    as part of this series

Significant (but not critical) remaining TODOs:
- Integration of rcu sheaves handling with kfree_rcu batching.
  - Currently the kfree_rcu batching is almost completely bypassed. I'm
    thinking it could be adjusted to handle rcu sheaves in addition to
    individual objects, to get the best of both.
- Performance evaluation. Petr Tesarik has been doing that on the RFC
  with some promising results (thanks!) and also found a memory leak.

Note that as many things, this caching scheme change is a tradeoff, as
summarized by Christoph:

  https://lore.kernel.org/all/f7c33974-e520-387e-9e2f-1e523bfe1545@gentwo.org/

- Objects allocated from sheaves should have better temporal locality
  (likely recently freed, thus cache hot) but worse spatial locality
  (likely from many different slabs, increasing memory usage and
  possibly TLB pressure on kernel's direct map).

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
Changes in v4:
- Fix up both missing and spurious r-b tags from v3, and add new ones
  (big thanks to Hao Li, Harry, and Suren!)
- Fix infinite recursion with kmemleak (Breno Leitao)
- Use cache_has_sheaves() in pcs_destroy() (Suren)
- Use cache_has_sheaves() in kvfree_rcu_barrier_on_cache() (Hao Li)
- Bypass sheaf for remote object free also in kfree_nolock() (Harry)
- WRITE_ONCE slab->counters in __update_freelist_slow() so
  get_partial_node_bulk() can stop being paranoid (Harry)
- Tweak conditions in alloc_from_new_slab() (Hao Li, Suren)
- Rename get_partial*() functions to get_from_partial*() (Suren)
- Rename variable freelist to object in ___slab_alloc() (Suren)
- Separate struct partial_bulk_context instead of extending.
- Rename flush_cpu_slab() to flush_cpu_sheaves() (Hao Li)
- Add "mm/slab: fix false lockdep warning in __kfree_rcu_sheaf()" from
  Harry.
- Add counting of FREE_SLOWPATH stat to some missing places (Suren, Hao
  Li)
- Link to v3: https://patch.msgid.link/20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz

Changes in v3:
- Rebase to current slab/for-7.0/sheaves which itself is rebased to
  slab/for-next-fixes to include commit a4ae75d1b6a2 ("slab: fix
  kmalloc_nolock() context check for PREEMPT_RT")
- Revert a4ae75d1b6a2 as part of "slab: simplify kmalloc_nolock()" as
  it's no longer necessary.
- Add cache_has_sheaves() helper to test for s->sheaf_capacity, use it
  in more places instead of s->cpu_sheaves tests that were missed
  (Hao Li)
- Fix a bug where kmalloc_nolock() could end up trying to allocate empty
  sheaf (not compatible with !allow_spin) in __pcs_replace_full_main()
  (Hao Li)
- Fix missing inc_slabs_node() in ___slab_alloc() ->
  alloc_from_new_slab() path. (Hao Li)
  - Also a bug where refill_objects() -> alloc_from_new_slab ->
    free_new_slab_nolock() (previously defer_deactivate_slab()) would
    do inc_slabs_node() without matching dec_slabs_node()
- Make __free_slab call free_frozen_pages_nolock() when !allow_spin.
  This was correct in the first RFC. (Hao Li)
- Add patch to make SLAB_CONSISTENCY_CHECKS prevent merging.
- Add tags from sveral people (thanks!)
- Fix checkpatch warnings.
- Link to v2: https://patch.msgid.link/20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz

Changes in v2:
- Rebased to v6.19-rc1+slab.git slab/for-7.0/sheaves
  - Some of the preliminary patches from the RFC went in there.
- Incorporate feedback/reports from many people (thanks!), including:
  - Make caches with sheaves mergeable.
  - Fix a major memory leak.
- Cleanup of stat items.
- Link to v1: https://patch.msgid.link/20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz

---
Harry Yoo (1):
      mm/slab: fix false lockdep warning in __kfree_rcu_sheaf()

Vlastimil Babka (21):
      mm/slab: add rcu_barrier() to kvfree_rcu_barrier_on_cache()
      slab: add SLAB_CONSISTENCY_CHECKS to SLAB_NEVER_MERGE
      mm/slab: move and refactor __kmem_cache_alias()
      mm/slab: make caches with sheaves mergeable
      slab: add sheaves to most caches
      slab: introduce percpu sheaves bootstrap
      slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
      slab: handle kmalloc sheaves bootstrap
      slab: add optimized sheaf refill from partial list
      slab: remove cpu (partial) slabs usage from allocation paths
      slab: remove SLUB_CPU_PARTIAL
      slab: remove the do_slab_free() fastpath
      slab: remove defer_deactivate_slab()
      slab: simplify kmalloc_nolock()
      slab: remove struct kmem_cache_cpu
      slab: remove unused PREEMPT_RT specific macros
      slab: refill sheaves from all nodes
      slab: update overview comments
      slab: remove frozen slab checks from __slab_free()
      mm/slub: remove DEACTIVATE_TO_* stat items
      mm/slub: cleanup and repurpose some stat items

 include/linux/slab.h |    6 -
 mm/Kconfig           |   11 -
 mm/internal.h        |    1 +
 mm/page_alloc.c      |    5 +
 mm/slab.h            |   65 +-
 mm/slab_common.c     |   61 +-
 mm/slub.c            | 2689 ++++++++++++++++++--------------------------------
 7 files changed, 1031 insertions(+), 1807 deletions(-)
---
base-commit: a66f9c0f1ba2dd05fa994c800ebc63f265155f91
change-id: 20251002-sheaves-for-all-86ac13dc47a5

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-0-041323d506f7%40suse.cz.
