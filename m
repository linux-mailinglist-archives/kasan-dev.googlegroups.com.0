Return-Path: <kasan-dev+bncBDXYDPH3S4OBB25ASTFQMGQEADIM5IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04351D138C2
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:01 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-477c49f273fsf67239025e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231020; cv=pass;
        d=google.com; s=arc-20240605;
        b=ct8uU0yGCOaCN7CWE9wusR+N3+IU/StYkMCzIGkwtJYoArGP18Jv2Y+8bXsdVZMzRd
         ykI8tAA3rGMLRxARIcPyI5mSoCpwj+AZOeoUopltrZ3FyNge2LyDddgCE60TwMS79z1b
         SeZIl1FfKgyxyjEVlsMNEkltfw9vhc0ehSBNJ2+Pvo5ldagmzBmtTD6ejG33BBeVtFOf
         cIX1HPO5QuAOVVXi8bQ6TvlqhWUI5UhSwsvOwQuJItc2Rp1XWugIkG79kVesMfkwoYEF
         VTFHfSOkUH5EUXIMQz8p0y0Du06ZrLmPpagkFlt36xBi0DxwMz2znF3hfFkSQa1EBh5i
         yGyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=zCi3Y9tCeBfz7RypJaegtWKOLxXWq8olCNplAImzLnM=;
        fh=lxHYAjWm/jFrwInLqpBSxuvxFStrU7tiYYKvfuvuunQ=;
        b=ZHxD27gN9eNgABvQ6KQT9BkU32wVoHbWNpADS16EIZGIfHoursNfJ1U6CbjgHUVilp
         cDjqZABdNnVY4stkcbrO/Xhu0wDaT5bnkuyMmyqaYRIiB7OmLcKwJD7S/0J7HA76w91Y
         m6AHer2kDz2+DceUAhghB8ExgFqA5ih9BgHkGYBtAulOOYTFBGlROX175PljoSozv/p7
         TgwwFK+fe+sXgiLO5wSbEUrZ7fM+zgrlULMVCVn2NSgGF3ExUtvp6zfRfSCHv/3tTPWM
         dxNIyULc5E+wcoegrMiBQhDb3xxyToJTvTc50rFLEoiP2omZ6xVX7OP+ingM9F6CntiO
         pVNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="QqC/vZ+P";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="QqC/vZ+P";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231020; x=1768835820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zCi3Y9tCeBfz7RypJaegtWKOLxXWq8olCNplAImzLnM=;
        b=Tg0Vr8MpqpSiKScQ4rmGpesZQXRI/CnvqORwjbclNrGEB+DRKPznpaxIevk3mxWVA4
         YlDARzO4M+TazrrdKH7NKxanY/r96/PJa0FeylKwe/Z2bGvxrqAo6iU6eAqXNLEXdGV2
         YP8Qxp/icy5S71Lutz0+8cWi+Bn7/2PT5ztd/eTPOpKQH/T29c/f9IYdKFbVDfQG+kt4
         gkqPE9ezKu6SxtEUjNT392De81CTlrGOoI0GrsYCMLomvrn0kqEtb/YqwN8FMfJCHROk
         ZyIHZVFgZSNVyT3pUMDFS9dsbanedAfdENerTO+vrrl+IhImNmU91m/iqxI7LZoObXHb
         nJpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231020; x=1768835820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zCi3Y9tCeBfz7RypJaegtWKOLxXWq8olCNplAImzLnM=;
        b=HvRsvy9yIuAZcJZkRGIOWLqV1n1ZUk+HtjDf7e8kG/+sP8QImgebAZp5GAPrLC5R+C
         QH2wjcvI75Me2GqhgwPnSsHJxBHXfo76fWNkJnIDO72uargXofX4W2zfgCf11tUhsf5M
         k0tje+Op6etOVsdOpx+C28cpuA+IyGfjo/0W0ADXbSHCl8cuxtu1k+VO2d4QR6ZhqGrP
         f1U/OwXLkb4JLAunMenLuRMe85OQ4vXOnIydJ3Hxe+MdeSV7x3ULcje7NPr5ZydD+vXy
         aMSs8F4CKp2syAc0Me4B1hwJz+1DXl0wKIDIHtpfLRuxbylVxeqM+PI/1cXIwmC0VJrV
         L9Bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZCTH/o4I5+e1ytVg438tpaNuHSsv2+RQ3jqQJIw9vYuxLNNZoorQemx8nNAo5NreNZEoNsA==@lfdr.de
X-Gm-Message-State: AOJu0YyaeEwBHYpBgki233q0kBPR/tTK9yuZozRC/f5BxvVcuAUv47BO
	YztKFofyDVv1JhHO4/7cpBU6km96Kcmm0f0vsBJqPFD31p9aCfc/yNK6
X-Google-Smtp-Source: AGHT+IFP1V+JHIa49ZY6nSd79SQiJi1yKf0BEXOCoraBMvqyKkE4qfVRMPL57pcy6b2RzCyEU9PkGw==
X-Received: by 2002:a05:600c:8b2c:b0:47d:3690:7490 with SMTP id 5b1f17b1804b1-47d84b1849emr224062785e9.9.1768231020143;
        Mon, 12 Jan 2026 07:17:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EIF+AIVZGDHu1GgdTDtrMgYgR492pYn2rPw/GCqMOsKQ=="
Received: by 2002:a05:600c:1f95:b0:479:10b7:a7cb with SMTP id
 5b1f17b1804b1-47d7eb1ea7dls47494355e9.2.-pod-prod-02-eu; Mon, 12 Jan 2026
 07:16:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXf+BAyNymxLvnjUf0w1i6/G64kotQ+buAxMqn1X64Mgmu7XjG3LU+/m32EO4qsKmajUZ/DpNIUNFw=@googlegroups.com
X-Received: by 2002:a05:600c:3e8e:b0:477:93f7:bbc5 with SMTP id 5b1f17b1804b1-47d84b18596mr214388945e9.10.1768231017764;
        Mon, 12 Jan 2026 07:16:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231017; cv=none;
        d=google.com; s=arc-20240605;
        b=hqbA1hrF6Yc+1mD+P/r48Rsr6Nw8sidamWYNxpyi22cIMlmCLNqPUc5cm3Q0Sq7ga3
         Vy02XtG4EY9YQ7eCVGRJNK5aX2XQfSJ2kXLVDYGEvKhLQpUd7IXWkkx0f0/2vrZOj7l2
         foEHGc+ApyxzVdg/8MJ7idRYQgmsOxxn4nHk5d+LCoFFTpmcgQ1iHiTYbHJYv6kwblHZ
         EKMroDGVUorNIz+uxpWc52Chcx3iMcCTYSHyAT3+KaPzcASwpPdRj5Lp/s3x9j4ipl5f
         15owUgqQoPRxCqR0dfm2uAvTRAgFgYg9ptbNfBZ7YxlGSAGZSSHeDZJrtBwjaARTZ56L
         gByA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=+UvoqRnkM3qauOW0euhXUnny67QRfa6cbf3yuk2gvkI=;
        fh=ZDxAv8XPBkZG++ei96Z+swcHRAJrJtblU7Ri5E43an0=;
        b=IgZpGVCnCzeS95a9kcYtrkjcs80hjsSoCGWVx4F5Ez7xyZfvmXxKQ/qvKUP6JUHN+4
         LDnHlPwgElzRGUqdST96E96aWgG8SHYrG54sPyVU7d1vajOaKmsyCfzLeAkMjnN0+YSi
         d+9WBHelEiUiir05ndDZbpYSXMN2WRFKsNqhyeln7BoKMCYmJC4A0ysHKcVY+09OxWSk
         zl3Zi9noN2F+eUtkGptbQ7GXvt4KaJ0sYKpt1cKlwM4GxPZb/TKNLrFRYb5dG7jjVLFr
         Zlt/+u+UkzRf4RbU8Pzz5s4Vc+LEC7M2tpeNRTH14DQDCN0ckvj27HqTRdBtopMjWO2g
         vviA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="QqC/vZ+P";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="QqC/vZ+P";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47d7f3cc0ffsi549955e9.1.2026.01.12.07.16.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:16:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 32B1533686;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F034C3EA63;
	Mon, 12 Jan 2026 15:16:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 1wH0OWgQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:56 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH RFC v2 00/20] slab: replace cpu (partial) slabs with
 sheaves
Date: Mon, 12 Jan 2026 16:16:54 +0100
Message-Id: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAGYQZWkC/2WNzQrCMBCEX6Xs2ZUk/dF6EgQfwKv0ENKNCZRWs
 hrUknc3xKPHb4b5ZgWm4InhUK0QKHr2y5xBbSowTs83Qj9mBiVUK4VQyI50JEa7BNTThPtOG1m
 PptnpFvLqHsj6VzFe4XI+wZBD5/mxhHd5ibJUP6Gq/4RRosDOWq1M3zfSiCM/mbbmA0NK6QuPS
 fcDsQAAAA==
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
 stable@vger.kernel.org
X-Mailer: b4 0.14.3
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz,intel.com];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,msgid.link:url,suse.cz:mid,suse.cz:email]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="QqC/vZ+P";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="QqC/vZ+P";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as
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

This v2 is the first non-RFC. I would consider exposing the series to
linux-next at this point.

Git branch for the v2:
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=sheaves-for-all-v2

Based on:
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab.git/log/?h=slab/for-7.0/sheaves
  - includes a sheaves optimization that seemed minor but there was lkp
    test robot result with significant improvements:
    https://lore.kernel.org/all/202512291555.56ce2e53-lkp@intel.com/
    (could be an uncommon corner case workload though)

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
Changes in v2:
- Rebased to v6.19-rc1+slab.git slab/for-7.0/sheaves
  - Some of the preliminary patches from the RFC went in there.
- Incorporate feedback/reports from many people (thanks!), including:
  - Make caches with sheaves mergeable.
  - Fix a major memory leak.
- Cleanup of stat items.
- Link to v1: https://patch.msgid.link/20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz

---
Vlastimil Babka (20):
      mm/slab: add rcu_barrier() to kvfree_rcu_barrier_on_cache()
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
 mm/slab.h            |   53 +-
 mm/slab_common.c     |   56 +-
 mm/slub.c            | 2591 +++++++++++++++++---------------------------------
 7 files changed, 950 insertions(+), 1773 deletions(-)
---
base-commit: aff9fb2fffa1175bd5ae3b4630f3d4ae53af450b
change-id: 20251002-sheaves-for-all-86ac13dc47a5

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-0-98225cfb50cf%40suse.cz.
