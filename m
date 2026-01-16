Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZ43VHFQMGQE3R2RQIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 753E9D32C44
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:41 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59b6a320b35sf1735532e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574441; cv=pass;
        d=google.com; s=arc-20240605;
        b=KbqzQE9PW3lxoLh1EI8BQwFeAgA9HlkY49PRCqX2UXeVgaC6JLF6sNxmMZR1UAmzOf
         1B+XVyfPFdPw9dO7u3+OuwHz3KuF0xQytATYPvW4icWJhkZVWm+twTgpCLAfIlU76pHH
         oYds8+EjyU4C95iB6/G7ZL4HpNEuPiuV7PED7mmQJIxdJIpEds+fXmdxgnA1dUkzYU5U
         Dc49w+TDc0Zz+QKJULI6rX5KbshJMwW9wOsxdtOAn3jh9A14PeFt8sa9uxyC/ytU/0Fh
         lc6k1k/FlzDlTr5fWfOZmYxV5N74rezX1OjLaE7Q5kNscmLqnVFTjcwHLrB7DXqm0r4Z
         x1gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=XiUqhW7lFXaGI+myAVceBlBHwkGWxroNAOipp4Bejb8=;
        fh=EyXJpS4+SHd7ygyR52R0j1m3/e6L6CrISn5AXMC7+QA=;
        b=GoyCR/XMvZkCII2EUp6L4TAUJuWF5jVpj1cBjIJzEQcq9+JuPPtLNnnLpBEQSf6Ic5
         pfpyumIqg7VOUnlbo8I/Uv41aYqqpQHS+9H3eXVkGgaxtaUH41Hn1+1xX8CWTZ/NcOha
         M2yP09oK6SHltV49TH0S0zBXr4bzwFO/7jilOnfbkuQJmYSMFc27iTVE497psry2Si1b
         0OQnn5ZwvdJ38S55GiR5sPXoLR9D1ACu7gnyKokWxAVTYk3JBlPTZKF2tHEwU+ipNRyt
         357rmN1POnOfpHAA2S97jfg8Yrrnv4siFckW/v/vkBK1yrG/iRzCFBslaRB7Tw/shIJ8
         8p9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=W2cXZQcE;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=W2cXZQcE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574441; x=1769179241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XiUqhW7lFXaGI+myAVceBlBHwkGWxroNAOipp4Bejb8=;
        b=VxqA3i5ylbrHBXJkHZfLTAnrLS3FD+xVhKI0i6XVMuRf2HwITQw0puBNJzdQEfFcHc
         5CDObN/CAs8NfkvYD5sdts8KAAP/kVBiiKdwYJgUqo/6NLFw4eRUCuWTfxjv1bJlCrTq
         qP5yf+BMy8jADrEOq9OPnjqDuMbN65mo47eMScsflBeUBcfXkHDtvcQ5fPoQPZV3oPSw
         5LFw2S+E/846J8judGQTorf/1/mPP9rt8EU0sxGh4Lq9tZ5xwwGBYoKBGXnfMFDLI7zX
         DjFafXyOfaEwH/BBk0YWyt/pLcPjEswAZomXjYSfj3QSeJ9IsShBo9CCK1Jp2VzhxOvP
         WF6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574441; x=1769179241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XiUqhW7lFXaGI+myAVceBlBHwkGWxroNAOipp4Bejb8=;
        b=YehS/TNI9T7juQ694FfTQ+iZicZCMUDLPOvFuOwiY/nVDZrdDw6t7bsQs1pNY+V98R
         sE0mfjC/nroGtUt1ySXf+9osCeoeltzqI9MGIvv/kygezNIeC9/TTjM6qqY4jqtsAsIR
         coKfxECx7+j9TRKuSSlXRCa2eYfiAx+ccsyhtMyLF73fO/VNiOBx+ABZPLbsO2WUhleY
         R+75iGRG1E7RyOeFmQxsPR016MX8cUjSVhto+luu6fSBuOb+tCU9+/soV2NZ+5e+ZqtB
         CViM3/rHocle2nd1M0hWVklIc2pVc72TmRy9sScZYQFAEZWQRSGxUEyUnJy0sXwWbKqx
         rxog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURqAQGcvkBDpfQ1/uH1voPre8dLVhKI+BXF6sdAviz2gWzHYB1P/Jf1oBcRoV42KFwyYM9OQ==@lfdr.de
X-Gm-Message-State: AOJu0YwNLLpqvNEpoY66rMjiwA6Yv9wWunKQ/4A7YQhM3ErM5ndCFmP9
	TdGew4CY1rby7VEOqtF7XyPh/edZoEUILkvFqr1c1vXwPHl/MDqRbt/s
X-Received: by 2002:a05:6512:230a:b0:595:9195:338f with SMTP id 2adb3069b0e04-59baf19284fmr1038884e87.23.1768574440340;
        Fri, 16 Jan 2026 06:40:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HuKBRcYeTmd1/r890hvQ6h/Q/4IdNltNWKzWVT4hUZCQ=="
Received: by 2002:a05:6512:b9d:b0:59b:8bd6:838 with SMTP id
 2adb3069b0e04-59ba7185cacls79086e87.1.-pod-prod-00-eu; Fri, 16 Jan 2026
 06:40:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWiVaarokIacowlYd6Iq1sno9nKroC+zDJJ3rWFsUzXVkohp+bsZQrrxuz8H1x5JdSgo6Slmm7PI3I=@googlegroups.com
X-Received: by 2002:a2e:a7ca:0:b0:383:18c9:f1e8 with SMTP id 38308e7fff4ca-38384cefa00mr12526871fa.8.1768574437539;
        Fri, 16 Jan 2026 06:40:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574437; cv=none;
        d=google.com; s=arc-20240605;
        b=eMbi1x/Y7IOIa8cjwUiLtQHWBjhorq33LkgE4NV74mjW6IKiPu1GIWzPKffd/Lmkhn
         zosRN0YjtFvUu/6YQP2lspjamleMlRk1D/D0HsdTdDTgUCQmIhKin9JuDx8rNJaELWnY
         Nz+cUQKhtnvAqp7daoLY1xIZbsgFoBuEdv3Tg6hONZw+pGu4Qitj0nzWLOfyDVjr5BtN
         ry473T6wACSFwpf5vEQqyIa7lOn651BxhGOt1QVWNzDqi1Enb0GZ2lCmIcBhNcx/XQKu
         vtG/7nwnRmTTq0hh2MYFgrCPfalwXdpuyd1Mf1GBkNE1OUQ2Kadump6VQ2Wg7HV2ic71
         CzHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=D8kSMH2gta+Yma3QMnDCuvguK/0toKW9byQx/lVBXFU=;
        fh=ZDxAv8XPBkZG++ei96Z+swcHRAJrJtblU7Ri5E43an0=;
        b=IFqjkvYLaxK/oMvsFe3kZLsX5YME1q6YhqjNLgmsspzSqPCMQVoT4QKJ3cqLEfcKSp
         vM1nelrDML6ugxmy9zH0ldImbmnKQDyl2R3r2NbzxQxhR5wz0ClJJJucCr+D0GdlgmHu
         48vWXpAK1iYslLkZMCA1djxRKpH6Mx7E3HosZUEb2a0dVfNPQsLGnKFIE4rihjWSvOF8
         lRg3LYn5TEXtGnWl9zDWlpfWlJ5sBQ0QZKPIZLo4tU81TVih6/D0WfE7aGNRBDD/leWw
         s+KPNtX31DZQRGVcLpj5DN8TYOmMkq+wR54qmCcdpzU1IdWZiVGp19D71wTfX0pPLSks
         TbnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=W2cXZQcE;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=W2cXZQcE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e78091si504911fa.8.2026.01.16.06.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8C65233789;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 46A2D3EA63;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id sj7VEORNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH v3 00/21] slab: replace cpu (partial) slabs with sheaves
Date: Fri, 16 Jan 2026 15:40:20 +0100
Message-Id: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIANVNamkC/2WOQQ6CMBBFr0K6tqYdKIIr72Fc1GEqTQiQjjYq4
 e4WonHB8k3y3p9JMAVPLI7ZJAJFz37oE+S7TGBr+xtJ3yQWoMBopUBySzYSSzcEabtOVqVFnTd
 YHKwRyRoDOf9ci+dL4tbzfQivdSDq5fptQb5pRS2VLJ2zgHVdaFQnfjDt8S2WUoSfXSqtt59ES
 HZdARh0V6PQ/e15nj//IYhq6gAAAA==
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
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz,intel.com];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCPT_COUNT_TWELVE(0.00)[20];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 8C65233789
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=W2cXZQcE;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=W2cXZQcE;       dkim=neutral
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

This v3 is the first non-RFC (for real). I plan to expose the series to
linux-next at this point. Because of the ongoing troubles with
kmalloc_nolock() that are solved with sheaves, I think it's worth aiming
for 7.0 if it passes linux-next testing.

Git branch for the v3
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=sheaves-for-all-v3

Which is a snapshot of:
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=b4/sheaves-for-all

Based on:
  https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab.git/log/?h=slab/for-7.0/sheaves
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
 mm/slab.h            |   53 +-
 mm/slab_common.c     |   61 +-
 mm/slub.c            | 2631 +++++++++++++++++---------------------------------
 7 files changed, 972 insertions(+), 1796 deletions(-)
---
base-commit: aa2ab7f1e8dc9d27b9130054e48b0c6accddfcba
change-id: 20251002-sheaves-for-all-86ac13dc47a5

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-0-5595cb000772%40suse.cz.
