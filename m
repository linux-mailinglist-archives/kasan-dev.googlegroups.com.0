Return-Path: <kasan-dev+bncBAABBFHR6DFQMGQEZTBT2NA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SOO3CJY4fGnSLQIAu9opvQ
	(envelope-from <kasan-dev+bncBAABBFHR6DFQMGQEZTBT2NA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 05:50:30 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id C8587B7286
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 05:50:29 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59e149ccc86sf565175e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 20:50:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769748629; cv=pass;
        d=google.com; s=arc-20240605;
        b=DISpw9aOzz/WnNM4ofVaev43nDJgXKF4lHsBjJk4h1fSQ1WPbNmM99GxpwWZ/boAYd
         V45KoCyS4a0m14astIaTTUfY5XOC8L2Ye41LS7QgrvXsqFqhClA5UAf5rCMMtR5K5W6y
         T/EippTT/M+WogN0aHQHGLLQ3OuZzmnoSArOlxMYzl1u+AMqy/wa6K2N+0J2v4m8i39V
         jWz4HCQ1jr7JyKSVk0hYgmHY0I0QNjRUdUn+/yv9WS31VMxPm0QbeYqdg4G4aWZ1u4np
         U//qm0hYhTGbBgpNMepcejekEdZfvYXPEKDYyb07WDIBzMvcHd4IhHcDG9NSicv55sKV
         Yq4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qCBgrTA4JiEFdROuJ6/b4izTnDdtj0kx8amZofRmV+I=;
        fh=t/by15tfbqNXQnHeCSZThvJx7EjukysRxPrr2u1hOCA=;
        b=IWt4Hdi5lKbMWCYdym6gNJ00LD6d02hSgtajYZN173Wo1weXpZJS2qKMCbSBw2Idb0
         ul2R8nielmnQ6B/TCNMdpLF5pihnIx89hTvmtEQRgJOUIyxOGDrqzqLMcctQ8dPDNagC
         UqXfo9phzOLQXP0+3SUl1zu9HZCZ3kZlr5/vZMYDn0r/TmLUO8oCA5k2097m9YFdUWQd
         NhwTJ/HG5pMxt/TuJ6ACfrhO4bQspeWtKy6a4gVqlvozFHQWnLcdOPKlHNBSQ3tnxjtn
         9rEGaG79MCByzlDLJDrnW1vmpATq66ENEE8+Nmh63zkwDOO53oOt4IVFtybO5wrHIg+y
         MJ8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MTZFazTp;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769748629; x=1770353429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qCBgrTA4JiEFdROuJ6/b4izTnDdtj0kx8amZofRmV+I=;
        b=J+TQvQZGYkGcc/6c3A0dXi29df4WPXCqw2ViEe8ms93JWR3ub3842sBHqHm2j08h8S
         U8kAqS4wyrb9fMjnavSrjtUKmLudWZFDLd4a8QqmYkwYxJFfmHtVLbYBXH8F+WugwUCA
         s0d5lT5YmT5YBxHiMl8syIDH5hiTWuRWEjQH8NqH01hr74IEJT6akWZv7FHLl7Bk1ZdR
         3CPwbjeX61Zv+dB/Eok8epIs93bDlOdsCr+mJf4IXOs4iUadAc0S7uRfNpvNPfSpve1D
         PwgI9wJTTYEq9e7vUs/pcgrvuW7jSrZEaqjwQWDo/1k4LZAJNYZTsHoOQBDhwmZ94ulr
         mlGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769748629; x=1770353429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qCBgrTA4JiEFdROuJ6/b4izTnDdtj0kx8amZofRmV+I=;
        b=so5zXmBd1augtCp8T/2+hwlmS6ZdmERQhsWDOrqL3n2LpfBaNtGQ9THWtl+OoNBm86
         i2oxTyoApLX+LQwQMVD8YfxX8uC3ala6zXSH/FgEBu9diCmEhdfT3GAtOZcfiR1vtBvW
         8kyGuAi1EYUVX0SPAz5zPp0h2KNG5gJJFrjEHYyOdluIdZgHiFPKqe+fRYHaA8TEJkAN
         zLkLPAqGeOjYUcrj/LeppIzXRsS0MfCRabAcPoVVcAlNkYJSIx8UXe+9AOsemsGun2fj
         sf8XF3zCMCkClsNy0MrSZGhXDYRjyOpujz4qMBPB79KiY5sckzzVvJbB/w9ztEMH6bP7
         CLWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXKyb8EhejBm6od2yF6fdOYfI86Y3ThzbW75X4ovH7kxmGzaZfUWAx6cp4OynkzU9nqUbrNw==@lfdr.de
X-Gm-Message-State: AOJu0YyUuHPrdsgdQnI8WcHLcFfh28csPrXHfHF4JF/0wDiZhqAxmnAE
	GTcJx54zLG3Q2/qs8Tpc2uShdUXUtvzDtB+eP72bcRkaTOpcvEhUgVgO
X-Received: by 2002:ac2:4c52:0:b0:59e:340:e557 with SMTP id 2adb3069b0e04-59e1640219bmr538076e87.19.1769748628891;
        Thu, 29 Jan 2026 20:50:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GECWEw6qNN0PY9H4vzs5H6ht1jprwQEqq5JWv8f+nUhQ=="
Received: by 2002:a05:6512:318f:b0:59b:6d59:3201 with SMTP id
 2adb3069b0e04-59e0f1ae924ls605900e87.0.-pod-prod-06-eu; Thu, 29 Jan 2026
 20:50:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUCSLMWIPVpNI8oBOTMLRT/FLTUwwGEbFeqpvLFh6Al4cD3VKEzaJu+hQX+C611b0QCcROUvMo4kIQ=@googlegroups.com
X-Received: by 2002:a05:6512:639a:20b0:59e:19e3:f724 with SMTP id 2adb3069b0e04-59e19e3f72cmr33814e87.42.1769748626832;
        Thu, 29 Jan 2026 20:50:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769748626; cv=none;
        d=google.com; s=arc-20240605;
        b=CjFfMCnFUzfWV175mvpgycusj1dGloak1bW80vntSjD1v42Og+hkugC+zrt5f95z+8
         EB7xaHg/fWIvmrM4IXB1l/1dMV0PxEJ5JA5MR09JXwdl8z94sgJ6H5Qfw+ElQIz/K07s
         Kfob5pdQTEbG+j6Q7GnxjnD1xqYdx4NDjQaGlRosJCrwVLFoBy95UYdTtpgTZU8qrnDO
         r6alCxxgSx3YkfVDGOwzu4b21Uonop/2DK2IAFKIzEc3w2Gl5/Qvcdt30R2nIld4pGIn
         ZSgKwhoUf84FFD4yMPMCPsPyvAVgkhgxGc3ce5jiBWoevZFHS+trOY2SrPb27KyK6KAW
         hYCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=o0LolDkIeVgydx+lUvvnJuU5rTPe49ECMjoBW0cqVvs=;
        fh=IJc/xULCf01o48qWj7VfHKXKmbbWC8yCQEzHfREZ7bs=;
        b=g303fNXRQBUxtXmFbgFfwnexJ2WtyhA7O9iKetqxsd8LUj48Er4+CpE3CJD2MB+q1E
         r+DUSH9+8AG5F/mhlNMhs3n+jYccfmJYCTVZIWSVREdX57bcSuexvzu0Sx3Gs8cU0f83
         gJN1nngnRBX2vdMPOtvRGeAXyDmQriRQobm9p73L98DMJsCDHI5ZXDYYkWPhG8Nlh9o3
         YO6hd9hVCJmRUCSB5yN2TcqpQ/2LXyaALAI7/KoUsns0dm/ig/H4O1JFzN7xBCMPCzGg
         35ADbR+rP3POKQxWEhySo8BjuN5vX0V95WhWBU8oFv/Aff4GuREWg6NCyWG4/FH5mA5H
         VwBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MTZFazTp;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta1.migadu.com (out-186.mta1.migadu.com. [2001:41d0:203:375::ba])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59e0736afcasi181570e87.0.2026.01.29.20.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 20:50:25 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ba as permitted sender) client-ip=2001:41d0:203:375::ba;
Date: Fri, 30 Jan 2026 12:50:14 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
	kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org, "Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH v4 00/22] slab: replace cpu (partial) slabs with sheaves
Message-ID: <pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7@la3hyiqigpir>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
 <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=MTZFazTp;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ba as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBAABBFHR6DFQMGQEZTBT2NA];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: C8587B7286
X-Rspamd-Action: no action

On Thu, Jan 29, 2026 at 04:28:01PM +0100, Vlastimil Babka wrote:
> 
> So previously those would become kind of double
> cached by both sheaves and cpu (partial) slabs (and thus hopefully benefited
> more than they should) since sheaves introduction in 6.18, and now they are
> not double cached anymore?
> 

I've conducted new tests, and here are the details of three scenarios:

  1. Checked out commit 9d4e6ab865c4, which represents the state before the
     introduction of the sheaves mechanism.
  2. Tested with 6.19-rc5, which includes sheaves but does not yet apply the
     "sheaves for all" patchset.
  3. Applied the "sheaves for all" patchset and also included the "avoid
     list_lock contention" patch.


Results:

For scenario 2 (with sheaves but without "sheaves for all"), there is a
noticeable performance improvement compared to scenario 1:

will-it-scale.128.processes +34.3%
will-it-scale.192.processes +35.4%
will-it-scale.64.processes +31.5%
will-it-scale.per_process_ops +33.7%

For scenario 3 (after applying "sheaves for all"), performance slightly
regressed compared to scenario 1:

will-it-scale.128.processes -1.3%
will-it-scale.192.processes -4.2%
will-it-scale.64.processes -1.2%
will-it-scale.per_process_ops -2.1%

Analysis:

So when the sheaf size for maple nodes is set to 32 by default, the performance
of fully adopting the sheaves mechanism roughly matches the performance of the
previous approach that relied solely on the percpu slab partial list.

The performance regression observed with the "sheaves for all" patchset can
actually be explained as follows: moving from scenario 1 to scenario 2
introduces an additional cache layer, which boosts performance temporarily.
When moving from scenario 2 to scenario 3, this additional cache layer is
removed, then performance reverted to its original level.

So I think the performance of the percpu partial list and the sheaves mechanism
is roughly the same, which is consistent with our expectations.

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7%40la3hyiqigpir.
