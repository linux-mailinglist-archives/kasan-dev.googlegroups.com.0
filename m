Return-Path: <kasan-dev+bncBD56ZXUYQUBRBLGU4K6QMGQEEGQU5TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 743ECA3FB46
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 17:30:38 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6e6819c3edbsf51986066d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 08:30:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740155437; cv=pass;
        d=google.com; s=arc-20240605;
        b=YhNsptpCRzYymJiNj/C6nwE+/OsOxojXkFPgJauyw5UBwPDyeULJ9TwTHmAi+gGa8G
         6uYtMFSpCRa4MfjeHfqS+wISz9pNms+HvgIbOb6pdwGhxRZOyH1w9HlkQLIIEBx9q5Az
         dsdilZxg7kJ86qSU4Cu5REmHTHqOt4hW5XJ9rl0026iJZMp0BExGQWNsE7QjyaFqyWwZ
         6Lwdo1uZYToyEqDVlMrZUqyatu0cFyEgOkFmwnK68M14+pouHofUHN9mrLAIxSFC3ppT
         DQuDNlm3nNXWiIg+WUwROp2XtJIg1u7rrkp4hPYCKAz4mLDWuu467koQ7ow4lw892VhI
         /aww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:reply-to
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=x5FmAqoj9SbVYv+Q9NrvZPCiGMpXoMnBfUjgDZZT8nw=;
        fh=wu7/SeF7MmZq/P/5tX0uaqzd8yz+4okKsGYOANbG8Vw=;
        b=EmGrHJYiQ6nLxAJxHHIt06OJFhPjeH2urKAZFe81OFR9YjmMmEsgtvw43CENRtX+Rd
         PSo8hImQNRcRpDfKbl8r09UkvQz+muY5XtNTvmi+xuRCtiHV+DbyRXBAYod2PKguxjCL
         bhpx/CapLmtVMRk7CuiGQqtSNdyyd16RJyZ476HAVmgKMOZsVaJ1EQ9f2OxOIErfSXC4
         o3lhHQYXsey2LjJyqYiHCOb9pArBRb8RkxdbB0wO/EWdnz51WXIFjFWup8V5aY4u69sq
         JwGhE68amuE+pS6p+W8SJ0EscsqECHMOGl++pn/j01zYZdXozL7y95Vb0lGNjQJGdmfC
         HcGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IBrZU0d8;
       spf=pass (google.com: domain of kbusch@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740155437; x=1740760237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=x5FmAqoj9SbVYv+Q9NrvZPCiGMpXoMnBfUjgDZZT8nw=;
        b=MHAySVjXLOJ2QXRT9GLaoddvs/JoezJJFWuSU80OXRHFBUSsORyb2Es1XwnxDJiL/Y
         xOKTbO2ZLrNCOBgkszHCdB67A8Ze4iZjairRAl81swCrCgtO4yWD6vjCaFlXX7zPIlHI
         PGxE0CeoBUuT+gGV/IhkLuefLzEpQrYp7X+ZcQJJ5E1/0GcgQ3ymCbq5EIz+Hq2Dh016
         8nbYzG6ZtVc4K1czKnzemQTdz6oj0YA1ioJKm5N17ScR5x3LodyLU3YAwRK7w7RV3InA
         kqZmmNhJYDePKBnGfL1fEFccEMlYS4dnIZ+JyRLsIh0UTtKtQ4bGhNIcGB7w4D9DoMpb
         Erdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740155437; x=1740760237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x5FmAqoj9SbVYv+Q9NrvZPCiGMpXoMnBfUjgDZZT8nw=;
        b=jvp2o/gTz++124OF/VByqWGLZnETiEYDuzUqcfVKu/MHGag5Y7R0VSJqaZl0wKG78N
         swZnV3AgkBcU/qtoxaE7xN01ho8I0U11RL7uIcL3Wt42P+y6WOerK2ujpQTOt8Qca80X
         zO3P3KZHLoIPBHw9F35Jj46ED2MGnGF/Geyw/TcuufNTk7sI/a9cOJC1bGi+mAeyScYC
         stH5SQJKM/YBcXfONdISaTHP6DuY6Ed8Jgq6R7bDen7Lv1zvb5Jox4nLCMfCMBjzlZnc
         DmF6Kipg7FpRulD+I6L7vmOz+3Z4vXBFcK4tEg7YMasGV40G4UdIblIsRSfOqNOZAsl9
         EO5w==
X-Forwarded-Encrypted: i=2; AJvYcCUS7tzktIjprdV6aU5vRwfklULCxLvQ2UbgqYf3juP36Xz7OneB4pBD8FaWHLx6Yo3PYbW/RQ==@lfdr.de
X-Gm-Message-State: AOJu0YzZuMRZv4/y/Szw/Z7HZbwqGqgdyZEjaZ1+BUcFLD4XlqV5Op0E
	ME8k2bBHCBNQu7aCOYDc33YzO52dSl+oTHBMU0i6LB7zkkWP8z2s
X-Google-Smtp-Source: AGHT+IEsNT6TZU1Mrnaqd7m7ZEDSsTGqttA8mv8PthvNuwsKNCFAo3R5g0u23se0zNnbNnDdROZgFQ==
X-Received: by 2002:a05:6214:1314:b0:6e6:4969:effc with SMTP id 6a1803df08f44-6e6ae9bb86amr48501346d6.29.1740155436876;
        Fri, 21 Feb 2025 08:30:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHDQmWbLy9vgJBuvAKKp/7mby4Xi+8p6iYBcV5/tsEOzw==
Received: by 2002:a05:6214:c7:b0:6d9:b90:7629 with SMTP id 6a1803df08f44-6e6a2083cbfls8931096d6.0.-pod-prod-04-us;
 Fri, 21 Feb 2025 08:30:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVoP/u2nzj1Ck0+V5uyN+n3O3uVC6R8AM10GQ7kEtgGUf/PD3BvwcwyxHt0c9dF55Rd8CbiB3PEaCQ=@googlegroups.com
X-Received: by 2002:a05:620a:4155:b0:7c0:c1a6:d0d with SMTP id af79cd13be357-7c0ceee286cmr691586885a.8.1740155435975;
        Fri, 21 Feb 2025 08:30:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740155435; cv=none;
        d=google.com; s=arc-20240605;
        b=atg/lqOHMzn3j9Sn0WYAkfFrKFiyOyGWOxs4NmUj2mM1PiCye1CtzPtesqVowh2n80
         AnndYFsQOu2gBDakyeF/JisnCCi1Xv69fCRudbsLC3w2gMfstn8T7Oke3BoH33cZmFJ6
         mjZf4MbTXwuH61YJyyuCgLDtRcZ8Hcdcgx7gpm9DYmch+Wwan1tGJwIekWZBF9CjyfZb
         XUfF+m2zdAZkDHEcHD4L+QDPrxpVk5rKxECxAz2CoWplMpeuz/pcJn5LY8wcaQSfMiER
         W4Gn/fZJLwbGy1o2UXHHub4ovXkulkS9yl8xNV4wdpvr2AltIUSBTwzkFcigsxzJWf4z
         tS6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u1rJcr0E4srTcqTLbk7vYO/8bEZ4/iAouOB6dwNH0mc=;
        fh=H5KbUCyaLQMxPFiklPd9JyUtEEYcP1Z/Oc4SxDKHm1g=;
        b=NE0jmLdlbQBMK/vjTQ/JUgx2rUm6Oy1xvEUzpB9jIp5UydIpyfPmpVo2HC3LMxxnwy
         wT4v+E9mMbMFgTagvPJeU8Tiv0UvRvyHlBcGBF0oSvCZpIwozqMqSFatX0+NtsDPiKRv
         ZVyWM1dwc2E6TN4FO5eenbouStjGpQzbORcfsw+/OQMWbs9ZkIk2nreBOyqnwjOfpW/B
         vBM3tCt/JKvsEhkiZw3DsAgyAYaXBZas00vcFct6fUi6ErG3q/ORqv58ZG4YPTSrgQAf
         O902/M51cRbB72VW6C717+2A5JNek5by0pnTwZz6HCobXmRjl6CPEmdWmSK7eRC9z2Z4
         lXHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IBrZU0d8;
       spf=pass (google.com: domain of kbusch@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c0a49255ddsi44983185a.6.2025.02.21.08.30.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Feb 2025 08:30:35 -0800 (PST)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3D6845C69C7;
	Fri, 21 Feb 2025 16:29:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1702AC4CED6;
	Fri, 21 Feb 2025 16:30:32 +0000 (UTC)
Date: Fri, 21 Feb 2025 09:30:30 -0700
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z7iqJtCjHKfo8Kho@kbusch-mbp>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IBrZU0d8;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
Content-Transfer-Encoding: quoted-printable
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

On Wed, Aug 07, 2024 at 12:31:19PM +0200, Vlastimil Babka wrote:
> We would like to replace call_rcu() users with kfree_rcu() where the
> existing callback is just a kmem_cache_free(). However this causes
> issues when the cache can be destroyed (such as due to module unload).
>=20
> Currently such modules should be issuing rcu_barrier() before
> kmem_cache_destroy() to have their call_rcu() callbacks processed first.
> This barrier is however not sufficient for kfree_rcu() in flight due
> to the batching introduced by a35d16905efc ("rcu: Add basic support for
> kfree_rcu() batching").
>=20
> This is not a problem for kmalloc caches which are never destroyed, but
> since removing SLOB, kfree_rcu() is allowed also for any other cache,
> that might be destroyed.
>=20
> In order not to complicate the API, put the responsibility for handling
> outstanding kfree_rcu() in kmem_cache_destroy() itself. Use the newly
> introduced kvfree_rcu_barrier() to wait before destroying the cache.
> This is similar to how we issue rcu_barrier() for SLAB_TYPESAFE_BY_RCU
> caches, but has to be done earlier, as the latter only needs to wait for
> the empty slab pages to finish freeing, and not objects from the slab.
>=20
> Users of call_rcu() with arbitrary callbacks should still issue
> rcu_barrier() before destroying the cache and unloading the module, as
> kvfree_rcu_barrier() is not a superset of rcu_barrier() and the
> callbacks may be invoking module code or performing other actions that
> are necessary for a successful unload.
>=20
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab_common.c | 3 +++
>  1 file changed, 3 insertions(+)
>=20
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index c40227d5fa07..1a2873293f5d 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -508,6 +508,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  	if (unlikely(!s) || !kasan_check_byte(s))
>  		return;
> =20
> +	/* in-flight kfree_rcu()'s may include objects from our cache */
> +	kvfree_rcu_barrier();
> +
>  	cpus_read_lock();
>  	mutex_lock(&slab_mutex);

This patch appears to be triggering a new warning in certain conditions
when tearing down an nvme namespace's block device. Stack trace is at
the end.

The warning indicates that this shouldn't be called from a
WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
and tearing down block devices, so this is a memory reclaim use AIUI.
I'm a bit confused why we can't tear down a disk from within a memory
reclaim workqueue. Is the recommended solution to simply remove the WQ
flag when creating the workqueue?

  ------------[ cut here ]------------
  workqueue: WQ_MEM_RECLAIM nvme-wq:nvme_scan_work is flushing !WQ_MEM_RECL=
AIM events_unbound:kfree_rcu_work
  WARNING: CPU: 21 PID: 330 at kernel/workqueue.c:3719 check_flush_dependen=
cy+0x112/0x120
  Modules linked in: intel_uncore_frequency(E) intel_uncore_frequency_commo=
n(E) skx_edac(E) skx_edac_common(E) nfit(E) libnvdimm(E) x86_pkg_temp_therm=
al(E) intel_powerclamp(E) coretemp(E) kvm_intel(E) iTCO_wdt(E) xhci_pci(E) =
mlx5_ib(E) ipmi_si(E) iTCO_vendor_support(E) i2c_i801(E) ipmi_devintf(E) ev=
dev(E) kvm(E) xhci_hcd(E) ib_uverbs(E) acpi_cpufreq(E) wmi(E) i2c_smbus(E) =
ipmi_msghandler(E) button(E) efivarfs(E) autofs4(E)
  CPU: 21 UID: 0 PID: 330 Comm: kworker/u144:6 Tainted: G            E     =
 6.13.2-0_g925d379822da #1
  Hardware name: Wiwynn Twin Lakes MP/Twin Lakes Passive MP, BIOS YMM20 02/=
01/2023
  Workqueue: nvme-wq nvme_scan_work
  RIP: 0010:check_flush_dependency+0x112/0x120
  Code: 05 9a 40 14 02 01 48 81 c6 c0 00 00 00 48 8b 50 18 48 81 c7 c0 00 0=
0 00 48 89 f9 48 c7 c7 90 64 5a 82 49 89 d8 e8 7e 4f 88 ff <0f> 0b eb 8c cc=
 cc cc cc cc cc cc cc cc cc 0f 1f 44 00 00 41 57 41
  RSP: 0018:ffffc90000df7bd8 EFLAGS: 00010082
  RAX: 000000000000006a RBX: ffffffff81622390 RCX: 0000000000000027
  RDX: 00000000fffeffff RSI: 000000000057ffa8 RDI: ffff88907f960c88
  RBP: 0000000000000000 R08: ffffffff83068e50 R09: 000000000002fffd
  R10: 0000000000000004 R11: 0000000000000000 R12: ffff8881001a4400
  R13: 0000000000000000 R14: ffff88907f420fb8 R15: 0000000000000000
  FS:  0000000000000000(0000) GS:ffff88907f940000(0000) knlGS:0000000000000=
000
  CR2: 00007f60c3001000 CR3: 000000107d010005 CR4: 00000000007726f0
  PKRU: 55555554
  Call Trace:
   <TASK>
   ? __warn+0xa4/0x140
   ? check_flush_dependency+0x112/0x120
   ? report_bug+0xe1/0x140
   ? check_flush_dependency+0x112/0x120
   ? handle_bug+0x5e/0x90
   ? exc_invalid_op+0x16/0x40
   ? asm_exc_invalid_op+0x16/0x20
   ? timer_recalc_next_expiry+0x190/0x190
   ? check_flush_dependency+0x112/0x120
   ? check_flush_dependency+0x112/0x120
   __flush_work.llvm.1643880146586177030+0x174/0x2c0
   flush_rcu_work+0x28/0x30
   kvfree_rcu_barrier+0x12f/0x160
   kmem_cache_destroy+0x18/0x120
   bioset_exit+0x10c/0x150
   disk_release.llvm.6740012984264378178+0x61/0xd0
   device_release+0x4f/0x90
   kobject_put+0x95/0x180
   nvme_put_ns+0x23/0xc0
   nvme_remove_invalid_namespaces+0xb3/0xd0
   nvme_scan_work+0x342/0x490
   process_scheduled_works+0x1a2/0x370
   worker_thread+0x2ff/0x390
   ? pwq_release_workfn+0x1e0/0x1e0
   kthread+0xb1/0xe0
   ? __kthread_parkme+0x70/0x70
   ret_from_fork+0x30/0x40
   ? __kthread_parkme+0x70/0x70
   ret_from_fork_asm+0x11/0x20
   </TASK>
  ---[ end trace 0000000000000000 ]---

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
7iqJtCjHKfo8Kho%40kbusch-mbp.
