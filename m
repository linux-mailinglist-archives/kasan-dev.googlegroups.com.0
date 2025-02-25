Return-Path: <kasan-dev+bncBD56ZXUYQUBRBX6T666QMGQEIXFCHCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 808A2A44554
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 17:03:45 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-6f2793679ebsf73851817b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 08:03:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740499424; cv=pass;
        d=google.com; s=arc-20240605;
        b=NLxkNOS13Ylfpv9RI51gacEn+8qmk0izsrerwqy7KBz1kuV3msle4tdMOg0BcpyzOs
         bfwoyLLrHPdqWhwsT+WULeGSTY7PB+V+aWdJqokbQ3iZGB88yqDyM9f5jfF9V7X4yODf
         S3TxNl5XmrdR1/fsDIEgKYL97R9P89BE7pkxmXBAtL87MRGv6W/sXh774jHk8zOjUN5n
         QCDEA2dMwuVrmKh3WxeIPQ8U9HR0H2CD0XQqfQiERiwZAJA9x5k9r/j6IGDRJ2hXdg0y
         3k83/sTYmI2qw3aiSKZ1Zyp8tUVbsV+44ZCV9HN1clbQgQHoSsU8PFjlf9s0477IFkO0
         9HwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:reply-to
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ixFE9ongVzAX58nPIuv14MWr9QuWcnmfZBwcOxjG8y4=;
        fh=4xlgriSQ0c7qnfPxVEUO7tS7war1mDpiYn/9NxfFReM=;
        b=H0Cy6d/8NYPX34uWGKjfdN9bA52cGCJ9tGPuM7LJaavPcPotLPo+SNGPJs0EI3juMG
         Kx+FV20IQES1oKL5Ynb9Q+1f+1B9qT6NWT827W0xBzwoGrzpPT3ht5UhJRoLye+oCleg
         PCbxlAjYdj/MmcVVan4eXXr5cvGkEazZhOAknfB1/Qc/MBrGxOcRFWF1Zgn9y5g/T6d1
         kkTTUL8WvpOFLHwF4Vj2bvrR4clqkkWP/zrbdTT1qZMlPI+F1+TpXsLREE0gbRsc8ypN
         cZwuim9cvQna6x7Z1afDg++JFvFj7sbH4c3tZXHh/lAMTX0Ta9iu+E/fMfhNmA1Ute9d
         Q6Ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zg+BK2ZN;
       spf=pass (google.com: domain of kbusch@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740499424; x=1741104224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ixFE9ongVzAX58nPIuv14MWr9QuWcnmfZBwcOxjG8y4=;
        b=nfHQN2tOTfV7YjCVxO5PueI5aS1OLv3RRDbCPCjVL2FU63T+uKl1Hm7GvW4vPBtrRF
         UFnPNLAALS5Lrld2R4FhQ4VYJH4HxJr1piS2W0g0j0K7csIFft0F2itFejrtFAPeBvdG
         jSi7aH2V5MR2JzXwCuAhUxj68iEajVtBv8f6/KOtp3TscFN5lBmOpVz4s03qRBIkAsmX
         /YkQRo8BYvOsqVsLiy0sS0IFSeCuyoVHDiMK8nAnsFE8k7NZRgKUKzPP/J+N49XGVeTX
         VP7PdU1YDZUh6aNRcK6nz59x5iAg1zra3bby5AgRtzEjfDH8UTE27XVDxQCNLsI8ClGe
         jptA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740499424; x=1741104224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ixFE9ongVzAX58nPIuv14MWr9QuWcnmfZBwcOxjG8y4=;
        b=usVRt3dRoX8+XejBelhbnTai14ajNoDlbgzKs/+qIZ0IlAtN5ARjIyC4WnY6mDzQQY
         wLOXktHC6ab0lHXIjPCdDB4p2zL40cATRA9E5o3ACG2TqB2+QSZLJKUvcEEX4teP7wOT
         4t/keBN64AFa4aJC9IaTpFjK4R+2ymdNO5KdjOxZE1CW5D4hqCTssCTc5kVBj3Y5rUVy
         tGAGIg0+ap9pkaTDOfk5erbciPAymUJAfk6n/VbhmMOdR9+ySruDeBvi5sbM+y3h2FJk
         vfR42TR9hXvzhikveyrgejbP3kSotF+BWVNRVPQZtm89ruhi8bAeJFWI6vIsNCG33U/y
         Udnw==
X-Forwarded-Encrypted: i=2; AJvYcCUIRljbpSvQeG+JHw2urrogpMUbQ8/ahWAZ4K5tHEb0Gc08HBnEJVk7n2MclQFX0iFnw4BPAg==@lfdr.de
X-Gm-Message-State: AOJu0Yx7aViNs6niww6pYrR1b9or1caAhb1A49J57Uq+hug5eW61h1Pq
	/kCSP0Hca0pwUzVMvKhHhzmWbxaZPINM1NFlWYiU1cRBNHzXwv4K
X-Google-Smtp-Source: AGHT+IFbXQdMfIu3BxJOofo01QNtxJSEtVPPG7wGPptDzMQ0kSgSSM5J6DeddomT+6wtpKWnSDcWmQ==
X-Received: by 2002:a05:6902:158c:b0:e5d:dcc5:59bc with SMTP id 3f1490d57ef6-e5e2466edbdmr14796939276.39.1740499424102;
        Tue, 25 Feb 2025 08:03:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGz66oYWFwrZvwqEoYrEusEqDJuKIKLDsPxS9vWJw/uOA==
Received: by 2002:a25:840f:0:b0:e60:8901:aead with SMTP id 3f1490d57ef6-e608901b049ls144283276.2.-pod-prod-07-us;
 Tue, 25 Feb 2025 08:03:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUxBhX3RqmPYY/JtSkL3ezddJqvTyaPXYqnqfG8Z3zfG020pMP6G5gqbnN9s5DgF/hyDUye26GPIN8=@googlegroups.com
X-Received: by 2002:a05:690c:4482:b0:6f9:938a:57af with SMTP id 00721157ae682-6fd21e29f90mr93607b3.17.1740499422552;
        Tue, 25 Feb 2025 08:03:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740499422; cv=none;
        d=google.com; s=arc-20240605;
        b=WDKEyYfKljyJ6zrqZ2V//LpinDFTKWxxlULaLlhDWuM+HYw9kqUSRbNwNvDTWW1q6p
         e28O4iVcE1eMBssbwgRqXYGZLMuVPIvuzuESGBz/CwXzYCtwZR1xvZXrnhX8N7P2JrZ1
         br0uHbxqPaq4f7yt0WE7/pMcU1Ii2XZrl7hN/JxlOSW3xzaaeToKQ/PRS1GG7NiR0hqg
         WIlUdxEo4r6byItlJ/Lq3LSoat4p8hRBE6bgxctDVsQVuQioe9MzdwE0tR8AmfQLJ7jX
         EkroCwzF/31QvTaXDfJxO3Bne6fHTZozDIj9WxTNmMXfPUzUDpD0Zgn/DlYrkWJB3o5v
         tK4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZA/z7q9kCF5Lt65d14NWTfWdgZTE+Al3KkUXcPo/sbk=;
        fh=zD6pWAJ0LeFN8cgc+B4OY7oxEWOhWpNXS9ujxl0Xy2I=;
        b=Fgy/D7fwuiWRsDB0fimX9opk0iM7UnSUV9vrAd0kymCW8wQ5MGsGQHY3dGVep9bCQ+
         bu7aFkhgzvQSsvg7l0qGYA2w129X1+nosQQmNtjtaIU+RJdfvAmIVmrJjKT5WT2zDTC2
         SO/5D8EjUbFO/T2FGIc/2tzLxlL59NjbGpsYaFPfpUSnlny/tcCKgNmS2RtaLn0YCWO1
         5RnvMD+oEMowbbCsCRNwlYVXa4Hegc3B8CYlIcrYCIjCqgIi/u2+TpyJfkb7NstvgiHa
         5u6YFPddm/t+N52CYPIXoZ1YH+hAinG26KaZEITTXfDJ+C2Eu6IfEneA35RAohmseFRt
         gwYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zg+BK2ZN;
       spf=pass (google.com: domain of kbusch@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6fd1149c9fasi1230167b3.0.2025.02.25.08.03.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Feb 2025 08:03:42 -0800 (PST)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 09EE85C5879;
	Tue, 25 Feb 2025 16:03:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 482EFC4CEDD;
	Tue, 25 Feb 2025 16:03:40 +0000 (UTC)
Date: Tue, 25 Feb 2025 09:03:38 -0700
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
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
Message-ID: <Z73p2lRwKagaoUnP@kbusch-mbp>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Zg+BK2ZN;       spf=pass
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

On Tue, Feb 25, 2025 at 10:57:38AM +0100, Vlastimil Babka wrote:
> I tried to create a kunit test for it, but it doesn't trigger anything. M=
aybe
> it's too simple, or racy, and thus we are not flushing any of the queues =
from
> kvfree_rcu_barrier()?

Thanks, your test readily triggers it for me, but only if I load
rcutorture at the same time.

[  142.223220] CPU: 11 UID: 0 PID: 186 Comm: kworker/u64:11 Tainted: G     =
       E    N 6.13.0-04839-g5e7b40f0ddce-dirty #831
[  142.223222] Tainted: [E]=3DUNSIGNED_MODULE, [N]=3DTEST
[  142.223223] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel=
-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014
[  142.223224] Workqueue: test_kfree_rcu_destroy_wq cache_destroy_workfn [s=
lub_kunit]
[  142.223230] Call Trace:
[  142.223231]  <TASK>
[  142.223233]  dump_stack_lvl+0x64/0x90
[  142.223239]  print_circular_bug+0x2c5/0x400
[  142.223243]  check_noncircular+0x103/0x120
[  142.223246]  ? save_trace+0x3e/0x360
[  142.223249]  __lock_acquire+0x1481/0x24b0
[  142.223252]  lock_acquire+0xaa/0x2a0
[  142.223253]  ? console_lock_spinning_enable+0x3e/0x60
[  142.223255]  ? lock_release+0xb3/0x250
[  142.223257]  console_lock_spinning_enable+0x5a/0x60
[  142.223258]  ? console_lock_spinning_enable+0x3e/0x60
[  142.223260]  console_flush_all+0x2b1/0x490
[  142.223262]  ? console_flush_all+0x29/0x490
[  142.223264]  console_unlock+0x49/0xf0
[  142.223266]  vprintk_emit+0x12b/0x300
[  142.223269]  ? kfree_rcu_shrink_scan+0x120/0x120
[  142.223270]  _printk+0x48/0x50
[  142.223272]  ? kfree_rcu_shrink_scan+0x120/0x120
[  142.223273]  __warn_printk+0xb4/0xe0
[  142.223276]  ? 0xffffffffa05d6000
[  142.223278]  ? kfree_rcu_shrink_scan+0x120/0x120
[  142.223279]  check_flush_dependency.part.0+0xad/0x100
[  142.223282]  __flush_work+0x38a/0x4a0
[  142.223284]  ? find_held_lock+0x2b/0x80
[  142.223287]  ? flush_rcu_work+0x26/0x40
[  142.223289]  ? lock_release+0xb3/0x250
[  142.223290]  ? __mutex_unlock_slowpath+0x2c/0x270
[  142.223292]  flush_rcu_work+0x30/0x40
[  142.223294]  kvfree_rcu_barrier+0xe9/0x130
[  142.223296]  kmem_cache_destroy+0x2b/0x1f0
[  142.223297]  cache_destroy_workfn+0x20/0x40 [slub_kunit]
[  142.223299]  process_one_work+0x1cd/0x560
[  142.223302]  worker_thread+0x183/0x310
[  142.223304]  ? rescuer_thread+0x330/0x330
[  142.223306]  kthread+0xd8/0x1d0
[  142.223308]  ? ret_from_fork+0x17/0x50
[  142.223310]  ? lock_release+0xb3/0x250
[  142.223311]  ? kthreads_online_cpu+0xf0/0xf0
[  142.223313]  ret_from_fork+0x2d/0x50
[  142.223315]  ? kthreads_online_cpu+0xf0/0xf0
[  142.223317]  ret_from_fork_asm+0x11/0x20
[  142.223321]  </TASK>
[  142.371052] workqueue: WQ_MEM_RECLAIM test_kfree_rcu_destroy_wq:cache_de=
stroy_workfn [slub_kunit] is flushing !WQ_MEM_RECLAIM events_unbound:kfree_=
rcu_work
[  142.371072] WARNING: CPU: 11 PID: 186 at kernel/workqueue.c:3715 check_f=
lush_dependency.part.0+0xad/0x100
[  142.375748] Modules linked in: slub_kunit(E) rcutorture(E) torture(E) ku=
nit(E) iTCO_wdt(E) iTCO_vendor_support(E) intel_uncore_frequency_common(E) =
skx_edac_common(E) nfit(E) libnvdimm(E) kvm_intel(E) kvm(E) evdev(E) bochs(=
E) serio_raw(E) drm_kms_helper(E) i2c_i801(E) e1000e(E) i2c_smbus(E) intel_=
agp(E) intel_gtt(E) lpc_ich(E) agpgart(E) mfd_core(E) drm_shm]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
73p2lRwKagaoUnP%40kbusch-mbp.
