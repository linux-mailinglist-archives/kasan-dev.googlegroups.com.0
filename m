Return-Path: <kasan-dev+bncBDXYDPH3S4OBBA7LZGVAMGQES3S7QTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3744E7EA35F
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:13 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-32fd35e1693sf2093512f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902852; cv=pass;
        d=google.com; s=arc-20160816;
        b=ji7HmrkXSxxkNQJmQz4H00ivvC1hCb++Q8yTnGh3gvDFfgwuR3mXwbYr/KkUilAmGc
         Z7Xoplkdbe4PN+ORXotH5RUqPNGp71ug32inKaklrbUrHo2wvQ7XSkk618NVmMS1JMoJ
         2Pp9qwsC4gGeo/d+iCMazGlJzOpH+awmoRTyI6doXyYYOGnASpVghK8oJ17jnCOCrWDy
         /bwCsHIHJPrgdO1eLUdSn936/Kz37AA2iQyklVo+Ek9UBOjx+K9sOICstu0eDkX3t7iD
         tyaUjr4+3ebFeFRgDy1a1+ZZuoX537K0bJgGAe+oxm+Db6TZGxM8ctKne+/0R1eVWsnV
         glHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FPTk02ibReAAXZlW/WZp/xUXJ8FbfXqm/+/MlC/Lo3k=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=QPCrR9bQfv+MC5SQZpQe4LVJu5rdAufiMMVYIIIl+cOhJVJodWE4eafRHFb3QwOPBb
         9cW3zxYYg2yqXAVO0Q6cWan1SWUmp2hYuwgAQ0HX3GMeIH1ByPgHfnbGP2lHLQWxyMh/
         AqOyolwnD4D0lLifKG4vRUgO3kHeb01S1BfBSWvilS0DHEuBw3ccr20ddQ4hHqx4NTjz
         SF6ksLkcvSPN2fA6MWUaFx/NktpIp37QnjqS1f5lLSLDBNAbrkoljO4ciq6hQgCne6cW
         RPuz/eooPPui3+QFO+lAcVMFc0+EXNkYygpKO41wRQ+2yCPqjxtIRTW0qmFy7LEslNPI
         L4Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="iXl/C1dL";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=Ikh9Erxs;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902852; x=1700507652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FPTk02ibReAAXZlW/WZp/xUXJ8FbfXqm/+/MlC/Lo3k=;
        b=B7zp+rf/PUzRCf1uE8uzvshYaUMGWmA6WG8XWABibL9yVUTYbzIsgzmjlvqvkM8paT
         jYSjdhwFJBNP5BRi/F5xBwNSYK5X0HxDZNKyWr0VGMB+e/fBoOYg0xUD9Zgee7KlbF09
         vdiNd0Khl4d5d8jPST8/xmU0yWhcnBMcNJzwTCAavLUYn2KAUxFYwIXAdDWmB8lXQol0
         WXSICcvBM0NTe4ivCQR3BGOhujdtNElaEAKSQQ+9AwcmY3uM3XQots4nPSu9A8Qqyvt4
         X5mNuY7yawyWvpoq8j0RvWxqexUHhlWvEx8GhtEWFP5DQ2L9i3H5Kf0eDCayvu5NPN7E
         Tzqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902852; x=1700507652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FPTk02ibReAAXZlW/WZp/xUXJ8FbfXqm/+/MlC/Lo3k=;
        b=rv06DunRPZiFrA/uERGHALbkTNUiYyaTtN4EMOCHtVeDD6gmeVXn84FgbpOn4YDCV/
         kAIwcmMO8Phx9/c6VdQxM+v/ocpXkzs7770vthFpKt9NRFXpQhgyJoB01q3a186P2TXS
         mAksCXlvu6v10/rDw3zfvmJ8D4HHnNq9+WewXfcUmEyh2e1ZcIMseWG0rRlNGRgJFi/C
         7QW1EPRCVwY6DfX/9bv4PKvLfGbb55bPvoN3bq228E2apTah42L6q4Er1eIOe6rDv2kc
         vVCxVPw0jr2+lu4ciyhKnicLqecca4hAAIcrzsoFMrGYTG/YC/1R9hZInJj4m7lOaqVA
         OAdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxQVWyBMKvzN1gETcFV6f/5OuW0gcK5/11d3CfopeKhkUfxUnuf
	YNM+C5MFbTzK0LgqUWxxWcw=
X-Google-Smtp-Source: AGHT+IFeTMFBVDEYtbA2wtnGj07THVNZKuUXYuq0KwiUqHbPUKCGUt3x7l/nyOyNh9a5Do59eMydng==
X-Received: by 2002:a5d:5850:0:b0:323:1887:dd6d with SMTP id i16-20020a5d5850000000b003231887dd6dmr6367385wrf.3.1699902851824;
        Mon, 13 Nov 2023 11:14:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:70d:b0:323:3654:7d7d with SMTP id
 bs13-20020a056000070d00b0032336547d7dls1507590wrb.2.-pod-prod-03-eu; Mon, 13
 Nov 2023 11:14:10 -0800 (PST)
X-Received: by 2002:adf:b355:0:b0:32f:dc95:ea3e with SMTP id k21-20020adfb355000000b0032fdc95ea3emr3990225wrd.70.1699902849909;
        Mon, 13 Nov 2023 11:14:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902849; cv=none;
        d=google.com; s=arc-20160816;
        b=Psabh1iB5j7oeQBnFAVjImgj3V6mMExLbiin1J06hEXqZvKy+x8H4Ie9hgKhy9XGxE
         R3duy1My1f2SG+s7UbYbTWR2V1D2hFaEjSCwFOTNKe3Viq4sn/a7/FlXqSIAj8sOnn6z
         en6Mp/M5siqTnK5KYEWOJr6IA0QPfIEYVqxh6pLiaonpJ1brv8bfZtiXeqJkeRgAgB0r
         5FWYCtzLZ8izUZBamjPyf4yhgh+ER/ZeNT+XQeWG82gMiIBJ9KuEusW7zVnkZa3wUYh9
         EpMfm1EuTTJpdu4vUQn2vGCvfNNJSDYfGCBdmvnj8xdgNyJKayiCfdgD8SlC4pcCjhba
         Nm7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=W7QXmIFPtyA621azrDtsOPQFV81EzYubbdba9PHLL0k=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=mMK0I9a4s0zvuN/LNLFDrJfsrtniLy11UbFgIy/EqH19W48nVwyPDzkTs4Vs6NU6N8
         R+0IOKOoGFCfvhf3ubcT8EnBtqizwJr8QZAZSrDPsgU1yYW/wZbgZOlTc5/qC5y06qEL
         palaQ5XBJfusrnRkx2I+sU1O+t+OCFb5HKmu0pN1/62qMbgyVUIyKvtO6eyREUH0+P7M
         uH/gMGfh1zRCpr63lx86ZEuGksLLLj+xRI6giSYZJWjAcBK7392qOfqfU/+eBuUvQOl8
         zQKjeg4rq5kxNOw8LCFvtfj3KGBrd7i6gKj+jLOzWwsrPfLaeYwuIUikCP+eoqyEaKQk
         0flg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="iXl/C1dL";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=Ikh9Erxs;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id bo29-20020a056000069d00b003263a6f9a2csi249026wrb.8.2023.11.13.11.14.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:09 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 52E101F854;
	Mon, 13 Nov 2023 19:14:09 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id F2EE313398;
	Mon, 13 Nov 2023 19:14:08 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id Us6jOoB1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:08 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 00/20] remove the SLAB allocator
Date: Mon, 13 Nov 2023 20:13:41 +0100
Message-ID: <20231113191340.17482-22-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="iXl/C1dL";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=Ikh9Erxs;       spf=softfail (google.com: domain of transitioning
 vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

The SLAB allocator has been deprecated since 6.5 and nobody has objected
so far. As we agreed at LSF/MM, we should wait with the removal until
the next LTS kernel is released. AFAIK that version hasn't been
announced yet, but assuming it would be 6.7, we can aim for 6.8 and
start exposing the removal to linux-next during the 6.7 cycle.

To keep the series reasonably sized and not pull in people from other
subsystems than mm and closely related ones, I didn't attempt to remove
every trace of unnecessary reference to dead config options in external
areas, nor in the defconfigs. Such cleanups can be sent to and handled
by respective maintainers after this is merged.

Instead I have added some patches aimed to reap some immediate benefits
of the removal, mainly by not having to split some fastpath code between
slab_common.c and slub.c anymore. But that is also not an exhaustive
effort and I expect more cleanups and optimizations will follow later.

Patch 08 updates CREDITS for the removed mm/slab.c. Please point out if
I missed someone not yet credited.

Git version: https://git.kernel.org/vbabka/l/slab-remove-slab-v1r4

Vlastimil Babka (20):
  mm/slab: remove CONFIG_SLAB from all Kconfig and Makefile
  KASAN: remove code paths guarded by CONFIG_SLAB
  KFENCE: cleanup kfence_guarded_alloc() after CONFIG_SLAB removal
  mm/memcontrol: remove CONFIG_SLAB #ifdef guards
  cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
  mm/slab: remove CONFIG_SLAB code from slab common code
  mm/mempool/dmapool: remove CONFIG_DEBUG_SLAB ifdefs
  mm/slab: remove mm/slab.c and slab_def.h
  mm/slab: move struct kmem_cache_cpu declaration to slub.c
  mm/slab: move the rest of slub_def.h to mm/slab.h
  mm/slab: consolidate includes in the internal mm/slab.h
  mm/slab: move pre/post-alloc hooks from slab.h to slub.c
  mm/slab: move memcg related functions from slab.h to slub.c
  mm/slab: move struct kmem_cache_node from slab.h to slub.c
  mm/slab: move kfree() from slab_common.c to slub.c
  mm/slab: move kmalloc_slab() to mm/slab.h
  mm/slab: move kmalloc() functions from slab_common.c to slub.c
  mm/slub: remove slab_alloc() and __kmem_cache_alloc_lru() wrappers
  mm/slub: optimize alloc fastpath code layout
  mm/slub: optimize free fast path code layout

 CREDITS                  |   12 +-
 arch/arm64/Kconfig       |    2 +-
 arch/s390/Kconfig        |    2 +-
 arch/x86/Kconfig         |    2 +-
 include/linux/slab.h     |   21 +-
 include/linux/slab_def.h |  124 --
 include/linux/slub_def.h |  204 --
 kernel/cpu.c             |    5 -
 lib/Kconfig.debug        |    1 -
 lib/Kconfig.kasan        |   11 +-
 lib/Kconfig.kfence       |    2 +-
 lib/Kconfig.kmsan        |    2 +-
 mm/Kconfig               |   50 +-
 mm/Kconfig.debug         |   16 +-
 mm/Makefile              |    6 +-
 mm/dmapool.c             |    2 +-
 mm/kasan/common.c        |   13 +-
 mm/kasan/kasan.h         |    3 +-
 mm/kasan/quarantine.c    |    7 -
 mm/kasan/report.c        |    1 +
 mm/kfence/core.c         |    4 -
 mm/memcontrol.c          |    6 +-
 mm/mempool.c             |    6 +-
 mm/slab.c                | 4026 --------------------------------------
 mm/slab.h                |  550 ++----
 mm/slab_common.c         |  231 +--
 mm/slub.c                |  597 +++++-
 27 files changed, 784 insertions(+), 5122 deletions(-)
 delete mode 100644 include/linux/slab_def.h
 delete mode 100644 include/linux/slub_def.h
 delete mode 100644 mm/slab.c

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-22-vbabka%40suse.cz.
