Return-Path: <kasan-dev+bncBD63B2HX4EPBBB53X37AKGQEYJUGPMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B59C2D2E5B
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 16:36:40 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id z8sf16105559ilq.21
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 07:36:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607441799; cv=pass;
        d=google.com; s=arc-20160816;
        b=J7vNUcsi3O747Ge2T0bTVOew0U29Ve4gIOq6O/Y3+v1C60s6qJJ9K3lzaMANEWk0gk
         uWr33P5mcBRKUjaAxB6luo6SObbC3dxE7HeWsmKkj0K/uypXHIgSNs+KA4OneAiU8PvS
         VHIjl0B7vZkspDkhd52QKEjqImB6ai2IPLXfSUOAZjDxpEs2vkQxa1XNiASv5EHjH4jF
         vGa5+NySa22K1HKdV6eVVVLJhQTfhZ5FyvGl+bbSNT3tLKVcHeTAYr0bsqzWKGs/w/Zy
         CIkNoMGAFv+1+PqhInBWqyNTfjcGfUOuOu/s7X7zv4nEbD8dgOx1AKxyHU94iTXCXWxn
         gGyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=mOdDpHAfFSAYQH6JOUBblrYU1owY9rgcALit7d6wICI=;
        b=JGc/doIosp+s7kD81xU7YnzTozDjFsXatwHNFOBtPviax37APT9AD1EbnrhxFYulHN
         P58cqKIzrsIrJWPGgZy0jiaH77vOs4WzcfzVlxN6U3pqdKHvHrSw7gbP5EEimpUtpprl
         ddUlp/MFBB37btKg7F4dE99rlhUUVjiCSttLBlsOaCWXmyp1bCna2zNpT8rwM6yz7OnS
         4yXw14691mRhSrmUBybyD3EHNBKCO1Xt6/GYrdDLKmt16CIeo+24AZITF9QGHPW49qJa
         Mw5sFVFVHPPxG3a0Go9hDYe1jDX43jgItEJAHwFYygZ4nt3kMk8c7ldHZ/oisyidZIGe
         LIXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b="aZ4B/VwW";
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mOdDpHAfFSAYQH6JOUBblrYU1owY9rgcALit7d6wICI=;
        b=ngb750DXffjsTcWQ4a4LhC0SPiJKEia0yQ017oRgGTcgMe3/AdEOcHMMXA6JNpztYk
         9Q10wgurgeImSIN8FtfO47wQep12uKqptYqcCL5txfXcRRtV1UTiXOah5FOTeDH+qJnS
         9P8EysVn8wlr/ch0KJwfypUpnr/SVaSWvV2UuO3Vh24TB9I/B4jwj/6itea5Sukdcy8H
         sROCTQ83VELhUdR3ElFUPmPQwieNKvDG0KDHXWqHArAuQ85FqlLuqG7yFMdsjLZUoKpO
         vQkHjzt4gAL7rbna0O6j5qWEvCnskc9jKCpiIz8xbSgdafpAimURAFcwr0odWVZak6LU
         a4AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mOdDpHAfFSAYQH6JOUBblrYU1owY9rgcALit7d6wICI=;
        b=LsWBwF9XnZFQtqIhN+eHEfW0PwIcVT2WEEQ3U3sJi01Hg+9zf7bZqzcVQnf+JL66/f
         +hXlWMlc3jSQTszh/rd0MFgjqWOWL4zqf9eKP6ILQLPdD6VvJ9NWwencGhtkAKYs20hw
         HFVtoytDrqW/NQAE6qv6eO9gmkHDPBzm2+mXtp2VCniHhP+EHQzhY3TotJ19c8sc0vtR
         /UteiWsGlNaOFhlwyZ9QdBi77ERcrz/au2G0kAvcJrXpWICaFg0ycR82X8M85Crc+HyH
         FsRuUWDZBtTwV5bh7/AEWtiV6aXAq+a9zhsKRgYQOLx3t/PlLm8nax6vAMrf+FHh+s/6
         oa8w==
X-Gm-Message-State: AOAM530R4+bzWndt+C9XxRL+vg+yEn0HAWicM/4zPwIEIERFkaniFzFt
	jesZWJBtCsJWd6VYAb1M9pM=
X-Google-Smtp-Source: ABdhPJwqqEP9eSSK9I8NGj+r/86xWJJxehQpWdNmxvqF6j4v/NZI+aslHysTj1EHRsLdjVFkBMKTSA==
X-Received: by 2002:a92:7109:: with SMTP id m9mr26063465ilc.232.1607441799353;
        Tue, 08 Dec 2020 07:36:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8c86:: with SMTP id g6ls3331829ion.0.gmail; Tue, 08 Dec
 2020 07:36:39 -0800 (PST)
X-Received: by 2002:a6b:dd19:: with SMTP id f25mr25232109ioc.205.1607441798977;
        Tue, 08 Dec 2020 07:36:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607441798; cv=none;
        d=google.com; s=arc-20160816;
        b=GNzvCkXsJ7QYvVADkLNRHAoUSDALBiC8PoBmMR2cl8ZRbPfDlgI45hrbiMM7eivFVQ
         u1fcgojMq5whZcKwJR7j99Q9hDF7Csqw5adqu/r+QFXON+PC+eF1Zk7/cUyFQSFpKbY6
         C45+jN2hUB59YjyLxfdiG5cNo99z1c8sRE/s+i7DJTQ+y6GX58gcNK229HHDgNmIWmIH
         RQWRUq6hJDOnuVQejZpei5En5x1wcenZXEyXK03HFhn5BBXyXPttK0/KgwiVw7ntD6Nf
         ayQfLCxYfGmt4CdftSJqa6kzeoQc5u58vXciX9r1JxNJr/bCDuDIXoWnvJyimz8txBK7
         CUaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=0dA7App4RBkkyBDPa20cpqGGQxG6bheIESDA9IpqY1k=;
        b=P1twruyWXw1lsH4a5MuK0/R5E2+8yYJrHbjXqntPW0XgqgGDJlzRyusqkJbVYwYmb7
         nV7/2OXBRSMHphwheMfkCM+YU5OX5IW3JrKZZGFuoBuuO97ibFy2RIbsh/Ik0BRG1ZTA
         YsnYjTTAZFwOLEOUyOpD0tsjw9ymi5qBdSpdQdfTrISJqNNHIZw+9T8HM8bgAYMhckY1
         Ogea8wyTMfrMOjqUtf9FcM4BOGl2/q2kgmthk7qv3w2G4llLbV1WRRKtGZv/9EI/SRYz
         RtsQxxZj1ouYcleQmu/UGnOKla0yqWZixMlagY4OajsbLTBM/vHUVwk2Hp3MJ0eqQpad
         e/Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b="aZ4B/VwW";
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id b14si1082679ios.2.2020.12.08.07.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Dec 2020 07:36:38 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id 4so7158630plk.5
        for <kasan-dev@googlegroups.com>; Tue, 08 Dec 2020 07:36:38 -0800 (PST)
X-Received: by 2002:a17:902:6a82:b029:da:fc41:bafe with SMTP id n2-20020a1709026a82b02900dafc41bafemr9087222plk.20.1607441798304;
        Tue, 08 Dec 2020 07:36:38 -0800 (PST)
Received: from cork (dyndsl-091-248-004-182.ewe-ip-backbone.de. [91.248.4.182])
        by smtp.gmail.com with ESMTPSA id jz7sm3760687pjb.14.2020.12.08.07.36.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Dec 2020 07:36:36 -0800 (PST)
Date: Tue, 8 Dec 2020 07:36:32 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201208153632.GB2140704@cork>
References: <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
 <X83y/etcPKUnPxeD@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <X83y/etcPKUnPxeD@elver.google.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b="aZ4B/VwW";       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Mon, Dec 07, 2020 at 10:16:45AM +0100, Marco Elver wrote:
> On Mon, Dec 07, 2020 at 09:28AM +0100, Marco Elver wrote:
> [...]
> > Please try the patch below and let us know if this improves your
> > 1ms-sample-interval setup (of course set CONFIG_KFENCE_STATIC_KEYS=3Dn)=
.
> > If that works better for you, let's send it for inclusion in mainline.
>=20
> Patch can be optimized a little further (no more wake_up()
> wait_event() calls). See new version below.

I went one step further.  Not sure how to measure the overhead of
interrupt vs. schedule(), but I suspect they are pretty close.  At any
rate, hrtimers are needed to go faster than 1ms and are more precise in
environments with high scheduler latency.

Patch is a mess, you definitely don't want it as-is.  But it allows me
to go more extreme and test the limits of kfence.  If it works for me at
10kHz, it should work for you at 10Hz. :)

J=C3=B6rn

--
I lose count of the number of times people say to me, =E2=80=9CWhen outside=
rs
ask us for leadership, what they mean is money.=E2=80=9D
-- Timothy Garton Ash

---
 include/linux/kfence.h | 17 +++++++++++-----
 mm/kfence/core.c       | 46 ++++++++++++++++++------------------------
 2 files changed, 32 insertions(+), 31 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index ed2d48acdafe..2cb326567cdd 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -15,12 +15,10 @@
  * extended guard page, but otherwise has no special purpose.
  */
 #define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
=20
-DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
-
 /**
  * is_kfence_address() - check if an address belongs to KFENCE pool
  * @addr: address to check
  *
  * Return: true or false depending on whether the address is within the KF=
ENCE
@@ -84,10 +82,12 @@ void kfence_shutdown_cache(struct kmem_cache *s);
  * Allocate a KFENCE object. Allocators must not call this function direct=
ly,
  * use kfence_alloc() instead.
  */
 void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);
=20
+extern atomic_t allocation_gate;
+
 /**
  * kfence_alloc() - allocate a KFENCE object with a low probability
  * @s:     struct kmem_cache with object requirements
  * @size:  exact size of the object to allocate (can be less than @s->size
  *         e.g. for kmalloc caches)
@@ -102,13 +102,20 @@ void *__kfence_alloc(struct kmem_cache *s, size_t siz=
e, gfp_t flags);
  * probability using a static branch (the probability is controlled by the
  * kfence.sample_interval boot parameter).
  */
 static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t siz=
e, gfp_t flags)
 {
-	if (static_branch_unlikely(&kfence_allocation_key))
-		return __kfence_alloc(s, size, flags);
-	return NULL;
+#if 0
+	static unsigned long last;
+	if (last !=3D jiffies) {
+		last =3D jiffies;
+		pr_info("kfence_alloc\n");
+	}
+#endif
+	if (atomic_read(&allocation_gate))
+		return NULL;
+	return __kfence_alloc(s, size, flags);
 }
=20
 /**
  * kfence_ksize() - get actual amount of memory allocated for a KFENCE obj=
ect
  * @addr: pointer to a heap object
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index bb3fd36e68a9..b506f09985a7 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -34,11 +34,11 @@
=20
 /* =3D=3D=3D Data =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */
=20
 static bool kfence_enabled __read_mostly;
=20
-static unsigned long kfence_sample_interval __read_mostly =3D CONFIG_KFENC=
E_SAMPLE_INTERVAL;
+static unsigned long kfence_sample_ns __read_mostly =3D 100000;
=20
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
 #endif
 #define MODULE_PARAM_PREFIX "kfence."
@@ -70,11 +70,11 @@ static int param_get_sample_interval(char *buffer, cons=
t struct kernel_param *kp
=20
 static const struct kernel_param_ops sample_interval_param_ops =3D {
 	.set =3D param_set_sample_interval,
 	.get =3D param_get_sample_interval,
 };
-module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sampl=
e_interval, 0600);
+module_param_cb(sample_ns, &sample_interval_param_ops, &kfence_sample_ns, =
0600);
=20
 /* The pool of pages used for guard pages and objects. */
 char *__kfence_pool;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
=20
@@ -87,18 +87,12 @@ struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NU=
M_OBJECTS];
=20
 /* Freelist with available objects. */
 static struct list_head kfence_freelist =3D LIST_HEAD_INIT(kfence_freelist=
);
 static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freel=
ist. */
=20
-/* The static key to set up a KFENCE allocation. */
-DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
-
 /* Gates the allocation, ensuring only one succeeds in a given period. */
-static atomic_t allocation_gate =3D ATOMIC_INIT(1);
-
-/* Wait queue to wake up allocation-gate timer task. */
-static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
+atomic_t allocation_gate =3D ATOMIC_INIT(1);
=20
 /* Statistics counters for debugfs. */
 enum kfence_counter_id {
 	KFENCE_COUNTER_ALLOCATED,
 	KFENCE_COUNTER_ALLOCS,
@@ -510,10 +504,11 @@ err:
 static int stats_show(struct seq_file *seq, void *v)
 {
 	int i;
=20
 	seq_printf(seq, "enabled: %i\n", READ_ONCE(kfence_enabled));
+	seq_printf(seq, "allocation_gate: %i\n", atomic_read(&allocation_gate));
 	for (i =3D 0; i < KFENCE_COUNTER_COUNT; i++)
 		seq_printf(seq, "%s: %ld\n", counter_names[i], atomic_long_read(&counter=
s[i]));
=20
 	return 0;
 }
@@ -608,49 +603,45 @@ late_initcall(kfence_debugfs_init);
  * with a total of 2 IPIs to all CPUs. If this ends up a problem in future=
 (with
  * more aggressive sampling intervals), we could get away with a variant t=
hat
  * avoids IPIs, at the cost of not immediately capturing allocations if th=
e
  * instructions remain cached.
  */
-static struct delayed_work kfence_timer;
-static void toggle_allocation_gate(struct work_struct *work)
+static struct hrtimer kfence_timer;
+
+static enum hrtimer_restart toggle_allocation_gate(struct hrtimer *timer)
 {
 	if (!READ_ONCE(kfence_enabled))
-		return;
+		return HRTIMER_NORESTART;
=20
-	/* Enable static key, and await allocation to happen. */
 	atomic_set(&allocation_gate, 0);
-	static_branch_enable(&kfence_allocation_key);
-	wait_event(allocation_wait, atomic_read(&allocation_gate) !=3D 0);
-
-	/* Disable static key and reset timer. */
-	static_branch_disable(&kfence_allocation_key);
-	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_inter=
val));
+	return HRTIMER_NORESTART;
 }
-static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
=20
 /* =3D=3D=3D Public interface =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */
=20
 void __init kfence_alloc_pool(void)
 {
-	if (!kfence_sample_interval)
+	if (!kfence_sample_ns)
 		return;
=20
 	__kfence_pool =3D phys_to_virt(memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE=
));
=20
 	if (!__kfence_pool)
 		pr_err("failed to allocate pool\n");
 }
=20
 void __init kfence_timer_init(void)
 {
-	schedule_delayed_work(&kfence_timer, 0);
+	hrtimer_init(&kfence_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
+	kfence_timer.function =3D toggle_allocation_gate;
+	hrtimer_start(&kfence_timer, ns_to_ktime(kfence_sample_ns), HRTIMER_MODE_=
REL);
 }
=20
 void __init kfence_init(void)
 {
-/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
-	if (!kfence_sample_interval)
+/* Setting kfence_sample_ns to 0 on boot disables KFENCE. */
+	if (!kfence_sample_ns)
 		return;
=20
 	if (!kfence_init_pool()) {
 		pr_err("%s failed\n", __func__);
 		return;
@@ -726,26 +717,29 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 	}
 }
=20
 void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
+	void *ret;
+
 	/*
 	 * allocation_gate only needs to become non-zero, so it doesn't make
 	 * sense to continue writing to it and pay the associated contention
 	 * cost, in case we have a large number of concurrent allocations.
 	 */
 	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) =
> 1)
 		return NULL;
-	wake_up(&allocation_wait);
+	hrtimer_start(&kfence_timer, ns_to_ktime(kfence_sample_ns), HRTIMER_MODE_=
REL);
=20
 	if (!READ_ONCE(kfence_enabled))
 		return NULL;
=20
 	if (size > PAGE_SIZE)
 		return NULL;
=20
-	return kfence_guarded_alloc(s, size, flags);
+	ret =3D kfence_guarded_alloc(s, size, flags);
+	return ret;
 }
=20
 size_t kfence_ksize(const void *addr)
 {
 	const struct kfence_metadata *meta =3D addr_to_metadata((unsigned long)ad=
dr);
--=20
2.25.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201208153632.GB2140704%40cork.
